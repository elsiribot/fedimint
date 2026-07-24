//! **Phase 7 Task 4 gating acceptance test.** Proves the ERC-4337 v0.7
//! mechanics end-to-end on real `anvil` -- `initCode`-based counterfactual
//! account deployment via `handleOps`, `SimpleAccount`'s
//! `execute`-wrapped ERC-20 sweep, and EIP-191 signature validation -- using
//! a **hand-signed** `UserOp` (a local secp256k1 key as the account owner,
//! signed directly, not the group/MPC key). This deliberately isolates the
//! 4337 mechanics from MPC signing (Phase 6's signing loop just produces a
//! compact `(r, s)` over an arbitrary digest; a later phase combines the
//! two).
//!
//! Skips (rather than fails) if `anvil` isn't available in this
//! environment; see `common::spawn_anvil`.

mod common;

use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::Context as _;
use fedimint_core::secp256k1;
use fedimint_usdt_common::user_op::{SignedUserOp, eth_signed_message_hash, user_op_hash};
use fedimint_usdt_common::{EvmAddress, UsdtAmount};
use fedimint_usdt_server::rpc::{AlloyEvmRpc, IServerEvmRpc};
use fedimint_usdt_server::user_op::{
    DeployAndSweepParams, GasBounds, assemble_eth_signature, build_deploy_and_sweep_userop,
};

sol! {
    #[sol(rpc)]
    interface IErc20Balance {
        function balanceOf(address account) external view returns (uint256);
    }

    #[sol(rpc)]
    interface IEntryPointDeposit {
        function depositTo(address account) external payable;
    }
}

/// Comfortably covers `GasBounds::DEPLOY_AND_SWEEP_DEVNET`'s worst-case
/// prefund (`(verification_gas_limit + call_gas_limit +
/// pre_verification_gas) * max_fee_per_gas` = `800_000 * 30 gwei` = `0.024
/// ETH`) several times over.
const ENTRY_POINT_DEPOSIT_WEI: u128 = 1_000_000_000_000_000_000; // 1 ETH

/// Deterministic, distinct-from-each-other test claim keypairs, mirroring
/// `erc4337_harness.rs`'s `test_pubkey` convention.
fn test_secret_key(byte: u8) -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_slice(&[byte; 32]).expect("nonzero byte is a valid secp256k1 scalar")
}

#[tokio::test]
async fn hand_signed_userop_deploys_and_sweeps_a_counterfactual_account() -> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!(
            "SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE to an anvil binary, or \
             install foundry, and re-run)"
        );
        return Ok(());
    };

    // Mint the USDT fixture's initial supply to anvil account 1, so it can
    // fund the counterfactual deposit account below (mirroring
    // `erc4337_harness.rs`'s
    // `deposit_to_counterfactual_create2_account_is_detected`).
    let usdt_holder = common::anvil_account_1_address()?;
    let stack = common::deploy_4337_stack(&anvil, usdt_holder, UsdtAmount(10_000_000)).await?;

    // A LOCAL secp256k1 key stands in for the group/MPC key, isolating 4337
    // mechanics from MPC signing (see this file's module doc comment). The
    // deposit account's CREATE2 owner, this key's signature, and the
    // UserOp's `initCode` all correspond to this SAME key.
    let secp = secp256k1::Secp256k1::new();
    let local_owner_sk = test_secret_key(0x42);
    let local_owner_pk = local_owner_sk.public_key(&secp);
    let owner = fedimint_usdt_common::evm_address(&local_owner_pk);

    let claim_pk = test_secret_key(0x07).public_key(&secp);

    let deposit_account = fedimint_usdt_common::derive_deposit_account(
        &local_owner_pk,
        stack.factory,
        stack.simple_account_impl,
        &claim_pk,
    );

    let rpc = AlloyEvmRpc::new(anvil.url())?
        .with_broadcaster(common::ANVIL_ACCOUNT_0_PRIVATE_KEY)?
        .with_entry_point(stack.entry_point);

    // Sanity: genuinely counterfactual (no code) before the deploy-and-sweep
    // UserOp lands.
    assert_eq!(
        rpc.get_code_len(deposit_account).await?,
        0,
        "the derived deposit account must have no code before submitting the UserOp"
    );

    // Fund the counterfactual account with USDT ONLY (no ETH) -- the whole
    // point of the ERC-4337 model this module uses.
    let deposit_amount = UsdtAmount(4_000_000);
    common::transfer_erc20_from_account_1(&anvil, stack.usdt, deposit_account, deposit_amount)
        .await
        .context("failed to fund the counterfactual deposit account with USDT")?;

    let pool = EvmAddress([0x99; 20]);

    let params = DeployAndSweepParams {
        account_factory: stack.factory,
        usdt_contract: stack.usdt,
        deposit_account,
        owner,
        claim_pk,
        amount: deposit_amount,
        pool,
        // `SimpleAccount`'s very first op is always nonce 0.
        nonce: U256::ZERO,
        needs_deploy: true,
        paymaster_and_data: Vec::new(),
        gas_bounds: GasBounds::DEPLOY_AND_SWEEP_DEVNET,
    };
    let unsigned = build_deploy_and_sweep_userop(params);

    let chain_id = rpc.get_chain_id().await?;
    let hash = user_op_hash(&unsigned, stack.entry_point, chain_id);
    let signed_digest = eth_signed_message_hash(hash);

    let message = secp256k1::Message::from_digest(signed_digest);
    let recoverable = secp.sign_ecdsa_recoverable(&message, &local_owner_sk);
    let (_recid, compact_rs) = recoverable.serialize_compact();

    let signature = assemble_eth_signature(compact_rs, signed_digest, owner)
        .context("failed to assemble a 65-byte Ethereum signature from the local signature")?;

    let signed = SignedUserOp {
        unsigned,
        signature: signature.to_vec(),
    };

    // This task's `paymasterAndData` is deliberately empty (see the Phase-7
    // plan's paymaster-economics scope decision), so the `EntryPoint`
    // requires the SENDER to cover its own prefund (`AA21 didn't pay
    // prefund` otherwise) -- either from the account's own ETH balance, or
    // (as here) a pre-existing `EntryPoint` deposit credited to `sender`.
    // The broadcaster fronts this deposit directly rather than the deposit
    // account ever holding ETH itself, keeping the deposit account USDT-only
    // end to end; `handleOps`'s `beneficiary` (also the broadcaster) is
    // refunded the unused portion once the op executes. Real paymaster
    // economics (a token paymaster covering this from ITS OWN deposit, so
    // no broadcaster pre-funding step is needed at all) are Task 6/Phase 8.
    let broadcaster_signer: PrivateKeySigner = common::ANVIL_ACCOUNT_0_PRIVATE_KEY.parse()?;
    let broadcaster_provider = ProviderBuilder::new()
        .wallet(broadcaster_signer)
        .connect_http(anvil.url().parse()?);
    let entry_point_deposit =
        IEntryPointDeposit::new(Address::from(stack.entry_point.0), &broadcaster_provider);
    entry_point_deposit
        .depositTo(Address::from(deposit_account.0))
        .value(U256::from(ENTRY_POINT_DEPOSIT_WEI))
        .send()
        .await
        .context("failed to send EntryPoint.depositTo(deposit_account)")?
        .get_receipt()
        .await
        .context("failed to confirm EntryPoint.depositTo(deposit_account)")?;

    rpc.submit_user_ops(vec![signed])
        .await
        .context("submit_user_ops(handleOps) failed")?;

    let receipt = rpc
        .get_user_op_receipt(hash)
        .await
        .context("get_user_op_receipt failed")?
        .context("UserOperationEvent not found after handleOps confirmed")?;

    assert!(
        receipt.success,
        "the UserOp's callData execution (the USDT sweep) must have succeeded"
    );

    assert!(
        rpc.get_code_len(deposit_account).await? > 0,
        "the deposit account must be deployed (have code) after the deploy-and-sweep UserOp"
    );

    let provider = ProviderBuilder::new().connect_http(anvil.url().parse()?);
    let usdt = IErc20Balance::new(Address::from(stack.usdt.0), &provider);
    let pool_balance = usdt
        .balanceOf(Address::from(pool.0))
        .call()
        .await
        .context("failed to read the pool's post-sweep USDT balance")?;
    assert_eq!(
        pool_balance,
        U256::from(deposit_amount.0),
        "the pool must have received exactly the swept USDT amount"
    );

    Ok(())
}
