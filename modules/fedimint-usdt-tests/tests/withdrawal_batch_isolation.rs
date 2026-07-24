//! Phase 8 Task 2 fast isolation test: proves the pool `SimpleAccount`
//! `executeBatch` withdrawal-batch `UserOp` mechanics end-to-end on real
//! `anvil` -- WITHOUT MPC or the federation. Mirrors
//! `user_op_isolation.rs` (which proves the single-`execute` deploy-and-sweep
//! path) but for the withdrawal-batch path: a pool-like `SimpleAccount`
//! (owner = a LOCAL secp256k1 key, `salt = pool_salt()`) funded with USDT,
//! deployed + paying out N recipients in one `executeBatch`.
//!
//! Skips (rather than fails) if `anvil` isn't available.

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
    GasBounds, WithdrawalBatchParams, assemble_eth_signature, build_withdrawal_batch_userop,
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

const ENTRY_POINT_DEPOSIT_WEI: u128 = 1_000_000_000_000_000_000; // 1 ETH

fn test_secret_key(byte: u8) -> secp256k1::SecretKey {
    secp256k1::SecretKey::from_slice(&[byte; 32]).expect("nonzero byte is a valid secp256k1 scalar")
}

#[tokio::test]
async fn hand_signed_withdrawal_batch_deploys_pool_and_pays_recipients() -> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!("SKIP: anvil not available");
        return Ok(());
    };

    let usdt_holder = common::anvil_account_1_address()?;
    let stack = common::deploy_4337_stack(&anvil, usdt_holder, UsdtAmount(10_000_000)).await?;

    // A LOCAL secp256k1 key stands in for the group/MPC key (isolating 4337
    // mechanics from MPC signing). The pool account's CREATE2 owner, this
    // key's signature, and the UserOp's `initCode` all correspond to it.
    let secp = secp256k1::Secp256k1::new();
    let local_owner_sk = test_secret_key(0x42);
    let local_owner_pk = local_owner_sk.public_key(&secp);
    let owner = fedimint_usdt_common::evm_address(&local_owner_pk);

    // The pool account: same derivation as production
    // (`derive_pool_account`), owner = the local key.
    let pool_account = fedimint_usdt_common::derive_pool_account(
        &local_owner_pk,
        stack.factory,
        stack.simple_account_impl,
    );

    let rpc = AlloyEvmRpc::new(anvil.url())?
        .with_broadcaster(common::ANVIL_ACCOUNT_0_PRIVATE_KEY)?
        .with_entry_point(stack.entry_point);

    assert_eq!(
        rpc.get_code_len(pool_account).await?,
        0,
        "the pool account must have no code before submitting the UserOp"
    );

    // Fund the pool with USDT ONLY (as the sweep would have) -- enough to
    // cover the batch payouts.
    let pool_funding = UsdtAmount(5_000_000);
    common::transfer_erc20_from_account_1(&anvil, stack.usdt, pool_account, pool_funding)
        .await
        .context("failed to fund the pool account with USDT")?;

    // Two withdrawals to two distinct recipients.
    let recipient_a = EvmAddress([0x91; 20]);
    let recipient_b = EvmAddress([0x92; 20]);
    let amount_a = UsdtAmount(1_000_000);
    let amount_b = UsdtAmount(2_000_000);
    let withdrawals = vec![(recipient_a, amount_a), (recipient_b, amount_b)];

    let needs_deploy = true;
    let params = WithdrawalBatchParams {
        account_factory: stack.factory,
        usdt_contract: stack.usdt,
        pool: pool_account,
        owner,
        withdrawals: withdrawals.clone(),
        nonce: U256::ZERO,
        needs_deploy,
        paymaster_and_data: Vec::new(),
        gas_bounds: GasBounds::withdrawal_batch(withdrawals.len(), needs_deploy),
    };
    let unsigned = build_withdrawal_batch_userop(params);

    let chain_id = rpc.get_chain_id().await?;
    let hash = user_op_hash(&unsigned, stack.entry_point, chain_id);
    let signed_digest = eth_signed_message_hash(hash);

    let message = secp256k1::Message::from_digest(signed_digest);
    let recoverable = secp.sign_ecdsa_recoverable(&message, &local_owner_sk);
    let (_recid, compact_rs) = recoverable.serialize_compact();

    let signature = assemble_eth_signature(compact_rs, signed_digest, owner)
        .context("failed to assemble a 65-byte Ethereum signature")?;

    let signed = SignedUserOp {
        unsigned,
        signature: signature.to_vec(),
    };

    // Prefund the pool's EntryPoint deposit (empty paymasterAndData -> sender
    // pays its own prefund).
    let broadcaster_signer: PrivateKeySigner = common::ANVIL_ACCOUNT_0_PRIVATE_KEY.parse()?;
    let broadcaster_provider = ProviderBuilder::new()
        .wallet(broadcaster_signer)
        .connect_http(anvil.url().parse()?);
    let entry_point_deposit =
        IEntryPointDeposit::new(Address::from(stack.entry_point.0), &broadcaster_provider);
    entry_point_deposit
        .depositTo(Address::from(pool_account.0))
        .value(U256::from(ENTRY_POINT_DEPOSIT_WEI))
        .send()
        .await
        .context("failed to send EntryPoint.depositTo(pool_account)")?
        .get_receipt()
        .await
        .context("failed to confirm EntryPoint.depositTo(pool_account)")?;

    // Submit. Capture and print the FULL error chain if handleOps reverts
    // (an AA validation FailedOp), so the exact AA code is visible.
    match rpc.submit_user_ops(vec![signed]).await {
        Ok(()) => eprintln!("submit_user_ops: handleOps tx confirmed"),
        Err(err) => {
            eprintln!("submit_user_ops ERROR CHAIN:");
            for (i, cause) in err.chain().enumerate() {
                eprintln!("  [{i}] {cause}");
            }
            return Err(err).context("submit_user_ops(handleOps) failed");
        }
    }

    let receipt = rpc
        .get_user_op_receipt(hash)
        .await
        .context("get_user_op_receipt failed")?
        .context("UserOperationEvent not found after handleOps confirmed")?;

    eprintln!(
        "UserOperationEvent: success={} block={} actual_cost={:?}",
        receipt.success, receipt.block, receipt.actual_cost_usdt
    );

    assert!(
        receipt.success,
        "the UserOp's executeBatch execution (the withdrawal payouts) must have succeeded"
    );

    assert!(
        rpc.get_code_len(pool_account).await? > 0,
        "the pool account must be deployed (have code) after the withdrawal batch"
    );

    let provider = ProviderBuilder::new().connect_http(anvil.url().parse()?);
    let usdt = IErc20Balance::new(Address::from(stack.usdt.0), &provider);
    for (recipient, amount) in &withdrawals {
        let balance = usdt
            .balanceOf(Address::from(recipient.0))
            .call()
            .await
            .context("failed to read recipient USDT balance")?;
        assert_eq!(
            balance,
            U256::from(amount.0),
            "recipient must have received exactly the withdrawal amount"
        );
    }

    Ok(())
}
