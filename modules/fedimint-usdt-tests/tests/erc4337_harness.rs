//! Hermetic integration test proving the Phase-7 Task 1 anvil harness
//! (`common::deploy_4337_stack`) brings up a working ERC-4337 v0.7 stack:
//! a canonical `EntryPoint` with real code, a `SimpleAccountFactory` that
//! answers `getAddress`, a staked and deposit-funded paymaster, and the
//! vendored USDT ERC-20 fixture. Touches no consensus/determinism surface
//! (see `modules/fedimint-usdt-server`'s config-gen tests for that).
//!
//! Skips (rather than fails) if `anvil` isn't available in this
//! environment; see `common::spawn_anvil`.

mod common;

use alloy::primitives::{Address, U256, keccak256};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use anyhow::Context as _;
use fedimint_core::secp256k1;
use fedimint_usdt_common::{DEPOSIT_ADDRESS_DOMAIN, EvmAddress, UsdtAmount};
use fedimint_usdt_server::rpc::{AlloyEvmRpc, IServerEvmRpc};

sol! {
    #[sol(rpc)]
    interface ISimpleAccountFactory {
        function getAddress(address owner, uint256 salt) external view returns (address);
    }
}

sol! {
    #[sol(rpc)]
    interface IPaymasterDeposit {
        function getDeposit() external view returns (uint256);
    }
}

sol! {
    #[sol(rpc)]
    interface IErc20Decimals {
        function decimals() external view returns (uint8);
    }
}

#[tokio::test]
async fn deploy_4337_stack_brings_up_a_working_stack() -> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!(
            "SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE to an anvil binary, or \
             install foundry, and re-run)"
        );
        return Ok(());
    };

    let rpc = AlloyEvmRpc::new(anvil.url())?;

    // Arbitrary future USDT holder; the harness only needs *an* address to
    // mint the fixture to.
    let usdt_holder = EvmAddress([0x42; 20]);
    let stack = common::deploy_4337_stack(&anvil, usdt_holder, UsdtAmount(5_000_000)).await?;

    // 1. EntryPoint has real code at the canonical address.
    assert!(
        rpc.get_code_len(stack.entry_point).await? > 0,
        "EntryPoint must have non-empty code at the canonical address"
    );

    let provider = ProviderBuilder::new().connect_http(anvil.url().parse()?);

    // 2. SimpleAccountFactory.getAddress(owner, salt) resolves to a 20-byte address
    //    (the CREATE2-derived counterfactual account address) for an arbitrary
    //    owner/salt pair.
    let factory = ISimpleAccountFactory::new(Address::from(stack.factory.0), &provider);
    let owner = Address::from([0x11; 20]);
    let salt = U256::from(1u64);
    let derived = factory
        .getAddress(owner, salt)
        .call()
        .await
        .context("factory.getAddress(owner, salt) eth_call failed")?;
    assert_ne!(
        derived,
        Address::ZERO,
        "factory.getAddress must resolve to a non-zero counterfactual address"
    );

    // 3. The paymaster is staked and deposit-funded on the EntryPoint.
    let paymaster = IPaymasterDeposit::new(Address::from(stack.paymaster.0), &provider);
    let deposit = paymaster
        .getDeposit()
        .call()
        .await
        .context("paymaster.getDeposit() eth_call failed")?;
    assert!(
        deposit > U256::ZERO,
        "paymaster EntryPoint deposit must be > 0"
    );

    // 4. The USDT fixture is a real 6-decimal ERC-20.
    let usdt = IErc20Decimals::new(Address::from(stack.usdt.0), &provider);
    let decimals = usdt
        .decimals()
        .call()
        .await
        .context("usdt.decimals() eth_call failed")?;
    assert_eq!(decimals, 6, "USDT fixture must report 6 decimals");

    Ok(())
}

/// Deterministic, distinct-from-each-other test claim keypairs (fixed
/// non-zero secp256k1 scalars, mirroring `fedimint-usdt-server`'s
/// `test_pubkey` test helper convention).
fn test_pubkey(byte: u8) -> secp256k1::PublicKey {
    secp256k1::SecretKey::from_slice(&[byte; 32])
        .expect("nonzero byte is a valid secp256k1 scalar")
        .public_key(secp256k1::SECP256K1)
}

/// **Phase 7 Task 2 gating acceptance test.** Pins off-chain
/// `fedimint_usdt_common::derive_deposit_account`'s CREATE2 math against the
/// real, anvil-deployed `SimpleAccountFactory.getAddress`: for 3 distinct
/// claim keys, the two must agree byte-for-byte. `salt` is computed here
/// independently of `derive_deposit_account`'s own internals (straight from
/// the public [`DEPOSIT_ADDRESS_DOMAIN`] constant and `claim_pk`'s
/// serialization) so this test cannot pass merely because both sides share
/// a (potentially buggy) salt helper -- it genuinely cross-checks the
/// off-chain `ERC1967Proxy`-creation-code/`initCode`-hash construction
/// against the on-chain factory.
#[tokio::test]
async fn derive_deposit_account_matches_factory_get_address() -> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!(
            "SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE to an anvil binary, or \
             install foundry, and re-run)"
        );
        return Ok(());
    };

    let usdt_holder = EvmAddress([0x42; 20]);
    let stack = common::deploy_4337_stack(&anvil, usdt_holder, UsdtAmount(0)).await?;

    let provider = ProviderBuilder::new().connect_http(anvil.url().parse()?);
    let factory = ISimpleAccountFactory::new(Address::from(stack.factory.0), &provider);

    // An arbitrary (not-a-real-DKG-group) group public key: this test pins
    // pure CREATE2 address math, not MPC custody, so any valid secp256k1
    // point works.
    let group_pk = test_pubkey(0xaa);
    let owner = Address::from(fedimint_usdt_common::evm_address(&group_pk).0);

    for claim_byte in [0x01u8, 0x02, 0x03] {
        let claim_pk = test_pubkey(claim_byte);

        // Independently reproduce `derive_deposit_account`'s salt formula
        // (`keccak256(DEPOSIT_ADDRESS_DOMAIN ‖ claim_pk.serialize())`) rather
        // than calling any -common helper for it.
        let mut salt_preimage = DEPOSIT_ADDRESS_DOMAIN.to_vec();
        salt_preimage.extend_from_slice(&claim_pk.serialize());
        let salt = U256::from_be_bytes(keccak256(salt_preimage).0);

        let onchain = factory
            .getAddress(owner, salt)
            .call()
            .await
            .with_context(|| {
                format!("factory.getAddress eth_call failed for claim {claim_byte:#04x}")
            })?;

        let offchain = fedimint_usdt_common::derive_deposit_account(
            &group_pk,
            stack.factory,
            stack.simple_account_impl,
            &claim_pk,
        );

        assert_eq!(
            Address::from(offchain.0),
            onchain,
            "off-chain derive_deposit_account must match on-chain \
             SimpleAccountFactory.getAddress for claim key {claim_byte:#04x}"
        );
    }

    Ok(())
}

/// Deposit-detection regression (Phase 7 Task 2): a USDT `transfer` to a
/// *counterfactual* (no code deployed yet) CREATE2 `SimpleAccount` address
/// must still be visible via `AlloyEvmRpc::get_erc20_balance`, exactly like
/// Phase 5's EOA deposit addresses. The whole point of the CREATE2 model is
/// that the account only gets deployed lazily on first sweep (Task 4+); if
/// balance reads silently required code to exist first, deposits would
/// never be observed.
#[tokio::test]
async fn deposit_to_counterfactual_create2_account_is_detected() -> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!(
            "SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE to an anvil binary, or \
             install foundry, and re-run)"
        );
        return Ok(());
    };

    // Mint the USDT fixture's initial supply to anvil account 1, so
    // `common::transfer_erc20_from_account_1` can move some of it to the
    // derived deposit account below.
    let usdt_holder = common::anvil_account_1_address()?;
    let stack = common::deploy_4337_stack(&anvil, usdt_holder, UsdtAmount(10_000_000)).await?;

    let group_pk = test_pubkey(0xbb);
    let claim_pk = test_pubkey(0x07);
    let deposit_account = fedimint_usdt_common::derive_deposit_account(
        &group_pk,
        stack.factory,
        stack.simple_account_impl,
        &claim_pk,
    );

    let rpc = AlloyEvmRpc::new(anvil.url())?;

    // Confirm the account is genuinely counterfactual (no code) before the
    // deposit -- otherwise this test wouldn't actually be exercising the
    // "code-less address" case it claims to.
    assert_eq!(
        rpc.get_code_len(deposit_account).await?,
        0,
        "the derived deposit account must have no code before any deploy-and-sweep UserOp"
    );

    let deposit_amount = UsdtAmount(1_500_000);
    common::transfer_erc20_from_account_1(&anvil, stack.usdt, deposit_account, deposit_amount)
        .await
        .context("failed to transfer USDT to the counterfactual deposit account")?;

    let at_block = rpc
        .get_block_number()
        .await
        .context("failed to read the post-transfer block number")?;
    let observed = rpc
        .get_erc20_balance(stack.usdt, deposit_account, at_block)
        .await
        .context("failed to read the counterfactual deposit account's USDT balance")?;

    assert_eq!(
        observed, deposit_amount,
        "a USDT transfer to a counterfactual (code-less) CREATE2 SimpleAccount address must \
         still be visible via get_erc20_balance"
    );

    Ok(())
}
