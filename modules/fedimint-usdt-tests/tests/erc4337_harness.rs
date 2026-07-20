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

use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use anyhow::Context as _;
use fedimint_usdt_common::{EvmAddress, UsdtAmount};
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
