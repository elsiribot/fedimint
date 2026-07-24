//! Hermetic integration test proving `fedimint_usdt_server::rpc::AlloyEvmRpc`
//! correctly reads chain and ERC-20 state from a real (if ephemeral) EVM
//! node. Spins up a local `anvil` dev-node, deploys the vendored `TestUsdt`
//! ERC-20 fixture to it, and reads it back over the wire — no mocking of the
//! JSON-RPC transport.
//!
//! Skips (rather than fails) if `anvil` isn't available in this environment;
//! see `common::spawn_anvil`.

mod common;

use fedimint_usdt_common::{EvmAddress, UsdtAmount};
use fedimint_usdt_server::rpc::{AlloyEvmRpc, IServerEvmRpc};

#[tokio::test]
async fn alloy_evm_rpc_reads_chain_and_erc20_state() -> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!(
            "SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE to an anvil binary, or \
             install foundry, and re-run)"
        );
        return Ok(());
    };

    let rpc = AlloyEvmRpc::new(anvil.url())?;

    // Chain id matches anvil's configured `--chain-id 31337`.
    assert_eq!(rpc.get_chain_id().await?, 31337);

    // Deploy the vendored TestUsdt fixture and seed anvil's account 1 (a
    // real, funded, key-controlled account, not an arbitrary address) with
    // 1 USDT (1_000_000 in its 6-decimal smallest unit) so we can later sign
    // a transfer *from* it.
    let holder = common::anvil_account_1_address()?;
    let token = common::deploy_test_erc20(&anvil, holder, UsdtAmount(1_000_000)).await?;

    let head_after_mint = rpc.get_block_number().await?;
    assert_eq!(
        rpc.get_erc20_balance(token, holder, head_after_mint)
            .await?,
        UsdtAmount(1_000_000)
    );

    // Code is present at the deployed token, absent at an arbitrary
    // (never-used) address.
    assert!(rpc.get_code_len(token).await? > 0);
    assert_eq!(rpc.get_code_len(EvmAddress([0x22; 20])).await?, 0);

    // Fee estimate returns a plausible non-zero max fee (anvil always has a
    // non-zero base fee) alongside the Phase 4 placeholder USDT/ETH price.
    let fee = rpc.get_fee_estimate().await?;
    assert!(fee.max_fee_per_gas_wei > 0);

    // CRITICAL: prove `at_block` addressing works, since Phase 5's deposit
    // detection depends on reading a stable, confirmed balance regardless of
    // how far the chain has since advanced. Record the current head, move
    // part of the holder's balance away, mine, then assert that reading at
    // the OLD head still shows the OLD (pre-transfer) balance, while reading
    // at the new head shows the reduced balance.
    let pre_transfer_block = rpc.get_block_number().await?;
    let other = EvmAddress([0x33; 20]);
    common::transfer_erc20_from_account_1(&anvil, token, other, UsdtAmount(400_000)).await?;
    let post_transfer_block = rpc.get_block_number().await?;
    assert!(
        post_transfer_block > pre_transfer_block,
        "the transfer must land in a new block"
    );

    assert_eq!(
        rpc.get_erc20_balance(token, holder, pre_transfer_block)
            .await?,
        UsdtAmount(1_000_000),
        "reading at the pre-transfer block must show the OLD balance"
    );
    assert_eq!(
        rpc.get_erc20_balance(token, holder, post_transfer_block)
            .await?,
        UsdtAmount(600_000),
        "reading at the post-transfer block must show the NEW balance"
    );

    Ok(())
}
