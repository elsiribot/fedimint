//! **Drill B** (Phase 9 resilience, hardening-acceptance-audit plan Task 1):
//! a hermetic `anvil` reorg drill proving that
//! `AlloyEvmRpc::get_erc20_balance`, read at the deposit-checker's confirmed
//! block (mirroring `scan_pending_deposits`'s `head - confirmation_depth`
//! read, see `fedimint-usdt-server/src/lib.rs`), correctly reflects an
//! `anvil_reorg` that reorganizes a deposit-crediting transfer out of the
//! canonical chain -- i.e. the confirmed read the deposit checker would use
//! never observes funds that no longer exist post-reorg.
//!
//! This is the real-chain complement to the hermetic reorg coverage in
//! `fedimint-usdt-server/src/lib.rs` (the block-hash-ring anchor + proof
//! tests, which prove the module's own consensus logic only ever credits
//! against a threshold-agreed, confirmation-deep anchor); this drill
//! proves the OTHER half -- that the `AlloyEvmRpc` adapter's `at_block`
//! reads against a REAL node correctly observe a real reorg's effect,
//! rather than caching/misreading stale state.
//!
//! Skips (rather than fails) if `anvil` isn't available (see
//! `common::spawn_anvil`) or if the installed anvil doesn't implement
//! `anvil_reorg` (`std::io::ErrorKind`/RPC-method-not-found style failure).
//!
//! # `anvil_reorg` probe result (this environment)
//!
//! Verified directly (outside this test, via raw JSON-RPC against a scratch
//! `anvil --port <n> --chain-id 31337`, and separately via this test's own
//! [`anvil_reorg`] helper) against the PATH-resolved `anvil` binary
//! (foundry 1.4.4-dev): `anvil_reorg(depth, tx_block_pairs)` **is available
//! and works as documented** -- `anvil_reorg(5, [])` on a 10-block chain
//! replaces the hash of every block strictly above `head - depth` with a
//! freshly-mined (empty, since `tx_block_pairs` was empty) block, leaves
//! blocks at/below that height byte-identical, and leaves the head HEIGHT
//! unchanged (blocks are replaced 1:1, not truncated). This test relies on
//! exactly that behavior.
//!
//! # Reorg-depth precision matters
//!
//! `reorg_depth` is computed to reorg out exactly the deposit's own mint
//! block and everything after it, while deliberately leaving the token
//! CONTRACT'S deployment block untouched. Reorging deep enough to also
//! evict the contract's own deployment would make `balanceOf` calls at that
//! historical height fail with a "not a contract" / empty-return-data
//! decode error (correct EVM behavior for calling an address with no code)
//! rather than cleanly returning a zero balance -- which is a real footgun
//! this test hit and fixed while developing this drill, not a claim that
//! such a call is somehow wrong: it just means the test must reorg
//! precisely the transaction under test, not "deep enough plus a margin"
//! the way the confirmation-depth margin elsewhere in this harness does.
mod common;

use std::time::Duration;

use alloy::providers::{Provider, ProviderBuilder};
use anyhow::Context as _;
use fedimint_core::runtime::sleep;
use fedimint_usdt_common::{EvmAddress, UsdtAmount};
use fedimint_usdt_server::rpc::{AlloyEvmRpc, IServerEvmRpc};

/// Issues the `anvil_reorg` RPC directly against `anvil`, reorging the last
/// `depth` blocks with freshly-mined EMPTY blocks (no `tx_block_pairs`), via
/// the same `raw_request` pattern `tests/deploy_and_sweep_e2e.rs` and
/// `tests/withdraw_e2e.rs` already use for `evm_mine`.
///
/// # Errors
///
/// Returns an error if the RPC call itself fails (including "method not
/// found", covering an anvil build without reorg support) -- callers that
/// want to skip rather than fail on that should inspect the error.
async fn anvil_reorg(anvil: &common::AnvilHandle, depth: u64) -> anyhow::Result<()> {
    let provider =
        ProviderBuilder::new().connect_http(anvil.url().parse().context("invalid anvil URL")?);
    provider
        .raw_request::<_, Option<serde_json::Value>>(
            "anvil_reorg".into(),
            (depth, Vec::<serde_json::Value>::new()),
        )
        .await
        .map(|_| ())
        .context("anvil_reorg RPC call failed")
}

/// Reads `get_erc20_balance(token, holder, at_block)`, retrying a bounded
/// number of times on error before giving up. Defensive, not required to
/// make this specific test pass (it doesn't paper over any observed
/// flakiness here) -- but it mirrors exactly how `scan_pending_deposits`
/// itself already treats a failed `get_erc20_balance` call in production
/// (never trusting a single failed read as authoritative; see that
/// function's `Err(err) => { debug!(...); continue; }` arm in
/// `fedimint-usdt-server/src/lib.rs`), which is the right posture for any
/// test driving a real RPC endpoint too.
///
/// # Errors
///
/// Returns the last error if every attempt fails.
async fn read_balance_retrying(
    rpc: &AlloyEvmRpc,
    token: EvmAddress,
    holder: EvmAddress,
    at_block: u64,
) -> anyhow::Result<UsdtAmount> {
    let mut last_err = None;
    for _ in 0..20 {
        match rpc.get_erc20_balance(token, holder, at_block).await {
            Ok(balance) => return Ok(balance),
            Err(err) => last_err = Some(err),
        }
        sleep(Duration::from_millis(50)).await;
    }
    Err(last_err.expect("the loop above always runs at least once"))
}

#[tokio::test]
async fn anvil_reorg_evicts_a_deposit_transfer_from_the_confirmed_read_block() -> anyhow::Result<()>
{
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!(
            "SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE to an anvil binary, or \
             install foundry, and re-run)"
        );
        return Ok(());
    };

    let rpc = AlloyEvmRpc::new(anvil.url())?;

    // Probe `anvil_reorg` availability/reliability BEFORE anything
    // drill-relevant happens: some anvil builds don't implement it, and the
    // probe reorg itself perturbs whatever the current head block is, so it
    // must run against a throwaway empty block, not the deposit's own
    // block. If it errors here, skip the rest of this drill rather than
    // failing the suite (per the Phase-9 task's "SKIP if
    // unavailable/unreliable, rely on Drill A" instruction).
    let mine_provider =
        ProviderBuilder::new().connect_http(anvil.url().parse().context("invalid anvil URL")?);
    mine_provider
        .raw_request::<_, String>("evm_mine".into(), ())
        .await
        .context("failed to mine a throwaway probe block")?;
    if let Err(err) = anvil_reorg(&anvil, 1).await {
        eprintln!(
            "SKIP: this anvil build does not support (or errored on) anvil_reorg: \
             {err:#}. Relying on Drill A's hermetic MockEvmRpc reorg tests instead."
        );
        return Ok(());
    }

    // Deploy the token and mint `deposit_amount` to anvil's account 1 (a
    // real, key-controlled account -- needed since the "deposit" below must
    // be a signed transfer FROM somewhere), settling in its own early
    // blocks. The reorg below must evict only the LATER transfer (the
    // "deposit"), not this deployment -- see this module's "Reorg-depth
    // precision matters" doc comment for why that distinction matters.
    let holder = EvmAddress([0x44; 20]);
    let deposit_amount = UsdtAmount(4_000_000);
    let account_1 = common::anvil_account_1_address()?;
    let token = common::deploy_test_erc20(&anvil, account_1, deposit_amount).await?;

    // A "deposit": transfer `deposit_amount` from account 1 to `holder`,
    // exactly mirroring how `evm_adapter.rs` proves `at_block` addressing --
    // this transfer is the ONLY thing that ever credits `holder`, so if it
    // gets reorged out, `holder`'s balance at any post-reorg block must
    // read back to zero.
    common::transfer_erc20_from_account_1(&anvil, token, holder, deposit_amount).await?;
    let deposit_block = rpc.get_block_number().await?;

    // Mine `confirmation_depth` blocks worth of margin on top of the mint,
    // mirroring `scan_pending_deposits`'s `head - confirmation_depth` read
    // and `deploy_and_sweep_e2e.rs`'s identical need to advance the head
    // past the funding transaction before a confirmed read can see it.
    let confirmation_depth = 6u64;
    let mine_provider =
        ProviderBuilder::new().connect_http(anvil.url().parse().context("invalid anvil URL")?);
    for _ in 0..confirmation_depth {
        mine_provider
            .raw_request::<_, String>("evm_mine".into(), ())
            .await
            .context("failed to mine an anvil block past the mint")?;
    }

    let head_before_reorg = rpc.get_block_number().await?;
    let confirmed_read_block = head_before_reorg.saturating_sub(confirmation_depth);
    assert!(
        confirmed_read_block >= deposit_block,
        "test setup: the confirmed read block ({confirmed_read_block}) must be at or after \
         the deposit's block ({deposit_block})"
    );

    // Sanity: BEFORE the reorg, the confirmed read a real deposit-checker
    // would perform sees the deposit.
    assert_eq!(
        read_balance_retrying(&rpc, token, holder, confirmed_read_block).await?,
        deposit_amount,
        "pre-reorg: the confirmed read must see the deposit"
    );

    // Reorg out EXACTLY the mint's block and everything after it -- NOT the
    // token contract's own (earlier) deployment block, which must survive
    // so `balanceOf` stays queryable post-reorg (see this module's
    // "Reorg-depth precision matters" doc comment).
    let reorg_depth = head_before_reorg - deposit_block + 1;
    anvil_reorg(&anvil, reorg_depth)
        .await
        .context("anvil_reorg failed after the availability probe already succeeded")?;

    let head_after_reorg = rpc.get_block_number().await?;
    assert_eq!(
        head_after_reorg, head_before_reorg,
        "anvil_reorg replaces blocks 1:1 (per this test's probed behavior); the head height \
         must be unchanged"
    );

    // THE ASSERTION: reading at the SAME confirmed block number post-reorg
    // must now show the pre-mint (zero) balance -- the deposit checker's
    // confirmed read must never credit funds that no longer exist on the
    // new canonical chain.
    assert_eq!(
        read_balance_retrying(&rpc, token, holder, confirmed_read_block).await?,
        UsdtAmount(0),
        "post-reorg: the confirmed read must NOT see the reorged-out deposit"
    );
    // Also true at the fresh head, for completeness.
    assert_eq!(
        read_balance_retrying(&rpc, token, holder, head_after_reorg).await?,
        UsdtAmount(0),
        "post-reorg: the current head must not show the reorged-out deposit either"
    );

    Ok(())
}
