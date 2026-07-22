//! **Phase 8 Task 5 gating acceptance test.** Continues past
//! `deploy_and_sweep_e2e.rs`'s deposit-and-sweep gate into a full
//! **withdrawal**: the pool `SimpleAccount` is deployed by the first
//! withdrawal batch's `initCode` and pays a fresh EOA via a real
//! **MPC-signed** `executeBatch` `UserOp` submitted to the real `EntryPoint`
//! on `anvil`.
//!
//! Skips (rather than fails) if `anvil` isn't available in this environment;
//! see `common::spawn_anvil`.
//!
//! # Wiring, reusing `deploy_and_sweep_e2e.rs`'s two "real challenges"
//!
//! **Challenge A (deposit-account CREATE2 addressing before DKG)** is
//! handled identically to that test: deploy the 4337 stack FIRST, inject its
//! addresses into config-gen via `UsdtInit::with_gen_params`, then derive the
//! deposit account only after the federation's real group key exists.
//!
//! **Challenge B (gas prefund)** now applies TWICE: once for the deposit
//! account (the deploy-and-sweep leg, exactly as in
//! `deploy_and_sweep_e2e.rs`), and a SECOND time for the **pool**
//! `SimpleAccount` itself -- the withdrawal batch `UserOp` is sent from the
//! pool with an empty `paymasterAndData` (Phase 8 still owns real paymaster
//! economics; see that test's module doc comment for the scope decision this
//! mirrors), so the pool needs its own `EntryPoint` deposit prefunded by the
//! broadcaster before it can pay for its own `validateUserOp`/`executeBatch`
//! gas. This remains federation-fronts-ETH, NOT ETH-net-zero -- deferred to
//! Phase 8's paymaster work, same as the sweep leg.
//!
//! **New for this test -- e-cash funding.** Unlike `deploy_and_sweep_e2e.rs`
//! (which never touches e-cash), a withdrawal burns real `USDT_UNIT`-
//! denominated notes, so this federation needs a `mintv2` instance
//! registered as the primary module for `USDT_UNIT` (mirroring `tests.rs`'s
//! `dual_mint_fixtures`) -- `deploy_and_sweep_e2e.rs`'s plain `mint`-primary
//! fixture cannot fund a withdrawal at all.
//!
//! **New for this test -- the block-count-driven batch trigger.** The
//! consensus-critical `Usdt::maybe_trigger_withdrawal_batch` only fires once
//! `consensus_block_count() >= oldest_queued.requested_block +
//! batch_interval_blocks()` (or `BATCH_MAX_ITEMS` queued withdrawals pile
//! up). With `NEXTEST=1` set (this test's expected invocation),
//! `batch_interval_blocks()` is the small test-env value (`3`) rather than
//! the production `200`; `consensus_block_count` itself tracks the REAL
//! anvil chain height (via each guardian's 1s `block_count` poller reading
//! the shared real `AlloyEvmRpc`), not a mock counter. So, after `withdraw`
//! is accepted (which stamps `requested_block` at that moment's converged
//! consensus block count), this test mines a handful of extra empty `anvil`
//! blocks -- mirroring `deploy_and_sweep_e2e.rs`'s identical "mine past the
//! last real transaction" trick -- to push the real chain head (and hence,
//! within a poll cycle or two, `consensus_block_count`) past the interval
//! threshold.
//!
//! **New for this test -- dynamic 512-alignment.** This module's convention
//! (see `tests.rs`) is that every e-cash amount must be a 512-msat multiple
//! (`mintv2`'s smallest client denomination, avoiding denomination-rounding
//! dust that would break exact-equality assertions): the claim mints exactly
//! `deposit_amount`, and each withdrawal burns `amount + max_fee`, which must
//! itself land on a 512 multiple. `tests.rs` hardcodes this against a
//! *scripted* `MockEvmRpc` fee vote; this test drives a REAL node with a REAL
//! (anvil-default, decaying-over-idle-blocks) gas price, so instead of
//! assuming a fixed `quote % 512` remainder, it reads the federation's live
//! `withdraw_fee_quote`, derives `max_fee` from it (with a margin -- see
//! below), and pads a target `amount` up to whatever multiple of 512 makes
//! `amount + max_fee` land exactly on one, regardless of the real quote's
//! value.
//!
//! Slow (real anvil + real DKG + TWO real cggmp21 threshold-ECDSA MPC
//! sessions -- the sweep, then the withdrawal batch); intentionally run in
//! the foreground, not `#[ignore]`d.

mod common;

use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::{Context as _, bail};
use fedimint_client::ClientHandleArc;
use fedimint_core::runtime::{Instant, sleep};
use fedimint_core::{Amount, PeerId};
use fedimint_mintv2_client::MintClientInit as Mintv2ClientInit;
use fedimint_mintv2_common::KIND as MINTV2_KIND;
use fedimint_mintv2_common::config::MintGenParams;
use fedimint_mintv2_server::MintInit as Mintv2Init;
use fedimint_testing::fixtures::Fixtures;
use fedimint_usdt_client::{UsdtClientInit, UsdtClientModule};
use fedimint_usdt_common::{
    EvmAddress, FeeVote, USDT_UNIT, UsdtAmount, UsdtGenParams, WithdrawalStatus,
    withdrawal_fee_quote,
};
use fedimint_usdt_server::UsdtInit;
use fedimint_usdt_server::rpc::{AlloyEvmRpc, IServerEvmRpc};

sol! {
    #[sol(rpc)]
    interface IEntryPointDeposit {
        function depositTo(address account) external payable;
    }
}

/// Comfortably covers the worst-case first-withdrawal-batch prefund
/// (`GasBounds::withdrawal_batch(1, needs_deploy = true)`:
/// `(500_000 + 140_000 + 120_000) * 30 gwei` ~= `0.0228 ETH`) several times
/// over. Mirrors `deploy_and_sweep_e2e.rs`'s identical constant.
const ENTRY_POINT_DEPOSIT_WEI: u128 = 1_000_000_000_000_000_000; // 1 ETH

/// Mines `count` empty blocks on `anvil`, advancing its real chain head
/// without sending any transaction. Used twice in this test: once to work
/// around the same instant-mine confirmation-depth bug
/// `deploy_and_sweep_e2e.rs` documents (mining past the deposit-funding
/// transfer so the deposit checker's confirmed read lands at-or-after it),
/// and once to push the real chain head past the withdrawal batch's
/// `batch_interval_blocks()` threshold.
async fn mine_empty_blocks(anvil: &common::AnvilHandle, count: u32) -> anyhow::Result<()> {
    let provider = ProviderBuilder::new().connect_http(anvil.url().parse()?);
    for _ in 0..count {
        provider
            .raw_request::<_, String>("evm_mine".into(), ())
            .await
            .context("failed to mine an anvil block")?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn withdrawal_is_batched_deployed_and_paid_via_real_mpc_and_real_entrypoint()
-> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!(
            "SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE to an anvil binary, or \
             install foundry, and re-run)"
        );
        return Ok(());
    };

    // 1. Deploy the full ERC-4337 v0.7 stack on anvil FIRST (Challenge A), exactly
    //    like `deploy_and_sweep_e2e.rs`.
    let usdt_holder = common::anvil_account_1_address()?;
    let stack = common::deploy_4337_stack(&anvil, usdt_holder, UsdtAmount(50_000_000)).await?;

    // Deploy a mock Chainlink ETH/USD feed reporting a fixed $4000.00000000
    // (8 decimals), proving `AlloyEvmRpc::get_fee_estimate` reads a REAL
    // on-chain feed into the withdrawal fee quote rather than the static
    // `$3000` anvil fallback (see step 9's assertion below).
    const MOCK_FEED_ANSWER_E8: i128 = 4000_00000000;
    let price_feed = common::deploy_mock_price_feed(&anvil, MOCK_FEED_ANSWER_E8).await?;

    // 2. The REAL AlloyEvmRpc, broadcaster = anvil account 0, shared across every
    //    guardian.
    let evm_rpc: Arc<dyn IServerEvmRpc> = AlloyEvmRpc::new(anvil.url())?
        .with_broadcaster(common::ANVIL_ACCOUNT_0_PRIVATE_KEY)?
        .with_entry_point(stack.entry_point)
        // Point the shared injected RPC at the mock Chainlink feed deployed
        // above. This test injects a real `AlloyEvmRpc` via `with_evm_rpc`, so
        // `init()` uses THIS instance rather than building one from
        // `cfg.consensus` -- meaning the feed must be configured here (the
        // `gen_params.eth_usd_price_feed` below only drives the non-override
        // path). Without this, every guardian falls back to the static
        // `$3000` price and the Task-5 quote assertion below cannot pass.
        .with_price_feed(price_feed, 1_000_000)
        .into_dyn();

    // 3. Config-gen the federation with the REAL deployed addresses (Challenge A),
    //    with a `mintv2` instance registered as the USDT_UNIT primary module (New
    //    for this test -- e-cash funding; see this file's module doc comment).
    // Part A: the module self-deploys its own SimpleAccountFactory; config
    // points at the DERIVED (CREATE2) factory/impl addresses it will deploy
    // at, not a harness-deployed factory.
    let account_factory =
        fedimint_usdt_server::factory_bytecode::derive_account_factory(stack.entry_point);
    let simple_account_impl =
        fedimint_usdt_server::factory_bytecode::derive_simple_account_impl(account_factory);
    let gen_params = UsdtGenParams {
        usdt_contract: stack.usdt,
        chain_id: 31337,
        confirmation_depth: 1,
        entry_point: stack.entry_point,
        account_factory,
        simple_account_impl,
        check_ttl_blocks: 10_000,
        broadcaster_min_balance_wei: 0,
        // Point every guardian at the mock Chainlink feed deployed above
        // (real read, Task 3/5 of the ETH/USD price-feed plan) instead of
        // the static `$3000` fallback. A generously large staleness bound:
        // this test's real DKG + two real cggmp21 MPC sessions can take
        // several minutes of REAL anvil chain time, all of which must stay
        // within the feed's fixed `updatedAt` staleness window.
        eth_usd_price_feed: price_feed,
        price_feed_max_staleness_secs: 1_000_000,
    };

    let fed = Fixtures::new_primary(Mintv2ClientInit, Mintv2Init)
        .with_extra_module_instance(
            MINTV2_KIND,
            MintGenParams {
                amount_unit: USDT_UNIT,
            },
        )
        .with_module(
            UsdtClientInit,
            UsdtInit::with_evm_rpc(evm_rpc.clone()).with_gen_params(gen_params),
        )
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;

    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;
    let peers: Vec<PeerId> = usdt.all_peers().into_iter().collect();
    assert_eq!(
        peers.len(),
        4,
        "this test assumes the default 4-guardian fixture"
    );

    let broadcaster_signer: PrivateKeySigner = common::ANVIL_ACCOUNT_0_PRIVATE_KEY.parse()?;
    let broadcaster_provider = ProviderBuilder::new()
        .wallet(broadcaster_signer)
        .connect_http(anvil.url().parse()?);
    let entry_point_deposit =
        IEntryPointDeposit::new(Address::from(stack.entry_point.0), &broadcaster_provider);

    // 4. The pool `SimpleAccount`'s address is a pure function of config (group
    //    public key + factory + impl), so it's already known post-DKG, before any
    //    sweep or withdrawal has ever happened. Prefund ITS EntryPoint deposit now
    //    (Challenge B, pool leg) -- there is no race: the withdrawal batch below
    //    only reaches `handleOps` after real MPC signing completes, minutes later.
    let pool_account = usdt.pool_state(peers[0]).await?.account;
    entry_point_deposit
        .depositTo(Address::from(pool_account.0))
        .value(U256::from(ENTRY_POINT_DEPOSIT_WEI))
        .send()
        .await
        .context("failed to send EntryPoint.depositTo(pool_account)")?
        .get_receipt()
        .await
        .context("failed to confirm EntryPoint.depositTo(pool_account)")?;

    // 5. NOW derive the deposit account (Challenge A's second half) and prefund ITS
    //    EntryPoint deposit too (Challenge B, sweep leg) -- mirrors
    //    `deploy_and_sweep_e2e.rs` steps 4-5 exactly.
    //
    // Part C: wait for the readiness state machine to report Ready (real
    // deployed stack + funded broadcaster) before allocating -- the client
    // gates `allocate_deposit` on it.
    common::await_usdt_ready(&usdt, Duration::from_secs(60)).await?;
    let (claim_keypair, deposit_account) = usdt.allocate_deposit().await?;
    assert_eq!(
        evm_rpc.get_code_len(deposit_account).await?,
        0,
        "the counterfactual deposit account must have no code before the sweep"
    );
    entry_point_deposit
        .depositTo(Address::from(deposit_account.0))
        .value(U256::from(ENTRY_POINT_DEPOSIT_WEI))
        .send()
        .await
        .context("failed to send EntryPoint.depositTo(deposit_account)")?
        .get_receipt()
        .await
        .context("failed to confirm EntryPoint.depositTo(deposit_account)")?;

    // 6. Fund the counterfactual deposit account with USDT ONLY, then mine past the
    //    funding transfer (the same instant-mine confirmation-depth workaround
    //    `deploy_and_sweep_e2e.rs` documents in detail).
    //
    //    512-msat-aligned (Task-1/tests.rs convention): the claim below mints
    //    EXACTLY `deposit_amount` as e-cash notes, and it must comfortably cover
    //    the later withdrawal's `amount + max_fee` (also 512-aligned -- see step
    //    9's comment). `5_120_000 == 512 * 10_000`.
    let deposit_amount = UsdtAmount(5_120_000);
    common::transfer_erc20_from_account_1(&anvil, stack.usdt, deposit_account, deposit_amount)
        .await
        .context("failed to fund the counterfactual deposit account with USDT")?;
    mine_empty_blocks(&anvil, 5).await?;

    // 7. Check + claim: mints `deposit_amount` of USDT_UNIT e-cash into the
    //    client's spendable balance (needed to fund the withdrawal below).
    usdt.check_and_claim(&claim_keypair, Duration::from_secs(120))
        .await?;
    let claimed_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if client.get_balance_for_unit(USDT_UNIT).await? == Amount::from_msats(deposit_amount.0) {
            break;
        }
        if Instant::now() >= claimed_deadline {
            bail!("USDT e-cash was never minted before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    }

    // 8. The automatic deploy-and-sweep pipeline (Phase 7) deploys the deposit
    //    account and sweeps it to the pool via a real MPC-signed UserOp -- poll to
    //    convergence on every guardian, exactly like `deploy_and_sweep_e2e.rs`.
    for &peer in &peers {
        let deadline = Instant::now() + Duration::from_secs(600);
        loop {
            let pool = usdt.pool_state(peer).await?;
            if pool.balance == deposit_amount {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "guardian {peer} PoolState.balance never converged to the swept amount \
                     before the deadline (last read {})",
                    pool.balance
                );
            }
            sleep(Duration::from_secs(2)).await;
        }
    }
    assert!(
        evm_rpc.get_code_len(deposit_account).await? > 0,
        "the deposit account must have code after the deploy-and-sweep UserOp"
    );

    // 9. Fetch a fresh withdrawal fee quote and derive a 512-aligned
    //    `amount`/`max_fee` pair from it live (New for this test -- dynamic
    //    512-alignment; see this file's module doc comment for why this can't be a
    //    hardcoded constant like `tests.rs`'s). The FeeVote consensus has had
    //    several minutes (the whole deposit+sweep above) to converge, so this
    //    should resolve near-instantly; a short poll guards against any residual
    //    race.
    let quote_deadline = Instant::now() + Duration::from_secs(30);
    let raw_quote = loop {
        let quote = usdt.withdraw_fee_quote(UsdtAmount(1_000_000)).await?;
        if quote.max_fee.0 != 0 {
            break quote.max_fee;
        }
        if Instant::now() >= quote_deadline {
            bail!("withdraw_fee_quote never converged to a nonzero quote before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };

    // THE TASK-5 GATE: the federation's live quote (fed by every guardian's
    // real read of the mock $4000 Chainlink feed configured above) must be
    // STRICTLY GREATER than what the same pure `withdrawal_fee_quote` formula
    // would produce for the same gas price at the static `$3000` fallback --
    // proving the on-chain feed read, not the placeholder, drove the quote.
    // `evm_rpc` (this harness's own `AlloyEvmRpc`, built above with no
    // `.with_price_feed(..)`) reads the SAME live anvil gas price the
    // guardians just voted with, but falls back to the static
    // `usdt_per_eth_e6 == 3_000_000_000` price (no feed configured), giving
    // an apples-to-apples baseline via the real formula rather than a magic
    // number.
    let baseline_fee_vote = evm_rpc.get_fee_estimate().await?;
    let baseline_quote = withdrawal_fee_quote(&FeeVote {
        max_fee_per_gas_wei: baseline_fee_vote.max_fee_per_gas_wei,
        usdt_per_eth_e6: 3_000_000_000,
    })
    .context("baseline withdrawal_fee_quote must not overflow for a realistic anvil gas price")?;
    assert!(
        raw_quote.0 > baseline_quote.0,
        "the live quote ({raw_quote}), driven by the mock $4000 Chainlink feed, must exceed the \
         same formula's output at the static $3000 fallback ({baseline_quote}) -- otherwise the \
         real on-chain feed read isn't actually driving the quote"
    );

    // 20% margin over the live quote, covering fee-market movement between this
    // read and the withdrawal transaction actually being processed (mirrors
    // `WITHDRAWAL_FEE_BUFFER_PERCENT`'s own rationale in `-common`, applied again
    // here on top of it since this is a real, non-scripted node).
    let max_fee = UsdtAmount(raw_quote.0 + raw_quote.0 / 5);
    let target_amount: u64 = 2_000_000;
    let remainder = (target_amount + max_fee.0) % 512;
    let padding = if remainder == 0 { 0 } else { 512 - remainder };
    let amount = UsdtAmount(target_amount + padding);
    assert_eq!(
        (amount.0 + max_fee.0) % 512,
        0,
        "amount + max_fee must be 512-aligned so the withdrawal burns notes with no \
         denomination-rounding dust"
    );
    if amount.0 + max_fee.0 > deposit_amount.0 {
        bail!(
            "chosen amount ({amount}) + max_fee ({max_fee}) exceeds deposit_amount \
             ({deposit_amount}) -- the live fee quote came back higher than expected"
        );
    }

    // 10. Submit the withdrawal: burns `amount + max_fee` of e-cash, enqueues an
    //     on-chain payout of `amount` to a fresh recipient EOA. `withdraw` awaits
    //     the transaction's consensus acceptance before returning, which is when
    //     the server stamps `requested_block` for the batch-trigger interval (see
    //     step 11).
    let recipient = EvmAddress([0x42; 20]);
    let range = usdt.withdraw(recipient, amount, max_fee).await?;
    let out_point = UsdtClientModule::withdrawal_out_point(&range);

    // 11. Mine extra empty blocks to push the REAL anvil chain head (and hence,
    //     within a guardian poll cycle, `consensus_block_count`) past
    //     `batch_interval_blocks()` (New for this test -- the block-count-driven
    //     batch trigger; see this file's module doc comment). With `NEXTEST=1` this
    //     threshold is `3`; mining well beyond that is a cheap safety margin.
    mine_empty_blocks(&anvil, 15).await?;

    // 12. `maybe_trigger_withdrawal_batch` fires once the interval elapses,
    //     batching this (sole) queued withdrawal into a `Withdraw`-purpose UserOp:
    //     `needs_deploy = true` (the pool's first-ever op), so its `initCode`
    //     deploys the pool `SimpleAccount` via the real `SimpleAccountFactory`.
    //     Real MPC signs it, the guardian-local submitter calls `handleOps` on the
    //     real EntryPoint, and the federation threshold-votes `UserOpConfirmed`.
    //     `await_withdrawal_confirmed` (Task 3) polls `withdrawal_status` to
    //     convergence for us; a generous deadline for real MPC + a real chain
    //     round-trip.
    let confirmed_block = usdt
        .await_withdrawal_confirmed(out_point, Duration::from_secs(600))
        .await
        .context("withdrawal never reached WithdrawalState::Confirmed")?;

    // 13. THE PHASE-8 GATE.

    // (a) The recipient's ON-CHAIN USDT balance equals the withdrawn amount --
    //     read directly from anvil via the real AlloyEvmRpc, independent of the
    //     federation's own bookkeeping.
    let latest_block = evm_rpc.get_block_number().await?;
    let recipient_balance = evm_rpc
        .get_erc20_balance(stack.usdt, recipient, latest_block)
        .await
        .context("failed to read the recipient's on-chain USDT balance")?;
    assert_eq!(
        recipient_balance, amount,
        "the recipient's on-chain USDT balance must equal the withdrawn amount"
    );

    // (b) The pool account now has code -- proving the batch's `initCode` really
    //     deployed it via the real SimpleAccountFactory, not just executed a call
    //     against an already-existing account.
    assert!(
        evm_rpc.get_code_len(pool_account).await? > 0,
        "the pool account must have code after the first withdrawal batch's initCode deploy"
    );

    // (c) The federation's consensus-agreed PoolState.balance is debited by
    //     EXACTLY `amount` (NOT `amount + max_fee` -- the fee was already burned
    //     from e-cash and accrues to the federation, mirroring `tests.rs`) on
    //     EVERY guardian.
    let expected_pool_balance = UsdtAmount(deposit_amount.0 - amount.0);
    for &peer in &peers {
        let pool = usdt.pool_state(peer).await?;
        assert_eq!(
            pool.balance, expected_pool_balance,
            "guardian {peer}'s consensus PoolState.balance must be debited by exactly the \
             withdrawn amount"
        );
    }

    // (d) The withdrawal's consensus-agreed status is Confirmed (Task 3's
    //     `withdrawal_status` endpoint), at the same block `await_withdrawal_
    //     confirmed` returned above.
    let status = usdt.withdrawal_status(out_point).await?.status;
    assert_eq!(
        status,
        WithdrawalStatus::Confirmed {
            block: confirmed_block
        },
        "withdrawal_status must report Confirmed at the block the UserOp landed"
    );

    // (e) ETH-net-zero / gas-paid-in-USDT via a real paymaster remains DEFERRED to
    //     Phase 8's paymaster work (see this file's module doc comment) -- not
    //     asserted here, mirroring `deploy_and_sweep_e2e.rs`'s identical
    //     deferral. What's proven above is the Phase-8 gate itself: a queued
    //     withdrawal batched, MPC-signed, and paid out on the real EntryPoint,
    //     deploying the pool via its own initCode along the way.

    Ok(())
}
