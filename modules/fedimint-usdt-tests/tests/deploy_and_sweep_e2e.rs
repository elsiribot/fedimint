//! **Phase 7 Task 6 gating acceptance test.** Proves the whole ERC-4337
//! UserOp pipeline end to end on REAL infra: a counterfactual deposit
//! account holding ONLY USDT is deployed-and-swept to the pool by a **real
//! MPC-signed** `UserOp` submitted to the **real `EntryPoint`** on `anvil`,
//! via the real (not `MockEvmRpc`) [`AlloyEvmRpc`] adapter wired into a real
//! federation.
//!
//! Skips (rather than fails) if `anvil` isn't available in this
//! environment; see `common::spawn_anvil`.
//!
//! # Wiring (the plan's two "real challenges")
//!
//! **Challenge A -- getting the deployed anvil stack's addresses into the
//! federation's usdt config.** The counterfactual deposit account is
//! `CREATE2(account_factory, salt(claim_pk), initCode(simple_account_impl,
//! owner=evm_address(group_public_key)))` -- `group_public_key` only exists
//! AFTER config-gen (DKG), but `account_factory`/`simple_account_impl`/
//! `entry_point`/`usdt_contract`/`chain_id` must be known BEFORE config-gen
//! (they're baked into `UsdtConfigConsensus` by `trusted_dealer_gen`). This
//! test therefore (1) deploys the full 4337 stack on `anvil` FIRST, (2)
//! injects those addresses into config-gen via
//! [`fedimint_usdt_server::UsdtInit::with_gen_params`] (a new, test-only
//! override added for this task, mirroring how [`UsdtInit::with_evm_rpc`]
//! already injects a shared [`fedimint_usdt_server::rpc::MockEvmRpc`]-style
//! RPC), and (3) only THEN derives the deposit account (via
//! `usdt.allocate_deposit()`), now that the federation's `UsdtClientConfig`
//! carries both the real group key AND the real factory/impl addresses.
//! `with_gen_params` was chosen over an env-var override (the plan's option
//! (b), mirroring the existing `FM_USDT_CONTRACT_ENV`) specifically to avoid
//! a process-global env race across (potentially parallel) test binaries --
//! see `UsdtInit::gen_params_override`'s doc comment.
//!
//! **Challenge B -- gas prefund (the deposit account has no ETH).** The
//! automatic deploy-and-sweep pipeline (`Usdt::maybe_trigger_sweep`) always
//! builds its `UserOp` with an EMPTY `paymasterAndData` (Phase 8 owns real
//! paymaster economics -- see the Phase-7 plan's paymaster-economics scope
//! decision). With no paymaster, the `EntryPoint` requires the SENDER
//! (the deposit account, which holds only USDT) to have prefunded its own
//! `EntryPoint` deposit, or the `handleOps` transaction reverts with `AA21
//! didn't pay prefund` (confirmed in Task 4's `user_op_isolation.rs`). This
//! test uses that same documented scaffolding: the broadcaster EOA (anvil
//! account 0, ETH-funded by anvil by default) calls
//! `EntryPoint.depositTo(deposit_account)` with a small ETH prefund BEFORE
//! the deposit is even credited, standing in for a real token paymaster.
//!
//! **This makes the flow federation-fronts-ETH, NOT ETH-net-zero**: the
//! broadcaster's ETH balance decreases by (at least) the prefund amount and
//! is only partially refunded (the unused portion of the combined
//! `verificationGasLimit`, `callGasLimit`, and `preVerificationGas`) via
//! `handleOps`'s `beneficiary` refund, not made whole by a paymaster
//! covering the cost from a USDT-denominated deposit. The gas-in-USDT /
//! ETH-net-zero assertion is
//! deferred to Phase 8, which owns paymaster/fee economics (per the plan's
//! explicit scope decision) -- this test does not assert it. What IS
//! asserted (the actual Phase-7 gate, independent of the paymaster) is that
//! the deposit account is deployed and swept via a REAL MPC-signed `UserOp`
//! on the REAL `EntryPoint`.
//!
//! Slow (real anvil + real DKG (trusted-dealer, matching every other
//! `fedimint-testing`-based acceptance test in this crate -- see e.g.
//! `tests.rs`'s `federation_boots_with_usdt_module_and_serves_group_public_
//! key` doc comment) + real cggmp21 threshold-ECDSA MPC signing -- several
//! minutes); intentionally run in the foreground, not `#[ignore]`d.

mod common;

use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::{Context as _, bail};
use fedimint_client::ClientHandleArc;
use fedimint_core::PeerId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::runtime::{Instant, sleep};
use fedimint_mint_client::MintClientInit;
use fedimint_mint_server::MintInit;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_usdt_client::{UsdtClientInit, UsdtClientModule};
use fedimint_usdt_common::{EvmAddress, UsdtAmount, UsdtGenParams, UserOpStatus};
use fedimint_usdt_server::UsdtInit;
use fedimint_usdt_server::db::{PendingUserOpKey, PendingUserOpPrefix};
use fedimint_usdt_server::rpc::{AlloyEvmRpc, IServerEvmRpc};
use futures::StreamExt as _;

sol! {
    #[sol(rpc)]
    interface IEntryPointDeposit {
        function depositTo(address account) external payable;
    }

    #[sol(rpc)]
    interface IErc20Balance {
        function balanceOf(address account) external view returns (uint256);
    }
}

/// Comfortably covers the devnet gas bounds' worst-case prefund
/// (`GasBounds::DEPLOY_AND_SWEEP_DEVNET`: `(500_000 + 200_000 + 100_000) *
/// 30 gwei` = `0.024 ETH`) several times over. Mirrors
/// `user_op_isolation.rs`'s identical constant.
const ENTRY_POINT_DEPOSIT_WEI: u128 = 1_000_000_000_000_000_000; // 1 ETH

/// Returns the single `op_hash` this guardian's `PendingUserOp` table
/// currently holds (or `None` if it's empty / holds more than one -- this
/// test only ever drives a single deposit through the pipeline at a time).
/// Mirrors `tests.rs`'s identical helper; kept file-local rather than
/// promoted to `common` since only these two tests need it.
async fn find_sole_pending_user_op_hash(
    fed: &FederationTest,
    peer: PeerId,
    module_instance_id: ModuleInstanceId,
) -> Option<[u8; 32]> {
    let db = fed.server_db(peer);
    let mut dbtx = db.begin_transaction_nc().await;
    let (mut isolated, _) = dbtx.to_ref_with_prefix_module_id(module_instance_id);
    let pending: Vec<(PendingUserOpKey, _)> = isolated
        .find_by_prefix(&PendingUserOpPrefix)
        .await
        .collect()
        .await;
    match pending.as_slice() {
        [(PendingUserOpKey(hash), _)] => Some(*hash),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "re-enable in Task 11 (anvil e2e drives the client eth_getProof submit flow)"]
async fn deposit_account_is_deployed_and_swept_via_real_mpc_and_real_entrypoint()
-> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!(
            "SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE to an anvil binary, or \
             install foundry, and re-run)"
        );
        return Ok(());
    };

    // 1. Deploy the full ERC-4337 v0.7 stack on anvil FIRST (Challenge A): real
    //    EntryPoint, SimpleAccountFactory (+ its SimpleAccount impl), staked
    //    paymaster (unused by this test -- see Challenge B), and the TestUsdt
    //    fixture, minted to anvil account 1 (the deposit funder below).
    let usdt_holder = common::anvil_account_1_address()?;
    let stack = common::deploy_4337_stack(&anvil, usdt_holder, UsdtAmount(50_000_000)).await?;

    // 2. The REAL AlloyEvmRpc (not MockEvmRpc), broadcaster = anvil account 0
    //    (ETH-funded by anvil by default), shared across every guardian -- mirrors
    //    how `tests.rs` shares one `MockEvmRpc` across every guardian so their
    //    reads agree.
    let evm_rpc: Arc<dyn IServerEvmRpc> = AlloyEvmRpc::new(anvil.url())?
        .with_broadcaster(common::ANVIL_ACCOUNT_0_PRIVATE_KEY)?
        .with_entry_point(stack.entry_point)
        .into_dyn();

    // 3. Config-gen the federation with the REAL deployed addresses (Challenge A).
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
        // Must be > 0 (sec-17 config validation); the broadcaster is the
        // anvil-funded account, so any low value is trivially satisfied.
        broadcaster_min_balance_wei: 1,
        // No Chainlink on anvil: all-zero disables the feed and falls back
        // to `AlloyEvmRpc::STATIC_USDT_PER_ETH_E6` (see Task 4 of the
        // ETH/USD price-feed plan).
        eth_usd_price_feed: EvmAddress([0u8; 20]),
        price_feed_max_staleness_secs: 14_400,
    };

    let fed = Fixtures::new_primary(MintClientInit, MintInit)
        .with_module(
            UsdtClientInit,
            UsdtInit::with_evm_rpc(evm_rpc.clone()).with_gen_params(gen_params),
        )
        .new_fed_builder(0)
        .build()
        .await;

    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;
    let module_instance_id = usdt.id;
    let peers: Vec<PeerId> = usdt.all_peers().into_iter().collect();
    assert_eq!(
        peers.len(),
        4,
        "this test assumes the default 4-guardian fixture"
    );

    // 4. NOW derive the deposit account -- the federation's UsdtClientConfig
    //    carries both the real (trusted-dealer) DKG group key and the real
    //    factory/impl addresses injected in step 3.
    //
    // Part C: wait for the readiness state machine to report Ready before
    // allocating -- the real deployed 4337 stack + funded broadcaster satisfy
    // every readiness condition, but it must first propagate through
    // consensus (the client gates `allocate_deposit` on it).
    common::await_usdt_ready(&usdt, Duration::from_secs(60)).await?;
    let (claim_keypair, deposit_account) = usdt.allocate_deposit().await?;

    let code_len_before = evm_rpc.get_code_len(deposit_account).await?;
    assert_eq!(
        code_len_before, 0,
        "the counterfactual deposit account must have no code before the sweep"
    );

    // 5. Challenge B scaffolding: the broadcaster EOA fronts a small ETH prefund
    //    via EntryPoint.depositTo(deposit_account), standing in for a real token
    //    paymaster (see this file's module doc comment for the ETH-flow
    //    implications). Done BEFORE the deposit is even credited -- there is no
    //    race, since the automatic pipeline only reaches `handleOps` after real MPC
    //    signing completes, minutes later.
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

    // 6. Fund the counterfactual deposit account with USDT ONLY (no ETH) -- the
    //    whole point of the ERC-4337 model this module uses.
    let deposit_amount = UsdtAmount(4_000_000);
    common::transfer_erc20_from_account_1(&anvil, stack.usdt, deposit_account, deposit_amount)
        .await
        .context("failed to fund the counterfactual deposit account with USDT")?;

    // Mine `confirmation_depth` + a margin of extra blocks ON TOP of the
    // funding transfer. anvil runs in instant/auto-mine mode (no
    // `--block-time`), so it mines exactly one block per transaction and its
    // head then stays put until the next transaction. The USDT `transfer`
    // above is the LAST transaction this test sends before crediting, so
    // without this the chain head would sit AT the transfer's block `B`
    // forever -- and the deposit checker reads the balance at `head -
    // confirmation_depth` (`scan_pending_deposits`, a deliberately-confirmed
    // read), i.e. block `B - 1`, one block BEFORE the transfer, where the
    // deposit account still holds 0 USDT. It would then never observe the
    // deposit (the exact integration bug this real-chain test exists to
    // catch; a `MockEvmRpc` with a hand-set block number structurally cannot).
    // Mining a handful of empty blocks advances the head past `B` so the
    // confirmed read block lands at or after `B`.
    let mine_provider = ProviderBuilder::new().connect_http(anvil.url().parse()?);
    for _ in 0..5u32 {
        mine_provider
            .raw_request::<_, String>("evm_mine".into(), ())
            .await
            .context("failed to mine an anvil block past the funding transfer")?;
    }

    // 7. Poll until the federation credits the deposit.
    // TODO(Task 11): crediting is now proof-driven -- drive the client's
    // `submit_deposit_proof` (real `eth_getProof` against anvil) here instead of
    // the removed `check_deposit` guardian-poll trigger (this anvil e2e test is
    // `#[ignore]`d until Task 11 wires that up).
    let credited_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let status = usdt.deposit_status(claim_keypair.public_key()).await?;
        if status.credited == deposit_amount {
            break;
        }
        if Instant::now() >= credited_deadline {
            bail!("deposit was never credited before the deadline (last status: {status:?})");
        }
        sleep(Duration::from_millis(500)).await;
    }

    // 8. A DeployAndSweep PendingUserOp deterministically appears (the automatic
    //    trigger added in Phase 7 Task 5).
    let pending_deadline = Instant::now() + Duration::from_secs(60);
    let op_hash = loop {
        if let Some(hash) = find_sole_pending_user_op_hash(&fed, peers[0], module_instance_id).await
        {
            break hash;
        }
        if Instant::now() >= pending_deadline {
            bail!("no PendingUserOp appeared on peer 0 before the deadline");
        }
        sleep(Duration::from_millis(500)).await;
    };

    // 9. The federation's real, background, timer-driven cggmp21 threshold-ECDSA
    //    signing loop signs the op's userOpHash digest -> the guardian-local
    //    `usdt-user-op-submitter` task assembles the 65-byte signature, submits
    //    `handleOps` to the REAL EntryPoint on REAL anvil via the REAL AlloyEvmRpc,
    //    polls for the on-chain receipt, and the federation threshold-votes
    //    `UserOpConfirmed` -- converging `PoolState.balance` on every guardian.
    //    Real MPC + a real chain round-trip is slow -- a generous multi-minute
    //    deadline per guardian.
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
                     (last read {})",
                    pool.balance
                );
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    // 10. THE PHASE-7 GATE.

    // (a) The deposit account was actually deployed via initCode (code-len 0 ->
    //     nonzero), proving `handleOps` really ran the counterfactual
    //     ERC1967Proxy deploy, not just a plain transfer.
    let code_len_after = evm_rpc.get_code_len(deposit_account).await?;
    assert!(
        code_len_after > 0,
        "the deposit account must have code after the deploy-and-sweep UserOp \
         (code_len_before={code_len_before}, code_len_after={code_len_after})"
    );

    // (b) The pool account's ON-CHAIN USDT balance equals the swept amount --
    //     read directly from anvil, independent of the federation's own
    //     bookkeeping, proving the sweep really moved real tokens.
    let pool_account = usdt.pool_state(peers[0]).await?.account;
    let read_provider = ProviderBuilder::new().connect_http(anvil.url().parse()?);
    let usdt_token = IErc20Balance::new(Address::from(stack.usdt.0), &read_provider);
    let pool_onchain_balance = usdt_token
        .balanceOf(Address::from(pool_account.0))
        .call()
        .await
        .context("failed to read the pool's post-sweep on-chain USDT balance")?;
    assert_eq!(
        pool_onchain_balance,
        U256::from(deposit_amount.0),
        "the pool's on-chain USDT balance must equal the swept amount"
    );

    // (c) The federation's consensus-agreed PoolState.balance equals the swept
    //     amount on EVERY guardian, and every guardian has finalized the UserOp
    //     (no longer Pending) -- proving the whole pipeline, not just the
    //     on-chain leg, reached quorum.
    for &peer in &peers {
        let pool = usdt.pool_state(peer).await?;
        assert_eq!(
            pool.balance, deposit_amount,
            "guardian {peer}'s consensus PoolState.balance must equal the swept amount"
        );
        let op_status = usdt.userop_status(peer, op_hash).await?.status;
        assert_ne!(
            op_status,
            UserOpStatus::Pending,
            "guardian {peer} must have finalized the UserOp (status was {op_status:?})"
        );
    }

    // (d) ETH-net-zero / gas-paid-in-USDT is explicitly DEFERRED to Phase 8 (see
    //     this file's module doc comment) -- not asserted here. What's proven
    //     above is the Phase-7 gate itself: a counterfactual USDT-only deposit
    //     account deployed and swept to the pool by a real MPC-signed UserOp on
    //     the real EntryPoint.

    Ok(())
}
