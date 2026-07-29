mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use common::MockEvmRpc;
use fedimint_client::ClientHandleArc;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{IDatabaseTransactionOpsCore, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::runtime::{Instant, sleep};
use fedimint_core::{Amount, BitcoinHash as _, PeerId, secp256k1};
use fedimint_mint_client::{MintClientInit, MintClientModule};
use fedimint_mint_server::MintInit;
use fedimint_mintv2_client::MintClientInit as Mintv2ClientInit;
use fedimint_mintv2_common::KIND as MINTV2_KIND;
use fedimint_mintv2_common::config::MintGenParams;
use fedimint_mintv2_server::MintInit as Mintv2Init;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_usdt_client::api::UsdtFederationApi;
use fedimint_usdt_client::{UsdtClientInit, UsdtClientModule};
use fedimint_usdt_common::user_op::UserOpReceipt;
use fedimint_usdt_common::{
    EvmAddress, FeeVote, USDT_UNIT, UsdtAmount, UserOpStatus, withdrawal_fee_quote,
};
use fedimint_usdt_server::UsdtInit;
use fedimint_usdt_server::db::{
    PendingUserOpKey, PendingUserOpPrefix, RefundKey, UnclaimedWithdrawalKey,
    UnclaimedWithdrawalPrefix, UsdtWithdrawalV0, WithdrawalState, WithdrawalStateKey,
};
use futures::StreamExt as _;

fn fixtures() -> Fixtures {
    Fixtures::new_primary(MintClientInit, MintInit).with_module(UsdtClientInit, UsdtInit::default())
}

/// A federation with TWO mintv2 instances (the default Bitcoin-denominated
/// primary plus a second instance denominated in [`USDT_UNIT`], mirroring the
/// Phase 4.5 dual-mint fixture in `fedimint-mintv2-tests`) and the usdt
/// module wired up with `mock` as EVERY guardian's [`fedimint_usdt_server::
/// rpc::IServerEvmRpc`] (via [`UsdtInit::with_evm_rpc`]). Sharing one mock
/// across all guardians is what lets their independently-run deposit-checker
/// tasks observe identical balances and reach the deposit-observation
/// consensus threshold.
///
/// The usdt module's claim path funds transactions in `USDT_UNIT`
/// (`fedimint_usdt_server::process_input`), so the client needs a primary
/// module registered for that unit to balance/mint the claimed e-cash into —
/// the second mintv2 instance serves that role.
fn dual_mint_fixtures(mock: Arc<MockEvmRpc>) -> Fixtures {
    Fixtures::new_primary(Mintv2ClientInit, Mintv2Init)
        .with_extra_module_instance(
            MINTV2_KIND,
            MintGenParams {
                amount_unit: USDT_UNIT,
            },
        )
        .with_module(UsdtClientInit, UsdtInit::with_evm_rpc(mock))
}

/// Boots a federation with the usdt module attached alongside mint (the
/// fee-paying primary module). `fedimint-testing` performs trusted-dealer
/// config generation (not `distributed_gen`), so this exercises
/// `UsdtInit::trusted_dealer_gen`, client-side module initialization, and the
/// `group_public_key` diagnostic API endpoint added in this phase.
#[tokio::test(flavor = "multi_thread")]
async fn federation_boots_with_usdt_module_and_serves_group_public_key() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let (client1, client2): (ClientHandleArc, ClientHandleArc) = fed.two_clients().await;

    // The client module must have initialized successfully for both clients,
    // proving their `UsdtClientConfig` (with a `group_public_key`) was loaded
    // from the trusted-dealer-generated consensus config.
    let usdt1 = client1.get_first_module::<UsdtClientModule>()?;
    let usdt2 = client2.get_first_module::<UsdtClientModule>()?;

    // The mint module must also be usable, confirming the federation is a
    // healthy, fully functioning fedimint federation with usdt attached.
    let _mint_module = client1.get_first_module::<MintClientModule>()?;

    // Exercise the `group_public_key` diagnostic endpoint end-to-end: it
    // proves the DKG(trusted-dealer)-produced config is loaded on the server
    // side and queryable over the wire, and that every guardian agrees on the
    // same group public key.
    let key1 = client1
        .api()
        .with_module(usdt1.id)
        .group_public_key()
        .await?;
    let key2 = client2
        .api()
        .with_module(usdt2.id)
        .group_public_key()
        .await?;

    assert_eq!(
        key1, key2,
        "all guardians must agree on the same DKG group public key"
    );
    assert_eq!(
        key1.serialize().len(),
        33,
        "group_public_key must be a valid compressed secp256k1 public key"
    );

    Ok(())
}

/// Derivation-parity test (Task 10): the client's `deposit_address` must
/// compute the exact same address as `fedimint_usdt_common::
/// derive_deposit_account` given the same group public key and claim key, so
/// the two independent call sites (client-side derivation vs. what the
/// server derives and watches) can never silently diverge.
#[tokio::test(flavor = "multi_thread")]
async fn client_deposit_address_matches_common_derivation() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let client: ClientHandleArc = fed.new_client().await;

    let usdt = client.get_first_module::<UsdtClientModule>()?;
    let group_public_key = client.api().with_module(usdt.id).group_public_key().await?;

    let claim_keypair =
        secp256k1::Keypair::new(secp256k1::SECP256K1, &mut secp256k1::rand::thread_rng());
    let claim_pk = claim_keypair.public_key();

    // `account_factory`/`simple_account_impl` are NOT `UsdtGenParams::
    // default()`'s raw placeholder `EvmAddress([0; 20])`: config-gen
    // deterministically self-deploys/derives both from `entry_point` (see
    // `fedimint_usdt_server`'s `derive_account_factory`/
    // `derive_simple_account_impl`), so read the federation's actual values
    // straight off the client config instead of assuming the placeholder --
    // this is a derivation-parity test, not a config-gen test, so it must
    // feed `derive_deposit_account` whatever the federation actually agreed
    // on rather than a stale hard-coded guess.
    let expected = fedimint_usdt_common::derive_deposit_account(
        &group_public_key,
        usdt.config().account_factory,
        usdt.config().simple_account_impl,
        &claim_pk,
    );
    let actual = usdt.deposit_address(&claim_pk);

    assert_eq!(
        actual, expected,
        "client deposit_address must match fedimint_usdt_common::derive_deposit_account"
    );

    Ok(())
}

/// **Phase 5 gating acceptance test.** Drives the full deposit -> claim ->
/// USDT-denominated e-cash flow over a hermetic in-process federation: a
/// shared [`MockEvmRpc`] stands in for the EVM chain (every guardian reads
/// the exact same balances, so their independently-run block-count pollers
/// and deposit-checker tasks reach deposit-observation consensus on their own
/// 1s test-interval timers -- no test hook forcing progress), and the second
/// mintv2 instance (denominated in [`USDT_UNIT`]) mints the claimed e-cash.
#[tokio::test(flavor = "multi_thread")]
async fn deposit_becomes_claimable_usdt_ecash() -> anyhow::Result<()> {
    let mock = Arc::new(MockEvmRpc::new());
    // The usdt module's default `UsdtGenParams::usdt_contract`
    // (`fedimint_usdt_common::UsdtGenParams::default`), so the mock must
    // script balances for this exact token address.
    let usdt_contract = EvmAddress([0u8; 20]);
    mock.set_chain_id(31337);
    // Well past `confirmation_depth: 1` so the checker's read block is never
    // ahead of this guardian's cached head.
    mock.set_block_number(100);

    // Mint fees disabled: this test asserts the USDT-denominated e-cash
    // balance is *exactly* the deposited amount, which would otherwise be
    // reduced by the USDT-`mintv2` instance's (`mintv2` fee schedule,
    // irrelevant to what this test is verifying: deposit-detection consensus
    // and claim correctness, not fee accounting).
    let fed = dual_mint_fixtures(mock.clone())
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;
    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    // Part C gate proof: before the on-chain readiness stack is observed,
    // the module is not `Ready` and `allocate_deposit` is refused.
    let group_public_key = client.api().with_module(usdt.id).group_public_key().await?;
    assert_ne!(
        usdt.status().await?.state,
        fedimint_usdt_common::BootstrapState::Ready,
        "module must not be Ready before the readiness stack is observed"
    );
    assert!(
        usdt.allocate_deposit().await.is_err(),
        "allocate_deposit must be gated until the module is Ready"
    );

    // Drive the readiness state machine to `Ready` (script the mock so every
    // guardian's bootstrap poll votes all-true), then wait for it to
    // propagate through consensus.
    common::mock_ready_stack(
        &mock,
        &group_public_key,
        usdt.config().entry_point,
        usdt.config().account_factory,
        usdt.config().simple_account_impl,
    );
    common::await_usdt_ready(&usdt, Duration::from_secs(60)).await?;

    // 1. Derive a deposit address.
    let (claim_keypair, account) = usdt.allocate_deposit().await?;

    // 1b. Wait for a `FeeVote` median to exist. `MockEvmRpc`'s default
    //     `FeeVote` is now sane and nonzero (see `common::mock::State::
    //     default`), but the guardians' 1s poller ticks + consensus still need
    //     real wall-clock time to converge on a median after boot, and
    //     `deposit_fee_quote` returns an `Err` (not a placeholder `Ok`) until
    //     one exists (security finding 06's client-confusion facet) -- so this
    //     retries PAST the `Err`, not just past an `Ok` with a zero fee,
    //     mirroring
    // `deposit_sweep_pipeline_is_deterministic_and_confirms_pool_balance`'s
    //     own wait. `process_input` would otherwise reject a claim with
    //     `DepositFeeInsufficient` before any median exists, so this must
    //     converge to a NONZERO value before the claim below.
    let fee_deadline = Instant::now() + Duration::from_secs(30);
    let deposit_fee = loop {
        if let Ok(quote) = usdt.deposit_fee_quote().await
            && quote.fee.0 > 0
        {
            break quote.fee;
        }
        if Instant::now() >= fee_deadline {
            bail!("deposit_fee_quote never converged to a nonzero quote before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };

    // 2. Simulate the confirmed on-chain USDT transfer (confirmed as of block 10,
    //    well behind the chain head of 100). The NET e-cash amount the claim mints
    //    is `net_deposit_amount` (`2_560_000`, a multiple of 512 msat -- mintv2's
    //    smallest client denomination, `fedimint_mintv2_common::config::
    //    client_denominations`, `Denomination(9) == 2^9` -- so it's exactly
    //    representable as e-cash notes with no denomination-rounding dust, letting
    //    step 4 assert *exact* equality below); the on-chain deposit must therefore
    //    fund `net_deposit_amount + deposit_fee` (the fee is deducted at claim time
    //    -- Task 3/4 of the deposit-fee plan).
    let net_deposit_amount = UsdtAmount(2_560_000);
    let deposit_amount = UsdtAmount(net_deposit_amount.0 + deposit_fee.0);
    mock.set_erc20_balance_at(usdt_contract, account, 10, deposit_amount);

    // 3. Client checks + claims; guardians observe (block-count poller +
    //    deposit-checker on their 1s test ticks) and credit at threshold, then the
    //    client submits the claim transaction. A generous deadline: consensus
    //    sessions + the 1s poll ticks need real wall-clock time.
    usdt.check_and_claim(&claim_keypair, Duration::from_secs(120))
        .await?;

    // 4. The USDT-denominated e-cash balance equals the deposit MINUS the deposit
    //    fee. Issuance is asynchronous even after the claim transaction is
    //    accepted, so poll with a timeout rather than asserting on the first read.
    let poll_deadline = fedimint_core::runtime::Instant::now() + Duration::from_secs(30);
    let balance = loop {
        let balance = client.get_balance_for_unit(USDT_UNIT).await?;
        if balance == Amount::from_msats(net_deposit_amount.0)
            || fedimint_core::runtime::Instant::now() >= poll_deadline
        {
            break balance;
        }
        sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        balance,
        Amount::from_msats(net_deposit_amount.0),
        "the claim must mint deposited - deposit_fee of USDT e-cash"
    );

    // 5. Replay/double-claim of the same account is rejected: every credited msat
    //    was already claimed, so the deposit never becomes claimable again and
    //    `check_and_claim` must time out with an error. The balance must also not
    //    have moved.
    let replay = usdt
        .check_and_claim(&claim_keypair, Duration::from_secs(5))
        .await;
    assert!(
        replay.is_err(),
        "a second claim of an already-fully-claimed account must not succeed"
    );
    assert_eq!(
        client.get_balance_for_unit(USDT_UNIT).await?,
        Amount::from_msats(net_deposit_amount.0),
        "a rejected replay must not change the USDT-denominated balance"
    );

    Ok(())
}

/// Returns the single `op_hash` this guardian's `PendingUserOp` table
/// currently holds (or `None` if it's empty / holds more than one -- this
/// test only ever drives a single deposit through the pipeline at a time).
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

/// Dumps EVERY raw key/value pair in `peer`'s usdt module instance
/// (`module_instance_id`), for asserting byte-identical consensus state
/// across guardians. Raw (undecoded) bytes, so this is a strict superset of
/// any single table's content -- any consensus-DB divergence anywhere in the
/// module, not just in the tables this task added, would show up here.
async fn dump_usdt_module_db(
    fed: &FederationTest,
    peer: PeerId,
    module_instance_id: ModuleInstanceId,
) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let db = fed.server_db(peer);
    let mut dbtx = db.begin_transaction_nc().await;
    let (mut isolated, _) = dbtx.to_ref_with_prefix_module_id(module_instance_id);
    isolated
        .raw_find_by_prefix(&[])
        .await
        .expect("raw_find_by_prefix never fails against an in-memory test DB")
        .collect::<Vec<(Vec<u8>, Vec<u8>)>>()
        .await
        .into_iter()
        .collect()
}

/// **Phase 7 Task 5 gating acceptance test.** Drives the automatic,
/// deterministic deposit -> sweep pipeline end to end over a hermetic
/// 4-guardian federation (a shared [`MockEvmRpc`] stands in for the EVM
/// chain; which 3-of-4 guardians sign is digest-seeded by `signer_subset`
/// (sec-10 hardening) rather than always the lowest-`t` guardians, but the
/// federation-wide consensus state this test asserts on -- `PoolState`,
/// `UserOpStatus` -- converges identically on every guardian regardless of
/// whether it happened to sign):
///
/// 1. Allocate + fund a deposit; the federation credits it.
/// 2. Assert a `DeployAndSweep` `PendingUserOp` and its `SigningPurpose::
///    UserOp` session appear -- byte-identically -- on every guardian
///    (deterministic trigger, Task 5 part 1).
/// 3. The federation's real MPC signing loop (no manual pumping -- this runs
///    the actual `fedimintd`-style consensus loop) signs it; every guardian's
///    `MpcSignature` arm deterministically produces an identical
///    `SubmittedUserOp` (Task 5 part 2).
/// 4. Every guardian's guardian-local `usdt-user-op-submitter` task submits the
///    op (recorded by the mock, Task 5 part 3) and polls for a receipt; once
///    the test scripts a successful receipt, guardians threshold-vote
///    `UserOpConfirmed` and `PoolState.balance` converges to the swept amount
///    on every guardian (Task 5 part 4).
/// 5. Asserts every guardian's ENTIRE usdt module database is byte-identical at
///    the terminal state (signer and non-signer alike), and that letting the
///    guardian-local tasks keep ticking afterward (replay) does not change
///    anything.
///
/// Slow (real MPC over a real, real-timer-driven federation, ~1-3 min);
/// intentionally run in the foreground.
#[tokio::test(flavor = "multi_thread")]
async fn deposit_sweep_pipeline_is_deterministic_and_confirms_pool_balance() -> anyhow::Result<()> {
    let mock = Arc::new(MockEvmRpc::new());
    // The usdt module's default `UsdtGenParams::usdt_contract` placeholder.
    let usdt_contract = EvmAddress([0u8; 20]);
    mock.set_chain_id(31337);
    mock.set_block_number(100);
    // Security finding 02 (Task 4.3): `maybe_trigger_sweep` now defers any
    // sweep until it can price `deposit_fee_quote`, which requires a fresh,
    // *sane* `FeeVote` median (`fee_vote_in_sane_range` would reject an
    // out-of-range vote outright, so an unscripted/invalid reading would
    // never even be accepted into consensus). Script a low (but sane,
    // non-zero) estimate up front, overriding `MockEvmRpc`'s own sane nonzero
    // default, so the guardians' pollers converge on a median well before the
    // deposit below is credited; low enough that its `deposit_fee_quote`
    // stays well under `deposit_amount` (a high gas price here would make
    // this otherwise-ordinary deposit dust under the finding-02 gate, which
    // is not what this test is about).
    let scripted_fee = FeeVote {
        max_fee_per_gas_wei: 100_000_000,
        usdt_per_eth_e6: 3_000_000_000,
    };
    mock.set_fee_estimate(scripted_fee);

    let fed = dual_mint_fixtures(mock.clone())
        .new_fed_builder(0)
        .disable_mint_fees()
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
    // Arbitrary guardian used to double-check federation-wide consensus
    // state below. Named `non_signer` for readability, but which guardians
    // actually sign is digest-seeded by `signer_subset` (sec-10 hardening),
    // not a fixed lowest-`t` subset -- the assertions below hold on this
    // peer's view regardless of whether it happened to be a signer.
    let non_signer = PeerId::from(3);

    // Part C: drive the module to Ready before allocating a deposit.
    let group_public_key = client.api().with_module(usdt.id).group_public_key().await?;
    common::mock_ready_stack(
        &mock,
        &group_public_key,
        usdt.config().entry_point,
        usdt.config().account_factory,
        usdt.config().simple_account_impl,
    );
    common::await_usdt_ready(&usdt, Duration::from_secs(60)).await?;

    // 1a. Wait for the scripted `FeeVote` to actually converge to a fresh
    //     median before crediting the deposit below -- nothing re-triggers a
    //     sweep for an account that only ever received a single credit, so
    //     crediting before a median exists would strand this deposit
    //     un-swept for the rest of the test. `deposit_fee_quote` itself
    //     `Err`s (not a placeholder `Ok`) until a median is available, so
    //     this retries past the `Err`, not just a zero `Ok`.
    let fee_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if matches!(usdt.deposit_fee_quote().await, Ok(quote) if quote.fee.0 > 0) {
            break;
        }
        if Instant::now() >= fee_deadline {
            bail!("deposit_fee_quote never converged to a nonzero quote before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    }

    // 1. Allocate + fund a deposit; wait for it to be credited.
    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    let deposit_amount = UsdtAmount(2_500_000);
    mock.set_erc20_balance_at(usdt_contract, account, 10, deposit_amount);
    usdt.check_deposit(claim_keypair.public_key()).await?;

    let credited_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = usdt.deposit_status(claim_keypair.public_key()).await?;
        if status.credited == deposit_amount {
            break;
        }
        if Instant::now() >= credited_deadline {
            bail!("deposit was never credited before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    }

    // 2. A DeployAndSweep PendingUserOp deterministically appears on every
    //    guardian, with the identical op_hash.
    let pending_deadline = Instant::now() + Duration::from_secs(30);
    let op_hash = loop {
        if let Some(hash) = find_sole_pending_user_op_hash(&fed, peers[0], module_instance_id).await
        {
            break hash;
        }
        if Instant::now() >= pending_deadline {
            bail!("no PendingUserOp appeared on peer 0 before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };
    for &peer in &peers {
        let status = usdt.userop_status(peer, op_hash).await?;
        assert_eq!(
            status.status,
            UserOpStatus::Pending,
            "guardian {peer} must deterministically hold the identical PendingUserOp"
        );
    }

    // 3. The federation's real (background, timer-driven) MPC signing loop signs it
    //    -> every guardian's MpcSignature arm deterministically produces a
    //    SubmittedUserOp. Poll until the guardian-local submission task has
    //    actually recorded a submission with the mock (proves the SubmittedUserOp
    //    landed and the guardian-local task picked it up), then script a successful
    //    receipt.
    let submit_deadline = Instant::now() + Duration::from_secs(600);
    loop {
        if !mock.submitted_user_ops().is_empty() {
            break;
        }
        if Instant::now() >= submit_deadline {
            bail!("no UserOp submission was recorded by the mock before the deadline");
        }
        sleep(Duration::from_secs(1)).await;
    }
    mock.set_user_op_receipt(
        op_hash,
        UserOpReceipt {
            success: true,
            block: 42,
            block_hash: [0u8; 32],
            actual_gas_cost_wei: UsdtAmount(0),
        },
    );

    // Every guardian -- signer and non-signer alike -- deterministically
    // reaches Submitted (or, if the confirmation vote already landed by the
    // time we poll, Unknown -- both prove the deterministic
    // Completed -> SubmittedUserOp step ran identically).
    for &peer in &peers {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let status = usdt.userop_status(peer, op_hash).await?.status;
            if matches!(status, UserOpStatus::Submitted | UserOpStatus::Unknown) {
                break;
            }
            if Instant::now() >= deadline {
                bail!("guardian {peer} UserOp never reached Submitted (status={status:?})");
            }
            sleep(Duration::from_millis(300)).await;
        }
    }

    // 4. Threshold-voted confirmation: PoolState.balance converges to the swept
    //    amount on EVERY guardian, including the non-signer.
    for &peer in &peers {
        let deadline = Instant::now() + Duration::from_secs(120);
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
            sleep(Duration::from_millis(300)).await;
        }
    }
    // Explicitly confirm the non-signer specifically -- the whole point of
    // this determinism test.
    let non_signer_pool = usdt.pool_state(non_signer).await?;
    assert_eq!(non_signer_pool.balance, deposit_amount);
    assert!(
        usdt.userop_status(non_signer, op_hash).await?.status != UserOpStatus::Pending,
        "the non-signer must have finalized the UserOp deterministically too"
    );

    // 5. Every guardian's usdt module database is byte-identical at the terminal
    //    state.
    let mut reference: Option<BTreeMap<Vec<u8>, Vec<u8>>> = None;
    for &peer in &peers {
        let items = dump_usdt_module_db(&fed, peer, module_instance_id).await;
        match &reference {
            Some(reference) => assert_eq!(
                &items, reference,
                "guardian {peer}'s usdt module DB diverges from peer {}'s",
                peers[0]
            ),
            None => reference = Some(items),
        }
    }
    let reference = reference.expect("at least one peer");

    // Replay-safety: let the guardian-local background tasks keep ticking
    // (they will keep re-submitting/re-polling every ~1s in the test env)
    // and confirm nothing changes -- no double-credit, no DB drift.
    sleep(Duration::from_secs(3)).await;
    let pool_after_replay_window = usdt.pool_state(peers[0]).await?;
    assert_eq!(
        pool_after_replay_window.balance, deposit_amount,
        "letting the background tasks keep ticking must not double-credit the pool"
    );
    let items_after = dump_usdt_module_db(&fed, peers[0], module_instance_id).await;
    assert_eq!(
        items_after, reference,
        "the usdt module DB must be unchanged after the replay window"
    );

    Ok(())
}

/// Returns the sole `(OutPoint, UsdtWithdrawal)` this guardian's
/// `UnclaimedWithdrawal` table currently holds (or `None` if it's empty /
/// holds more than one -- this test only ever drives a single withdrawal at
/// a time), mirroring [`find_sole_pending_user_op_hash`].
async fn find_sole_unclaimed_withdrawal(
    fed: &FederationTest,
    peer: PeerId,
    module_instance_id: ModuleInstanceId,
) -> Option<(fedimint_core::OutPoint, UsdtWithdrawalV0)> {
    let db = fed.server_db(peer);
    let mut dbtx = db.begin_transaction_nc().await;
    let (mut isolated, _) = dbtx.to_ref_with_prefix_module_id(module_instance_id);
    let queued: Vec<(UnclaimedWithdrawalKey, UsdtWithdrawalV0)> = isolated
        .find_by_prefix(&UnclaimedWithdrawalPrefix)
        .await
        .collect()
        .await;
    match queued.as_slice() {
        [(UnclaimedWithdrawalKey(out_point), withdrawal)] => Some((*out_point, withdrawal.clone())),
        _ => None,
    }
}

/// **Phase 8 Task 3 gating acceptance test.** Exercises the client-facing
/// `withdrawal_status` endpoint/wrapper without waiting on any real-MPC
/// pipeline (deliberately fast, unlike the Task-1/Task-2 tests above which
/// wait for the Phase-7 sweep and/or Phase-8 batch to reach a quiescent
/// terminal state before their byte-identical whole-DB compares): a bogus
/// `OutPoint` (never enqueued) must report [`WithdrawalStatus::Unknown`], and
/// a genuinely-submitted withdrawal must report [`WithdrawalStatus::Queued`]
/// immediately after `withdraw()` returns (before any batch has had a chance
/// to trigger, since the mock's block count never advances past its initial
/// value here).
#[tokio::test(flavor = "multi_thread")]
async fn withdrawal_status_reports_unknown_then_queued() -> anyhow::Result<()> {
    let mock = Arc::new(MockEvmRpc::new());
    let usdt_contract = EvmAddress([0u8; 20]);
    mock.set_chain_id(31337);
    mock.set_block_number(100);
    let scripted_fee = FeeVote {
        max_fee_per_gas_wei: 20_000_000_000,
        usdt_per_eth_e6: 3_000_000_000,
    };
    mock.set_fee_estimate(scripted_fee);
    let expected_quote =
        withdrawal_fee_quote(&scripted_fee).expect("scripted fee must produce a quote");

    let fed = dual_mint_fixtures(mock.clone())
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;
    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    // A bogus, never-enqueued OutPoint must report Unknown.
    let bogus_out_point = fedimint_core::OutPoint {
        txid: fedimint_core::TransactionId::from_byte_array([0xab; 32]),
        out_idx: 0,
    };
    assert_eq!(
        usdt.withdrawal_status(bogus_out_point).await?.status,
        fedimint_usdt_common::WithdrawalStatus::Unknown
    );

    // Wait for the fee-vote median quote to converge (needed for a valid
    // `max_fee`). Retries PAST an `Err` (not just past a stale/zero `Ok`):
    // `withdraw_fee_quote` returns `Err` until a `FeeVote` median exists
    // (security finding 06's client-confusion facet), and the guardians' 1s
    // poller ticks + consensus still need real wall-clock time after boot to
    // converge on one, even with `MockEvmRpc`'s sane nonzero default
    // `FeeVote`.
    let quote_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(quote) = usdt.withdraw_fee_quote(UsdtAmount(1_000_000)).await
            && quote.max_fee == expected_quote
        {
            break;
        }
        if Instant::now() >= quote_deadline {
            bail!("withdraw_fee_quote never converged before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    }
    // The same `FeeVote` median backs `deposit_fee_quote`, which has already
    // converged now that `withdraw_fee_quote` has (Task 5 of the deposit-fee
    // plan).
    let deposit_fee = usdt.deposit_fee_quote().await?.fee;

    // Fund the withdrawal: deposit + claim USDT e-cash. The claim mints the NET
    // `net_deposit_amount` (`51_200_000` is a 512-msat multiple, comfortably
    // covering `amount + max_fee` below -- with this scripted fee, both the
    // deposit fee (`SWEEP_GAS_UNITS`-derived) and the withdrawal fee
    // (`WITHDRAWAL_GAS_UNITS`-derived) are themselves large, so the deposit must
    // be sized well above their historical Task-1 (150k gas units) figures --
    // mirrors `withdrawal_output_debits_queues_and_fee_median_is_deterministic`'s
    // identical scripted fee, so the same deposit amount suffices here too), so
    // the on-chain deposit must fund `net_deposit_amount + deposit_fee`.
    // This does NOT wait for the Phase-7 background sweep pipeline the
    // credited deposit auto-triggers -- unlike the Task-1/Task-2 tests
    // above, this test never reads pool/sweep state, so there is nothing to
    // wait on it for.
    //
    // Part C: drive the module to Ready before allocating a deposit.
    let group_public_key = client.api().with_module(usdt.id).group_public_key().await?;
    common::mock_ready_stack(
        &mock,
        &group_public_key,
        usdt.config().entry_point,
        usdt.config().account_factory,
        usdt.config().simple_account_impl,
    );
    common::await_usdt_ready(&usdt, Duration::from_secs(60)).await?;
    let net_deposit_amount = UsdtAmount(51_200_000);
    let deposit_amount = UsdtAmount(net_deposit_amount.0 + deposit_fee.0);
    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    mock.set_erc20_balance_at(usdt_contract, account, 10, deposit_amount);
    usdt.check_and_claim(&claim_keypair, Duration::from_secs(120))
        .await?;
    let fund_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if client.get_balance_for_unit(USDT_UNIT).await? == Amount::from_msats(net_deposit_amount.0)
        {
            break;
        }
        if Instant::now() >= fund_deadline {
            bail!("USDT e-cash was never minted before the deadline");
        }
        sleep(Duration::from_millis(200)).await;
    }

    // Submit the withdrawal (amount % 512 == 0 so amount + max_fee stays
    // 512-aligned, mirroring the other withdrawal tests' dust-avoidance).
    let recipient = EvmAddress([0x77; 20]);
    let amount = UsdtAmount(2_048_000);
    let range = usdt.withdraw(recipient, amount, expected_quote).await?;
    let out_point = UsdtClientModule::withdrawal_out_point(&range);

    // `withdraw()` already awaited the transaction's consensus acceptance,
    // so `process_output` has run and the server-side `WithdrawalState`
    // exists by the time we get here -- but `withdrawal_status` is a
    // `request_current_consensus` call across a threshold of guardians who
    // may apply the ordered output at slightly different wall-clock moments,
    // so poll to convergence rather than reading eagerly.
    let status_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = usdt.withdrawal_status(out_point).await?.status;
        if status == fedimint_usdt_common::WithdrawalStatus::Queued {
            break;
        }
        if Instant::now() >= status_deadline {
            bail!("withdrawal_status never reported Queued before the deadline (last {status:?})");
        }
        sleep(Duration::from_millis(200)).await;
    }

    Ok(())
}

/// **Phase 8 Task 1 gating acceptance test.** Drives the withdrawal
/// debit/queue + FeeVote-median path end to end over a hermetic 4-guardian
/// federation (shared [`MockEvmRpc`], so every guardian's fee-estimate poller
/// reads the identical scripted `get_fee_estimate`, votes the identical
/// `FeeVote`, and thus computes the identical median):
///
/// 1. Every guardian proposes its `FeeVote` (from the scripted mock) on its 1s
///    poller tick; the `withdraw_fee_quote` endpoint converges to the SAME
///    quote on every guardian (fee-vote median is deterministic + identical).
/// 2. A user first deposits + claims USDT e-cash (funding the withdrawal), then
///    submits a `UsdtOutput::V0` withdrawal whose `max_fee` equals the quote;
///    `process_output` debits `amount + max_fee` and enqueues an
///    `UnclaimedWithdrawal` + `WithdrawalState::Queued` -- byte-identically on
///    every guardian.
/// 3. Asserts every guardian's ENTIRE usdt module DB is byte-identical at the
///    terminal state (reusing the same `dump_usdt_module_db` raw byte-compare
///    helper as the Phase-7 sweep test).
///
/// Slow (real DKG + a real, real-timer-driven federation); run in the
/// foreground.
#[tokio::test(flavor = "multi_thread")]
async fn withdrawal_output_debits_queues_and_fee_median_is_deterministic() -> anyhow::Result<()> {
    let mock = Arc::new(MockEvmRpc::new());
    let usdt_contract = EvmAddress([0u8; 20]);
    mock.set_chain_id(31337);
    mock.set_block_number(100);
    // Every guardian reads THIS scripted fee estimate, so every guardian
    // votes it and the per-field median trivially equals it -- identical on
    // all guardians.
    let scripted_fee = FeeVote {
        max_fee_per_gas_wei: 20_000_000_000,
        usdt_per_eth_e6: 3_000_000_000,
    };
    mock.set_fee_estimate(scripted_fee);
    let expected_quote =
        withdrawal_fee_quote(&scripted_fee).expect("scripted fee must produce a quote");

    let fed = dual_mint_fixtures(mock.clone())
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;
    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;
    let module_instance_id = usdt.id;
    let peers: Vec<PeerId> = usdt.all_peers().into_iter().collect();
    assert_eq!(peers.len(), 4, "this test assumes the 4-guardian fixture");

    // 1. Wait for the fee-vote median to be populated (guardians vote on their 1s
    //    poller ticks), then assert `withdraw_fee_quote` is identical across every
    //    guardian and equals the pure-function quote. Retries PAST an `Err` (not
    //    just past a stale/zero `Ok`): `withdraw_fee_quote` returns `Err` until a
    //    `FeeVote` median exists (security finding 06's client-confusion facet).
    let quote_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match usdt.withdraw_fee_quote(UsdtAmount(1_000_000)).await {
            Ok(quote) if quote.max_fee == expected_quote => break,
            _ => {}
        }
        if Instant::now() >= quote_deadline {
            bail!("withdraw_fee_quote never converged to {expected_quote} before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    }
    // `withdraw_fee_quote` is a `request_current_consensus` call, so a
    // response at all means a threshold of guardians agreed on it; assert the
    // value equals the deterministic quote.
    let quote = usdt.withdraw_fee_quote(UsdtAmount(1_000_000)).await?;
    assert_eq!(quote.max_fee, expected_quote);
    // The same `FeeVote` median backs `deposit_fee_quote`, already converged.
    let deposit_fee = usdt.deposit_fee_quote().await?.fee;

    // 2. Fund the withdrawal: deposit + claim USDT e-cash. The claim mints the NET
    //    `net_deposit_amount` (`51_200_000` is a multiple of 512 msat -- no mintv2
    //    denomination-rounding dust -- and comfortably covers `amount + max_fee`;
    //    with this scripted fee both the deposit fee and the (post-Task-1,
    //    360k-gas-unit) withdrawal fee are large, so the deposit must be sized well
    //    above their historical figures), so the on-chain deposit must fund
    //    `net_deposit_amount + deposit_fee` (Task 3/4 of the deposit-fee plan).
    //
    // Part C: drive the module to Ready before allocating a deposit.
    let group_public_key = client.api().with_module(usdt.id).group_public_key().await?;
    common::mock_ready_stack(
        &mock,
        &group_public_key,
        usdt.config().entry_point,
        usdt.config().account_factory,
        usdt.config().simple_account_impl,
    );
    common::await_usdt_ready(&usdt, Duration::from_secs(60)).await?;
    let net_deposit_amount = UsdtAmount(51_200_000);
    let deposit_amount = UsdtAmount(net_deposit_amount.0 + deposit_fee.0);
    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    mock.set_erc20_balance_at(usdt_contract, account, 10, deposit_amount);
    usdt.check_and_claim(&claim_keypair, Duration::from_secs(120))
        .await?;
    let fund_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if client.get_balance_for_unit(USDT_UNIT).await? == Amount::from_msats(net_deposit_amount.0)
        {
            break;
        }
        if Instant::now() >= fund_deadline {
            bail!("USDT e-cash was never minted before the deadline");
        }
        sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        client.get_balance_for_unit(USDT_UNIT).await?,
        Amount::from_msats(net_deposit_amount.0),
        "the claim must mint deposited - deposit_fee of USDT e-cash"
    );

    // 2b. Crediting a deposit auto-triggers the Phase-7 deploy-and-sweep MPC
    //     pipeline (`Usdt::maybe_trigger_sweep`). That pipeline mutates the
    //     consensus DB (signing sessions, round chunks) asynchronously and
    //     is transiently divergent across guardians mid-signing, so drive it
    //     to its quiescent terminal state (pool balance == deposit) BEFORE
    //     the byte-identical whole-DB compare below, exactly as the Phase-7
    //     sweep acceptance test does.
    let submit_deadline = Instant::now() + Duration::from_secs(600);
    // Capture the sweep op_hash from the `PendingUserOp` table BEFORE waiting
    // for the submission: the sweep lifecycle clears `PendingUserOp` ->
    // `SubmittedUserOp` when the signing session completes, which happens
    // before the guardian-local submitter ever records a submission. Reading
    // the submission first would leave nothing in `PendingUserOp` to capture
    // (mirrors the Phase-7 `deposit_sweep_pipeline` ordering).
    let sweep_op_hash = loop {
        if let Some(hash) = find_sole_pending_user_op_hash(&fed, peers[0], module_instance_id).await
        {
            break hash;
        }
        if Instant::now() >= submit_deadline {
            bail!("no sweep PendingUserOp appeared before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };
    loop {
        if !mock.submitted_user_ops().is_empty() {
            break;
        }
        if Instant::now() >= submit_deadline {
            bail!("no sweep UserOp submission was recorded before the deadline");
        }
        sleep(Duration::from_secs(1)).await;
    }
    mock.set_user_op_receipt(
        sweep_op_hash,
        UserOpReceipt {
            success: true,
            block: 42,
            block_hash: [0u8; 32],
            actual_gas_cost_wei: UsdtAmount(0),
        },
    );
    for &peer in &peers {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if usdt.pool_state(peer).await?.balance == deposit_amount {
                break;
            }
            if Instant::now() >= deadline {
                bail!("guardian {peer} pool balance never converged before the deadline");
            }
            sleep(Duration::from_millis(300)).await;
        }
    }

    // 2c. **Task 5 (deposit-fee plan) solvency gate.** After the sweep, the pool
    //     holds the FULL on-chain `deposit_amount` (asserted above) while the
    //     `USDT_UNIT`-denominated mintv2 instance has only issued the NET
    //     `net_deposit_amount` of e-cash -- the difference (`deposit_fee`) is the
    //     federation's collected fee revenue and must show up as a solvent (never
    //     negative) surplus on the federation's global audited balance sheet. No
    //     other module in this fixture holds/issues any Bitcoin-denominated
    //     value, so the global `net_assets` figure reduces to exactly this
    //     module pair's surplus.
    let audit = fed
        .new_admin_api(peers[0])
        .await?
        .audit(fedimint_core::module::ApiAuth::new("pass".to_string()))
        .await?;
    assert_eq!(
        audit.net_assets,
        i64::try_from(deposit_fee.0).expect("deposit_fee fits an i64"),
        "the federation's global net assets must equal exactly the collected deposit fee \
         after a sweep with no withdrawals yet"
    );
    assert!(
        audit.net_assets >= 0,
        "the federation must remain solvent (non-negative net assets) after the sweep"
    );

    // 3. Submit the withdrawal output (max_fee == quote). `amount` is a 512-msat
    //    multiple (quote is itself 512-aligned post-Task-1, so `amount + max_fee`
    //    stays 512-aligned with no offset needed).
    let recipient = EvmAddress([0x99; 20]);
    let amount = UsdtAmount(2_048_000);
    usdt.withdraw(recipient, amount, expected_quote).await?;

    // 4. An UnclaimedWithdrawal + WithdrawalState::Queued deterministically appears
    //    on every guardian, with identical contents.
    let queued_deadline = Instant::now() + Duration::from_secs(30);
    let out_point = loop {
        if let Some((out_point, _)) =
            find_sole_unclaimed_withdrawal(&fed, peers[0], module_instance_id).await
        {
            break out_point;
        }
        if Instant::now() >= queued_deadline {
            bail!("no UnclaimedWithdrawal appeared on peer 0 before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };
    for &peer in &peers {
        // Guardians apply the ordered output at slightly different wall-clock
        // moments, so poll each one to convergence rather than reading it
        // eagerly (the write itself is a deterministic pure function of the
        // ordered output + config, identical on every guardian).
        let peer_deadline = Instant::now() + Duration::from_secs(30);
        let withdrawal = loop {
            if let Some((_, w)) =
                find_sole_unclaimed_withdrawal(&fed, peer, module_instance_id).await
            {
                break w;
            }
            if Instant::now() >= peer_deadline {
                panic!("guardian {peer} must hold the identical UnclaimedWithdrawal");
            }
            sleep(Duration::from_millis(300)).await;
        };
        assert_eq!(withdrawal.recipient, recipient);
        assert_eq!(withdrawal.amount, amount);
        assert_eq!(withdrawal.max_fee, expected_quote);

        let state = loop {
            let state = {
                let db = fed.server_db(peer);
                let mut dbtx = db.begin_transaction_nc().await;
                let (mut isolated, _) = dbtx.to_ref_with_prefix_module_id(module_instance_id);
                isolated.get_value(&WithdrawalStateKey(out_point)).await
            };
            if let Some(state) = state {
                break state;
            }
            if Instant::now() >= peer_deadline {
                panic!("guardian {peer} must hold the WithdrawalState");
            }
            sleep(Duration::from_millis(300)).await;
        };
        assert_eq!(state, WithdrawalState::Queued);
    }

    // 5. The claimed USDT e-cash was debited by exactly `amount + max_fee`. The
    //    mint spend's change is reissued asynchronously (a mint output state
    //    machine fetches the blind signatures after the tx is accepted), so poll
    //    until the balance settles rather than reading it eagerly -- exactly like
    //    the deposit-claim balance poll above. If this were a real over-charge (not
    //    change-settlement timing) the balance would never reach the expected value
    //    and this still fails at the deadline.
    let expected_balance = Amount::from_msats(net_deposit_amount.0 - amount.0 - expected_quote.0);
    let burn_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let balance_after = client.get_balance_for_unit(USDT_UNIT).await?;
        if balance_after == expected_balance {
            break;
        }
        if Instant::now() >= burn_deadline {
            assert_eq!(
                balance_after, expected_balance,
                "the withdrawal must burn exactly amount + max_fee of USDT e-cash"
            );
        }
        sleep(Duration::from_millis(300)).await;
    }

    // 6. Every guardian's ENTIRE usdt module DB converges to byte-identical at the
    //    terminal state. Guardians apply the final ordered items at slightly
    //    different wall-clock moments, so poll to convergence rather than comparing
    //    eagerly; the federation is quiescent here (static block count + static fee
    //    -> the pollers are redundancy-guarded and propose nothing new), so a fixed
    //    point is reached. A REAL divergence never converges and still fails at the
    //    deadline with the diverging peer.
    let converge_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut dumps: Vec<BTreeMap<Vec<u8>, Vec<u8>>> = Vec::with_capacity(peers.len());
        for &peer in &peers {
            dumps.push(dump_usdt_module_db(&fed, peer, module_instance_id).await);
        }
        if dumps.iter().all(|d| d == &dumps[0]) {
            break;
        }
        if Instant::now() >= converge_deadline {
            for (i, &peer) in peers.iter().enumerate() {
                assert_eq!(
                    &dumps[i], &dumps[0],
                    "guardian {peer}'s usdt module DB diverges from peer {}'s",
                    peers[0]
                );
            }
        }
        sleep(Duration::from_millis(300)).await;
    }

    Ok(())
}

/// **Phase 8 Task 2 gating acceptance test.** Drives TWO queued withdrawals
/// through the deterministic batching -> real-MPC-signing -> guardian-local
/// submission -> threshold-confirm lifecycle end to end over a hermetic
/// 4-guardian federation (shared [`MockEvmRpc`]; real MPC signing, no
/// hand-signing):
///
/// 1. Deposit + claim USDT e-cash, then let the Phase-7 sweep pipeline fund the
///    pool (mirrors
///    `withdrawal_output_debits_queues_and_fee_median_is_deterministic`'s steps
///    1-2b).
/// 2. Queue TWO withdrawal outputs (`UsdtOutput::V0`), waiting for both to
///    reach `WithdrawalState::Queued` on every guardian.
/// 3. Advance the shared mock's block count;
///    `Usdt::maybe_trigger_withdrawal_batch` (wired into the `BlockCount`
///    consensus arm) deterministically batches BOTH queued withdrawals into ONE
///    `Withdraw`-purpose `UserOp` once the trigger policy fires.
/// 4. The federation's real (background, timer-driven) MPC signing loop signs
///    it; every guardian's guardian-local `usdt-user-op-submitter` task submits
///    it (recorded by the mock) and polls for a receipt; once the test scripts
///    a successful receipt, guardians threshold-vote `UserOpConfirmed` and
///    `PoolState.balance` debits by exactly the two withdrawals' combined
///    `amount`, both `WithdrawalState`s converge to `Confirmed`, and both
///    `UnclaimedWithdrawal` records are removed -- on EVERY guardian.
/// 5. Asserts every guardian's ENTIRE usdt module database is byte-identical at
///    the terminal state (signer and non-signer alike).
///
/// CRITICAL (mirrors the Phase-7 sweep acceptance test and Phase-8 Task 1's
/// bugfix, per that task's own report): every per-guardian read below is
/// POLLED TO CONVERGENCE, never read eagerly -- guardians apply the same
/// ordered consensus items at slightly different wall-clock moments, so an
/// eager per-peer read would be a flaky false negative, not a genuine
/// divergence check. The `PendingUserOp` for the batch is captured BEFORE
/// waiting for its on-chain submission, exactly like the sweep op above (the
/// signing-completion step clears `PendingUserOp` -> `SubmittedUserOp`
/// before the guardian-local submitter task ever records a submission).
///
/// Slow (real MPC over a real, real-timer-driven federation, ~2-4 min);
/// intentionally run in the foreground.
#[tokio::test(flavor = "multi_thread")]
async fn withdrawal_batch_confirms_and_debits_pool_for_two_queued_withdrawals() -> anyhow::Result<()>
{
    let mock = Arc::new(MockEvmRpc::new());
    let usdt_contract = EvmAddress([0u8; 20]);
    mock.set_chain_id(31337);
    mock.set_block_number(100);
    let scripted_fee = FeeVote {
        max_fee_per_gas_wei: 20_000_000_000,
        usdt_per_eth_e6: 3_000_000_000,
    };
    mock.set_fee_estimate(scripted_fee);
    let expected_quote =
        withdrawal_fee_quote(&scripted_fee).expect("scripted fee must produce a quote");

    let fed = dual_mint_fixtures(mock.clone())
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;
    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;
    let module_instance_id = usdt.id;
    let peers: Vec<PeerId> = usdt.all_peers().into_iter().collect();
    assert_eq!(peers.len(), 4, "this test assumes the 4-guardian fixture");
    // Arbitrary guardian used to double-check federation-wide consensus
    // state below. Named `non_signer` for readability, but which guardians
    // actually sign is digest-seeded by `signer_subset` (sec-10 hardening),
    // not a fixed lowest-`t` subset -- the assertions below hold on this
    // peer's view regardless of whether it happened to be a signer.
    let non_signer = PeerId::from(3);

    // 0. Wait for the fee-vote median quote to converge (needed to compute a valid
    //    `max_fee` below), mirroring the Task-1 test's own step 1. Retries PAST an
    //    `Err` (not just past a stale/zero `Ok`): `withdraw_fee_quote` returns
    //    `Err` until a `FeeVote` median exists (security finding 06's
    //    client-confusion facet), and the guardians' 1s poller ticks + consensus
    //    still need real wall-clock time after boot to converge on one, even with
    //    `MockEvmRpc`'s sane nonzero default `FeeVote`.
    let quote_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(quote) = usdt.withdraw_fee_quote(UsdtAmount(1_000_000)).await
            && quote.max_fee == expected_quote
        {
            break;
        }
        if Instant::now() >= quote_deadline {
            bail!("withdraw_fee_quote never converged before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    }
    // The same `FeeVote` median backs `deposit_fee_quote`, already converged.
    let deposit_fee = usdt.deposit_fee_quote().await?.fee;

    // 1. Fund + sweep: deposit -> claim -> pool funded (Task-1 test's steps 2-2b).
    //    All e-cash amounts are 512-msat-aligned to avoid mintv2 denomination dust:
    //    the claim mints exactly `net_deposit_amount` (must be a 512 multiple), and
    //    each withdrawal burns `amount_i + quote` (which must be a 512 multiple --
    //    `quote` is itself 512-aligned post-Task-1 (360k gas units), so each
    //    `amount_i` is chosen as a 512 multiple directly, no offset needed). With
    //    this scripted fee both the deposit fee and the withdrawal fee are large
    //    (`SWEEP_GAS_UNITS`/`WITHDRAWAL_GAS_UNITS`-derived), so the deposit must be
    //    sized well above their historical (Task-1, 150k gas units) figures. The
    //    on-chain deposit funds `net_deposit_amount + deposit_fee` (the fee
    //    deducted at claim time -- Task 3/4 of the deposit-fee plan).
    // Part C: drive the module to Ready before allocating a deposit.
    let group_public_key = client.api().with_module(usdt.id).group_public_key().await?;
    common::mock_ready_stack(
        &mock,
        &group_public_key,
        usdt.config().entry_point,
        usdt.config().account_factory,
        usdt.config().simple_account_impl,
    );
    common::await_usdt_ready(&usdt, Duration::from_secs(60)).await?;
    let net_deposit_amount = UsdtAmount(61_440_000);
    let deposit_amount = UsdtAmount(net_deposit_amount.0 + deposit_fee.0);
    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    mock.set_erc20_balance_at(usdt_contract, account, 10, deposit_amount);
    usdt.check_and_claim(&claim_keypair, Duration::from_secs(120))
        .await?;
    let fund_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if client.get_balance_for_unit(USDT_UNIT).await? == Amount::from_msats(net_deposit_amount.0)
        {
            break;
        }
        if Instant::now() >= fund_deadline {
            bail!("USDT e-cash was never minted before the deadline");
        }
        sleep(Duration::from_millis(200)).await;
    }

    let submit_deadline = Instant::now() + Duration::from_secs(600);
    // Capture the sweep's op_hash from `PendingUserOp` BEFORE waiting for its
    // submission -- see this test's own doc comment for why.
    let sweep_op_hash = loop {
        if let Some(hash) = find_sole_pending_user_op_hash(&fed, peers[0], module_instance_id).await
        {
            break hash;
        }
        if Instant::now() >= submit_deadline {
            bail!("no sweep PendingUserOp appeared before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };
    loop {
        if !mock.submitted_user_ops().is_empty() {
            break;
        }
        if Instant::now() >= submit_deadline {
            bail!("no sweep UserOp submission was recorded before the deadline");
        }
        sleep(Duration::from_secs(1)).await;
    }
    mock.set_user_op_receipt(
        sweep_op_hash,
        UserOpReceipt {
            success: true,
            block: 42,
            block_hash: [0u8; 32],
            actual_gas_cost_wei: UsdtAmount(0),
        },
    );
    for &peer in &peers {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if usdt.pool_state(peer).await?.balance == deposit_amount {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "guardian {peer} pool balance never converged to the swept amount before the deadline"
                );
            }
            sleep(Duration::from_millis(300)).await;
        }
    }

    // 1b. **Task 5 (deposit-fee plan) solvency gate.** After the sweep, the pool
    //     holds the full on-chain `deposit_amount` while the `USDT_UNIT`-
    //     denominated mintv2 instance has issued only the NET
    //     `net_deposit_amount` -- the federation's global audited net assets
    //     must equal exactly the collected `deposit_fee` (a solvent, non-negative
    //     surplus). No Bitcoin-denominated value exists in this fixture, so the
    //     global figure reduces to this module pair's surplus alone.
    let audit_after_sweep = fed
        .new_admin_api(peers[0])
        .await?
        .audit(fedimint_core::module::ApiAuth::new("pass".to_string()))
        .await?;
    assert_eq!(
        audit_after_sweep.net_assets,
        i64::try_from(deposit_fee.0).expect("deposit_fee fits an i64"),
        "the federation's global net assets must equal exactly the collected deposit fee \
         after the sweep, before any withdrawal"
    );

    // 2. Queue TWO withdrawals. `withdraw` awaits each transaction's acceptance
    //    before returning (so its server-side WithdrawalState exists), but the
    //    USDT-`mintv2` primary module reissues each withdrawal's mint-CHANGE
    //    asynchronously -- so between the two back-to-back withdrawals we poll the
    //    client's USDT balance down to the expected post-burn-1 value, ensuring the
    //    second withdrawal's implicit funding sees the settled change (mirrors this
    //    module's claim path, which likewise polls for the effect). The withdrawal
    //    OUTPUT is always at `out_idx` 0 of the returned range's `txid` (the sole
    //    output added, before the primary module's change) -- the returned
    //    `OutPointRange` is itself the mint-CHANGE range, so we must NOT use its
    //    `start_out_point()`.
    let recipient_1 = EvmAddress([0x11; 20]);
    let recipient_2 = EvmAddress([0x22; 20]);
    let amount_1 = UsdtAmount(2_048_000); // % 512 == 0 -> amount_1 + quote is 512-aligned
    let amount_2 = UsdtAmount(2_560_000); // % 512 == 0 -> amount_2 + quote is 512-aligned
    let withdrawal_out_point = |range: fedimint_core::OutPointRange| fedimint_core::OutPoint {
        txid: range.txid(),
        out_idx: 0,
    };

    let out_point_1 =
        withdrawal_out_point(usdt.withdraw(recipient_1, amount_1, expected_quote).await?);

    // Wait for withdrawal 1's mint-change to settle before issuing
    // withdrawal 2, so 2's funding sees enough spendable notes.
    let after_burn_1 = Amount::from_msats(net_deposit_amount.0 - amount_1.0 - expected_quote.0);
    let settle_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if client.get_balance_for_unit(USDT_UNIT).await? == after_burn_1 {
            break;
        }
        if Instant::now() >= settle_deadline {
            bail!("withdrawal 1's change never settled before the deadline");
        }
        sleep(Duration::from_millis(200)).await;
    }

    let out_point_2 =
        withdrawal_out_point(usdt.withdraw(recipient_2, amount_2, expected_quote).await?);

    for &peer in &peers {
        for out_point in [out_point_1, out_point_2] {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                let state = {
                    let db = fed.server_db(peer);
                    let mut dbtx = db.begin_transaction_nc().await;
                    let (mut isolated, _) = dbtx.to_ref_with_prefix_module_id(module_instance_id);
                    isolated.get_value(&WithdrawalStateKey(out_point)).await
                };
                if state == Some(WithdrawalState::Queued) {
                    break;
                }
                if Instant::now() >= deadline {
                    panic!("guardian {peer} must reach WithdrawalState::Queued for {out_point}");
                }
                sleep(Duration::from_millis(300)).await;
            }
        }
    }

    // 3. Advance the shared mock's block count -- the guardians' block-count
    //    poller/consensus-proposal picks it up, and the `BlockCount` consensus arm
    //    deterministically triggers a single `Withdraw`-purpose batch of BOTH
    //    queued withdrawals once the oldest of them has waited
    //    `batch_interval_blocks()` consensus blocks.
    mock.set_block_number(400);

    let batch_deadline = Instant::now() + Duration::from_secs(120);
    // Capture the batch's op_hash from `PendingUserOp` BEFORE waiting for its
    // submission, exactly like the sweep op above.
    let batch_op_hash = loop {
        if let Some(hash) = find_sole_pending_user_op_hash(&fed, peers[0], module_instance_id).await
        {
            break hash;
        }
        if Instant::now() >= batch_deadline {
            bail!("no withdrawal-batch PendingUserOp appeared before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };
    for &peer in &peers {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let state = {
                let db = fed.server_db(peer);
                let mut dbtx = db.begin_transaction_nc().await;
                let (mut isolated, _) = dbtx.to_ref_with_prefix_module_id(module_instance_id);
                isolated.get_value(&WithdrawalStateKey(out_point_1)).await
            };
            if state == Some(WithdrawalState::Signing(batch_op_hash)) {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "guardian {peer} must deterministically include out_point_1 in the batch \
                     (last state {state:?})"
                );
            }
            sleep(Duration::from_millis(300)).await;
        }
    }

    let submit_deadline = Instant::now() + Duration::from_secs(600);
    loop {
        // The mock records one `Vec<SignedUserOp>` per `submit_user_ops`
        // call; the sweep already recorded (at least) one above, so the
        // batch's submission is a SECOND (or later) one.
        if mock.submitted_user_ops().len() >= 2 {
            break;
        }
        if Instant::now() >= submit_deadline {
            bail!("no withdrawal-batch UserOp submission was recorded before the deadline");
        }
        sleep(Duration::from_secs(1)).await;
    }
    mock.set_user_op_receipt(
        batch_op_hash,
        UserOpReceipt {
            success: true,
            block: 77,
            block_hash: [0u8; 32],
            actual_gas_cost_wei: UsdtAmount(0),
        },
    );

    // 4. Pool debited by exactly amount_1 + amount_2 (NOT the fees, which were
    //    already burned from e-cash and accrue to the federation) and both
    //    withdrawals Confirmed -- poll to convergence on EVERY guardian.
    let expected_pool_balance = UsdtAmount(deposit_amount.0 - amount_1.0 - amount_2.0);
    for &peer in &peers {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if usdt.pool_state(peer).await?.balance == expected_pool_balance {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "guardian {peer} pool balance never converged to the post-withdrawal amount \
                     (last {})",
                    usdt.pool_state(peer).await?.balance
                );
            }
            sleep(Duration::from_millis(300)).await;
        }
    }
    // Explicitly confirm the non-signer specifically -- the whole point of
    // this determinism test.
    assert_eq!(
        usdt.pool_state(non_signer).await?.balance,
        expected_pool_balance
    );

    for &peer in &peers {
        for out_point in [out_point_1, out_point_2] {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let (state, unclaimed) = {
                    let db = fed.server_db(peer);
                    let mut dbtx = db.begin_transaction_nc().await;
                    let (mut isolated, _) = dbtx.to_ref_with_prefix_module_id(module_instance_id);
                    let state = isolated.get_value(&WithdrawalStateKey(out_point)).await;
                    let unclaimed = isolated.get_value(&UnclaimedWithdrawalKey(out_point)).await;
                    (state, unclaimed)
                };
                if state == Some(WithdrawalState::Confirmed { block: 77 }) && unclaimed.is_none() {
                    break;
                }
                if Instant::now() >= deadline {
                    panic!(
                        "guardian {peer} must reach WithdrawalState::Confirmed with its \
                         UnclaimedWithdrawal removed for {out_point} (last state {state:?}, \
                         unclaimed present: {})",
                        unclaimed.is_some()
                    );
                }
                sleep(Duration::from_millis(300)).await;
            }
        }
    }

    // 4b. **Phase 8 Task 3 gating assertion.** The client-facing
    //     `withdrawal_status` endpoint (a `request_current_consensus` call,
    //     mirroring `deposit_status`/`withdraw_fee_quote`) must report the
    //     SAME `Confirmed { block: 77 }` this test already confirmed
    //     server-side above (step 4) via `WithdrawalStateKey`, reached
    //     through `UsdtClientModule::await_withdrawal_confirmed`'s polling
    //     loop -- not by re-deriving it from the raw server DB. An `OutPoint`
    //     that was never enqueued (a bogus `out_idx` on a real withdrawal's
    //     `txid`) must report `Unknown`.
    for out_point in [out_point_1, out_point_2] {
        let block = usdt
            .await_withdrawal_confirmed(out_point, Duration::from_secs(30))
            .await?;
        assert_eq!(block, 77);
    }
    let never_enqueued_out_point = fedimint_core::OutPoint {
        txid: out_point_1.txid,
        out_idx: 99,
    };
    assert_eq!(
        usdt.withdrawal_status(never_enqueued_out_point)
            .await?
            .status,
        fedimint_usdt_common::WithdrawalStatus::Unknown
    );

    // 5. Every guardian's ENTIRE usdt module DB converges to byte-identical at the
    //    terminal state.
    let converge_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut dumps: Vec<BTreeMap<Vec<u8>, Vec<u8>>> = Vec::with_capacity(peers.len());
        for &peer in &peers {
            dumps.push(dump_usdt_module_db(&fed, peer, module_instance_id).await);
        }
        if dumps.iter().all(|d| d == &dumps[0]) {
            break;
        }
        if Instant::now() >= converge_deadline {
            for (i, &peer) in peers.iter().enumerate() {
                assert_eq!(
                    &dumps[i], &dumps[0],
                    "guardian {peer}'s usdt module DB diverges from peer {}'s",
                    peers[0]
                );
            }
        }
        sleep(Duration::from_millis(300)).await;
    }

    // 6. **Task 5 (deposit-fee plan) round-trip solvency gate.** After a FULL
    //    deposit -> claim -> sweep -> withdraw -> confirm round trip, the
    //    federation's global net assets equal exactly the SUM of every fee
    //    collected (the one deposit fee plus both withdrawals' `max_fee`s) -- per
    //    `audit`'s own doc comment this figure stays CONSTANT across the withdrawal
    //    queue -> batch -> confirm lifecycle (matching the `audit_after_sweep`
    //    checkpoint taken before these withdrawals were even queued) -- and it is
    //    never negative, so the federation remains solvent throughout.
    let audit_after_round_trip = fed
        .new_admin_api(peers[0])
        .await?
        .audit(fedimint_core::module::ApiAuth::new("pass".to_string()))
        .await?;
    let expected_fee_revenue = i64::try_from(deposit_fee.0).expect("deposit_fee fits an i64")
        + 2 * i64::try_from(expected_quote.0).expect("expected_quote fits an i64");
    assert_eq!(
        audit_after_round_trip.net_assets, expected_fee_revenue,
        "the federation's global net assets after a full deposit->claim->sweep->withdraw->confirm \
         round trip must equal exactly the sum of the collected deposit fee and both withdrawal \
         fees"
    );
    assert!(
        audit_after_round_trip.net_assets >= 0,
        "the federation must remain solvent (non-negative net assets) after the full round trip"
    );

    Ok(())
}

/// **Security finding 09 (terminal-withdrawal refund) end-to-end acceptance.**
/// A single withdrawal is queued, batched into a SINGLETON `UserOp`, MPC-
/// signed and submitted, then observed as REVERTED on-chain (a failing
/// `UserOpReceipt`). Because the singleton reverted in isolation, the server
/// marks it terminal `Failed` and reissues its `(amount + max_fee)` e-cash as
/// a `Refund` (with zero incurred gas here, so the FULL amount). The client's
/// attached withdrawal state machine then claims that refund via a
/// `UsdtInput::RefundV0` and the burned e-cash is restored to the client's
/// spendable balance -- without any manual intervention.
#[tokio::test(flavor = "multi_thread")]
async fn client_claims_refund_on_terminal_failure() -> anyhow::Result<()> {
    let mock = Arc::new(MockEvmRpc::new());
    let usdt_contract = EvmAddress([0u8; 20]);
    mock.set_chain_id(31337);
    mock.set_block_number(100);
    let scripted_fee = FeeVote {
        max_fee_per_gas_wei: 20_000_000_000,
        usdt_per_eth_e6: 3_000_000_000,
    };
    mock.set_fee_estimate(scripted_fee);
    let expected_quote =
        withdrawal_fee_quote(&scripted_fee).expect("scripted fee must produce a quote");

    let fed = dual_mint_fixtures(mock.clone())
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;
    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;
    let module_instance_id = usdt.id;
    let peers: Vec<PeerId> = usdt.all_peers().into_iter().collect();

    // Wait for the fee-vote median quote to converge.
    let quote_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(quote) = usdt.withdraw_fee_quote(UsdtAmount(1_000_000)).await
            && quote.max_fee == expected_quote
        {
            break;
        }
        if Instant::now() >= quote_deadline {
            bail!("withdraw_fee_quote never converged before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    }
    let deposit_fee = usdt.deposit_fee_quote().await?.fee;

    // Fund + sweep: deposit -> claim -> pool funded.
    let group_public_key = client.api().with_module(usdt.id).group_public_key().await?;
    common::mock_ready_stack(
        &mock,
        &group_public_key,
        usdt.config().entry_point,
        usdt.config().account_factory,
        usdt.config().simple_account_impl,
    );
    common::await_usdt_ready(&usdt, Duration::from_secs(60)).await?;
    let net_deposit_amount = UsdtAmount(61_440_000);
    let deposit_amount = UsdtAmount(net_deposit_amount.0 + deposit_fee.0);
    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    mock.set_erc20_balance_at(usdt_contract, account, 10, deposit_amount);
    usdt.check_and_claim(&claim_keypair, Duration::from_secs(120))
        .await?;
    let fund_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if client.get_balance_for_unit(USDT_UNIT).await? == Amount::from_msats(net_deposit_amount.0)
        {
            break;
        }
        if Instant::now() >= fund_deadline {
            bail!("USDT e-cash was never minted before the deadline");
        }
        sleep(Duration::from_millis(200)).await;
    }

    let submit_deadline = Instant::now() + Duration::from_secs(600);
    let sweep_op_hash = loop {
        if let Some(hash) = find_sole_pending_user_op_hash(&fed, peers[0], module_instance_id).await
        {
            break hash;
        }
        if Instant::now() >= submit_deadline {
            bail!("no sweep PendingUserOp appeared before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };
    loop {
        if !mock.submitted_user_ops().is_empty() {
            break;
        }
        if Instant::now() >= submit_deadline {
            bail!("no sweep UserOp submission was recorded before the deadline");
        }
        sleep(Duration::from_secs(1)).await;
    }
    mock.set_user_op_receipt(
        sweep_op_hash,
        UserOpReceipt {
            success: true,
            block: 42,
            block_hash: [0u8; 32],
            actual_gas_cost_wei: UsdtAmount(0),
        },
    );
    for &peer in &peers {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if usdt.pool_state(peer).await?.balance == deposit_amount {
                break;
            }
            if Instant::now() >= deadline {
                bail!("guardian {peer} pool balance never converged before the deadline");
            }
            sleep(Duration::from_millis(300)).await;
        }
    }

    // Queue a SINGLE withdrawal (amount + quote is 512-aligned).
    let recipient = EvmAddress([0x11; 20]);
    let amount = UsdtAmount(2_048_000);
    let out_point = {
        let range = usdt.withdraw(recipient, amount, expected_quote).await?;
        fedimint_core::OutPoint {
            txid: range.txid(),
            out_idx: 0,
        }
    };
    // Balance after burning `amount + quote` (before any refund lands).
    let after_burn = Amount::from_msats(net_deposit_amount.0 - amount.0 - expected_quote.0);
    let settle_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if client.get_balance_for_unit(USDT_UNIT).await? == after_burn {
            break;
        }
        if Instant::now() >= settle_deadline {
            bail!("withdrawal burn/change never settled before the deadline");
        }
        sleep(Duration::from_millis(200)).await;
    }

    // Trigger the (singleton) batch.
    mock.set_block_number(400);
    let batch_deadline = Instant::now() + Duration::from_secs(120);
    let batch_op_hash = loop {
        if let Some(hash) = find_sole_pending_user_op_hash(&fed, peers[0], module_instance_id).await
        {
            break hash;
        }
        if Instant::now() >= batch_deadline {
            bail!("no withdrawal-batch PendingUserOp appeared before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };
    let submit_deadline = Instant::now() + Duration::from_secs(600);
    loop {
        if mock.submitted_user_ops().len() >= 2 {
            break;
        }
        if Instant::now() >= submit_deadline {
            bail!("no withdrawal-batch UserOp submission was recorded before the deadline");
        }
        sleep(Duration::from_secs(1)).await;
    }
    // The batch UserOp REVERTS on-chain (success = false), with zero recorded
    // gas so the refund is the full `amount + max_fee`.
    mock.set_user_op_receipt(
        batch_op_hash,
        UserOpReceipt {
            success: false,
            block: 88,
            block_hash: [0u8; 32],
            actual_gas_cost_wei: UsdtAmount(0),
        },
    );

    // Every guardian marks the withdrawal terminal Failed and creates a
    // reissued-e-cash Refund (UnclaimedWithdrawal replaced by RefundKey).
    for &peer in &peers {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let (state, refund) = {
                let db = fed.server_db(peer);
                let mut dbtx = db.begin_transaction_nc().await;
                let (mut isolated, _) = dbtx.to_ref_with_prefix_module_id(module_instance_id);
                (
                    isolated.get_value(&WithdrawalStateKey(out_point)).await,
                    isolated.get_value(&RefundKey(out_point)).await,
                )
            };
            if let (Some(WithdrawalState::Failed { .. }), Some(refund)) = (&state, refund) {
                assert_eq!(
                    refund.amount,
                    UsdtAmount(amount.0 + expected_quote.0),
                    "zero incurred gas -> the full amount + max_fee is refunded"
                );
                break;
            }
            if Instant::now() >= deadline {
                bail!("guardian {peer} never reached terminal Failed + Refund (last {state:?})");
            }
            sleep(Duration::from_millis(300)).await;
        }
    }

    // The client's attached withdrawal state machine claims the refund on its
    // own; the burned e-cash is restored to the client's spendable balance.
    let refund_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if client.get_balance_for_unit(USDT_UNIT).await? == Amount::from_msats(net_deposit_amount.0)
        {
            break;
        }
        if Instant::now() >= refund_deadline {
            bail!(
                "client balance was not restored by the refund before the deadline (last {})",
                client.get_balance_for_unit(USDT_UNIT).await?
            );
        }
        sleep(Duration::from_millis(300)).await;
    }

    // Once claimed, the refund record is gone (claimed exactly once) and the
    // client-facing `refund_status` reports it as no longer live.
    let claimed_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if usdt.refund_status(out_point).await?.refund.is_none() {
            break;
        }
        if Instant::now() >= claimed_deadline {
            bail!("refund record was never cleared after the client claimed it");
        }
        sleep(Duration::from_millis(300)).await;
    }

    Ok(())
}

/// Server DB migration coverage for the `usdt` module (security finding 06):
/// its first-ever migration, `migrate_db_v0`, changes `FeeVoteKey`'s value
/// shape from a bare `FeeVote` to `StoredFeeVote` (adds the `recorded_block`
/// freshness stamp `fee_vote_median`'s TTL/quorum gate needs). Mirrors
/// `fedimint-mint-tests`' `fedimint_migration_tests` module (see that
/// module's doc comments for the general pattern).
#[cfg(test)]
mod fedimint_migration_tests {
    use anyhow::ensure;
    use fedimint_core::db::{
        Database, IDatabaseTransactionOpsCore, IDatabaseTransactionOpsCoreTyped,
    };
    use fedimint_core::encoding::Encodable;
    use fedimint_core::{BitcoinHash as _, OutPoint, PeerId, TransactionId, secp256k1};
    use fedimint_logging::TracingSetup;
    use fedimint_server::core::DynServerModuleInit;
    use fedimint_testing::db::{snapshot_db_migrations, validate_migrations_server};
    use fedimint_usdt_common::user_op::{SignedUserOp, UnsignedUserOp};
    use fedimint_usdt_common::{
        BootstrapObservation, DepositObservation, EvmAddress, FeeVote, UsdtAmount, UsdtCommonInit,
        signing_session_id,
    };
    use fedimint_usdt_server::db::{
        BlockCountVoteKey, BootstrapVoteKey, DbKeyPrefix, DepositObservationVoteKey, DepositRecord,
        DepositRecordKey, FeeVoteKey, FeeVotePrefix, HasEverBeenReadyKey, MpcRoundChunk,
        MpcRoundChunkKey, PendingCheck, PendingCheckKey, PendingUserOp, PendingUserOpKey,
        PoolState, PoolStateKey, SessionState, SigningPurpose, SigningSession, SigningSessionKey,
        StoredFeeVote, SubmittedUserOpKey, UserOpConfirmedObservation, UserOpConfirmedVoteKey,
        UserOpPurpose, WithdrawalState, WithdrawalStateKey,
    };
    use futures::StreamExt as _;
    use strum::IntoEnumIterator;
    use tracing::info;

    use crate::UsdtInit;

    fn test_pubkey() -> secp256k1::PublicKey {
        let secp = secp256k1::Secp256k1::new();
        secp256k1::SecretKey::from_slice(&[0x11; 32])
            .expect("valid scalar")
            .public_key(&secp)
    }

    fn test_out_point(idx: u64) -> OutPoint {
        OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: idx,
        }
    }

    fn sample_unsigned_user_op() -> UnsignedUserOp {
        UnsignedUserOp {
            sender: EvmAddress([0x21; 20]),
            nonce: alloy::primitives::U256::ZERO,
            init_code: vec![0xde, 0xad],
            call_data: vec![0xbe, 0xef],
            verification_gas_limit: 500_000,
            call_gas_limit: 200_000,
            pre_verification_gas: alloy::primitives::U256::from(100_000u64),
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 30_000_000_000,
            paymaster_and_data: vec![],
        }
    }

    /// Create a database with pre-`migrate_db_v0` (i.e. this module's very
    /// first shipped) data: one record per `DbKeyPrefix` variant (matching
    /// `fedimint-usdt-server`'s own `dump_database_covers_every_key_prefix`
    /// coverage), EXCEPT `FeeVoteKey`, which is written at the RAW byte
    /// level as the pre-hardening bare `FeeVote` shape (the current crate no
    /// longer has a Rust type for it, since `FeeVoteKey`'s value is now
    /// `StoredFeeVote`) so this genuinely exercises the old on-disk layout
    /// `migrate_db_v0` must handle.
    ///
    /// This function should not be updated when database keys/values
    /// change -- instead a new function should be added that creates a new
    /// database backup that can be tested (mirroring
    /// `fedimint-mint-tests`' convention).
    async fn create_server_db_with_v0_data(db: Database) {
        let claim_pk = test_pubkey();
        let account = EvmAddress([0x31; 20]);
        let op_hash = [0x41; 32];
        let out_point = test_out_point(9);
        let session_id = signing_session_id(&[0x51; 32], 0);

        let mut dbtx = db.begin_transaction().await;

        dbtx.insert_new_entry(&BlockCountVoteKey(PeerId::from(0)), &42u64)
            .await;

        // The pre-`migrate_db_v0` `FeeVoteKey -> FeeVote` shape, written at
        // the raw byte level (see this function's doc comment).
        let mut old_fee_vote_key_bytes = vec![DbKeyPrefix::FeeVote as u8];
        old_fee_vote_key_bytes
            .extend_from_slice(&FeeVoteKey(PeerId::from(0)).consensus_encode_to_vec());
        let old_fee_vote_value_bytes = FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        }
        .consensus_encode_to_vec();
        dbtx.raw_insert_bytes(&old_fee_vote_key_bytes, &old_fee_vote_value_bytes)
            .await
            .expect("DB error");

        dbtx.insert_new_entry(
            &DepositRecordKey(account),
            &DepositRecord {
                claim_pk,
                credited: UsdtAmount(1_000_000),
                claimed: UsdtAmount(0),
                last_observed_block: 1,
                swept: UsdtAmount(0),
                nonce: 0,
            },
        )
        .await;
        // The pre-`migrate_db_v1` `DepositObservationVoteKey -> DepositObservation`
        // shape (findings 04/12/15), written at the raw byte level because the
        // current `DepositObservation` type now carries a `block_hash` the old
        // on-disk rows did not (mirrors the raw `FeeVote` write above). A
        // derived struct encodes as the concatenation of its fields in order,
        // so this is exactly the old four-field layout `migrate_db_v1` must
        // drop.
        let mut old_deposit_vote_key_bytes = vec![DbKeyPrefix::DepositObservationVote as u8];
        old_deposit_vote_key_bytes.extend_from_slice(
            &DepositObservationVoteKey(account, PeerId::from(0)).consensus_encode_to_vec(),
        );
        let mut old_deposit_vote_value_bytes = Vec::new();
        old_deposit_vote_value_bytes.extend_from_slice(&account.consensus_encode_to_vec());
        old_deposit_vote_value_bytes
            .extend_from_slice(&UsdtAmount(1_000_000).consensus_encode_to_vec());
        old_deposit_vote_value_bytes.extend_from_slice(&1u64.consensus_encode_to_vec());
        old_deposit_vote_value_bytes.extend_from_slice(&claim_pk.consensus_encode_to_vec());
        dbtx.raw_insert_bytes(&old_deposit_vote_key_bytes, &old_deposit_vote_value_bytes)
            .await
            .expect("DB error");
        dbtx.insert_new_entry(
            &PendingCheckKey(account),
            &PendingCheck {
                claim_pk,
                requested_at_block: 1,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &SigningSessionKey(session_id),
            &SigningSession {
                purpose: SigningPurpose::UserOp(op_hash),
                digest: [0x61; 32],
                signers: vec![PeerId::from(0)],
                round: 0,
                state: SessionState::InProgress,
                attempt: 0,
                last_progress_block: 1,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &MpcRoundChunkKey(session_id, 0, PeerId::from(0), 0),
            &MpcRoundChunk {
                count: 1,
                bytes: vec![0x01],
            },
        )
        .await;
        dbtx.insert_new_entry(
            &PendingUserOpKey(op_hash),
            &PendingUserOp {
                op: sample_unsigned_user_op(),
                purpose: UserOpPurpose::DeployAndSweep { source: account },
                created_block: 1,
            },
        )
        .await;
        // The pre-0.6 `SubmittedUserOp` shape, written RAW (like the vote tables
        // above) rather than via the typed current API: `migrate_db_v2` upgrades
        // a v1 row by APPENDING the `superseded` byte, so the frozen fixture row
        // must NOT already carry it. Old three-field layout:
        // `signed ++ purpose ++ submitted_block` (no `superseded`). Writing the
        // typed struct here would embed `superseded: false` and make
        // `migrate_db_v2`'s byte-append double-append `0x00` on regeneration ->
        // trailing-bytes decode failure.
        let signed = SignedUserOp {
            unsigned: sample_unsigned_user_op(),
            signature: vec![0x71; 65],
        };
        let mut old_submitted_key_bytes = vec![DbKeyPrefix::SubmittedUserOp as u8];
        old_submitted_key_bytes
            .extend_from_slice(&SubmittedUserOpKey(op_hash).consensus_encode_to_vec());
        let mut old_submitted_value_bytes = Vec::new();
        old_submitted_value_bytes.extend_from_slice(&signed.consensus_encode_to_vec());
        old_submitted_value_bytes.extend_from_slice(
            &UserOpPurpose::DeployAndSweep { source: account }.consensus_encode_to_vec(),
        );
        old_submitted_value_bytes.extend_from_slice(&1u64.consensus_encode_to_vec());
        dbtx.raw_insert_bytes(&old_submitted_key_bytes, &old_submitted_value_bytes)
            .await
            .expect("DB error");
        dbtx.insert_new_entry(
            &PoolStateKey,
            &PoolState {
                account,
                balance: UsdtAmount(1_000_000),
                nonce: 0,
            },
        )
        .await;
        // The pre-`migrate_db_v1` `UserOpConfirmedVoteKey ->
        // UserOpConfirmedObservation` shape (findings 04/15), written raw for
        // the same reason as the deposit vote above (the current type gained a
        // `block_hash`). Old three-field layout: `success ++ block ++ swept`.
        let mut old_userop_vote_key_bytes = vec![DbKeyPrefix::UserOpConfirmedVote as u8];
        old_userop_vote_key_bytes.extend_from_slice(
            &UserOpConfirmedVoteKey(op_hash, PeerId::from(0)).consensus_encode_to_vec(),
        );
        let mut old_userop_vote_value_bytes = Vec::new();
        old_userop_vote_value_bytes.extend_from_slice(&true.consensus_encode_to_vec());
        old_userop_vote_value_bytes.extend_from_slice(&1u64.consensus_encode_to_vec());
        old_userop_vote_value_bytes
            .extend_from_slice(&UsdtAmount(1_000_000).consensus_encode_to_vec());
        dbtx.raw_insert_bytes(&old_userop_vote_key_bytes, &old_userop_vote_value_bytes)
            .await
            .expect("DB error");
        // The pre-0.8 `UnclaimedWithdrawalKey -> UsdtWithdrawalV0` shape
        // (security finding 09), written RAW (like the vote/SubmittedUserOp
        // rows above) because the current `UsdtWithdrawalV0` now carries a
        // trailing `refund_pubkey` the old on-disk rows did not. A derived
        // struct encodes as the concatenation of its fields in order, so this
        // is exactly the old four-field layout `migrate_db_v3` upgrades by
        // APPENDING the placeholder refund pubkey. Writing the typed struct
        // here would embed a `refund_pubkey` and make `migrate_db_v3`'s
        // byte-append double-append -> trailing-bytes decode failure.
        let mut old_unclaimed_key_bytes = vec![DbKeyPrefix::UnclaimedWithdrawal as u8];
        old_unclaimed_key_bytes.extend_from_slice(
            &fedimint_usdt_server::db::UnclaimedWithdrawalKey(out_point).consensus_encode_to_vec(),
        );
        let mut old_unclaimed_value_bytes = Vec::new();
        old_unclaimed_value_bytes.extend_from_slice(&account.consensus_encode_to_vec());
        old_unclaimed_value_bytes
            .extend_from_slice(&UsdtAmount(1_000_000).consensus_encode_to_vec());
        old_unclaimed_value_bytes.extend_from_slice(&UsdtAmount(20_000).consensus_encode_to_vec());
        old_unclaimed_value_bytes.extend_from_slice(&1u64.consensus_encode_to_vec());
        dbtx.raw_insert_bytes(&old_unclaimed_key_bytes, &old_unclaimed_value_bytes)
            .await
            .expect("DB error");
        dbtx.insert_new_entry(&WithdrawalStateKey(out_point), &WithdrawalState::Queued)
            .await;
        dbtx.insert_new_entry(
            &BootstrapVoteKey(PeerId::from(0)),
            &BootstrapObservation {
                entry_point_ok: true,
                factory_ok: true,
                impl_ok: true,
                broadcaster_funded: true,
                rpc_healthy: true,
            },
        )
        .await;
        dbtx.insert_new_entry(&HasEverBeenReadyKey, &()).await;

        dbtx.commit_tx().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_server_db_migrations() -> anyhow::Result<()> {
        snapshot_db_migrations::<_, UsdtCommonInit>("usdt-server-v0", |db| {
            Box::pin(async {
                create_server_db_with_v0_data(db).await;
            })
        })
        .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_server_db_migrations() -> anyhow::Result<()> {
        let _ = TracingSetup::default().init();

        let module = DynServerModuleInit::from(UsdtInit::default());
        validate_migrations_server(module, "usdt-server", |db| async move {
            let mut dbtx = db.begin_transaction_nc().await;

            for prefix in DbKeyPrefix::iter() {
                match prefix {
                    DbKeyPrefix::BlockCountVote => {
                        let votes = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::BlockCountVotePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(!votes.is_empty(), "no BlockCountVotes read back");
                        info!("Validated BlockCountVote");
                    }
                    DbKeyPrefix::FeeVote => {
                        // Security finding 06: `migrate_db_v0` DROPS
                        // pre-migration `FeeVote` rows rather than
                        // rewriting them (see that function's doc comment
                        // for why this loses nothing meaningful) -- so the
                        // only thing to assert is that the table reads back
                        // cleanly (in the NEW `StoredFeeVote` shape) as
                        // EMPTY, not that any data survived.
                        let votes = dbtx
                            .find_by_prefix(&FeeVotePrefix)
                            .await
                            .collect::<Vec<(FeeVoteKey, StoredFeeVote)>>()
                            .await;
                        ensure!(
                            votes.is_empty(),
                            "pre-migration FeeVote rows must be dropped by migrate_db_v0, not rewritten"
                        );
                        info!("Validated FeeVote (dropped, not rewritten)");
                    }
                    DbKeyPrefix::DepositRecord => {
                        let records = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::DepositRecordPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(!records.is_empty(), "no DepositRecords read back");
                        info!("Validated DepositRecord");
                    }
                    DbKeyPrefix::DepositObservationVote => {
                        // Findings 04/12/15: `migrate_db_v1` DROPS pre-migration
                        // `DepositObservationVote` rows (they carry no
                        // `block_hash` and are re-proposed every scan tick --
                        // see that function's doc comment), so the table must
                        // read back cleanly in the NEW shape as EMPTY.
                        let votes = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::DepositObservationVotePrefix)
                            .await
                            .collect::<Vec<(DepositObservationVoteKey, DepositObservation)>>()
                            .await;
                        ensure!(
                            votes.is_empty(),
                            "pre-migration DepositObservationVote rows must be dropped by \
                             migrate_db_v1, not rewritten"
                        );
                        info!("Validated DepositObservationVote (dropped, not rewritten)");
                    }
                    DbKeyPrefix::PendingCheck => {
                        let checks = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::PendingCheckPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(!checks.is_empty(), "no PendingChecks read back");
                        info!("Validated PendingCheck");
                    }
                    DbKeyPrefix::SigningSession => {
                        let sessions = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::SigningSessionPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(!sessions.is_empty(), "no SigningSessions read back");
                        info!("Validated SigningSession");
                    }
                    DbKeyPrefix::MpcRoundChunk => {
                        let chunks = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::MpcRoundChunkPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(!chunks.is_empty(), "no MpcRoundChunks read back");
                        info!("Validated MpcRoundChunk");
                    }
                    DbKeyPrefix::PendingUserOp => {
                        let ops = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::PendingUserOpPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(!ops.is_empty(), "no PendingUserOps read back");
                        info!("Validated PendingUserOp");
                    }
                    DbKeyPrefix::SubmittedUserOp => {
                        let ops = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::SubmittedUserOpPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(!ops.is_empty(), "no SubmittedUserOps read back");
                        info!("Validated SubmittedUserOp");
                    }
                    DbKeyPrefix::PoolState => {
                        let state = dbtx.get_value(&PoolStateKey).await;
                        ensure!(state.is_some(), "no PoolState read back");
                        info!("Validated PoolState");
                    }
                    DbKeyPrefix::UserOpConfirmedVote => {
                        // Findings 04/15: `migrate_db_v1` DROPS pre-migration
                        // `UserOpConfirmedVote` rows (no `block_hash`; re-polled
                        // and re-proposed every submit tick), so the table must
                        // read back cleanly in the NEW shape as EMPTY.
                        let votes = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::UserOpConfirmedVotePrefix)
                            .await
                            .collect::<Vec<(UserOpConfirmedVoteKey, UserOpConfirmedObservation)>>()
                            .await;
                        ensure!(
                            votes.is_empty(),
                            "pre-migration UserOpConfirmedVote rows must be dropped by \
                             migrate_db_v1, not rewritten"
                        );
                        info!("Validated UserOpConfirmedVote (dropped, not rewritten)");
                    }
                    DbKeyPrefix::UnclaimedWithdrawal => {
                        // Security finding 09: `migrate_db_v3` REWRITES each
                        // pre-0.8 `UsdtWithdrawalV0` row by APPENDING the
                        // placeholder `refund_pubkey` (these are still-funded
                        // obligations that must survive the upgrade, not be
                        // dropped). Assert the row decodes cleanly in the NEW
                        // shape AND carries exactly the placeholder key.
                        let withdrawals = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::UnclaimedWithdrawalPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(!withdrawals.is_empty(), "no UnclaimedWithdrawals read back");
                        let placeholder = fedimint_core::secp256k1::PublicKey::from_slice(
                            &fedimint_usdt_server::LEGACY_REFUND_PLACEHOLDER_PUBKEY,
                        )
                        .expect("placeholder is a valid pubkey");
                        for (_k, w) in &withdrawals {
                            ensure!(
                                w.refund_pubkey == placeholder,
                                "migrate_db_v3 must default a pre-0.8 withdrawal's refund_pubkey \
                                 to the unspendable placeholder"
                            );
                        }
                        info!("Validated UnclaimedWithdrawal (migrate_db_v3 refund_pubkey append)");
                    }
                    DbKeyPrefix::Refund => {
                        // Security finding 09: a brand-new prefix; the
                        // pre-migration snapshot predates it and no migration
                        // writes to it, so it must read back cleanly as EMPTY.
                        let refunds = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::RefundPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(
                            refunds.is_empty(),
                            "Refund is a brand-new prefix; the pre-migration snapshot must not \
                             contain any rows for it"
                        );
                        info!("Validated Refund (new prefix, empty)");
                    }
                    DbKeyPrefix::WithdrawalIncurredFee => {
                        // Security finding 09: a brand-new prefix; empty in the
                        // pre-migration snapshot, like `Refund` above.
                        let fees = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::WithdrawalIncurredFeePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(
                            fees.is_empty(),
                            "WithdrawalIncurredFee is a brand-new prefix; the pre-migration \
                             snapshot must not contain any rows for it"
                        );
                        info!("Validated WithdrawalIncurredFee (new prefix, empty)");
                    }
                    DbKeyPrefix::WithdrawalState => {
                        let states = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::WithdrawalStatePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(!states.is_empty(), "no WithdrawalStates read back");
                        info!("Validated WithdrawalState");
                    }
                    DbKeyPrefix::BootstrapVote => {
                        let votes = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::BootstrapVotePrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(!votes.is_empty(), "no BootstrapVotes read back");
                        info!("Validated BootstrapVote");
                    }
                    DbKeyPrefix::HasEverBeenReady => {
                        let latch = dbtx.get_value(&HasEverBeenReadyKey).await;
                        ensure!(latch.is_some(), "HasEverBeenReady latch not read back");
                        info!("Validated HasEverBeenReady");
                    }
                    DbKeyPrefix::WithdrawalBatchCap => {
                        // Security finding 05 (poisoned-batch isolation): a
                        // brand-new prefix added alongside this task, holding
                        // only new `u32` data -- the v0 snapshot fixture
                        // predates it and no migration writes to it, so it
                        // must read back cleanly as EMPTY (not dropped/
                        // rewritten, simply never populated pre-migration).
                        let caps = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::WithdrawalBatchCapPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(
                            caps.is_empty(),
                            "WithdrawalBatchCap is a brand-new prefix; the pre-migration v0 \
                             snapshot must not contain any rows for it"
                        );
                        info!("Validated WithdrawalBatchCap (new prefix, empty)");
                    }
                    DbKeyPrefix::BlockHashRing => {
                        // Deposit-by-proof task 3: a brand-new prefix, like
                        // `Refund`/`WithdrawalIncurredFee`/`WithdrawalBatchCap`
                        // above -- the pre-migration v0 snapshot predates it and
                        // no migration writes to it, so it must read back
                        // cleanly as EMPTY.
                        let ring = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::BlockHashRingPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(
                            ring.is_empty(),
                            "BlockHashRing is a brand-new prefix; the pre-migration v0 snapshot \
                             must not contain any rows for it"
                        );
                        info!("Validated BlockHashRing (new prefix, empty)");
                    }
                    DbKeyPrefix::LastSweepBlock => {
                        // LOCAL fedi extension (sweep-aware credit rule): a
                        // brand-new prefix holding only new `u64` data -- the
                        // v0 snapshot fixture predates it and no migration
                        // writes to it, so it must read back cleanly as EMPTY
                        // (never populated pre-migration).
                        let blocks = dbtx
                            .find_by_prefix(&fedimint_usdt_server::db::LastSweepBlockPrefix)
                            .await
                            .collect::<Vec<_>>()
                            .await;
                        ensure!(
                            blocks.is_empty(),
                            "LastSweepBlock is a brand-new prefix; the pre-migration v0 \
                             snapshot must not contain any rows for it"
                        );
                        info!("Validated LastSweepBlock (new prefix, empty)");
                    }
                }
            }

            Ok(())
        })
        .await
    }
}
