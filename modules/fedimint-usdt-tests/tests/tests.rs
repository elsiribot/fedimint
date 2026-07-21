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
use fedimint_core::{Amount, PeerId, secp256k1};
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
    EvmAddress, FeeVote, SigningSessionId, USDT_UNIT, UsdtAmount, UserOpStatus,
    withdrawal_fee_quote,
};
use fedimint_usdt_server::UsdtInit;
use fedimint_usdt_server::db::{
    PendingUserOpKey, PendingUserOpPrefix, UnclaimedWithdrawalKey, UnclaimedWithdrawalPrefix,
    UsdtWithdrawalV0, WithdrawalState, WithdrawalStateKey,
};
use futures::StreamExt as _;

fn fixtures() -> Fixtures {
    Fixtures::new_primary(MintClientInit, MintInit).with_module(UsdtClientInit, UsdtInit::default())
}

/// Like [`fixtures`] (single Bitcoin-denominated primary mint plus the usdt
/// module), but wires `mock` in as EVERY guardian's
/// [`fedimint_usdt_server::rpc::IServerEvmRpc`] (via
/// [`UsdtInit::with_evm_rpc`]) instead of the default `AlloyEvmRpc` (which,
/// absent a real EVM node, never advances and so can never drive the
/// block-count timeout). Needed by tests that must actually make
/// `consensus_block_count` cross a timeout threshold.
fn fixtures_with_evm_rpc(mock: Arc<MockEvmRpc>) -> Fixtures {
    Fixtures::new_primary(MintClientInit, MintInit)
        .with_module(UsdtClientInit, UsdtInit::with_evm_rpc(mock))
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

    // `fixtures()` never overrides `UsdtGenParams::default()`'s placeholder
    // `account_factory`/`simple_account_impl` (both `EvmAddress([0; 20])`;
    // see `fedimint_usdt_server::UsdtInit::default_config_gen_params`), so
    // that's what the federation's `UsdtClientConfig` actually carries here.
    let expected = fedimint_usdt_common::derive_deposit_account(
        &group_public_key,
        EvmAddress([0u8; 20]),
        EvmAddress([0u8; 20]),
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

    // 1. Derive a deposit address.
    let (claim_keypair, account) = usdt.allocate_deposit().await?;

    // 2. Simulate the confirmed on-chain USDT transfer (confirmed as of block 10,
    //    well behind the chain head of 100). `2_560_000` is a multiple of 512 msat
    //    (mintv2's smallest client denomination, `fedimint_mintv2_common::config::
    //    client_denominations`, `Denomination(9) == 2^9`), so the claimed amount is
    //    exactly representable as e-cash notes with no denomination-rounding dust,
    //    letting step 4 assert *exact* equality below.
    mock.set_erc20_balance_at(usdt_contract, account, 10, UsdtAmount(2_560_000));

    // 3. Client checks + claims; guardians observe (block-count poller +
    //    deposit-checker on their 1s test ticks) and credit at threshold, then the
    //    client submits the claim transaction. A generous deadline: consensus
    //    sessions + the 1s poll ticks need real wall-clock time.
    usdt.check_and_claim(&claim_keypair, Duration::from_secs(120))
        .await?;

    // 4. The USDT-denominated e-cash balance equals the deposit. Issuance is
    //    asynchronous even after the claim transaction is accepted, so poll with a
    //    timeout rather than asserting on the first read.
    let poll_deadline = fedimint_core::runtime::Instant::now() + Duration::from_secs(30);
    let balance = loop {
        let balance = client.get_balance_for_unit(USDT_UNIT).await?;
        if balance == Amount::from_msats(2_560_000)
            || fedimint_core::runtime::Instant::now() >= poll_deadline
        {
            break balance;
        }
        sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(balance, Amount::from_msats(2_560_000));

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
        Amount::from_msats(2_560_000),
        "a rejected replay must not change the USDT-denominated balance"
    );

    Ok(())
}

/// Polls `signing_session_status` across every guardian in `usdt`'s
/// federation until one of them (necessarily a signer -- non-signers and
/// signers still in progress return `None`, see
/// `fedimint_usdt_common::endpoint_constants::SIGNING_SESSION_STATUS_
/// ENDPOINT`'s doc comment) returns `Some(signature)`, or `deadline` elapses.
async fn poll_across_peers_until_some(
    usdt: &UsdtClientModule,
    session_id: SigningSessionId,
    deadline: Duration,
) -> anyhow::Result<Vec<u8>> {
    let deadline_at = Instant::now() + deadline;
    loop {
        for peer in usdt.all_peers() {
            if let Ok(Some(sig)) = usdt.signing_session_status(peer, session_id).await {
                return Ok(sig);
            }
        }

        if Instant::now() >= deadline_at {
            bail!("no guardian produced a signature for {session_id:?} before the deadline");
        }

        sleep(Duration::from_millis(500)).await;
    }
}

/// **Phase 6a gating acceptance test.** Drives a real threshold-ECDSA
/// signing session end to end over a hermetic 4-guardian federation: the
/// test triggers `UsdtConsensusItem::StartSigning` via the test-only
/// `debug_start_signing` API endpoint on a single guardian (starting a
/// session directly per-guardian would race the guardians' independent
/// consensus loops -- see `UsdtConsensusItem::StartSigning`'s doc comment),
/// then polls every guardian's guardian-LOCAL `signing_session_status` until
/// one of the 3 signers finishes, and verifies the resulting compact
/// signature against the federation's DKG group public key.
#[tokio::test(flavor = "multi_thread")]
async fn federation_signs_a_digest_via_mpc() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    let digest = [0x11u8; 32];

    // 1. Kick off signing via the debug endpoint on ONE guardian; the resulting
    //    `StartSigning` consensus item starts the session on all four.
    usdt.debug_start_signing(digest).await?;
    let session_id = fedimint_usdt_common::signing_session_id(&digest, 0);

    // 2. Poll `signing_session_status` across guardians until a signer returns
    //    `Some(sig)`. Real MPC over a real, real-timer-driven federation is slow --
    //    a generous multi-minute deadline.
    let sig_compact =
        poll_across_peers_until_some(&usdt, session_id, Duration::from_secs(600)).await?;

    // 3. Verify against the federation's group public key.
    let group_pk = client.api().with_module(usdt.id).group_public_key().await?;
    let msg = secp256k1::Message::from_digest(digest);
    let mut sig = secp256k1::ecdsa::Signature::from_compact(&sig_compact)?;
    sig.normalize_s();
    secp256k1::Secp256k1::verification_only()
        .verify_ecdsa(&msg, &sig, &group_pk)
        .expect("federation MPC signature verifies against the group key");

    Ok(())
}

/// **Phase 6b gating acceptance test (Task 4).** Drives the degraded-
/// federation recovery path end to end over a real, real-timer-driven
/// 4-guardian federation: attempt 0's fixed lowest-`t` signer subset
/// (`{0,1,2}` of 4, see `Usdt::signer_subset`) is forced to stall, the
/// deterministic block-count timeout fires, `RotateSigning` rotates the
/// session to attempt 1's subset (`{1,2,3}`), and attempt 1 produces a real,
/// verifiable signature.
///
/// **Degraded mechanism.** `fedimint-testing`'s `new_fed_degraded`/
/// `new_fed_builder(num_offline)` fixture always brings down the
/// HIGHEST-numbered `num_offline` peer(s) (see
/// `FederationTestBuilder::build`'s `u16::from(peer_id) >= self.num_peers -
/// self.num_offline` skip). Attempt 0's subset is always the fixed
/// lowest-`t` peers `{0,1,2}` (`signer_subset`'s `attempt=0` offset is
/// always `0`), so downing the highest peer (peer 3, for `num_offline=1` on
/// 4 peers) can NEVER make attempt 0 stall -- its signers are always the
/// ones the fixture leaves online. This test therefore takes the brief's
/// documented fallback: a full 4-guardian federation plus a test-only
/// `debug_suppress_attempt0_round` endpoint (Phase 6b Task 4 harness; see its
/// doc comment) that makes ONE guardian in `{0,1,2}` (peer 0) withhold its
/// `MpcRound` proposals for attempt-0 sessions only, so the round can never
/// reach 3-of-3 and the session genuinely stalls. Attempt 1's rotated subset
/// `{1,2,3}` excludes the suppressing peer 0, so it is unaffected and
/// completes normally -- this is not a full-federation happy path relabeled;
/// attempt 0 never produces a signature, and every peer in attempt 1's
/// subset is live and un-suppressed.
///
/// A shared [`MockEvmRpc`], injected into every guardian via
/// [`UsdtInit::with_evm_rpc`], stands in for the block-count poller's EVM
/// node so the block count can be driven past the timeout on demand (the
/// default `AlloyEvmRpc`, absent a real node, never advances, so the timeout
/// could never fire).
#[tokio::test(flavor = "multi_thread")]
async fn degraded_federation_recovers_signing_via_timeout_and_rotation() -> anyhow::Result<()> {
    let mock = Arc::new(MockEvmRpc::new());
    mock.set_block_number(0);

    let fed = fixtures_with_evm_rpc(mock.clone())
        .new_fed_not_degraded()
        .await;
    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    // 0. Arrange for peer 0 -- a member of attempt 0's fixed subset {0,1,2} -- to
    //    withhold its `MpcRound` proposals for attempt-0 sessions only, so the
    //    round can never reach 3-of-3 and the session stalls until it times out.
    let suppressed_peer = PeerId::from(0);
    usdt.debug_suppress_attempt0_round(suppressed_peer, true)
        .await?;

    let digest = [0x22u8; 32];
    let attempt0 = fedimint_usdt_common::signing_session_id(&digest, 0);
    let attempt1 = fedimint_usdt_common::signing_session_id(&digest, 1);

    // 1. Kick off signing; `StartSigning` starts attempt 0 (subset {0,1,2}) on
    //    every guardian. Give it a few seconds of real wall-clock time to actually
    //    start and genuinely stall (peer 0 never proposes its round-0 chunks, so
    //    `process_mpc_round` can never see all 3 signers complete).
    usdt.debug_start_signing(digest).await?;
    sleep(Duration::from_secs(5)).await;

    // 2. Drive the block-count poller (via the shared mock) far past the signing
    //    timeout so every guardian's `consensus_proposal` proposes `RotateSigning`
    //    for the stalled attempt-0 session on its next ~100ms proposal tick
    //    (guardians re-poll the mock on a 1s timer). NOTE:
    //    `is_running_in_test_env()` is FALSE for `fedimint-usdt-server` compiled as
    //    an integration-test dependency (`cfg!(test)` is false, `NEXTEST` unset
    //    under `cargo test`), so `timeout_blocks()` returns its PRODUCTION value
    //    here, not the small test value. Jump the block count well above that
    //    production timeout (and any plausible future bump to it) so the rotation
    //    fires regardless. The first block-count vote is unclamped (consensus block
    //    count starts at 0), so this single jump lands in one round; the mock then
    //    stays fixed, so the rotated attempt 1 (whose `last_progress_block` is this
    //    value) never itself times out.
    mock.set_block_number(1000);

    // 3. Poll `signing_session_status` for ATTEMPT 1 specifically (not attempt 0 --
    //    that session must never complete) across every guardian until a signer in
    //    the rotated subset finishes. Real MPC + a timeout cycle over a real
    //    federation is slow -- a generous multi-minute deadline.
    let sig_compact =
        poll_across_peers_until_some(&usdt, attempt1, Duration::from_secs(600)).await?;

    // 4. Verify the recovered signature against the federation's group key -- a
    //    real signature, produced by the rotated subset, not a relabeled happy
    //    path.
    let group_pk = client.api().with_module(usdt.id).group_public_key().await?;
    let msg = secp256k1::Message::from_digest(digest);
    let mut sig = secp256k1::ecdsa::Signature::from_compact(&sig_compact)?;
    sig.normalize_s();
    secp256k1::Secp256k1::verification_only()
        .verify_ecdsa(&msg, &sig, &group_pk)
        .expect("rotated-subset MPC signature verifies against the group key");

    // 5. The suppressed attempt-0 session must never have produced a signature:
    //    attempt 1 (created ONLY by `process_rotate_signing`, which first marks
    //    attempt 0 `Failed`) is the only session that ever completed, so this is a
    //    genuine stall-then-rotate recovery, not a full-federation happy path.
    let attempt0_status = usdt
        .signing_session_status(suppressed_peer, attempt0)
        .await?;
    assert_eq!(
        attempt0_status, None,
        "the suppressed attempt-0 session must never produce a signature"
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
/// chain, and guardian 3 never signs -- `signer_subset(0)` is the fixed
/// lowest-`t` subset `{0,1,2}`):
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
    let non_signer = PeerId::from(3); // signer_subset(0) is the fixed {0,1,2}

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
            actual_cost_usdt: UsdtAmount(0),
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
    //    guardian and equals the pure-function quote.
    let quote_deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let quote = usdt.withdraw_fee_quote(UsdtAmount(1_000_000)).await?;
        if quote.max_fee == expected_quote {
            break;
        }
        if Instant::now() >= quote_deadline {
            bail!(
                "withdraw_fee_quote never converged to {expected_quote} (last {})",
                quote.max_fee
            );
        }
        sleep(Duration::from_millis(300)).await;
    }
    // `withdraw_fee_quote` is a `request_current_consensus` call, so a
    // response at all means a threshold of guardians agreed on it; assert the
    // value equals the deterministic quote.
    let quote = usdt.withdraw_fee_quote(UsdtAmount(1_000_000)).await?;
    assert_eq!(quote.max_fee, expected_quote);

    // 2. Fund the withdrawal: deposit + claim USDT e-cash. `25_600_000` is a
    //    multiple of 512 msat (no mintv2 denomination-rounding dust) and
    //    comfortably covers `amount + max_fee`.
    let deposit_amount = UsdtAmount(25_600_000);
    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    mock.set_erc20_balance_at(usdt_contract, account, 10, deposit_amount);
    usdt.check_and_claim(&claim_keypair, Duration::from_secs(120))
        .await?;
    let fund_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if client.get_balance_for_unit(USDT_UNIT).await? == Amount::from_msats(deposit_amount.0) {
            break;
        }
        if Instant::now() >= fund_deadline {
            bail!("USDT e-cash was never minted before the deadline");
        }
        sleep(Duration::from_millis(200)).await;
    }

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
            actual_cost_usdt: UsdtAmount(0),
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

    // 3. Submit the withdrawal output (max_fee == quote).
    let recipient = EvmAddress([0x99; 20]);
    let amount = UsdtAmount(2_000_000);
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
    let expected_balance = Amount::from_msats(25_600_000 - amount.0 - expected_quote.0);
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
