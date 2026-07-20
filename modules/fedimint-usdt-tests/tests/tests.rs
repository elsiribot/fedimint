mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use common::MockEvmRpc;
use fedimint_client::ClientHandleArc;
use fedimint_core::runtime::{Instant, sleep};
use fedimint_core::{Amount, PeerId, secp256k1};
use fedimint_mint_client::{MintClientInit, MintClientModule};
use fedimint_mint_server::MintInit;
use fedimint_mintv2_client::MintClientInit as Mintv2ClientInit;
use fedimint_mintv2_common::KIND as MINTV2_KIND;
use fedimint_mintv2_common::config::MintGenParams;
use fedimint_mintv2_server::MintInit as Mintv2Init;
use fedimint_testing::fixtures::Fixtures;
use fedimint_usdt_client::api::UsdtFederationApi;
use fedimint_usdt_client::{UsdtClientInit, UsdtClientModule};
use fedimint_usdt_common::{EvmAddress, SigningSessionId, USDT_UNIT, UsdtAmount};
use fedimint_usdt_server::UsdtInit;

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

    let expected = fedimint_usdt_common::derive_deposit_account(&group_public_key, &claim_pk);
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
