//! Off-thread threshold-ECDSA signing sessions for the USDT module.
//!
//! This wraps the mechanism proved out by the Phase-6 spike
//! (`suspendable_pump_advances_offthread_signing_across_parked_rounds` in
//! `crypto/threshold-ecdsa/src/transport/off_thread.rs`): a `!Send`,
//! synchronous cggmp21 `signing` state machine is spawned on a dedicated OS
//! thread (see [`spawn_protocol`]) and driven from consensus by a
//! suspendable poll-all/submit-all pump, rather than by one continuous
//! [`ProtocolHandle::drive`] call. Between pumps the state machine sits
//! parked on its own thread, blocked inside its transport's `exchange` call,
//! for an arbitrary amount of wall-clock and any number of unrelated async
//! poll points — exactly what advancing a signing session across many
//! consensus rounds requires.
//!
//! No consensus wiring lives here yet: [`spawn_signing_session`] and
//! [`pump_slot_outgoing`] are the building blocks; a later phase task drives
//! them from `consensus_proposal`/`process_consensus_item`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use cggmp21::ExecutionId;
use fedimint_core::PeerId;
use fedimint_threshold_ecdsa::Curve;
use fedimint_threshold_ecdsa::transport::{
    EncryptedRoundCodec, ProtocolHandle, drive_over_exchange, spawn_protocol,
};
use fedimint_usdt_common::SigningSessionId;
use rand::rngs::OsRng;

use crate::config::UsdtConfig;

/// Domain-separation prefix for a signing session's `ExecutionId`, folded
/// together with the session id (itself already a domain-separated hash of
/// the digest and retry attempt — see
/// [`fedimint_usdt_common::signing_session_id`]) into a fresh eid unique to
/// this signing execution.
///
/// Config-gen eids (`usdt-dkg-keygen-v0`/`usdt-dkg-aux-v0` in `dkg.rs`) must
/// never be reused at runtime — cggmp21 requires every protocol execution to
/// use a distinct eid — so runtime signing derives its own here instead of
/// touching those.
const SIGNING_EID_PREFIX: &[u8] = b"fedimint-usdt-signing-eid/";

/// One in-flight off-thread signing session, as tracked by this guardian:
/// the parked handle to its dedicated-thread cggmp21 state machine, the
/// outgoing payload most recently pulled from it (waiting to be broadcast,
/// or already broadcast and waiting on the round's peer payloads), the
/// round number it belongs to, and whether the session has produced its
/// final output.
///
/// Deliberately holds no `SigningSessionId`/consensus bookkeeping of its own
/// — the `SessionStore` it lives in is keyed by that id, and the consensus
/// wiring that reads/writes `round` (a later phase task) is expected to
/// cross-check it against the persisted `SigningSession.round`.
pub struct SessionSlot {
    pub handle: ProtocolHandle<cggmp21::Signature<Curve>>,
    pub pending_outgoing: Option<Vec<u8>>,
    pub round: u16,
    pub done: bool,
}

// `ProtocolHandle` (its dedicated-thread `JoinHandle` and raw `mpsc`
// channels) has no meaningful/derivable `Debug` representation, but `Usdt`
// derives `Debug` and needs its `signing_sessions: SessionStore` field to be
// one. Print just the progress bookkeeping instead, mirroring
// `UsdtConfigPrivate`'s redacted `Debug` impl for its own non-`Debug`
// secret/state fields.
impl std::fmt::Debug for SessionSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSlot")
            .field("handle", &"<off-thread protocol handle>")
            .field(
                "pending_outgoing_len",
                &self.pending_outgoing.as_ref().map(Vec::len),
            )
            .field("round", &self.round)
            .field("done", &self.done)
            .finish()
    }
}

/// This guardian's in-memory table of currently-running off-thread signing
/// sessions, keyed by [`SigningSessionId`].
///
/// Deliberately not persisted: a `!Send`, non-serializable cggmp21 state
/// machine cannot survive a guardian restart, so a session's parked
/// `SessionSlot` is inherently guardian-process-lifetime state. A guardian
/// that restarts mid-session loses it and must have the session retried
/// consensus-side under a fresh `SigningSessionId` (a later phase's
/// concern, not this store's).
pub type SessionStore = Arc<Mutex<BTreeMap<SigningSessionId, SessionSlot>>>;

/// Spawns this guardian's off-thread cggmp21 signing state machine for
/// `session_id`, jointly signing `digest` with the `signers` subset of the
/// federation.
///
/// Returns `None` if `our_peer_id` is not a member of `signers` — nothing to
/// spawn for a guardian outside the signing subset. Otherwise returns
/// `Some(handle)`; the caller is expected to wrap it into a [`SessionSlot`]
/// (`round: 0, pending_outgoing: None, done: false`) and store it in the
/// module's [`SessionStore`] under `session_id`.
///
/// `signers` need not already be sorted; this function sorts a local copy.
/// Every subset member must independently call this with the identical
/// `signers` slice (so every party agrees on the resulting keygen-index
/// ordering and subset positions) and the identical `session_id`/`digest`.
///
/// # Panics
///
/// Panics if `signers` has more than `u16::MAX` members, or if any subset
/// member's `PeerId` is missing from `cfg.consensus.mpc_encryption_pks` —
/// both indicate a malformed federation configuration/signer set, not a
/// runtime condition this function is expected to recover from.
pub fn spawn_signing_session(
    session_id: SigningSessionId,
    digest: [u8; 32],
    signers: &[PeerId],
    our_peer_id: PeerId,
    cfg: &UsdtConfig,
) -> Option<ProtocolHandle<cggmp21::Signature<Curve>>> {
    let mut subset: Vec<PeerId> = signers.to_vec();
    subset.sort_unstable();

    let our_pos = u16::try_from(subset.iter().position(|&p| p == our_peer_id)?)
        .expect("signing subsets fit in u16 in every supported deployment");
    let t = u16::try_from(subset.len())
        .expect("signing subsets fit in u16 in every supported deployment");

    // `PeerId` wraps a `u16` directly and the federation's peer ids are
    // exactly `0..n` (see `fedimint_core::PeerId`/`NumPeers::peer_ids`), the
    // same index space cggmp21's keygen assigns parties across — this is
    // the same convention `dkg.rs`'s `resolve_party_assignment` relies on
    // (party index == position in the sorted peer id list == the peer id's
    // own `u16` value).
    let keygen_indices: Vec<u16> = subset.iter().map(|&p| u16::from(p)).collect();

    let signer_enc_pks: Vec<secp256k1::PublicKey> = subset
        .iter()
        .map(|peer| {
            *cfg.consensus
                .mpc_encryption_pks
                .get(peer)
                .expect("every signing subset member has a configured MPC encryption key")
        })
        .collect();

    // Fresh-per-signing eid, bound to the session id (itself already bound
    // to the digest and retry attempt), never reused across executions.
    let eid_bytes = [SIGNING_EID_PREFIX, session_id.0.as_slice()].concat();

    let data = cggmp21::DataToSign::from_scalar(
        cggmp21::generic_ec::Scalar::from_be_bytes_mod_order(digest),
    );

    let codec = EncryptedRoundCodec::new(
        our_pos,
        cfg.private.mpc_encryption_sk,
        signer_enc_pks,
        eid_bytes.clone(),
    );
    let key_share = cfg.private.key_share.clone();

    Some(spawn_protocol::<cggmp21::Signature<Curve>, _, _>(
        our_pos,
        t,
        move |mut chan| async move {
            let mut rng = OsRng;
            let eid = ExecutionId::new(&eid_bytes);
            let sm = cggmp21::signing(eid, our_pos, &keygen_indices, &key_share)
                .sign_sync(&mut rng, data);
            drive_over_exchange(sm, &codec, &mut chan)
                .await?
                .map_err(|e| anyhow::anyhow!("signing: {e}"))
        },
    ))
}

/// Advances `slot`'s pump by one step: if no payload is currently waiting to
/// be broadcast and the session has not finished, pulls the next outgoing
/// payload from the parked state machine (see
/// [`ProtocolHandle::next_outgoing`]).
///
/// `Some` payloads are left in `slot.pending_outgoing` for the caller to
/// broadcast (e.g. as an `MpcRound` consensus item) and leave the state
/// machine parked until [`ProtocolHandle::submit_round`] unparks it with the
/// round's full peer payload set; `None` (`slot.done = true`) means the
/// state machine has finished (or errored) and its output is ready via
/// [`ProtocolHandle::into_output`].
///
/// A no-op if a payload is already pending (not yet consumed by
/// `submit_round`) or the session is already done.
pub async fn pump_slot_outgoing(slot: &mut SessionSlot) {
    if slot.pending_outgoing.is_none() && !slot.done {
        match slot.handle.next_outgoing().await {
            Some(payload) => slot.pending_outgoing = Some(payload),
            None => slot.done = true,
        }
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::bitcoin::Network;
    use fedimint_server_core::{ConfigGenModuleArgs, ServerModuleInit as _};
    use fedimint_threshold_ecdsa::{convert_signature, group_public_key};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::UsdtInit;

    const N: u16 = 4;
    const T: usize = 3;

    /// Mirrors the Phase-6 spike
    /// (`suspendable_pump_advances_offthread_signing_across_parked_rounds`),
    /// but through the module-level `spawn_signing_session` +
    /// `pump_slot_outgoing` wrapper, over real `UsdtConfig`s built by the
    /// existing `UsdtInit::trusted_dealer_gen` (same helper
    /// `trusted_dealer_gen_produces_consistent_valid_configs` in `lib.rs`
    /// uses), rather than hand-rolled trusted-dealer shares and ad hoc
    /// transport keys. Proves the module wrapper reproduces the spike's
    /// suspendable-pump result with the module's real config plumbing.
    #[tokio::test(flavor = "multi_thread")]
    async fn offthread_signing_session_produces_verifying_signatures() {
        let peers: Vec<PeerId> = (0..N).map(PeerId::from).collect();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );

        // Lowest-3 subset of the N=4 federation (threshold is 3).
        let signers: Vec<PeerId> = peers[..T].to_vec();

        let digest: [u8; 32] = Sha256::digest(b"usdt module off-thread signing test").into();
        let session_id = fedimint_usdt_common::signing_session_id(&digest, 0);

        let mut slots: BTreeMap<PeerId, SessionSlot> = BTreeMap::new();
        for &peer in &signers {
            let cfg = server_cfgs[&peer]
                .clone()
                .to_typed::<UsdtConfig>()
                .expect("config was just generated by the same configgen");
            let handle = spawn_signing_session(session_id, digest, &signers, peer, &cfg)
                .expect("peer is a member of the signing subset");
            slots.insert(
                peer,
                SessionSlot {
                    handle,
                    pending_outgoing: None,
                    round: 0,
                    done: false,
                },
            );
        }

        // Manual, interleaved poll-all/submit-all pump simulating the
        // consensus cadence (see the spike's doc comment for why the
        // poll-ALL-then-submit-ALL interleaving is the suspendability
        // proof).
        let mut rounds = 0u32;
        loop {
            let mut round_payloads: BTreeMap<PeerId, Vec<u8>> = BTreeMap::new();
            for &peer in &signers {
                let slot = slots.get_mut(&peer).expect("slot present");
                pump_slot_outgoing(slot).await;
                if let Some(payload) = slot.pending_outgoing.take() {
                    round_payloads.insert(peer, payload);
                }
            }

            if round_payloads.is_empty() {
                assert!(
                    slots.values().all(|slot| slot.done),
                    "either every signer finished this round or none did"
                );
                break;
            }
            assert_eq!(
                round_payloads.len(),
                signers.len(),
                "a synchronous all-to-all protocol finishes on the same round for every party"
            );

            // Simulate the arbitrary wall-clock / many-consensus-calls gap
            // between a round being proposed and its peer items being
            // processed; every signer's state machine is parked on its own
            // thread throughout.
            tokio::task::yield_now().await;

            for &peer in &signers {
                let all_payloads: Vec<Vec<u8>> =
                    signers.iter().map(|p| round_payloads[p].clone()).collect();
                slots
                    .get_mut(&peer)
                    .expect("slot present")
                    .handle
                    .submit_round(all_payloads)
                    .await
                    .expect("submit round payloads to parked signer");
            }
            rounds += 1;
        }
        assert!(rounds >= 1, "signing must have taken at least one round");

        let group_pk = server_cfgs[&signers[0]]
            .clone()
            .to_typed::<UsdtConfig>()
            .expect("valid config")
            .consensus
            .group_public_key;
        let msg = secp256k1::Message::from_digest(digest);
        let verifier = secp256k1::Secp256k1::verification_only();

        for &peer in &signers {
            let slot = slots.remove(&peer).expect("slot present");
            let sig = slot
                .handle
                .into_output()
                .await
                .expect("signer produced its final signature after the parked pump");
            let ecdsa_sig = convert_signature(sig).expect("valid signature conversion");
            verifier
                .verify_ecdsa(&msg, &ecdsa_sig, &group_pk)
                .expect("signature from the off-thread module wrapper must verify");
        }

        // Independent sanity check that `group_pk` really is this key
        // share's group key (not just self-consistently threaded through).
        let cfg0 = server_cfgs[&signers[0]]
            .clone()
            .to_typed::<UsdtConfig>()
            .expect("valid config");
        assert_eq!(
            group_public_key(&cfg0.private.key_share).expect("valid key share"),
            group_pk
        );
    }

    /// **Phase 9, Drill C** (hardening-acceptance-audit plan Task 2):
    /// guardian restart / degraded-signing recovery.
    ///
    /// `fedimint-testing`'s `FederationTest` has no live kill/restart
    /// primitive for an already-running guardian -- `new_fed_degraded`/
    /// `new_fed_builder(num_offline)` only control how many peers are never
    /// spawned in the first place (a static genesis-time configuration; see
    /// `degraded_federation_recovers_signing_via_timeout_and_rotation`'s own
    /// doc comment in `fedimint-usdt-tests/tests/tests.rs` for why THAT test
    /// had to use a debug-suppress flag instead, precisely because
    /// `new_fed_degraded` cannot down a peer that's already running). Adding
    /// a genuine process-kill-and-respawn primitive to `fedimint-testing`
    /// itself is out of scope for this module's hardening pass.
    ///
    /// What this test proves instead, hermetically: [`SessionStore`]'s own
    /// doc comment states a guardian restart destroys exactly the in-memory,
    /// non-serializable `SessionSlot`/off-thread cggmp21 driver ("a `!Send`,
    /// non-serializable cggmp21 state machine cannot survive a guardian
    /// restart") and NOTHING else -- the persisted `key_share` a restarted
    /// guardian reloads from its encrypted `UsdtConfigPrivate` (see that
    /// struct's doc comment: "only ever serde-(de)serialized to/from the
    /// guardian's local, encrypted config file") is completely independent
    /// of whatever session was abandoned. This test models exactly that
    /// split: spawn a signing session, pump it partway (so it is genuinely
    /// mid-protocol, on its dedicated OS thread, when abandoned -- not
    /// merely spawned-and-idle), then DROP every `SessionSlot` without ever
    /// finishing it (the in-memory-loss half of a restart -- `ProtocolHandle`
    /// has no `Drop` impl of its own; dropping its channels simply lets the
    /// parked dedicated thread unwind on its own once it next tries to
    /// exchange over a closed channel). It then spawns a BRAND NEW session,
    /// for a different digest, from the SAME `UsdtConfig`s (i.e. the exact
    /// `key_share` a restarted guardian would have reloaded from disk) and
    /// drives it to a real, verifying signature.
    ///
    /// This is precisely what recovery via the Phase-6b timeout+rotation
    /// path requires of a restarted guardian: rejoin a NEW
    /// `SigningSessionId` (`RotateSigning`'s fresh attempt) with an intact
    /// key share -- exactly what this test demonstrates -- with no
    /// session-replay machinery, deliberately, per the Phase-9 task's scope
    /// ("Do NOT build session-replay machinery (deferred)").
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn key_share_signs_correctly_after_an_abandoned_session_models_a_restart() {
        let peers: Vec<PeerId> = (0..N).map(PeerId::from).collect();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );
        let signers: Vec<PeerId> = peers[..T].to_vec();

        // --- Phase 1: spawn a session, pump it partway, then ABANDON it
        // (models the guardian-process-lifetime loss a restart causes; see
        // this test's doc comment).
        let abandoned_digest: [u8; 32] =
            Sha256::digest(b"usdt drill-c abandoned session (never finishes)").into();
        let abandoned_session_id = fedimint_usdt_common::signing_session_id(&abandoned_digest, 0);

        let mut abandoned_slots: BTreeMap<PeerId, SessionSlot> = BTreeMap::new();
        for &peer in &signers {
            let cfg = server_cfgs[&peer]
                .clone()
                .to_typed::<UsdtConfig>()
                .expect("config was just generated by the same configgen");
            let handle =
                spawn_signing_session(abandoned_session_id, abandoned_digest, &signers, peer, &cfg)
                    .expect("peer is a member of the signing subset");
            abandoned_slots.insert(
                peer,
                SessionSlot {
                    handle,
                    pending_outgoing: None,
                    round: 0,
                    done: false,
                },
            );
        }
        // Pump every signer's round-0 outgoing payload once, so each
        // off-thread state machine is genuinely mid-protocol (parked
        // waiting on the OTHER signers' round-0 payloads it will now never
        // receive), not just spawned-and-untouched.
        for slot in abandoned_slots.values_mut() {
            pump_slot_outgoing(slot).await;
            assert!(
                slot.pending_outgoing.is_some() && !slot.done,
                "a freshly spawned session's first pump must yield a pending outgoing payload"
            );
        }
        // ABANDON: drop every slot without ever calling `submit_round` --
        // this is the in-memory session loss a guardian restart causes.
        drop(abandoned_slots);

        // --- Phase 2: the SAME `UsdtConfig`s (i.e. the SAME `key_share`,
        // exactly what a restarted guardian reloads from its persisted
        // private config) spawn a BRAND NEW session for a different digest
        // and drive it to a real, verifying signature -- proving the
        // abandoned session above left the key share completely unaffected.
        let fresh_digest: [u8; 32] =
            Sha256::digest(b"usdt drill-c fresh session after simulated restart").into();
        let fresh_session_id = fedimint_usdt_common::signing_session_id(&fresh_digest, 0);

        let mut fresh_slots: BTreeMap<PeerId, SessionSlot> = BTreeMap::new();
        for &peer in &signers {
            let cfg = server_cfgs[&peer]
                .clone()
                .to_typed::<UsdtConfig>()
                .expect("config was just generated by the same configgen");
            let handle =
                spawn_signing_session(fresh_session_id, fresh_digest, &signers, peer, &cfg)
                    .expect("peer is a member of the signing subset");
            fresh_slots.insert(
                peer,
                SessionSlot {
                    handle,
                    pending_outgoing: None,
                    round: 0,
                    done: false,
                },
            );
        }

        // Drive to completion (identical poll-all/submit-all pump to
        // `offthread_signing_session_produces_verifying_signatures` above).
        loop {
            let mut round_payloads: BTreeMap<PeerId, Vec<u8>> = BTreeMap::new();
            for &peer in &signers {
                let slot = fresh_slots.get_mut(&peer).expect("slot present");
                pump_slot_outgoing(slot).await;
                if let Some(payload) = slot.pending_outgoing.take() {
                    round_payloads.insert(peer, payload);
                }
            }
            if round_payloads.is_empty() {
                assert!(fresh_slots.values().all(|slot| slot.done));
                break;
            }
            assert_eq!(round_payloads.len(), signers.len());
            tokio::task::yield_now().await;
            for &peer in &signers {
                let all_payloads: Vec<Vec<u8>> =
                    signers.iter().map(|p| round_payloads[p].clone()).collect();
                fresh_slots
                    .get_mut(&peer)
                    .expect("slot present")
                    .handle
                    .submit_round(all_payloads)
                    .await
                    .expect("submit round payloads to parked signer");
            }
        }

        let group_pk = server_cfgs[&signers[0]]
            .clone()
            .to_typed::<UsdtConfig>()
            .expect("valid config")
            .consensus
            .group_public_key;
        let msg = secp256k1::Message::from_digest(fresh_digest);
        let verifier = secp256k1::Secp256k1::verification_only();
        for &peer in &signers {
            let slot = fresh_slots.remove(&peer).expect("slot present");
            let sig = slot.handle.into_output().await.expect(
                "signer produced its final signature from the SAME key share, after an \
                     unrelated earlier session was abandoned mid-protocol",
            );
            let ecdsa_sig = convert_signature(sig).expect("valid signature conversion");
            verifier.verify_ecdsa(&msg, &ecdsa_sig, &group_pk).expect(
                "a fresh session's signature, from the same persisted key share, must \
                     verify -- proving the abandoned session caused no key-share corruption",
            );
        }
    }
}
