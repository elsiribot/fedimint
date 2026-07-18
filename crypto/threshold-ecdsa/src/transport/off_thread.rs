//! Off-thread bridge for driving a `!Send` synchronous MPC state machine
//! (e.g. a cggmp21 `into_state_machine` keygen/signing state machine) from
//! an async, `Send` context.
//!
//! cggmp21's sync state machines are `!Send`, but Fedimint's async call
//! sites (e.g. a module's `distributed_gen`) must return `Send` futures.
//! [`spawn_protocol`] runs the state machine — driven, as usual, by
//! [`drive_over_exchange`](super::drive_over_exchange) — on a dedicated OS
//! thread with its own current-thread Tokio runtime. The `!Send` state
//! machine is built and lives entirely on that thread and never crosses
//! back to the caller: only round payloads (`Vec<u8>`) and the final,
//! `Send` output cross the thread boundary, over plain async
//! `tokio::sync::mpsc`/`oneshot` channels.
//!
//! The async side drives the exchange via [`ProtocolHandle::drive`],
//! servicing each round (e.g. via a real p2p transport or, in tests, an
//! [`in_memory_mesh`](super::in_memory_mesh) endpoint) and feeding the
//! result back to the thread.

use anyhow::Context as _;
use tokio::sync::{mpsc, oneshot};

use super::{PartyIndex, RoundExchange};

/// A [`RoundExchange`] whose rounds are serviced by an external async pump
/// rather than a real transport. Lives on the dedicated thread spawned by
/// [`spawn_protocol`]; `exchange` sends the round payload out over `req`
/// and awaits the serviced result over `resp`. Both channel operations are
/// fully async (no blocking calls), so this runs fine inside the thread's
/// own current-thread `block_on`.
pub struct ChannelExchange {
    index: PartyIndex,
    n: u16,
    req_tx: mpsc::Sender<Vec<u8>>,
    resp_rx: mpsc::Receiver<anyhow::Result<Vec<Vec<u8>>>>,
}

#[async_trait::async_trait]
impl RoundExchange for ChannelExchange {
    fn party_index(&self) -> PartyIndex {
        self.index
    }

    fn n(&self) -> u16 {
        self.n
    }

    async fn exchange(&mut self, ours: Vec<u8>) -> anyhow::Result<Vec<Vec<u8>>> {
        self.req_tx.send(ours).await.map_err(|_| {
            anyhow::anyhow!("protocol driver: async side dropped the request channel")
        })?;
        self.resp_rx.recv().await.context(
            "protocol driver: async side dropped the response channel before servicing this round",
        )?
    }
}

/// Handle (async side) to a `!Send` MPC state machine running on a
/// dedicated thread, returned by [`spawn_protocol`]. Drive it to
/// completion with [`Self::drive`].
pub struct ProtocolHandle<O> {
    req_rx: mpsc::Receiver<Vec<u8>>,
    resp_tx: mpsc::Sender<anyhow::Result<Vec<Vec<u8>>>>,
    output_rx: oneshot::Receiver<anyhow::Result<O>>,
    join: std::thread::JoinHandle<()>,
}

/// Spawn `f` — which builds and drives a `!Send` cggmp21 state machine
/// (typically via [`drive_over_exchange`](super::drive_over_exchange)) over
/// the given [`ChannelExchange`] — on a dedicated OS thread with its own
/// current-thread Tokio runtime. Returns a [`ProtocolHandle`] whose
/// [`ProtocolHandle::drive`] services each round from the async side.
///
/// The `!Send` state machine `f` builds lives and dies entirely on this
/// thread; only `Vec<u8>` round payloads and the final `Send` output `O`
/// ever cross back to the caller.
pub fn spawn_protocol<O, F, Fut>(index: PartyIndex, n: u16, f: F) -> ProtocolHandle<O>
where
    O: Send + 'static,
    F: FnOnce(ChannelExchange) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = anyhow::Result<O>>,
{
    // Capacity 1: the protocol thread has at most one round payload
    // in-flight at a time (it blocks on `exchange` until serviced), so a
    // deeper buffer would not let it get any further ahead.
    let (req_tx, req_rx) = mpsc::channel(1);
    let (resp_tx, resp_rx) = mpsc::channel(1);
    let (output_tx, output_rx) = oneshot::channel();

    let chan = ChannelExchange {
        index,
        n,
        req_tx,
        resp_rx,
    };

    let join = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime for MPC protocol");
        let result = rt.block_on(f(chan));
        // If the async side already gave up on `drive` (dropping
        // `output_rx`), there is no one left to deliver the result to;
        // nothing more to do from this thread.
        let _ = output_tx.send(result);
    });

    ProtocolHandle {
        req_rx,
        resp_tx,
        output_rx,
        join,
    }
}

impl<O: Send + 'static> ProtocolHandle<O> {
    /// Suspendable pump, step 1 of 2: pull the payload the `!Send` state
    /// machine wants broadcast for the round it is currently blocked on,
    /// or `None` once the protocol has finished (or errored) and produced
    /// its output — retrieve that with [`Self::into_output`].
    ///
    /// Unlike [`Self::drive`], this does not consume `self` and services
    /// no round on its own: it hands out the current round's outgoing
    /// payload and returns, leaving the state machine's thread PARKED
    /// (blocked inside [`ChannelExchange::exchange`] awaiting the response)
    /// until a later [`Self::submit_round`] delivers the peers' payloads.
    /// Because `ProtocolHandle` is `Send + 'static`, the whole session can
    /// be stashed in ordinary storage between these two calls — for an
    /// arbitrary amount of wall-clock and any number of unrelated async
    /// poll/await points — which is exactly what advancing a signing
    /// session across many consensus rounds requires. The `!Send` state
    /// machine itself never moves; only the `Vec<u8>` payload crosses back.
    ///
    /// Round alignment mirrors [`RoundExchange::exchange`]: for each
    /// `Some(payload)` returned here there must be exactly one matching
    /// [`Self::submit_round`] before the next `next_outgoing` will resolve.
    pub async fn next_outgoing(&mut self) -> Option<Vec<u8>> {
        self.req_rx.recv().await
    }

    /// Suspendable pump, step 2 of 2: deliver, for the round most recently
    /// handed out by [`Self::next_outgoing`], every party's payload indexed
    /// by party `0..n` (this party's own payload in slot `party_index`,
    /// ignored on open — same shape [`RoundExchange::exchange`] returns).
    /// Unparks the state machine's thread so it opens the peers' messages
    /// and advances to the next round boundary (or to its final output).
    pub async fn submit_round(&mut self, all_payloads: Vec<Vec<u8>>) -> anyhow::Result<()> {
        self.resp_tx.send(Ok(all_payloads)).await.map_err(|_| {
            anyhow::anyhow!(
                "protocol thread stopped listening before this round's payloads were submitted \
                 (it likely already finished or errored out)"
            )
        })
    }

    /// Retrieve the protocol's final output after [`Self::next_outgoing`]
    /// has returned `None`, reaping the state machine's thread. Consumes
    /// the handle.
    pub async fn into_output(self) -> anyhow::Result<O> {
        let output = self
            .output_rx
            .await
            .context("protocol thread exited without producing an output (it likely panicked)")?;
        if self.join.join().is_err() {
            return Err(anyhow::anyhow!("MPC protocol thread panicked"));
        }
        output
    }

    /// Drive the protocol to completion, fulfilling each all-to-all round
    /// via `service` (e.g. a real transport's exchange call, or an
    /// [`in_memory_mesh`](super::in_memory_mesh) endpoint in tests).
    /// Returns the protocol's output once the thread's state machine
    /// finishes.
    pub async fn drive<F, Fut>(mut self, mut service: F) -> anyhow::Result<O>
    where
        F: FnMut(Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = anyhow::Result<Vec<Vec<u8>>>>,
    {
        while let Some(payload) = self.req_rx.recv().await {
            let result = service(payload).await;
            if self.resp_tx.send(result).await.is_err() {
                // The thread stopped listening (its ChannelExchange was
                // dropped, e.g. because the protocol already errored out
                // without needing this round's result); its final output
                // is on its way regardless.
                break;
            }
        }

        let output = self
            .output_rx
            .await
            .context("protocol thread exited without producing an output (it likely panicked)")?;

        // By now the thread has nothing left to do but return from its
        // spawn closure, so this join is effectively instantaneous; do it
        // anyway to reap the thread and surface an unexpected late panic.
        if self.join.join().is_err() {
            return Err(anyhow::anyhow!("MPC protocol thread panicked"));
        }

        output
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn keygen_runs_off_thread_serviced_by_mesh() {
        use crate::transport::{
            EncryptedRoundCodec, RoundExchange as _, drive_over_exchange, in_memory_mesh,
            spawn_protocol,
        };

        const N: u16 = 4;
        const T: u16 = 3;

        let secp = secp256k1::Secp256k1::new();
        let enc_sks: Vec<_> = (0..N)
            .map(|i| {
                let mut b = [3u8; 32];
                b[31] = (i + 1) as u8;
                secp256k1::SecretKey::from_slice(&b).expect("valid scalar")
            })
            .collect();
        let enc_pks: Vec<_> = enc_sks.iter().map(|sk| sk.public_key(&secp)).collect();
        let eid_bytes = b"off-thread-keygen".to_vec();

        let meshes = in_memory_mesh(N);
        let mut tasks = Vec::with_capacity(usize::from(N));
        for (i, mesh) in meshes.into_iter().enumerate() {
            let i = i as u16;
            let codec = EncryptedRoundCodec::new(
                i,
                enc_sks[i as usize],
                enc_pks.clone(),
                eid_bytes.clone(),
            );
            let eidb = eid_bytes.clone();

            let handle = spawn_protocol::<cggmp21::IncompleteKeyShare<crate::Curve>, _, _>(
                i,
                N,
                move |mut chan| async move {
                    let mut rng = rand::rngs::OsRng;
                    let eid = cggmp21::ExecutionId::new(&eidb);
                    let sm = cggmp21::keygen::<crate::Curve>(eid, i, N)
                        .set_threshold(T)
                        .hd_wallet(true)
                        .into_state_machine(&mut rng);
                    drive_over_exchange(sm, &codec, &mut chan)
                        .await?
                        .map_err(|e| anyhow::anyhow!("keygen: {e}"))
                },
            );

            // `InMemoryMesh::exchange` needs `&mut self`, but the closure
            // passed to `drive` must be `FnMut(Vec<u8>) -> Fut` for one
            // fixed `Fut` type: a closure that merely captures `mesh` and
            // calls `mesh.exchange(payload)` would return a future
            // borrowing the closure's own captured state, which `FnMut`
            // cannot express (the borrow's lifetime would have to vary
            // per call). Wrapping the mesh in `Arc<Mutex<_>>` fixes this:
            // each call clones the (cheap) `Arc` handle into an owned
            // `async move` block, so the returned future owns everything
            // it touches instead of borrowing the closure's environment.
            let mesh = std::sync::Arc::new(tokio::sync::Mutex::new(mesh));
            // This crate has no fedimint-core dependency (by design), so
            // fedimint_core::runtime::spawn is unavailable here; raw
            // tokio::spawn is fine in this test-only code.
            // nosemgrep: ban-tokio-spawn
            tasks.push(tokio::spawn(async move {
                handle
                    .drive(move |payload| {
                        let mesh = mesh.clone();
                        async move { mesh.lock().await.exchange(payload).await }
                    })
                    .await
            }));
        }

        let mut shares = Vec::with_capacity(usize::from(N));
        for t in tasks {
            shares.push(
                t.await
                    .expect("join")
                    .expect("keygen driven off-thread over the mesh"),
            );
        }

        let group_pk = shares[0].shared_public_key();
        for share in &shares[1..] {
            assert_eq!(
                share.shared_public_key(),
                group_pk,
                "all off-thread parties must agree on the DKG group key"
            );
        }
    }

    /// PHASE 6 SPIKE — retire the highest-risk integration: can a `!Send`,
    /// non-serializable cggmp21 *signing* state machine be advanced across
    /// many consensus rounds by PARKING it between rounds, rather than
    /// running every round in one continuous [`ProtocolHandle::drive`] loop?
    ///
    /// This test drives a real 3-of-4 threshold signing off-thread with a
    /// **manual, interleaved pump** that simulates the consensus cadence:
    /// each "consensus round" it (1) pulls the CURRENT outgoing payload from
    /// every signer's parked handle (`consensus_proposal` would emit these
    /// as `MpcRound` items), then (2) delivers the full set of peers'
    /// payloads to every signer (`process_consensus_item` would call this
    /// once all subset peers' round-`r` items are in). The poll-ALL-then-
    /// submit-ALL interleaving is the suspendability proof: while we poll
    /// signer B and C, signer A's `!Send` state machine is sitting parked on
    /// its own thread, blocked inside `ChannelExchange::exchange`, making no
    /// progress until we choose to unpark it — precisely the "arbitrary
    /// wall-clock and many consensus calls later" gap Phase 6 needs.
    #[tokio::test(flavor = "multi_thread")]
    async fn suspendable_pump_advances_offthread_signing_across_parked_rounds() {
        use std::collections::BTreeMap;

        use sha3::{Digest as _, Keccak256};

        use super::ProtocolHandle;
        use crate::Curve;
        use crate::transport::{EncryptedRoundCodec, drive_over_exchange, spawn_protocol};

        // `ProtocolHandle` must be storable in `Send + 'static` session
        // storage between pumps — the whole point of parking. Assert it
        // statically so a regression that makes the handle `!Send` (e.g. by
        // parking some `!Send` bit of the SM on the async side) fails to
        // compile instead of silently defeating the spike.
        fn assert_send_static<T: Send + 'static>() {}
        assert_send_static::<ProtocolHandle<cggmp21::Signature<Curve>>>();

        const N: u16 = 4;
        const T: u16 = 3;

        // Trusted-dealer shares: this spike is about the runtime signing
        // pump, not DKG, so skip the (expensive) real keygen/aux-gen.
        let shares = cggmp21::trusted_dealer::builder::<Curve, _>(N)
            .set_threshold(Some(T))
            .hd_wallet(true)
            .generate_shares(&mut rand::rngs::OsRng)
            .expect("trusted dealer share generation");

        // Fresh-per-signing ExecutionId, derived from the digest. Config-gen
        // eids must NOT be reused at runtime (eid reuse is unsound), so a
        // real Phase 6 would derive the eid from the signing request; here we
        // bind it to the message digest.
        let digest: [u8; 32] = Keccak256::digest(b"phase6 suspendable pump spike").into();
        let mut eid_bytes = b"phase6-spike-signing/".to_vec();
        eid_bytes.extend_from_slice(&digest);

        let signers: [u16; T as usize] = [0, 1, 3];

        // Per-party static encryption keypairs for the codec (over the
        // signing subset, indexed by position 0..T).
        let secp = secp256k1::Secp256k1::new();
        let enc_sks: Vec<secp256k1::SecretKey> = (0..N)
            .map(|i| {
                let mut b = [5u8; 32];
                b[31] = (i + 1) as u8;
                secp256k1::SecretKey::from_slice(&b).expect("valid scalar")
            })
            .collect();
        let enc_pks: Vec<secp256k1::PublicKey> =
            enc_sks.iter().map(|sk| sk.public_key(&secp)).collect();
        let signer_pks: Vec<secp256k1::PublicKey> =
            signers.iter().map(|&k| enc_pks[usize::from(k)]).collect();

        let data = cggmp21::DataToSign::from_scalar(
            cggmp21::generic_ec::Scalar::from_be_bytes_mod_order(digest),
        );

        // Spawn each signer's signing state machine off-thread. Note we take
        // the `ProtocolHandle` and never call `.drive()` on it.
        let mut store: BTreeMap<u16, ProtocolHandle<cggmp21::Signature<Curve>>> = BTreeMap::new();
        for pos in 0..T {
            let keygen_index = signers[usize::from(pos)];
            let codec = EncryptedRoundCodec::new(
                pos,
                enc_sks[usize::from(keygen_index)],
                signer_pks.clone(),
                eid_bytes.clone(),
            );
            let share = shares[usize::from(keygen_index)].clone();
            let eidb = eid_bytes.clone();
            let signers_v = signers.to_vec();

            let handle = spawn_protocol::<cggmp21::Signature<Curve>, _, _>(
                pos,
                T,
                move |mut chan| async move {
                    let mut rng = rand::rngs::OsRng;
                    let eid = cggmp21::ExecutionId::new(&eidb);
                    let sm =
                        cggmp21::signing(eid, pos, &signers_v, &share).sign_sync(&mut rng, data);
                    drive_over_exchange(sm, &codec, &mut chan)
                        .await?
                        .map_err(|e| anyhow::anyhow!("signing: {e}"))
                },
            );
            store.insert(pos, handle);
        }

        // --- The manual, suspendable pump (simulated consensus cadence) ---
        //
        // Each iteration is "one consensus round". We deliberately drop every
        // reference to every handle between the two phases (only `&mut` via
        // the persistent `store`), leaving all state machines parked on their
        // threads across the phase boundary.
        let mut round: u16 = 0;
        loop {
            // Phase 1 — `consensus_proposal`: collect this round's outgoing
            // payload from every parked signer. Each `next_outgoing` leaves
            // that signer parked again; the others stay parked while we poll.
            let mut round_payloads: Vec<Vec<u8>> = vec![Vec::new(); usize::from(T)];
            let mut finished = false;
            for pos in 0..T {
                match store
                    .get_mut(&pos)
                    .expect("handle present")
                    .next_outgoing()
                    .await
                {
                    Some(payload) => round_payloads[usize::from(pos)] = payload,
                    // req_tx dropped: the SM ran to completion (or errored)
                    // and its output is waiting. A synchronous all-to-all
                    // protocol finishes on the same round for every party, so
                    // once one is done they all are.
                    None => finished = true,
                }
            }
            if finished {
                break;
            }

            // The whole federation is now parked mid-signature. Simulate the
            // arbitrary wall-clock / many-consensus-calls gap between a round
            // being proposed and its peer items being processed. Nothing here
            // touches the state machines; they simply wait.
            tokio::task::yield_now().await;

            // Phase 2 — `process_consensus_item`: all subset peers' round-`r`
            // items are in, so unpark every signer with the full payload set.
            for pos in 0..T {
                store
                    .get_mut(&pos)
                    .expect("handle present")
                    .submit_round(round_payloads.clone())
                    .await
                    .expect("submit round payloads to parked signer");
            }
            round += 1;
        }

        assert!(round >= 1, "signing must have taken at least one round");

        // Collect each signer's final signature and reap its thread.
        let mut signatures = Vec::with_capacity(usize::from(T));
        for pos in 0..T {
            let handle = store.remove(&pos).expect("handle present");
            signatures.push(
                handle
                    .into_output()
                    .await
                    .expect("signer produced its final signature after the parked pump"),
            );
        }

        // Independent verification against the group key with `secp256k1`.
        let group_pk = crate::group_public_key(&shares[0]).expect("group key");
        let msg = secp256k1::Message::from_digest(digest);
        let verifier = secp256k1::Secp256k1::verification_only();
        for sig in &signatures {
            let ecdsa_sig = crate::convert_signature(*sig).expect("valid signature conversion");
            verifier
                .verify_ecdsa(&msg, &ecdsa_sig, &group_pk)
                .expect("signature from the suspendable off-thread pump must verify");
        }
    }
}
