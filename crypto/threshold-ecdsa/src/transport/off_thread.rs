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
}
