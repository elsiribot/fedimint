use anyhow::Context as _;
use tokio::sync::mpsc;

use super::{PartyIndex, RoundExchange};

/// An in-memory, all-to-all connected endpoint for testing [`RoundExchange`]
/// consumers without real network transport. Build a connected set with
/// [`in_memory_mesh`].
///
/// Each ordered pair of parties `(sender, receiver)` gets its own dedicated
/// mpsc channel (rather than one shared inbox per party). Because each
/// channel only ever carries one sender's messages to one receiver, and
/// mpsc channels are FIFO, receiving exactly one payload per sender on each
/// `exchange` call is enough to guarantee round alignment: a fast peer's
/// round `r + 1` payload cannot overtake a slow peer's round `r` payload in
/// a channel it never shares with that peer.
pub struct InMemoryMesh {
    index: PartyIndex,
    n: u16,
    // senders[j] is our dedicated channel to party j (senders[index] is
    // unused and left `None`).
    senders: Vec<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    // receivers[j] is our dedicated channel from party j (receivers[index]
    // is unused and left `None`).
    receivers: Vec<Option<mpsc::UnboundedReceiver<Vec<u8>>>>,
}

/// Build `n` connected in-memory endpoints, one per party, wired all-to-all
/// with one dedicated mpsc channel per ordered `(sender, receiver)` pair.
///
/// This is a test utility, not a production transport (see the `transport`
/// module docs for where production [`RoundExchange`] impls live). It is
/// deliberately kept `pub` (not `#[cfg(test)]`-gated) rather than hidden
/// behind a `test-util` feature: later phases' own integration tests will
/// want to drive their consensus/config-gen adapters against this same
/// in-memory mesh, and gating it would force them to duplicate it instead.
pub fn in_memory_mesh(n: u16) -> Vec<InMemoryMesh> {
    let n_usize = usize::from(n);

    // tx[i][j] / rx[i][j] is the dedicated channel carrying party `i`'s
    // messages to party `j` (`None` on the diagonal: parties don't send to
    // themselves over the mesh).
    let mut tx: Vec<Vec<Option<mpsc::UnboundedSender<Vec<u8>>>>> = (0..n_usize)
        .map(|_| (0..n_usize).map(|_| None).collect())
        .collect();
    let mut rx: Vec<Vec<Option<mpsc::UnboundedReceiver<Vec<u8>>>>> = (0..n_usize)
        .map(|_| (0..n_usize).map(|_| None).collect())
        .collect();

    for (i, tx_row) in tx.iter_mut().enumerate() {
        for j in 0..n_usize {
            if i == j {
                continue;
            }
            let (sender, receiver) = mpsc::unbounded_channel();
            tx_row[j] = Some(sender);
            rx[i][j] = Some(receiver);
        }
    }

    (0..n_usize)
        .map(|i| {
            let senders = std::mem::take(&mut tx[i]);
            let receivers = (0..n_usize).map(|j| rx[j][i].take()).collect();
            InMemoryMesh {
                index: i as PartyIndex,
                n,
                senders,
                receivers,
            }
        })
        .collect()
}

#[async_trait::async_trait]
impl RoundExchange for InMemoryMesh {
    fn party_index(&self) -> PartyIndex {
        self.index
    }

    fn n(&self) -> u16 {
        self.n
    }

    async fn exchange(&mut self, ours: Vec<u8>) -> anyhow::Result<Vec<Vec<u8>>> {
        let n = usize::from(self.n);
        let my_index = usize::from(self.index);

        for j in 0..n {
            if j == my_index {
                continue;
            }
            self.senders[j]
                .as_ref()
                .with_context(|| format!("missing dedicated channel to party {j}"))?
                .send(ours.clone())
                .map_err(|_| anyhow::anyhow!("mesh peer {j} dropped"))?;
        }

        let mut slots: Vec<Option<Vec<u8>>> = vec![None; n];
        slots[my_index] = Some(ours);
        for (j, slot) in slots.iter_mut().enumerate() {
            if j == my_index {
                continue;
            }
            let receiver = self.receivers[j]
                .as_mut()
                .with_context(|| format!("missing dedicated channel from party {j}"))?;
            *slot = Some(receiver.recv().await.with_context(|| {
                format!("mesh channel from party {j} closed before sending this round's payload")
            })?);
        }

        slots
            .into_iter()
            .enumerate()
            .map(|(j, s)| s.with_context(|| format!("missing payload from party {j}")))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn mesh_exchanges_all_to_all() {
        use crate::transport::RoundExchange as _;

        let mut ends = crate::transport::in_memory_mesh(4);
        // Each party runs one round concurrently, broadcasting its index as
        // bytes.
        let handles: Vec<_> = ends
            .drain(..)
            .map(|mut e| {
                // This crate has no fedimint-core dependency (by design), so
                // fedimint_core::runtime::spawn is unavailable here; raw
                // tokio::spawn is fine in this test-only code.
                // nosemgrep: ban-tokio-spawn
                tokio::spawn(async move {
                    let got = e
                        .exchange(vec![e.party_index() as u8])
                        .await
                        .expect("exchange");
                    (e.party_index(), got)
                })
            })
            .collect();
        for h in handles {
            let (i, got) = h.await.expect("join");
            assert_eq!(got.len(), 4, "party {i} must receive n payloads");
            for (j, payload) in got.iter().enumerate() {
                assert_eq!(payload, &vec![j as u8], "slot j holds party j's payload");
            }
        }
    }

    /// Regression test for the mesh restructuring (per-ordered-pair
    /// channels instead of one shared inbox per party): with a shared
    /// inbox, a fast peer's round `r + 1` payload could be received before
    /// a slow peer's round `r` payload, landing in the wrong slot. With
    /// dedicated per-pair channels this cannot happen because each
    /// channel's FIFO order is scoped to a single sender.
    #[tokio::test(flavor = "multi_thread")]
    async fn mesh_stays_round_aligned_under_uneven_speeds() {
        use std::time::Duration;

        use crate::transport::RoundExchange as _;

        let mut ends = crate::transport::in_memory_mesh(3);
        let handles: Vec<_> = ends
            .drain(..)
            .map(|mut e| {
                // nosemgrep: ban-tokio-spawn
                tokio::spawn(async move {
                    let me = e.party_index();
                    for round in 0u8..3 {
                        // Party 0 races ahead; the others are slower, so
                        // party 0's later-round payloads are already queued
                        // by the time the others catch up.
                        if me != 0 {
                            // This crate has no fedimint-core dependency (by
                            // design), so fedimint_core::runtime::sleep is
                            // unavailable here; raw tokio::time::sleep is
                            // fine in this test-only code.
                            // nosemgrep: ban-tokio-sleep
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                        let got = e
                            .exchange(vec![me as u8, round])
                            .await
                            .expect("exchange");
                        for (j, payload) in got.iter().enumerate() {
                            assert_eq!(
                                payload,
                                &vec![j as u8, round],
                                "party {me} round {round}: slot {j} must hold party {j}'s round-{round} payload, not a later round's"
                            );
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.await.expect("join");
        }
    }
}
