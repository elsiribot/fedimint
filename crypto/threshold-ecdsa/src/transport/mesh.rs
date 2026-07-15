use anyhow::Context as _;
use tokio::sync::mpsc;

use super::{PartyIndex, RoundExchange};

/// An in-memory, all-to-all connected endpoint for testing [`RoundExchange`]
/// consumers without real network transport. Build a connected set with
/// [`in_memory_mesh`].
pub struct InMemoryMesh {
    index: PartyIndex,
    n: u16,
    // senders[j] delivers to party j's inbox; inbox receives (sender_index, bytes).
    senders: Vec<mpsc::UnboundedSender<(PartyIndex, Vec<u8>)>>,
    inbox: mpsc::UnboundedReceiver<(PartyIndex, Vec<u8>)>,
}

/// Build `n` connected in-memory endpoints, one per party, wired all-to-all.
pub fn in_memory_mesh(n: u16) -> Vec<InMemoryMesh> {
    let mut senders = Vec::with_capacity(n as usize);
    let mut inboxes = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let (tx, rx) = mpsc::unbounded_channel();
        senders.push(tx);
        inboxes.push(rx);
    }
    inboxes
        .into_iter()
        .enumerate()
        .map(|(i, inbox)| InMemoryMesh {
            index: i as PartyIndex,
            n,
            senders: senders.clone(),
            inbox,
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
        for j in 0..self.n {
            if j != self.index {
                self.senders[j as usize]
                    .send((self.index, ours.clone()))
                    .map_err(|_| anyhow::anyhow!("mesh peer {j} dropped"))?;
            }
        }
        let mut slots: Vec<Option<Vec<u8>>> = vec![None; self.n as usize];
        slots[self.index as usize] = Some(ours);
        for _ in 0..(self.n - 1) {
            let (sender, bytes) = self.inbox.recv().await.context("mesh closed")?;
            slots[sender as usize] = Some(bytes);
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
}
