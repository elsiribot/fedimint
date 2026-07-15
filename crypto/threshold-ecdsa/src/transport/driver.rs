//! Drives a `round_based` synchronous state machine (e.g. a wrapped cggmp21
//! protocol) to completion over a [`RoundExchange`], sealing/opening each
//! round's messages with an [`EncryptedRoundCodec`].

use std::collections::{BTreeMap, VecDeque};

use anyhow::{Context as _, anyhow};
use round_based::state_machine::{ProceedResult, StateMachine};
use round_based::{Incoming, MessageDestination, MessageType, Outgoing};

use super::{EncryptedRoundCodec, RoundExchange};

/// Drive a cggmp21 sync state machine to completion over a `RoundExchange`,
/// encrypting point-to-point messages per recipient via the codec.
pub async fn drive_over_exchange<SM>(
    mut sm: SM,
    codec: &EncryptedRoundCodec,
    exchange: &mut dyn RoundExchange,
) -> anyhow::Result<SM::Output>
where
    SM: StateMachine,
    SM::Msg: serde::Serialize + serde::de::DeserializeOwned,
{
    let me = exchange.party_index();
    let n = exchange.n();
    let mut broadcast_out: Option<SM::Msg> = None;
    let mut p2p_out: BTreeMap<u16, SM::Msg> = BTreeMap::new();
    let mut incoming: VecDeque<Incoming<SM::Msg>> = VecDeque::new();
    let mut next_id: u64 = 0;

    loop {
        match sm.proceed() {
            ProceedResult::Output(out) => return Ok(out),
            ProceedResult::Error(err) => return Err(anyhow!("mpc state machine failed: {err}")),
            ProceedResult::Yielded => continue,
            ProceedResult::SendMsg(Outgoing { recipient, msg }) => match recipient {
                MessageDestination::AllParties => broadcast_out = Some(msg),
                MessageDestination::OneParty(j) => {
                    p2p_out.insert(j, msg);
                }
            },
            ProceedResult::NeedsOneMoreMessage => {
                if let Some(msg) = incoming.pop_front() {
                    sm.received_msg(msg)
                        .map_err(|_| anyhow!("state machine rejected message"))?;
                    continue;
                }
                // Round boundary: exchange our buffered outgoing, refill incoming.
                let payload = codec
                    .seal_round(broadcast_out.as_ref(), &p2p_out)
                    .context("sealing round payload")?;
                broadcast_out = None;
                p2p_out.clear();
                let all = exchange.exchange(payload).await.context("round exchange")?;
                for sender in 0..n {
                    if sender == me {
                        continue;
                    }
                    let opened = codec
                        .open_round::<SM::Msg>(sender, &all[sender as usize])
                        .with_context(|| format!("opening round payload from party {sender}"))?;
                    if let Some(b) = opened.broadcast {
                        incoming.push_back(Incoming {
                            id: next_id,
                            sender,
                            msg_type: MessageType::Broadcast,
                            msg: b,
                        });
                        next_id += 1;
                    }
                    if let Some(p) = opened.p2p_to_me {
                        incoming.push_back(Incoming {
                            id: next_id,
                            sender,
                            msg_type: MessageType::P2P,
                            msg: p,
                        });
                        next_id += 1;
                    }
                }
                // Loop; proceed() will request the messages we just queued.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use round_based::state_machine::{ProceedResult, StateMachine};
    use round_based::{Incoming, MessageDestination, Outgoing};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    use super::drive_over_exchange;
    use crate::transport::{EncryptedRoundCodec, in_memory_mesh};

    /// A trivial 2-party state machine: broadcasts `mine` once, then waits
    /// for one message per peer, then outputs the sorted collection of
    /// `mine` plus everything it received.
    struct TrivialSm {
        mine: u8,
        sent: bool,
        n: u16,
        collected: Vec<u8>,
    }

    impl TrivialSm {
        fn new(mine: u8, n: u16) -> Self {
            Self {
                mine,
                sent: false,
                n,
                collected: vec![mine],
            }
        }
    }

    impl StateMachine for TrivialSm {
        type Output = Vec<u8>;
        type Msg = u8;

        fn proceed(&mut self) -> ProceedResult<Self::Output, Self::Msg> {
            if !self.sent {
                self.sent = true;
                return ProceedResult::SendMsg(Outgoing {
                    recipient: MessageDestination::AllParties,
                    msg: self.mine,
                });
            }
            if self.collected.len() < self.n as usize {
                return ProceedResult::NeedsOneMoreMessage;
            }
            let mut out = self.collected.clone();
            out.sort_unstable();
            ProceedResult::Output(out)
        }

        fn received_msg(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Incoming<Self::Msg>> {
            self.collected.push(msg.msg);
            Ok(())
        }
    }

    fn keypairs(n: u16) -> (Vec<SecretKey>, Vec<PublicKey>) {
        let secp = Secp256k1::new();
        let sks: Vec<_> = (0..n)
            .map(|i| {
                let mut b = [1u8; 32];
                b[31] = (i + 1) as u8;
                SecretKey::from_slice(&b).expect("valid scalar")
            })
            .collect();
        let pks = sks.iter().map(|sk| sk.public_key(&secp)).collect();
        (sks, pks)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn drives_trivial_state_machine_over_exchange() {
        let (sks, pks) = keypairs(2);
        let mut ends = in_memory_mesh(2);

        let handles: Vec<_> = ends
            .drain(..)
            .enumerate()
            .map(|(i, mut exchange)| {
                let codec = EncryptedRoundCodec::new(i as u16, sks[i], pks.clone());
                let sm = TrivialSm::new(i as u8, 2);
                // This crate has no fedimint-core dependency (by design), so
                // fedimint_core::runtime::spawn is unavailable here; raw
                // tokio::spawn is fine in this test-only code.
                // nosemgrep: ban-tokio-spawn
                tokio::spawn(async move { drive_over_exchange(sm, &codec, &mut exchange).await })
            })
            .collect();

        let mut outputs = Vec::new();
        for h in handles {
            let out = h.await.expect("join").expect("drive_over_exchange");
            outputs.push(out);
        }

        assert_eq!(outputs[0], vec![0, 1]);
        assert_eq!(outputs[1], vec![0, 1]);
    }
}
