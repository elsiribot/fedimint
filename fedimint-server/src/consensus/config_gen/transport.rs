//! P2P transport for module DKGs running on a live federation.
//!
//! At runtime the aleph network loop is the sole consumer of the shared p2p
//! connections, so DKG messages are wrapped in [`P2PMessage::ConfigGen`],
//! forwarded by that loop into a long-lived channel and consumed here. By
//! implementing [`IP2PConnections`] the transport can be passed to the
//! existing [`crate::config::peer_handle::PeerHandle`] and the module
//! `distributed_gen` implementations without changes.

use std::collections::{BTreeMap, VecDeque};

use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::config::P2PMessage;
use fedimint_core::config_gen::ModuleGenerationId;
use fedimint_core::net::peers::{DynP2PConnections, IP2PConnections, Recipient};
use fedimint_logging::LOG_CONSENSUS;
use tokio::sync::Mutex;
use tracing::debug;

/// Transport for one module config generation.
///
/// Outgoing messages are wrapped in [`P2PMessage::ConfigGen`] with this
/// generation's id; incoming messages of other generations are discarded.
/// The DKG protocol drives a single sequential worker task, so buffering per
/// sender is bounded by the DKG round structure.
pub struct GenerationTransport {
    generation_id: ModuleGenerationId,
    connections: DynP2PConnections<P2PMessage>,
    incoming: async_channel::Receiver<(PeerId, P2PMessage)>,
    buffered: Mutex<BTreeMap<PeerId, VecDeque<P2PMessage>>>,
}

impl GenerationTransport {
    pub fn new(
        generation_id: ModuleGenerationId,
        connections: DynP2PConnections<P2PMessage>,
        incoming: async_channel::Receiver<(PeerId, P2PMessage)>,
    ) -> Self {
        Self {
            generation_id,
            connections,
            incoming,
            buffered: Mutex::new(BTreeMap::new()),
        }
    }

    /// Receives the next message of this generation from the incoming
    /// channel, discarding messages of other generations.
    async fn next_message(&self) -> Option<(PeerId, P2PMessage)> {
        loop {
            let (peer, message) = self.incoming.recv().await.ok()?;

            let P2PMessage::ConfigGen(generation_id, inner) = message else {
                debug!(
                    target: LOG_CONSENSUS,
                    %peer,
                    "Discarding non config gen message on generation transport"
                );
                continue;
            };

            if generation_id != self.generation_id {
                debug!(
                    target: LOG_CONSENSUS,
                    %peer,
                    %generation_id,
                    "Discarding message of foreign config generation"
                );
                continue;
            }

            return Some((peer, *inner));
        }
    }
}

#[async_trait]
impl IP2PConnections<P2PMessage> for GenerationTransport {
    fn send(&self, recipient: Recipient, message: P2PMessage) {
        self.connections.send(
            recipient,
            P2PMessage::ConfigGen(self.generation_id, Box::new(message)),
        );
    }

    async fn receive(&self) -> Option<(PeerId, P2PMessage)> {
        let mut buffered = self.buffered.lock().await;

        if let Some((peer, message)) = buffered.iter_mut().find_map(|(peer, queue)| {
            let message = queue.pop_front()?;
            Some((*peer, message))
        }) {
            return Some((peer, message));
        }

        self.next_message().await
    }

    async fn receive_from_peer(&self, peer: PeerId) -> Option<P2PMessage> {
        let mut buffered = self.buffered.lock().await;

        loop {
            if let Some(message) = buffered.get_mut(&peer).and_then(VecDeque::pop_front) {
                return Some(message);
            }

            let (sender, message) = self.next_message().await?;

            if sender == peer {
                return Some(message);
            }

            buffered.entry(sender).or_default().push_back(message);
        }
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::net::peers::fake::make_fake_peer_connection;

    use super::*;

    #[tokio::test]
    async fn wraps_outgoing_and_demultiplexes_incoming() {
        let us = PeerId::from(0);
        let them = PeerId::from(1);
        let third = PeerId::from(2);

        let (our_connections, their_connections) =
            make_fake_peer_connection::<P2PMessage>(us, them, 16);

        let (incoming_sender, incoming_receiver) = async_channel::bounded(16);

        let transport =
            GenerationTransport::new(ModuleGenerationId(7), our_connections, incoming_receiver);

        // Outgoing messages are wrapped in ConfigGen with our generation id
        transport.send(
            Recipient::Peer(them),
            P2PMessage::Encodable(b"hello".to_vec()),
        );

        assert_eq!(
            their_connections.receive().await,
            Some((
                us,
                P2PMessage::ConfigGen(
                    ModuleGenerationId(7),
                    Box::new(P2PMessage::Encodable(b"hello".to_vec()))
                )
            ))
        );

        // A message from another peer is buffered, a foreign generation is
        // discarded, then the awaited peer's message is returned
        incoming_sender
            .send((
                third,
                P2PMessage::ConfigGen(
                    ModuleGenerationId(7),
                    Box::new(P2PMessage::Encodable(b"third".to_vec())),
                ),
            ))
            .await
            .expect("channel open");

        incoming_sender
            .send((
                them,
                P2PMessage::ConfigGen(
                    ModuleGenerationId(6),
                    Box::new(P2PMessage::Encodable(b"stale".to_vec())),
                ),
            ))
            .await
            .expect("channel open");

        incoming_sender
            .send((
                them,
                P2PMessage::ConfigGen(
                    ModuleGenerationId(7),
                    Box::new(P2PMessage::Encodable(b"current".to_vec())),
                ),
            ))
            .await
            .expect("channel open");

        assert_eq!(
            transport.receive_from_peer(them).await,
            Some(P2PMessage::Encodable(b"current".to_vec()))
        );

        assert_eq!(
            transport.receive_from_peer(third).await,
            Some(P2PMessage::Encodable(b"third".to_vec()))
        );
    }
}
