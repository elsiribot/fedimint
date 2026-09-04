//! Regression tests for the p2p connection state machine.
//!
//! Ported from upstream fedimint PR #9097 ("fix(server): drive the p2p send and
//! receive halves concurrently"), adapted to this branch's state machine, which
//! has neither connection status update streams nor a maximum connection age.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_core::{PeerId, runtime};
use fedimint_server_core::dashboard_ui::ConnectionType;
use futures::future;
use tokio::sync::{Notify, watch};
use tokio::time::timeout;

use super::{
    P2PConnectionSMCommon, P2PConnectionSMState, P2PConnectionState, P2PConnectionStateMachine,
};
use crate::net::p2p_connection::{DynIP2PFrame, DynP2PConnection, IP2PConnection, IP2PFrame};
use crate::net::p2p_connector::{DynP2PConnector, IP2PConnector};

/// A connector that never completes a connect or accept, so the state machine
/// only ever uses the connections handed to it directly.
struct PendingConnector;

#[async_trait]
impl IP2PConnector<u64> for PendingConnector {
    fn peers(&self) -> Vec<PeerId> {
        vec![PeerId::from(0)]
    }

    async fn connect(&self, _peer: PeerId) -> anyhow::Result<DynP2PConnection<u64>> {
        future::pending().await
    }

    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<u64>)> {
        future::pending().await
    }

    fn connection_type(&self, _peer: PeerId) -> Option<ConnectionType> {
        None
    }
}

/// A connection that accepts every send instantly and only ever fails a receive
/// when told to. Its `rtt` identifies it in the published status.
struct FakeConnection {
    rtt: Option<Duration>,
    disconnect: Arc<Notify>,
}

impl FakeConnection {
    fn new(rtt: Option<Duration>) -> Self {
        Self {
            rtt,
            disconnect: Arc::new(Notify::new()),
        }
    }
}

#[async_trait]
impl IP2PConnection<u64> for FakeConnection {
    async fn send(&self, _message: u64) -> anyhow::Result<()> {
        Ok(())
    }

    async fn receive(&self) -> anyhow::Result<DynIP2PFrame<u64>> {
        self.disconnect.notified().await;
        Err(anyhow!("fake connection disconnected"))
    }

    fn rtt(&self) -> Option<Duration> {
        self.rtt
    }
}

/// A frame that yields a single pre-baked message.
struct FakeFrame(u64);

#[async_trait]
impl IP2PFrame<u64> for FakeFrame {
    async fn read_to_end(&mut self) -> anyhow::Result<u64> {
        Ok(self.0)
    }
}

/// A connection whose `send` cannot complete until `receive` has been served at
/// least once. This is the shape of transport flow control: the peer has to
/// drain our stream before our write can finish.
struct FlowControlledConnection {
    /// Granted by `receive`, awaited by `send`.
    window: Arc<Notify>,
    frames: async_channel::Receiver<u64>,
    /// Number of sends that made it past the window wait.
    sends_completed: Arc<AtomicUsize>,
}

#[async_trait]
impl IP2PConnection<u64> for FlowControlledConnection {
    async fn send(&self, _message: u64) -> anyhow::Result<()> {
        self.window.notified().await;

        self.sends_completed.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    async fn receive(&self) -> anyhow::Result<DynIP2PFrame<u64>> {
        let message = self
            .frames
            .recv()
            .await
            .map_err(|_| anyhow!("frame channel closed"))?;

        self.window.notify_one();

        Ok(FakeFrame(message).into_dyn())
    }

    fn rtt(&self) -> Option<Duration> {
        None
    }
}

struct Harness {
    frame_sender: async_channel::Sender<u64>,
    connection_sender: async_channel::Sender<DynP2PConnection<u64>>,
    outgoing_sender: async_channel::Sender<u64>,
    incoming_receiver: async_channel::Receiver<u64>,
    status_receiver: watch::Receiver<P2PConnectionState>,
    sends_completed: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Harness {
    fn spawn(name: &'static str) -> Self {
        let (frame_sender, frames) = async_channel::bounded(1);
        let (connection_sender, incoming_connections) = async_channel::bounded(1);
        let (outgoing_sender, outgoing_receiver) = async_channel::bounded(1);
        let (incoming_sender, incoming_receiver) = async_channel::bounded(1);
        let (status_sender, status_receiver) = watch::channel(P2PConnectionState {
            connected: None,
            last_error: None,
        });

        let sends_completed = Arc::new(AtomicUsize::new(0));

        let connection = FlowControlledConnection {
            window: Arc::new(Notify::new()),
            frames,
            sends_completed: sends_completed.clone(),
        };

        let mut state_machine = P2PConnectionStateMachine {
            state: P2PConnectionSMState::Connected(Arc::new(connection)),
            common: P2PConnectionSMCommon {
                incoming_sender,
                outgoing_receiver,
                our_id: PeerId::from(1),
                our_id_str: "1".to_owned(),
                peer_id: PeerId::from(0),
                peer_id_str: "0".to_owned(),
                connector: Arc::new(PendingConnector) as DynP2PConnector<u64>,
                incoming_connections,
                status_sender,
            },
        };

        let task = runtime::spawn(name, async move {
            while let Some(next) = state_machine.state_transition().await {
                state_machine = next;
            }
        });

        Self {
            frame_sender,
            connection_sender,
            outgoing_sender,
            incoming_receiver,
            status_receiver,
            sends_completed,
            task,
        }
    }

    async fn wait_for_send(&self) {
        timeout(Duration::from_secs(5), async {
            while self.sends_completed.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("parked send completes once the window reopens");
    }

    async fn shutdown(self) {
        // If the closed frame channel is observed before the closed outgoing
        // channel, the machine transitions to Disconnected instead of shutting
        // down; the connection channel must be closed too for the task to end.
        drop(self.frame_sender);
        drop(self.outgoing_sender);
        drop(self.connection_sender);
        let _ = self.task.await;
    }
}

/// Regression test for a p2p deadlock: when send and receive were multiplexed
/// in a single `select!`, a send parked on transport flow control could no
/// longer poll `receive`, so the window never reopened. Two peers that both
/// started writing an oversized message hung forever, silently.
#[tokio::test]
async fn receives_while_a_send_is_parked_on_flow_control() {
    let harness = Harness::spawn("p2p-flow-control-test");

    // Park a send first, so the connection is mid-write when the peer's frame
    // arrives. Only a receive can unblock it.
    harness
        .outgoing_sender
        .send(7)
        .await
        .expect("outgoing queued");
    // Wait until the message is dequeued, so the send is genuinely parked
    // before the frame arrives. Without this the state machine is free to
    // serve the receive first, which stores the window permit and lets the
    // send complete without ever parking -- the pre-fix code passes that
    // interleaving, so the test would only catch the regression by chance.
    timeout(Duration::from_secs(5), async {
        while !harness.outgoing_sender.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("send is dequeued and in flight");

    harness.frame_sender.send(9).await.expect("frame queued");

    let received = timeout(Duration::from_secs(5), harness.incoming_receiver.recv())
        .await
        .expect("receive must be served while the send is parked")
        .expect("incoming channel is open");

    assert_eq!(received, 9);

    // The send can only get past the window wait because the receive was
    // served, so a completed send proves both halves made progress.
    harness.wait_for_send().await;

    harness.shutdown().await;
}

/// A replacement connection that arrives while a send is parked must not
/// cancel the in-flight send: the already dequeued message would be silently
/// lost, and e.g. the DKG sends every message exactly once.
#[tokio::test]
async fn replacement_connection_does_not_cancel_in_flight_send() {
    let mut harness = Harness::spawn("p2p-replacement-test");

    // Park a send on flow control and wait until the message is dequeued, so
    // the send is in flight before the replacement connection arrives.
    harness
        .outgoing_sender
        .send(7)
        .await
        .expect("outgoing queued");
    timeout(Duration::from_secs(5), async {
        while !harness.outgoing_sender.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("send is dequeued and in flight");

    // The replacement is identified by its `rtt`; the parked connection has
    // none.
    let replacement_rtt = Duration::from_millis(42);
    harness
        .connection_sender
        .send(Arc::new(FakeConnection::new(Some(replacement_rtt))))
        .await
        .expect("replacement queued");

    // Serving a receive reopens the window; the parked send must still be
    // alive to complete despite the queued replacement.
    harness.frame_sender.send(9).await.expect("frame queued");
    harness.wait_for_send().await;

    // Only then does the replacement connection take over.
    timeout(Duration::from_secs(5), async {
        loop {
            if harness
                .status_receiver
                .borrow_and_update()
                .connected
                .as_ref()
                .is_some_and(|status| status.rtt == Some(replacement_rtt))
            {
                return;
            }
            harness
                .status_receiver
                .changed()
                .await
                .expect("status sender remains alive");
        }
    })
    .await
    .expect("replacement connection takes over after the send completes");

    harness.shutdown().await;
}
