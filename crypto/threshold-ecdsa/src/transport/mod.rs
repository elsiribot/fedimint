//! Transport for driving cggmp21 protocols over synchronous all-to-all
//! byte-exchange rounds.
//!
//! This module provides the [`RoundExchange`] trait, an in-memory mesh
//! test transport ([`InMemoryMesh`] / [`in_memory_mesh`], `mesh.rs`),
//! [`EncryptedRoundCodec`] for encrypting/authenticating point-to-point
//! round messages (`codec.rs`), and [`drive_over_exchange`] (`driver.rs`),
//! which drives a `round_based` sync state machine to completion over a
//! [`RoundExchange`].
//!
//! # Round model
//!
//! [`RoundExchange`] models one *synchronous, all-to-all* byte-exchange
//! round: every party broadcasts one payload via [`RoundExchange::exchange`]
//! and blocks until it has received every other party's payload for that
//! same round. [`drive_over_exchange`] repeatedly calls `exchange` to carry
//! a `round_based` state machine's rounds one at a time; there is no
//! pipelining across rounds and no partial/asynchronous delivery.
//!
//! # What is encrypted
//!
//! A round's wire payload (built by [`EncryptedRoundCodec::seal_round`])
//! carries at most one broadcast message and any number of point-to-point
//! messages. The broadcast message, if present, is serialized **in the
//! clear** — every party is meant to see it, and cggmp21 does not require
//! it to be confidential. Each point-to-point message is individually
//! ECIES-boxed to its recipient (ephemeral-static ECDH, stretched via
//! HKDF-SHA256 into a ChaCha20-Poly1305 key; see `codec.rs`), so only the
//! addressed recipient can decrypt it and every party's inbound messages
//! are still authenticated.
//!
//! # Identity: `PartyIndex`, not `PeerId`
//!
//! [`PartyIndex`] (`0..n`) is the only notion of party identity this crate
//! knows about — it is what cggmp21, [`RoundExchange`], and
//! [`EncryptedRoundCodec`] all index by. This crate has no
//! `fedimint-core` dependency and therefore no concept of a federation's
//! `PeerId`. Mapping a federation's `PeerId` set to a stable `PartyIndex`
//! assignment (and keeping that mapping consistent with the DKG/aux-gen
//! output) is the consuming module's job, done in a later phase.
//!
//! # Where production `RoundExchange` impls live
//!
//! This crate ships exactly one [`RoundExchange`] implementation —
//! [`InMemoryMesh`], for tests. Production transports (a config-gen
//! `PeerHandleOps`-backed exchange during DKG, and a runtime
//! consensus-item-backed exchange for on-demand signing) are implemented
//! in the consuming module crate, which owns the actual peer connections
//! and consensus plumbing; they are out of scope here.
//!
//! # The driver's round-boundary rule
//!
//! [`drive_over_exchange`] buffers everything the state machine hands it
//! via `SendMsg` (at most one broadcast, plus zero or more per-recipient
//! p2p messages) without sending anything yet. It only calls
//! `exchange` — i.e. crosses a round boundary — when the state machine
//! asks for another message (`NeedsOneMoreMessage`) *and* its local
//! incoming queue is already empty. At that point the buffered outgoing
//! messages are sealed into one payload, exchanged, and the responses are
//! opened and queued as the new incoming messages for the next
//! iterations of the loop. This keeps each `exchange` call aligned with
//! exactly one cggmp21 round, even though the state machine's `SendMsg`
//! and `NeedsOneMoreMessage` requests are interleaved at a finer grain.
mod codec;
mod driver;
mod mesh;

pub use codec::{EncryptedRoundCodec, OpenedRound};
pub use driver::drive_over_exchange;
pub use mesh::{InMemoryMesh, in_memory_mesh};

/// The index of a party among `n` participants, in `0..n`.
pub type PartyIndex = u16;

/// One synchronous all-to-all byte-exchange round among `n` parties.
#[async_trait::async_trait]
pub trait RoundExchange: Send {
    /// This party's index in `0..n()`.
    fn party_index(&self) -> PartyIndex;
    /// The total number of parties in the exchange.
    fn n(&self) -> u16;
    /// Broadcast `ours`; return every party's payload indexed by party
    /// `0..n()` (our own payload in slot `party_index()`).
    async fn exchange(&mut self, ours: Vec<u8>) -> anyhow::Result<Vec<Vec<u8>>>;
}
