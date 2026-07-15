//! Transport for driving cggmp21 protocols over synchronous all-to-all
//! byte-exchange rounds.
//!
//! This module currently provides only the [`RoundExchange`] trait and an
//! in-memory mesh test transport ([`mesh`]). Later tasks add a codec
//! (`codec.rs`) for encrypting/authenticating point-to-point messages and a
//! driver (`driver.rs`) that adapts a [`RoundExchange`] into a
//! `round_based::Delivery`.
mod mesh;

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
