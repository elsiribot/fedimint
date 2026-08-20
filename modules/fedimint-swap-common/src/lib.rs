#![deny(clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::fmt;

use config::SwapClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{AmountUnit, CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{Amount, OutPoint, plugin_types_trait_impl_common};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Common contains types shared by both the client and server

// The client (and, in later phases, server) configuration
pub mod config;
pub mod endpoint_constants;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("swap");

/// Modules are non-compatible with older versions
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

/// Which side of a filled offer a claim is for. Explicit because the
/// server's `process_input` must PRODUCE the pubkey core verifies the
/// signature against; it cannot infer the side from who signed.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum Party {
    Maker,
    Taker,
}

impl fmt::Display for Party {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Party::Maker => write!(f, "Maker"),
            Party::Taker => write!(f, "Taker"),
        }
    }
}

/// Output for a fedimint transaction.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum SwapOutput {
    /// Lock the maker's leg and open an offer. Paired in the same tx with a
    /// mint input spending `maker_amount` of `maker_unit`.
    MakeOffer {
        maker_unit: AmountUnit,
        maker_amount: Amount,
        taker_unit: AmountUnit,
        taker_amount: Amount,
        /// Consensus-timestamp SECONDS after which the offer can no longer
        /// be filled.
        expiry: u64,
        maker_pk: PublicKey,
    },
    /// Fill an open offer. Paired with a mint input spending the taker leg.
    Fill {
        offer_id: OutPoint,
        taker_pk: PublicKey,
    },
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

impl fmt::Display for SwapOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SwapOutput::MakeOffer {
                maker_unit,
                maker_amount,
                taker_unit,
                taker_amount,
                expiry,
                ..
            } => write!(
                f,
                "SwapOutput::MakeOffer(maker={maker_amount} of unit {maker_unit:?}, \
                 taker={taker_amount} of unit {taker_unit:?}, expiry={expiry})"
            ),
            SwapOutput::Fill { offer_id, .. } => write!(f, "SwapOutput::Fill({offer_id})"),
            SwapOutput::Default { variant, bytes } => write!(
                f,
                "SwapOutput::Unknown(variant={variant}, bytes_len={})",
                bytes.len()
            ),
        }
    }
}

/// Input for a fedimint transaction.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum SwapInput {
    /// Withdraw the counterparty's leg of a filled offer. `party` selects
    /// which leg / which key (Maker withdraws the taker leg, Taker withdraws
    /// the maker leg).
    Claim { offer_id: OutPoint, party: Party },
    /// Maker reclaims their own leg from an offer that is still Open
    /// (voluntary cancel, or after expiry).
    Reclaim { offer_id: OutPoint },
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

impl fmt::Display for SwapInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SwapInput::Claim { offer_id, party } => {
                write!(f, "SwapInput::Claim(offer_id={offer_id}, party={party})")
            }
            SwapInput::Reclaim { offer_id } => write!(f, "SwapInput::Reclaim({offer_id})"),
            SwapInput::Default { variant, bytes } => write!(
                f,
                "SwapInput::Unknown(variant={variant}, bytes_len={})",
                bytes.len()
            ),
        }
    }
}

/// `output_status` payload: `Some` once the output landed.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct SwapOutputOutcome;

impl fmt::Display for SwapOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SwapOutputOutcome")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum OfferState {
    Open,
    Filled { taker_pk: PublicKey },
}

impl fmt::Display for OfferState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OfferState::Open => write!(f, "Open"),
            OfferState::Filled { .. } => write!(f, "Filled"),
        }
    }
}

/// The full offer record. Also the shape returned by `list_open_offers`
/// later.
///
/// Naming: legs are named by who DEPOSITS them (`maker_*`/`taker_*`); the
/// `*_claimed` flags are named by who CLAIMS -- each party withdraws the
/// OTHER's leg, so `maker_claimed` means the maker has taken the `taker`
/// leg.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Offer {
    pub maker_pk: PublicKey,
    pub maker_unit: AmountUnit,
    pub maker_amount: Amount,
    pub taker_unit: AmountUnit,
    pub taker_amount: Amount,
    pub expiry: u64,
    pub state: OfferState,
    pub maker_claimed: bool,
    pub taker_claimed: bool,
}

impl fmt::Display for Offer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Offer(maker={} of unit {:?}, taker={} of unit {:?}, expiry={}, state={}, \
             maker_claimed={}, taker_claimed={})",
            self.maker_amount,
            self.maker_unit,
            self.taker_amount,
            self.taker_unit,
            self.expiry,
            self.state,
            self.maker_claimed,
            self.taker_claimed
        )
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum SwapInputError {
    #[error("No offer exists for this id")]
    UnknownOffer,
    #[error("Offer is not filled; nothing to claim")]
    OfferNotFilled,
    #[error("Offer is not open; cannot reclaim a filled offer")]
    OfferNotOpen,
    #[error("This leg has already been claimed")]
    LegAlreadyClaimed,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum SwapOutputError {
    #[error("No offer exists for this id")]
    UnknownOffer,
    #[error("Offer is already filled")]
    OfferAlreadyFilled,
    #[error("Offer has expired")]
    OfferExpired,
    #[error("Offer expiry is in the past")]
    ExpiryInPast,
    #[error("Maker and taker units must differ")]
    SameUnit,
    #[error("Offer amounts must be non-zero")]
    ZeroAmount,
}

/// Consensus item: each guardian's proposed wall-clock time (the median of
/// the latest per-peer values is the module's monotonic clock, used for
/// expiry).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct SwapConsensusItem {
    pub unix_secs: u64,
}

impl fmt::Display for SwapConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SwapConsensusItem(unix_secs={})", self.unix_secs)
    }
}

/// Contains the types defined above
pub struct SwapModuleTypes;

// Wire together the types for this module
plugin_types_trait_impl_common!(
    KIND,
    SwapModuleTypes,
    SwapClientConfig,
    SwapInput,
    SwapOutput,
    SwapOutputOutcome,
    SwapConsensusItem,
    SwapInputError,
    SwapOutputError
);

#[derive(Debug)]
pub struct SwapCommonInit;

impl CommonModuleInit for SwapCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = SwapClientConfig;

    fn decoder() -> Decoder {
        SwapModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for SwapClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SwapClientConfig")
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::{BitcoinHash as _, TransactionId, secp256k1};

    use super::*;

    /// A fixed, valid secp256k1 public key for encoding round-trip tests.
    fn test_pubkey() -> PublicKey {
        secp256k1::SecretKey::from_slice(&[0x24; 32])
            .expect("valid scalar")
            .public_key(secp256k1::SECP256K1)
    }

    fn test_out_point(out_idx: u64) -> OutPoint {
        OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx,
        }
    }

    #[test]
    fn swap_input_claim_round_trips_through_consensus_encoding() {
        let input = SwapInput::Claim {
            offer_id: test_out_point(0),
            party: Party::Maker,
        };
        let bytes = input.consensus_encode_to_vec();
        let decoded = SwapInput::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("SwapInput::Claim should decode what it just encoded");

        assert_eq!(input, decoded);
    }

    #[test]
    fn swap_input_reclaim_round_trips_through_consensus_encoding() {
        let input = SwapInput::Reclaim {
            offer_id: test_out_point(1),
        };
        let bytes = input.consensus_encode_to_vec();
        let decoded = SwapInput::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("SwapInput::Reclaim should decode what it just encoded");

        assert_eq!(input, decoded);
    }

    #[test]
    fn swap_output_make_offer_round_trips_through_consensus_encoding() {
        let output = SwapOutput::MakeOffer {
            maker_unit: AmountUnit::new_custom(1),
            maker_amount: Amount::from_msats(1_000_000),
            taker_unit: AmountUnit::new_custom(2),
            taker_amount: Amount::from_msats(2_000_000),
            expiry: 1_800_000_000,
            maker_pk: test_pubkey(),
        };
        let bytes = output.consensus_encode_to_vec();
        let decoded = SwapOutput::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("SwapOutput::MakeOffer should decode what it just encoded");

        assert_eq!(output, decoded);
    }

    #[test]
    fn swap_output_fill_round_trips_through_consensus_encoding() {
        let output = SwapOutput::Fill {
            offer_id: test_out_point(2),
            taker_pk: test_pubkey(),
        };
        let bytes = output.consensus_encode_to_vec();
        let decoded = SwapOutput::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("SwapOutput::Fill should decode what it just encoded");

        assert_eq!(output, decoded);
    }

    #[test]
    fn offer_open_round_trips_through_consensus_encoding() {
        let offer = Offer {
            maker_pk: test_pubkey(),
            maker_unit: AmountUnit::new_custom(1),
            maker_amount: Amount::from_msats(1_000_000),
            taker_unit: AmountUnit::new_custom(2),
            taker_amount: Amount::from_msats(2_000_000),
            expiry: 1_800_000_000,
            state: OfferState::Open,
            maker_claimed: false,
            taker_claimed: false,
        };
        let bytes = offer.consensus_encode_to_vec();
        let decoded = Offer::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("Offer(Open) should decode what it just encoded");

        assert_eq!(offer, decoded);
    }

    #[test]
    fn offer_filled_round_trips_through_consensus_encoding() {
        let offer = Offer {
            maker_pk: test_pubkey(),
            maker_unit: AmountUnit::new_custom(1),
            maker_amount: Amount::from_msats(1_000_000),
            taker_unit: AmountUnit::new_custom(2),
            taker_amount: Amount::from_msats(2_000_000),
            expiry: 1_800_000_000,
            state: OfferState::Filled {
                taker_pk: test_pubkey(),
            },
            maker_claimed: true,
            taker_claimed: false,
        };
        let bytes = offer.consensus_encode_to_vec();
        let decoded = Offer::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("Offer(Filled) should decode what it just encoded");

        assert_eq!(offer, decoded);
    }

    #[test]
    fn swap_consensus_item_round_trips_through_consensus_encoding() {
        let item = SwapConsensusItem {
            unix_secs: 1_800_000_000,
        };
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            SwapConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("SwapConsensusItem should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    /// Manually builds the wire bytes of an unrecognized `SwapInput`
    /// variant (index `99`, which no known variant claims) and checks that
    /// decoding lands on the `#[encodable_default]` catch-all with the
    /// original variant index and payload preserved, and that re-encoding
    /// it reproduces the exact same bytes.
    #[test]
    fn swap_input_unknown_variant_round_trips_through_default_catch_all() {
        let variant: u64 = 99;
        let payload: Vec<u8> = vec![1, 2, 3, 4, 5];

        let mut original_bytes = Vec::new();
        variant
            .consensus_encode(&mut original_bytes)
            .expect("u64 encoding cannot fail");
        payload
            .consensus_encode(&mut original_bytes)
            .expect("Vec<u8> encoding cannot fail");

        let decoded =
            SwapInput::consensus_decode_whole(&original_bytes, &ModuleDecoderRegistry::default())
                .expect("an unknown variant should decode into the Default catch-all");

        assert_eq!(
            decoded,
            SwapInput::Default {
                variant,
                bytes: payload,
            }
        );

        let re_encoded_bytes = decoded.consensus_encode_to_vec();
        assert_eq!(original_bytes, re_encoded_bytes);
    }

    /// Mirrors
    /// [`swap_input_unknown_variant_round_trips_through_default_catch_all`]
    /// for `SwapOutput`.
    #[test]
    fn swap_output_unknown_variant_round_trips_through_default_catch_all() {
        let variant: u64 = 42;
        let payload: Vec<u8> = vec![9, 8, 7];

        let mut original_bytes = Vec::new();
        variant
            .consensus_encode(&mut original_bytes)
            .expect("u64 encoding cannot fail");
        payload
            .consensus_encode(&mut original_bytes)
            .expect("Vec<u8> encoding cannot fail");

        let decoded =
            SwapOutput::consensus_decode_whole(&original_bytes, &ModuleDecoderRegistry::default())
                .expect("an unknown variant should decode into the Default catch-all");

        assert_eq!(
            decoded,
            SwapOutput::Default {
                variant,
                bytes: payload,
            }
        );

        let re_encoded_bytes = decoded.consensus_encode_to_vec();
        assert_eq!(original_bytes, re_encoded_bytes);
    }
}
