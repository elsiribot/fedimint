#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::fmt;

use config::UsdtClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::plugin_types_trait_impl_common;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Common contains types shared by both the client and server

// The client (and, in later phases, server) configuration
pub mod config;
pub mod endpoint_constants;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("usdt");

/// Modules are non-compatible with older versions
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

/// A 20-byte EVM (Ethereum-style) address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EvmAddress(pub [u8; 20]);

impl fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;

        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

/// An amount of USDT expressed in its smallest on-chain unit (10^-6 USDT).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct UsdtAmount(pub u64);

impl fmt::Display for UsdtAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A federation member's vote on the current EVM fee market and USDT/ETH
/// exchange rate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeVote {
    pub max_fee_per_gas_wei: u64,
    pub usdt_per_eth_e6: u64,
}

impl fmt::Display for FeeVote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FeeVote(max_fee_per_gas_wei={}, usdt_per_eth_e6={})",
            self.max_fee_per_gas_wei, self.usdt_per_eth_e6
        )
    }
}

/// Non-transaction items that will be submitted to consensus
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct UsdtConsensusItem;

/// Input for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtInput;

/// Output for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtOutput;

/// Information needed by a client to update output funds
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtOutputOutcome;

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum UsdtInputError {
    #[error("This module does not support inputs")]
    NotSupported,
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum UsdtOutputError {
    #[error("This module does not support outputs")]
    NotSupported,
}

/// Contains the types defined above
pub struct UsdtModuleTypes;

// Wire together the types for this module
plugin_types_trait_impl_common!(
    KIND,
    UsdtModuleTypes,
    UsdtClientConfig,
    UsdtInput,
    UsdtOutput,
    UsdtOutputOutcome,
    UsdtConsensusItem,
    UsdtInputError,
    UsdtOutputError
);

#[derive(Debug)]
pub struct UsdtCommonInit;

impl CommonModuleInit for UsdtCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = UsdtClientConfig;

    fn decoder() -> Decoder {
        UsdtModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for UsdtInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UsdtInput")
    }
}

impl fmt::Display for UsdtOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UsdtOutput")
    }
}

impl fmt::Display for UsdtOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UsdtOutputOutcome")
    }
}

impl fmt::Display for UsdtConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UsdtConsensusItem")
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::core::ModuleKind;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    use super::*;

    #[test]
    fn test_kind_is_usdt() {
        assert_eq!(KIND, ModuleKind::from_static_str("usdt"));
    }

    #[test]
    fn test_evm_address_round_trips_through_consensus_encoding() {
        let address = EvmAddress([0x11; 20]);
        let bytes = address.consensus_encode_to_vec();
        let decoded = EvmAddress::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("EvmAddress should decode what it just encoded");

        assert_eq!(address, decoded);
    }

    #[test]
    fn test_usdt_amount_round_trips_through_consensus_encoding() {
        let amount = UsdtAmount(1_000_000);
        let bytes = amount.consensus_encode_to_vec();
        let decoded = UsdtAmount::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("UsdtAmount should decode what it just encoded");

        assert_eq!(amount, decoded);
    }

    #[test]
    fn test_fee_vote_round_trips_through_consensus_encoding() {
        let vote = FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let bytes = vote.consensus_encode_to_vec();
        let decoded = FeeVote::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("FeeVote should decode what it just encoded");

        assert_eq!(vote, decoded);
    }

    #[test]
    fn test_evm_address_display_is_lowercase_hex_with_0x_prefix() {
        let address = EvmAddress([
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
        ]);
        let rendered = address.to_string();

        assert!(rendered.starts_with("0x"));
        assert_eq!(rendered.len(), 42);
        assert!(
            rendered
                .chars()
                .skip(2)
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn test_module_decoder_builds() {
        let _decoder = UsdtModuleTypes::decoder_builder().build();
    }
}
