#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::fmt;

use anyhow::Context as _;
use config::UsdtClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{AmountUnit, CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{plugin_types_trait_impl_common, secp256k1};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

// Common contains types shared by both the client and server

// The client (and, in later phases, server) configuration
pub mod config;
pub mod endpoint_constants;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("usdt");

/// Modules are non-compatible with older versions
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

/// The [`AmountUnit`] that USDT-denominated ecash is issued in.
///
/// This is a coordination constant: it must be used both as the
/// `mintv2` config-gen param (`fedimint_mintv2_common::config::MintGenParams
/// { amount_unit: USDT_UNIT, .. }`) for the mint instance that issues
/// USDT-denominated notes, *and* by the usdt module's own consensus logic
/// (`process_input`/`process_output`, added in a later phase) when crediting
/// or debiting a guardian-observed USDT deposit/withdrawal. The client's
/// per-unit primary-module routing (`Client::primary_module_for_unit`) keys
/// off this exact value, so any mismatch between the mint instance's
/// configured unit and the value the usdt module credits would silently
/// route balance to the wrong (or no) mint instance.
pub const USDT_UNIT: AmountUnit = AmountUnit::new_custom(1);

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

impl std::str::FromStr for EvmAddress {
    type Err = anyhow::Error;

    /// Parses the inverse of [`Self::fmt`]: an optionally `0x`-prefixed,
    /// 40-hex-character (20-byte) address.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_str = s.strip_prefix("0x").unwrap_or(s);
        anyhow::ensure!(
            hex_str.len() == 40,
            "EvmAddress must be a (optionally 0x-prefixed) 20-byte hex address, got {} hex chars in {s:?}",
            hex_str.len()
        );

        let mut bytes = [0u8; 20];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
                .with_context(|| format!("invalid hex byte at position {i} in {s:?}"))?;
        }

        Ok(Self(bytes))
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

/// Domain-separation tag mixed into the provisional deposit-address tweak.
pub const DEPOSIT_ADDRESS_DOMAIN: &[u8] = b"fedimint-usdt-deposit-v0";

/// The standard Ethereum address of a secp256k1 public key: last 20 bytes of
/// `keccak256` over the 64-byte uncompressed point (SEC1 with the `0x04`
/// prefix stripped). WASM-safe (pure-Rust `sha3`); mirrors
/// `fedimint_threshold_ecdsa::evm_address`, and is independently verified
/// against the same canonical test vector as
/// `fedimint_threshold_ecdsa::evm_address`.
#[must_use]
pub fn evm_address(pk: &secp256k1::PublicKey) -> EvmAddress {
    let uncompressed = pk.serialize_uncompressed();
    let hash = Keccak256::digest(&uncompressed[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    EvmAddress(address)
}

/// Derives the per-user deposit EOA from the federation group key and the
/// user's claim key via an additive tweak: `group_pk ⊕ t·G` where
/// `t = keccak256(DOMAIN ‖ group_pk ‖ claim_pk)`.
///
/// PROVISIONAL (Phase 5): detection-only. The federation does not sign for
/// this address in Phase 5; signing custody (SLIP-10 / additive-tweak /
/// CREATE2 `SimpleAccount`) is reconciled in Phase 7. Both the client (wasm)
/// and every guardian call this exact function so the address they watch is
/// bit-for-bit identical.
///
/// # Panics
///
/// Panics only in the astronomically unlikely event that the keccak digest
/// used as the tweak is not a valid secp256k1 scalar, or that the resulting
/// tweaked point is not a valid public key.
#[must_use]
pub fn derive_deposit_account(
    group_public_key: &secp256k1::PublicKey,
    claim_pk: &secp256k1::PublicKey,
) -> EvmAddress {
    let mut hasher = Keccak256::new();
    hasher.update(DEPOSIT_ADDRESS_DOMAIN);
    hasher.update(group_public_key.serialize()); // 33-byte compressed
    hasher.update(claim_pk.serialize());
    let tweak_bytes: [u8; 32] = hasher.finalize().into();

    // keccak output ≥ curve order only with negligible probability; mirror
    // the wallet's `tweak_public_key` which treats this as infallible.
    let tweak = secp256k1::Scalar::from_be_bytes(tweak_bytes)
        .expect("keccak digest is a valid secp256k1 scalar with overwhelming probability");
    let derived = group_public_key
        .add_exp_tweak(secp256k1::SECP256K1, &tweak)
        .expect("additive tweak of a valid point is a valid point");

    evm_address(&derived)
}

/// Payload of a `UsdtConsensusItem::Deposit` observation.
///
/// `claim_pk` is carried in the observation itself (rather than being
/// recovered from a guardian's local `PendingCheck` when the item is
/// processed) so that crediting a deposit is a pure function of consensus
/// data: `process_consensus_item` must be byte-identical across every
/// honest guardian, but `PendingCheck` is guardian-local state that not
/// every guardian is guaranteed to have (e.g. a `check_deposit` API call
/// only reaches a threshold of guardians, not all of them). See
/// `Usdt::credit_deposit`'s doc comment in `fedimint-usdt-server` for the
/// full argument.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositObservation {
    pub account: EvmAddress,
    pub balance: UsdtAmount,
    pub block: u64,
    pub claim_pk: secp256k1::PublicKey,
}

/// Request to enqueue this guardian's local deposit-checker task to start
/// watching `claim_pk`'s deposit address (see [`derive_deposit_account`]),
/// and to have the derived address returned to the caller. Idempotent: a
/// repeated request for the same `claim_pk` does not overwrite an
/// already-enqueued [check][CheckDepositResponse].
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct CheckDepositRequest {
    pub claim_pk: secp256k1::PublicKey,
}

/// Response to [`CheckDepositRequest`]: the derived deposit account, and
/// whether this call is what enqueued the guardian-local check (`false` if
/// one was already enqueued for this account).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct CheckDepositResponse {
    pub account: EvmAddress,
    pub enqueued: bool,
}

/// Request for the current credited/claimed/claimable state of `claim_pk`'s
/// deposit account.
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositStatusRequest {
    pub claim_pk: secp256k1::PublicKey,
}

/// Response to [`DepositStatusRequest`]. `claimable` is `credited − claimed`
/// (saturating). If no deposit has been credited yet (or observed at all),
/// `credited`/`claimed`/`claimable` are all zero, with `account` still set to
/// the derived deposit address so the client can poll this endpoint before
/// any credit lands.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositStatusResponse {
    pub account: EvmAddress,
    pub credited: UsdtAmount,
    pub claimed: UsdtAmount,
    pub claimable: UsdtAmount,
}

/// Per-instance config-gen params for the USDT module (Phase 4.5 mechanism).
///
/// `Default` targets a local `anvil` dev federation: chain id 31337 and a
/// fast confirmation depth. `usdt_contract` is a placeholder — real
/// deployments (and the devimint e2e) must override this with the deployed
/// contract address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsdtGenParams {
    pub usdt_contract: EvmAddress,
    pub chain_id: u64,
    pub confirmation_depth: u64,
    pub check_ttl_blocks: u64,
}

impl Default for UsdtGenParams {
    fn default() -> Self {
        Self {
            usdt_contract: EvmAddress([0u8; 20]),
            chain_id: 31337,
            confirmation_depth: 1,
            check_ttl_blocks: 10_000,
        }
    }
}

/// Non-transaction items that will be submitted to consensus
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum UsdtConsensusItem {
    /// Guardian's view of the EVM chain head (median-voted, wallet-style).
    BlockCount(u64),
    /// Guardian's observation of a pending deposit account's confirmed
    /// balance (claim-triggered, D7).
    Deposit(DepositObservation),
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// Input for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum UsdtInput {
    /// Claim credited deposit funds. Core verifies the fedimint transaction is
    /// signed by `InputMeta.pub_key` = the deposit's claim key; there is no
    /// extra signature inside the input.
    V0(UsdtInputV0),
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// Data for a `UsdtInput::V0`
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtInputV0 {
    pub account: EvmAddress,
    pub amount: UsdtAmount,
}

/// Output for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtOutput;

/// Information needed by a client to update output funds
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtOutputOutcome;

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum UsdtInputError {
    #[error("No credited deposit record exists for this account")]
    UnknownDepositAccount,
    #[error("Claim of {requested} exceeds the {available} still claimable for this account")]
    InsufficientCredit {
        available: UsdtAmount,
        requested: UsdtAmount,
    },
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
        write!(f, "{self:?}")
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
        write!(f, "{self:?}")
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

    fn hex_20(s: &str) -> [u8; 20] {
        let bytes = (0..20)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>();
        bytes.try_into().unwrap()
    }

    #[test]
    fn evm_address_matches_keccak_last_20_of_uncompressed() {
        // A fixed secp256k1 pubkey → its well-known Ethereum address.
        // Secret key = 0x0000...0001; address is the canonical test vector.
        let sk = secp256k1::SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        })
        .expect("valid scalar");
        let pk = sk.public_key(secp256k1::SECP256K1);
        // keccak256(uncompressed[1..])[12..] for sk=1:
        let expected = EvmAddress(hex_20("7e5f4552091a69125d5dfcb7b8c2659029395bdf"));
        assert_eq!(evm_address(&pk), expected);
    }

    #[test]
    fn derive_deposit_account_is_deterministic_and_claim_specific() {
        let group = secp256k1::SecretKey::from_slice(&[2u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let claim_a = secp256k1::SecretKey::from_slice(&[3u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let claim_b = secp256k1::SecretKey::from_slice(&[4u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);

        // Deterministic
        assert_eq!(
            derive_deposit_account(&group, &claim_a),
            derive_deposit_account(&group, &claim_a)
        );
        // Distinct per claim key
        assert_ne!(
            derive_deposit_account(&group, &claim_a),
            derive_deposit_account(&group, &claim_b)
        );
        // Distinct from the untweaked group address (tweak is non-zero)
        assert_ne!(
            derive_deposit_account(&group, &claim_a),
            evm_address(&group)
        );
    }

    #[test]
    fn test_usdt_consensus_item_block_count_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::BlockCount(7);
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::BlockCount should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_deposit_round_trips_through_consensus_encoding() {
        let claim_pk = secp256k1::SecretKey::from_slice(&[5u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let item = UsdtConsensusItem::Deposit(DepositObservation {
            account: EvmAddress([9; 20]),
            balance: UsdtAmount(1_000_000),
            block: 42,
            claim_pk,
        });
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::Deposit should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_input_v0_round_trips_through_consensus_encoding() {
        let input = UsdtInput::V0(UsdtInputV0 {
            account: EvmAddress([9; 20]),
            amount: UsdtAmount(1_000_000),
        });
        let bytes = input.consensus_encode_to_vec();
        let decoded = UsdtInput::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("UsdtInput::V0 should decode what it just encoded");

        assert_eq!(input, decoded);
    }
}
