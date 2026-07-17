use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_usdt_common::EvmAddress;
use strum::Display;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, Display, EnumIter, Debug)]
pub enum DbKeyPrefix {
    /// Maps a derived deposit account to the claim keypair controlling it.
    ClaimKey = 0x01,
}

/// Maps a derived deposit account (see
/// [`fedimint_usdt_common::derive_deposit_account`]) to the claim keypair
/// that was used to derive it, so the client can sign the claim transaction
/// and, after a restart, recover which key controls a pending deposit.
///
/// Phase 9: deterministic-from-seed derivation for recovery; Phase 5 stores a
/// random per-deposit key here instead.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct ClaimKeyKey(pub EvmAddress);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct ClaimKeyPrefixAll;

impl_db_record!(
    key = ClaimKeyKey,
    value = Keypair,
    db_prefix = DbKeyPrefix::ClaimKey,
);

impl_db_lookup!(key = ClaimKeyKey, query_prefix = ClaimKeyPrefixAll);
