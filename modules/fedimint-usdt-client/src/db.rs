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
    /// Singleton counter: the next seed-derivation index
    /// [`crate::UsdtClientModule::allocate_deposit`] will use for a fresh
    /// deposit claim key.
    NextDepositIndex = 0x02,
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

/// Singleton key holding the next seed-derivation index used to derive a fresh
/// deposit claim key. Incremented (from a default of `0`) by
/// [`crate::UsdtClientModule::allocate_deposit`] every time it hands out a new
/// deposit address, so each deposit gets a distinct, deterministic-from-seed
/// claim key and a seed-only rescan
/// ([`crate::UsdtClientModule::recover_deposits`]) can walk the indices.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NextDepositIndexKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NextDepositIndexPrefixAll;

impl_db_record!(
    key = NextDepositIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextDepositIndex,
);

impl_db_lookup!(
    key = NextDepositIndexKey,
    query_prefix = NextDepositIndexPrefixAll
);
