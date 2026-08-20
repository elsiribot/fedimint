use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{OutPoint, impl_db_lookup, impl_db_record};
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, Debug, EnumIter)]
pub enum DbKeyPrefix {
    /// Maps one of our own swap outputs (a `MakeOffer` we created, keyed by
    /// the offer id, or a `Fill` we submitted, keyed by the fill output's
    /// `OutPoint`) to the seed-derivation index its signing keypair lives at.
    /// Persisted so a restarted client can re-derive the keypair to sign the
    /// eventual `Claim`/`Reclaim` input.
    KeyIndex = 0x01,
    /// Singleton counter: the next seed-derivation index
    /// [`crate::SwapClientModule::allocate_key_index`] will hand out for a
    /// fresh maker/taker keypair.
    NextKeyIndex = 0x02,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Maps one of our own swap outputs' `OutPoint` to the seed-derivation index
/// of the keypair that signs its offer (see
/// [`crate::SwapClientModule::offer_keypair_static`]). The maker keys this by
/// the offer id (its `MakeOffer` output's `OutPoint`); the taker keys it by
/// its `Fill` output's `OutPoint`. Both are globally unique `OutPoint`s, so
/// the two never collide even for the same underlying offer.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct KeyIndexKey(pub OutPoint);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct KeyIndexPrefixAll;

impl_db_record!(
    key = KeyIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::KeyIndex,
);

impl_db_lookup!(key = KeyIndexKey, query_prefix = KeyIndexPrefixAll);

/// Singleton key holding the next seed-derivation index used to derive a fresh
/// maker/taker keypair, mirroring `fedimint-usdt-client`'s
/// `NextDepositIndexKey`. Incremented (from a default of `0`) by
/// [`crate::SwapClientModule::allocate_key_index`] every time it hands out a
/// new key.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NextKeyIndexKey;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct NextKeyIndexPrefixAll;

impl_db_record!(
    key = NextKeyIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::NextKeyIndex,
);

impl_db_lookup!(key = NextKeyIndexKey, query_prefix = NextKeyIndexPrefixAll);
