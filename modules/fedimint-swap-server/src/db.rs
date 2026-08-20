use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{OutPoint, PeerId, impl_db_lookup, impl_db_record};
use fedimint_swap_common::Offer;
use strum_macros::EnumIter;

/// Namespaces DB keys for this module
#[repr(u8)]
#[derive(Clone, Copy, Debug, EnumIter)]
pub enum DbKeyPrefix {
    Offer = 0x01,
    ConsensusTs = 0x02,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Offer records, keyed by the `MakeOffer` output's `OutPoint`.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct OfferKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct OfferPrefix;

impl_db_record!(
    key = OfferKey,
    value = Offer,
    db_prefix = DbKeyPrefix::Offer
);
impl_db_lookup!(key = OfferKey, query_prefix = OfferPrefix);

/// Per-peer latest proposed timestamp; the median of the latest values is
/// the consensus clock (Phase 4 populates it).
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct ConsensusTsKey(pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct ConsensusTsPrefix;

impl_db_record!(
    key = ConsensusTsKey,
    value = u64,
    db_prefix = DbKeyPrefix::ConsensusTs
);
impl_db_lookup!(key = ConsensusTsKey, query_prefix = ConsensusTsPrefix);

#[cfg(test)]
mod tests {
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::module::AmountUnit;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::secp256k1::PublicKey;
    use fedimint_core::{Amount, BitcoinHash as _, TransactionId, secp256k1};
    use fedimint_swap_common::OfferState;

    use super::*;

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

    fn test_offer() -> Offer {
        Offer {
            maker_pk: test_pubkey(),
            maker_unit: AmountUnit::new_custom(1),
            maker_amount: Amount::from_msats(1_000_000),
            taker_unit: AmountUnit::new_custom(2),
            taker_amount: Amount::from_msats(2_000_000),
            expiry: 1_800_000_000,
            state: OfferState::Open,
            maker_claimed: false,
            taker_claimed: false,
        }
    }

    #[tokio::test]
    async fn offer_key_round_trips() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let out_point = test_out_point(0);
        let offer = test_offer();

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&OfferKey(out_point), &offer).await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        let fetched = dbtx.get_value(&OfferKey(out_point)).await;
        assert_eq!(fetched, Some(offer));
    }

    #[tokio::test]
    async fn consensus_ts_key_round_trips() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let peer = PeerId::from(3);
        let ts: u64 = 1_800_000_000;

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&ConsensusTsKey(peer), &ts).await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        let fetched = dbtx.get_value(&ConsensusTsKey(peer)).await;
        assert_eq!(fetched, Some(ts));
    }
}
