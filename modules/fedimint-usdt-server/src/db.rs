use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record};
use fedimint_usdt_common::{DepositObservation, EvmAddress, UsdtAmount};
use secp256k1::PublicKey;
use serde::Serialize;
use strum_macros::EnumIter;

/// Namespaces DB keys for this module.
///
/// `0x02` is intentionally skipped: it is reserved for a later-phase
/// `FeeVote` table and must not be reused.
#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    /// Per-peer votes on the current EVM block count (analogous to the
    /// wallet module's `BlockCountVote`, but `u64`-valued since EVM block
    /// numbers do not fit the wallet's `u32` bitcoin block heights).
    BlockCountVote = 0x01,
    /// Consensus-agreed state for a tracked deposit account.
    DepositRecord = 0x03,
    /// Per-peer votes on the observed balance of a deposit account at a
    /// given block.
    DepositObservationVote = 0x04,
    /// Guardian-local (non-consensus) bookkeeping for deposit accounts this
    /// guardian is actively polling.
    PendingCheck = 0x05,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct BlockCountVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockCountVotePrefix;

impl_db_record!(
    key = BlockCountVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::BlockCountVote,
);
impl_db_lookup!(key = BlockCountVoteKey, query_prefix = BlockCountVotePrefix);

/// Consensus-agreed state for a deposit account: how much of the observed
/// balance has been credited (i.e. a supermajority of guardians agree it was
/// observed) vs. already claimed by the depositor, plus the last block
/// height a deposit observation vote was processed for.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub struct DepositRecord {
    pub claim_pk: PublicKey,
    pub credited: UsdtAmount,
    pub claimed: UsdtAmount,
    pub last_observed_block: u64,
}

#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DepositRecordKey(pub EvmAddress);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct DepositRecordPrefix;

impl_db_record!(
    key = DepositRecordKey,
    value = DepositRecord,
    db_prefix = DbKeyPrefix::DepositRecord,
);
impl_db_lookup!(key = DepositRecordKey, query_prefix = DepositRecordPrefix);

/// A single peer's vote on the observed balance of a deposit account. The
/// `EvmAddress` field is ordered first so that
/// [`DepositObservationVoteAccountPrefix`] can look up every peer's vote for
/// one account.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DepositObservationVoteKey(pub EvmAddress, pub PeerId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DepositObservationVotePrefix;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DepositObservationVoteAccountPrefix(pub EvmAddress);

impl_db_record!(
    key = DepositObservationVoteKey,
    value = DepositObservation,
    db_prefix = DbKeyPrefix::DepositObservationVote,
);
impl_db_lookup!(
    key = DepositObservationVoteKey,
    query_prefix = DepositObservationVotePrefix,
    query_prefix = DepositObservationVoteAccountPrefix,
);

/// Guardian-local (non-consensus) record of a deposit account this guardian
/// is actively polling its configured EVM node for.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub struct PendingCheck {
    pub claim_pk: PublicKey,
    pub requested_at_block: u64,
}

#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct PendingCheckKey(pub EvmAddress);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingCheckPrefix;

impl_db_record!(
    key = PendingCheckKey,
    value = PendingCheck,
    db_prefix = DbKeyPrefix::PendingCheck,
);
impl_db_lookup!(key = PendingCheckKey, query_prefix = PendingCheckPrefix);

#[cfg(test)]
mod tests {
    use fedimint_core::PeerId;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_usdt_common::{DepositObservation, EvmAddress, UsdtAmount};
    use futures::StreamExt;
    use secp256k1::Secp256k1;

    use super::*;

    fn test_pubkey() -> PublicKey {
        let secp = Secp256k1::new();
        secp256k1::SecretKey::from_slice(&[0x11; 32])
            .expect("valid scalar")
            .public_key(&secp)
    }

    #[tokio::test]
    async fn deposit_record_round_trips() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let account = EvmAddress([0x42; 20]);
        let record = DepositRecord {
            claim_pk: test_pubkey(),
            credited: UsdtAmount(1_000_000),
            claimed: UsdtAmount(0),
            last_observed_block: 100,
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&DepositRecordKey(account), &record)
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        let fetched = dbtx.get_value(&DepositRecordKey(account)).await;
        assert_eq!(fetched, Some(record));
    }

    #[tokio::test]
    async fn deposit_observation_vote_round_trips_and_filters_by_account_prefix() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let account_a = EvmAddress([0xaa; 20]);
        let account_b = EvmAddress([0xbb; 20]);

        let vote = |account: EvmAddress, block: u64| DepositObservation {
            account,
            balance: UsdtAmount(2_000_000),
            block,
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &DepositObservationVoteKey(account_a, PeerId::from(0)),
            &vote(account_a, 10),
        )
        .await;
        dbtx.insert_new_entry(
            &DepositObservationVoteKey(account_a, PeerId::from(1)),
            &vote(account_a, 10),
        )
        .await;
        dbtx.insert_new_entry(
            &DepositObservationVoteKey(account_b, PeerId::from(0)),
            &vote(account_b, 11),
        )
        .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        let fetched = dbtx
            .get_value(&DepositObservationVoteKey(account_a, PeerId::from(0)))
            .await;
        assert_eq!(fetched, Some(vote(account_a, 10)));

        let account_a_votes: Vec<_> = dbtx
            .find_by_prefix(&DepositObservationVoteAccountPrefix(account_a))
            .await
            .collect()
            .await;
        assert_eq!(account_a_votes.len(), 2);
        assert!(account_a_votes.iter().all(|(key, _)| key.0 == account_a));
    }

    #[tokio::test]
    async fn block_count_vote_and_pending_check_round_trip() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let account = EvmAddress([0x77; 20]);
        let pending = PendingCheck {
            claim_pk: test_pubkey(),
            requested_at_block: 55,
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&BlockCountVoteKey(PeerId::from(2)), &42u64)
            .await;
        dbtx.insert_new_entry(&PendingCheckKey(account), &pending)
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            dbtx.get_value(&BlockCountVoteKey(PeerId::from(2))).await,
            Some(42u64)
        );
        assert_eq!(
            dbtx.get_value(&PendingCheckKey(account)).await,
            Some(pending)
        );
    }
}
