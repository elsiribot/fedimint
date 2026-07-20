use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record};
use fedimint_usdt_common::{DepositObservation, EvmAddress, SigningSessionId, UsdtAmount};
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
    /// Consensus-agreed state of a threshold-ECDSA signing session (Phase
    /// 6a).
    SigningSession = 0x06,
    /// Per-(session, round, peer, chunk) record of one `MpcRound` consensus
    /// item chunk this guardian has already processed (Phase 6a). A round's
    /// full per-peer payload is split into
    /// [`fedimint_usdt_common::MPC_ROUND_CHUNK_SIZE`]-byte chunks (each its
    /// own consensus item) to stay under the `AlephBFT` unit byte limit.
    MpcRoundChunk = 0x07,
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

/// What a signing session's digest is being signed for. Phase 6a only ever
/// creates [`SigningPurpose::Test`] sessions (exercising the round-advance
/// loop end to end); Phase 7 adds the real `DeployAndSweep`/`Withdraw`
/// purposes that drive actual EVM transactions.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub enum SigningPurpose {
    Test([u8; 32]),
}

/// A threshold-ECDSA signing session's current progress: `InProgress` while
/// guardians are still exchanging cggmp21 protocol messages, `Completed`
/// once a valid compact secp256k1 signature has been assembled, `Failed` if
/// the session could not converge (e.g. a participant misbehaved or dropped
/// out) and must be retried under a fresh [`SigningSessionId`] (see
/// [`fedimint_usdt_common::signing_session_id`]'s `attempt` parameter).
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub enum SessionState {
    InProgress,
    /// A compact (64-byte) secp256k1 signature over the session's digest.
    Completed(Vec<u8>),
    Failed,
}

/// Consensus-agreed state of one threshold-ECDSA signing session: what is
/// being signed ([`SigningPurpose`]/`digest`), which guardians are
/// participating, how far the cggmp21 round-advance loop has progressed, and
/// its outcome.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub struct SigningSession {
    pub purpose: SigningPurpose,
    pub digest: [u8; 32],
    pub signers: Vec<PeerId>,
    pub round: u16,
    pub state: SessionState,
}

#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct SigningSessionKey(pub SigningSessionId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SigningSessionPrefix;

impl_db_record!(
    key = SigningSessionKey,
    value = SigningSession,
    db_prefix = DbKeyPrefix::SigningSession,
);
impl_db_lookup!(key = SigningSessionKey, query_prefix = SigningSessionPrefix);

/// One chunk of one peer's payload for a single round of a signing session.
///
/// A round's full per-peer payload can exceed the `AlephBFT` unit byte limit,
/// so it is split into [`fedimint_usdt_common::MPC_ROUND_CHUNK_SIZE`]-byte
/// chunks, each stored under its own key. `count` is the total number of
/// chunks that make up this peer's full payload for this round (so a reader
/// knows when it has seen all of `0..count`).
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct MpcRoundChunk {
    pub count: u16,
    pub bytes: Vec<u8>,
}

/// One chunk of one peer's payload for a single round of a signing session,
/// keyed `(session, round, peer, chunk)`. The field order makes all three of
/// [`MpcRoundChunkPrefix`], [`MpcRoundChunkSessionRoundPrefix`], and
/// [`MpcRoundChunkSessionRoundPeerPrefix`] valid byte-prefixes (mirroring
/// [`DepositObservationVoteKey`]'s dual-prefix pattern, extended to a
/// three-level prefix hierarchy).
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct MpcRoundChunkKey(pub SigningSessionId, pub u16, pub PeerId, pub u16);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct MpcRoundChunkPrefix;

/// Every peer's every chunk for one session's round.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct MpcRoundChunkSessionRoundPrefix(pub SigningSessionId, pub u16);

/// One peer's chunks for one session's round.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct MpcRoundChunkSessionRoundPeerPrefix(pub SigningSessionId, pub u16, pub PeerId);

impl_db_record!(
    key = MpcRoundChunkKey,
    value = MpcRoundChunk,
    db_prefix = DbKeyPrefix::MpcRoundChunk,
);
impl_db_lookup!(
    key = MpcRoundChunkKey,
    query_prefix = MpcRoundChunkPrefix,
    query_prefix = MpcRoundChunkSessionRoundPrefix,
    query_prefix = MpcRoundChunkSessionRoundPeerPrefix,
);

#[cfg(test)]
mod tests {
    use fedimint_core::PeerId;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_usdt_common::{DepositObservation, EvmAddress, UsdtAmount, signing_session_id};
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

        let claim_pk = test_pubkey();
        let vote = |account: EvmAddress, block: u64| DepositObservation {
            account,
            balance: UsdtAmount(2_000_000),
            block,
            claim_pk,
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

    #[tokio::test]
    async fn signing_session_round_trips() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let id = signing_session_id(&[1; 32], 0);
        let session = SigningSession {
            purpose: SigningPurpose::Test([2; 32]),
            digest: [1; 32],
            signers: vec![PeerId::from(0), PeerId::from(1), PeerId::from(2)],
            round: 0,
            state: SessionState::InProgress,
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&SigningSessionKey(id), &session)
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(dbtx.get_value(&SigningSessionKey(id)).await, Some(session));
    }

    #[tokio::test]
    async fn mpc_round_chunk_round_trips_and_filters_by_session_round_and_peer_prefixes() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let id = signing_session_id(&[3; 32], 0);

        let chunk = |count: u16, bytes: Vec<u8>| MpcRoundChunk { count, bytes };

        let mut dbtx = db.begin_transaction().await;
        // Round 2: peer 0 has two chunks, peer 1 has one chunk.
        dbtx.insert_new_entry(
            &MpcRoundChunkKey(id, 2, PeerId::from(0), 0),
            &chunk(2, vec![1, 2]),
        )
        .await;
        dbtx.insert_new_entry(
            &MpcRoundChunkKey(id, 2, PeerId::from(0), 1),
            &chunk(2, vec![3, 4]),
        )
        .await;
        dbtx.insert_new_entry(
            &MpcRoundChunkKey(id, 2, PeerId::from(1), 0),
            &chunk(1, vec![5, 6]),
        )
        .await;
        // A different round must not leak into the round-2 prefix queries.
        dbtx.insert_new_entry(
            &MpcRoundChunkKey(id, 3, PeerId::from(0), 0),
            &chunk(1, vec![9]),
        )
        .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            dbtx.get_value(&MpcRoundChunkKey(id, 2, PeerId::from(0), 1))
                .await,
            Some(chunk(2, vec![3, 4]))
        );

        // All peers' chunks for (session, round 2): 2 (peer 0) + 1 (peer 1).
        let round_2: Vec<_> = dbtx
            .find_by_prefix(&MpcRoundChunkSessionRoundPrefix(id, 2))
            .await
            .collect()
            .await;
        assert_eq!(round_2.len(), 3);
        assert!(round_2.iter().all(|(key, _)| key.0 == id && key.1 == 2));

        // One peer's chunks for (session, round 2, peer 0): both of peer 0's.
        let peer0_round_2: Vec<_> = dbtx
            .find_by_prefix(&MpcRoundChunkSessionRoundPeerPrefix(id, 2, PeerId::from(0)))
            .await
            .collect()
            .await;
        assert_eq!(peer0_round_2.len(), 2);
        assert!(
            peer0_round_2
                .iter()
                .all(|(key, _)| key.0 == id && key.1 == 2 && key.2 == PeerId::from(0))
        );
    }
}
