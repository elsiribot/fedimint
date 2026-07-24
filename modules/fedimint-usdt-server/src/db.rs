use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{OutPoint, PeerId, impl_db_lookup, impl_db_record};
use fedimint_usdt_common::user_op::{SignedUserOp, UnsignedUserOp};
use fedimint_usdt_common::{
    BootstrapObservation, DepositObservation, EvmAddress, FeeVote, SigningSessionId, UsdtAmount,
};
use serde::Serialize;
use strum_macros::EnumIter;

/// Namespaces DB keys for this module.
#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    /// Per-peer votes on the current EVM block count (analogous to the
    /// wallet module's `BlockCountVote`, but `u64`-valued since EVM block
    /// numbers do not fit the wallet's `u32` bitcoin block heights).
    BlockCountVote = 0x01,
    /// Per-peer votes on the current EVM fee market and USDT/ETH exchange
    /// rate (Phase 8, Task 1), mirroring [`Self::BlockCountVote`]'s
    /// per-peer-vote shape. The federation's current fee quote is the
    /// per-field MEDIAN over these votes (see
    /// `fedimint_usdt_server::Usdt::fee_vote_median`), not any single
    /// peer's vote.
    FeeVote = 0x02,
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
    /// A `UserOp` deterministically enqueued for MPC signing but not yet
    /// federation-agreed-signed (Phase 7, Task 5).
    PendingUserOp = 0x08,
    /// A `UserOp` that has been federation-agreed-signed (its `SigningSession`
    /// reached `Completed`) and is awaiting/undergoing guardian-local
    /// on-chain submission and confirmation (Phase 7, Task 5).
    SubmittedUserOp = 0x09,
    /// The consensus-agreed pool `SimpleAccount`'s derived address and the
    /// USDT balance swept into it so far (Phase 7, Task 5). A module-wide
    /// singleton record (see [`PoolStateKey`]).
    PoolState = 0x0A,
    /// Per-peer votes on the observed on-chain outcome of a submitted
    /// `UserOp` (Phase 7, Task 5), mirroring [`DepositObservationVoteKey`]'s
    /// dual-prefix quorum shape.
    UserOpConfirmedVote = 0x0B,
    /// A withdrawal output that has been accepted (its `max_fee` cleared
    /// the fee-vote-median quote) and is queued for the next withdrawal
    /// batch (Phase 8, Task 1; batched into an actual `UserOp` by Task 2).
    UnclaimedWithdrawal = 0x0C,
    /// The consensus-agreed lifecycle stage of a queued withdrawal (Phase 8,
    /// Task 1).
    WithdrawalState = 0x0D,
    /// Per-peer votes on the module's on-chain readiness (Part C), mirroring
    /// [`Self::FeeVote`]'s per-peer-vote shape. The federation's readiness
    /// state is the per-field threshold count over these votes (see
    /// `fedimint_usdt_server::Usdt::bootstrap_state`), not any single peer's
    /// vote.
    BootstrapVote = 0x0E,
    /// A module-wide singleton latch (see [`HasEverBeenReadyKey`]): present
    /// once the readiness tally has reached `Ready` at least once (Part C).
    /// Set deterministically inside `process_consensus_item`, so
    /// `bootstrap_state` can distinguish `Degraded` (was `Ready`, regressed)
    /// from `AwaitingInfra` (never `Ready`) -- a pure count over the current
    /// votes cannot.
    HasEverBeenReady = 0x0F,
    /// The maximum batch size a given queued withdrawal may next be included
    /// in (security finding 05, poisoned-batch isolation). Absent means the
    /// default [`crate::BATCH_MAX_ITEMS`]. Halved (floor 1) on each failed
    /// batch that covered this withdrawal, forcing a poisoned batch to
    /// binary-split down to a singleton, and removed once the withdrawal
    /// reaches a terminal state (`Confirmed` or `Failed`). See
    /// [`WithdrawalBatchCapKey`].
    WithdrawalBatchCap = 0x10,
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

/// One peer's vote on the current EVM fee market / USDT-per-ETH exchange
/// rate (Phase 8, Task 1), mirroring [`BlockCountVoteKey`] exactly.
#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct FeeVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FeeVotePrefix;

/// The value stored at [`FeeVoteKey`] (security finding 06's freshness
/// facet): the peer's raw [`FeeVote`] plus the `consensus_block_count`
/// (`Usdt::consensus_block_count`) at which it was recorded. `fee_vote_median`
/// excludes votes whose `recorded_block` has fallen more than
/// `FEE_VOTE_TTL_BLOCKS` behind the current consensus block count, so a
/// guardian whose fee poller stops producing fresh observations ages out of
/// the quorum instead of pinning a stale (or Byzantine) value forever.
/// `recorded_block` is always stamped from `consensus_block_count(dbtx)` --
/// never wall-clock -- so every honest guardian computes the identical value
/// for the same ordered `FeeVote` item.
#[derive(Clone, Copy, Debug, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct StoredFeeVote {
    pub vote: FeeVote,
    pub recorded_block: u64,
}

impl_db_record!(
    key = FeeVoteKey,
    value = StoredFeeVote,
    db_prefix = DbKeyPrefix::FeeVote,
);
impl_db_lookup!(key = FeeVoteKey, query_prefix = FeeVotePrefix);

/// Consensus-agreed state for a deposit account: how much of the observed
/// balance has been credited (i.e. a supermajority of guardians agree it was
/// observed) vs. already claimed by the depositor, plus the last block
/// height a deposit observation vote was processed for.
///
/// `swept` (Phase 7, Task 5) is how much of `credited` has been moved
/// on-chain into the pool account by a confirmed `UserOp`
/// (`Usdt::apply_user_op_confirmed`) -- tracked here specifically so
/// `ServerModule::audit` can report each deposit's un-swept remainder
/// (`credited - swept`) instead of double-counting USDT that has already
/// become `PoolState.balance`. See `Usdt::audit`'s doc comment for the exact
/// solvency formula.
///
/// `nonce` is this deposit account's `SimpleAccount` nonce -- the number of
/// deploy-and-sweep `UserOp`s the `EntryPoint` has already consumed for it.
/// It advances by one every time such an op is confirmed (whether it
/// succeeded or reverted, mirroring the on-chain nonce, which the
/// `EntryPoint` validates and increments before the sweep `callData` runs).
/// `Usdt::maybe_trigger_sweep` builds each re-sweep of the `credited - swept`
/// remainder at exactly this nonce (and only populates `initCode` while it is
/// still `0`, i.e. before the account's first, deploying sweep), so a reused
/// deposit address is fully swept instead of leaving an unpooled remainder.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub struct DepositRecord {
    pub claim_pk: PublicKey,
    pub credited: UsdtAmount,
    pub claimed: UsdtAmount,
    pub last_observed_block: u64,
    pub swept: UsdtAmount,
    pub nonce: u64,
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

/// What a signing session's digest is being signed for. Deterministically
/// created alongside a [`PendingUserOp`] (see `Usdt::maybe_trigger_sweep`) to
/// drive the deploy-and-sweep flow -- `UserOp` is the ONLY variant (sec-01
/// hardening: an unauthenticated debug-only variant, which let a caller
/// drive an arbitrary-digest signing oracle over the group key via a
/// dedicated debug consensus item, has been removed entirely along with the
/// debug endpoints and that consensus item). `process_mpc_signature` relies
/// on this being the only purpose: every signing session MUST be backed by a
/// live [`PendingUserOp`] to finalize.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub enum SigningPurpose {
    /// Signing session for the `userOpHash`-derived EIP-191 digest of the
    /// [`PendingUserOp`] keyed by this `op_hash` (its `user_op_hash`, i.e.
    /// the [`PendingUserOpKey`]/[`SubmittedUserOpKey`] of the same op).
    UserOp([u8; 32]),
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
    /// How many prior attempts at signing this digest timed out and were
    /// retried under a rotated signer subset (Phase 6b, Task 3). `0` for a
    /// session's first attempt; see
    /// [`fedimint_usdt_common::signing_session_id`]'s `attempt` parameter,
    /// which this value is passed into to derive the retried session's id.
    pub attempt: u32,
    /// The consensus block count (see `Usdt::consensus_block_count`) as of
    /// this session's most recent progress: session creation, or — more
    /// recently — the last time an `MpcRound` item advanced `round`.
    /// Compared against a timeout threshold by `Usdt::timed_out` to detect a
    /// stalled session deterministically (consensus-DB-only, never
    /// wall-clock).
    pub last_progress_block: u64,
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
/// keyed `(session, round, peer, chunk)`. The field order makes all four of
/// [`MpcRoundChunkPrefix`], [`MpcRoundChunkSessionPrefix`],
/// [`MpcRoundChunkSessionRoundPrefix`], and
/// [`MpcRoundChunkSessionRoundPeerPrefix`] valid byte-prefixes (mirroring
/// [`DepositObservationVoteKey`]'s dual-prefix pattern, extended to a
/// four-level prefix hierarchy).
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct MpcRoundChunkKey(pub SigningSessionId, pub u16, pub PeerId, pub u16);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct MpcRoundChunkPrefix;

/// Every round's every peer's every chunk for one session (security finding
/// 11's GC hook): `process_rotate_signing` and `process_mpc_signature`
/// `remove_by_prefix` this once their session fails/completes, so a finished
/// or abandoned signing attempt's chunk records never linger in the
/// consensus DB.
#[derive(Debug, Clone, Encodable, Decodable)]
pub struct MpcRoundChunkSessionPrefix(pub SigningSessionId);

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
    query_prefix = MpcRoundChunkSessionPrefix,
    query_prefix = MpcRoundChunkSessionRoundPrefix,
    query_prefix = MpcRoundChunkSessionRoundPeerPrefix,
);

/// What a [`PendingUserOp`]/[`SubmittedUserOp`] is for. Phase 7 introduced
/// `DeployAndSweep` (a counterfactual deposit account's first, nonce-0 sweep
/// to the pool); Phase 8, Task 2 adds `Withdraw` (a batched payout FROM the
/// pool account).
/// [`Usdt::apply_user_op_confirmed`](crate::Usdt::apply_user_op_confirmed)
/// branches on this to decide whether a confirmed op credits the pool
/// (`DeployAndSweep`) or debits it (`Withdraw`).
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub enum UserOpPurpose {
    /// Deploys (if not already deployed) and sweeps `source`'s full credited
    /// balance to the pool account.
    DeployAndSweep { source: EvmAddress },
    /// A batched withdrawal payout `UserOp` from the pool `SimpleAccount`
    /// (Phase 8, Task 2): `executeBatch`-transfers every one of
    /// `outpoints`' queued `UsdtWithdrawalV0.amount` to its `recipient`.
    /// `outpoints` are the (deterministically OutPoint-sorted) keys of the
    /// [`UnclaimedWithdrawalKey`]/[`WithdrawalStateKey`] records this op
    /// settles once confirmed -- carried here (not re-derived) so
    /// `apply_user_op_confirmed` knows exactly which withdrawals this op
    /// covers even after some of them may have been superseded/re-queued by
    /// a later batch.
    Withdraw { outpoints: Vec<OutPoint> },
}

/// A `UserOp` deterministically built from consensus DB state and enqueued
/// for MPC signing (Phase 7, Task 5), keyed by its own
/// [`fedimint_usdt_common::user_op::user_op_hash`] (see [`PendingUserOpKey`]).
/// Cleared (and replaced by a [`SubmittedUserOp`]) once the
/// `SigningPurpose::UserOp(op_hash)` session it started reaches
/// `SessionState::Completed` (`Usdt::process_mpc_signature`).
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub struct PendingUserOp {
    pub op: UnsignedUserOp,
    pub purpose: UserOpPurpose,
    /// The consensus block count (`Usdt::consensus_block_count`) as of this
    /// op's enqueueing -- diagnostic bookkeeping only (no consensus decision
    /// reads it today).
    pub created_block: u64,
}

#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct PendingUserOpKey(pub [u8; 32]);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingUserOpPrefix;

impl_db_record!(
    key = PendingUserOpKey,
    value = PendingUserOp,
    db_prefix = DbKeyPrefix::PendingUserOp,
);
impl_db_lookup!(key = PendingUserOpKey, query_prefix = PendingUserOpPrefix);

/// A `UserOp` whose federation-agreed-signed [`SignedUserOp`] is ready for
/// guardian-local on-chain submission (Phase 7, Task 5), keyed by the same
/// `op_hash` its originating [`PendingUserOp`] was keyed by. Cleared once
/// `UsdtConsensusItem::UserOpConfirmed` reaches threshold agreement
/// (`Usdt::apply_user_op_confirmed`).
///
/// `purpose` (Phase 8, Task 2) is carried forward unchanged from the
/// originating [`PendingUserOp::purpose`] (`Usdt::process_mpc_signature`
/// copies it across when finalizing) so `apply_user_op_confirmed` knows,
/// purely from this consensus record, whether a confirmed op is a
/// `DeployAndSweep` (credit the pool) or a `Withdraw` (debit the pool and
/// settle the covered withdrawals) -- Phase 7 omitted this field since only
/// `DeployAndSweep` existed yet.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub struct SubmittedUserOp {
    pub signed: SignedUserOp,
    pub purpose: UserOpPurpose,
    /// The consensus block count as of this op's federation-agreed
    /// signature -- the timeout anchor the reprice/replacement path
    /// (`Usdt::process_replace_user_op`, security finding 03) compares against
    /// `consensus_block_count`.
    pub submitted_block: u64,
    /// `true` once this op has been timed out and REPLACED by a
    /// higher-fee op at the SAME `EntryPoint` `(sender, nonce)` (security
    /// finding 03). Added in `MODULE_CONSENSUS_VERSION` 0.6 (defaults `false`
    /// for pre-0.6 rows via `migrate_db_v2`). A superseded op is deliberately
    /// KEPT (not removed) so that, since the old and replacement ops are
    /// mutually exclusive on-chain (the `EntryPoint` includes at most one op
    /// per `(sender, nonce)`), a LATE confirmation of the old op still passes
    /// the `UserOpConfirmed` existence check and settles exactly once -- the
    /// RBF-nonce safety invariant. It is excluded from further timeout/replace
    /// (`Usdt::propose_replace_user_ops`) but STILL counts as in-flight for
    /// the batch/sweep guards (its purpose is unchanged), so a new batch/sweep
    /// is never built at a nonce whose replacement chain is still live. The
    /// whole chain for a `(sender, nonce)` is removed together the moment any
    /// member confirms (`Usdt::purge_user_op_nonce_chain`).
    pub superseded: bool,
}

#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct SubmittedUserOpKey(pub [u8; 32]);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SubmittedUserOpPrefix;

impl_db_record!(
    key = SubmittedUserOpKey,
    value = SubmittedUserOp,
    db_prefix = DbKeyPrefix::SubmittedUserOp,
);
impl_db_lookup!(
    key = SubmittedUserOpKey,
    query_prefix = SubmittedUserOpPrefix
);

/// The consensus-agreed pool `SimpleAccount`'s derived address, the USDT
/// balance swept into it so far (Phase 7, Task 5), and its `EntryPoint`
/// nonce (Phase 8, Task 2). A module-wide singleton (queried directly via
/// [`PoolStateKey`], mirroring e.g. `walletv2`'s `FederationWalletKey`)
/// rather than per-account: there is only ever one pool account per
/// federation.
///
/// `nonce` starts at `0`, meaning the pool `SimpleAccount` has never
/// submitted a `UserOp` of its own (Phase 7's sweeps are `UserOp`s FROM the
/// deposit account TO the pool, not from the pool itself -- the pool only
/// ever RECEIVES a plain ERC-20 `transfer`, which needs no code/nonce at
/// all, so a fresh federation's pool can sit un-deployed on-chain
/// indefinitely). It is incremented by exactly `1` for every withdrawal
/// batch `UserOp` the `EntryPoint` actually validates and includes --
/// `Usdt::apply_user_op_confirmed`'s `Withdraw` branch bumps it whenever a
/// `UserOpConfirmed` observation for a `Withdraw`-purpose op reaches
/// threshold, REGARDLESS of `success` (a reverted `callData` execution still
/// consumes the on-chain `EntryPoint` nonce; only validation/inclusion
/// failing means no `UserOperationEvent` -- and hence no `UserOpConfirmed`
/// observation at all -- is ever produced for that attempt). `nonce == 0` is
/// therefore exactly the condition under which the pool's `initCode` must be
/// populated (`needs_deploy`) the next time a withdrawal batch is built.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub struct PoolState {
    pub account: EvmAddress,
    pub balance: UsdtAmount,
    pub nonce: u64,
}

#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct PoolStateKey;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PoolStatePrefix;

impl_db_record!(
    key = PoolStateKey,
    value = PoolState,
    db_prefix = DbKeyPrefix::PoolState,
);
impl_db_lookup!(key = PoolStateKey, query_prefix = PoolStatePrefix);

/// One peer's vote on the observed on-chain outcome of a submitted `UserOp`
/// (Phase 7, Task 5). Mirrors [`DepositObservation`]'s role in
/// [`DepositObservationVoteKey`] exactly: `success`/`block`/`swept` are all
/// carried in the vote itself (not re-derived from any guardian-local
/// state), and this type's full-field `#[derive(PartialEq)]` is what lets
/// `Usdt::process_consensus_item`'s `UserOpConfirmed` arm tally only
/// EXACTLY-matching votes toward the threshold (divergent `block`/`swept`
/// values from a byzantine or lagging guardian cannot inflate the count).
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub struct UserOpConfirmedObservation {
    pub success: bool,
    pub block: u64,
    /// The canonical hash of `block` (security findings 04/15), carried in
    /// the vote so the full-field `#[derive(PartialEq)]` tally binds each
    /// vote to a specific fork: two guardians observing the same op on
    /// different forks at the same height produce non-equal observations that
    /// never aggregate toward threshold.
    pub block_hash: [u8; 32],
    pub swept: UsdtAmount,
}

/// A single peer's vote on `UserOp` `[u8; 32]`'s (its `op_hash`) on-chain
/// outcome. The `[u8; 32]` field is ordered first so that
/// [`UserOpConfirmedVoteOpPrefix`] can look up every peer's vote for one
/// `op_hash`, mirroring [`DepositObservationVoteKey`]'s dual-prefix shape.
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct UserOpConfirmedVoteKey(pub [u8; 32], pub PeerId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct UserOpConfirmedVotePrefix;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct UserOpConfirmedVoteOpPrefix(pub [u8; 32]);

impl_db_record!(
    key = UserOpConfirmedVoteKey,
    value = UserOpConfirmedObservation,
    db_prefix = DbKeyPrefix::UserOpConfirmedVote,
);
impl_db_lookup!(
    key = UserOpConfirmedVoteKey,
    query_prefix = UserOpConfirmedVotePrefix,
    query_prefix = UserOpConfirmedVoteOpPrefix,
);

/// A withdrawal output's queued payout details (Phase 8, Task 1), keyed by
/// the `OutPoint` of the `UsdtOutput::V0` that enqueued it (see
/// [`UnclaimedWithdrawalKey`]). Written once, atomically, alongside
/// [`WithdrawalStateKey`]`(out_point) = WithdrawalState::Queued` by
/// `Usdt::process_output`; removed once Task 2's batching logic confirms the
/// withdrawal (its `WithdrawalState` becomes terminal).
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub struct UsdtWithdrawalV0 {
    pub recipient: EvmAddress,
    pub amount: UsdtAmount,
    pub max_fee: UsdtAmount,
    /// The consensus block count (`Usdt::consensus_block_count`) as of this
    /// withdrawal's enqueueing -- diagnostic bookkeeping only (mirrors
    /// [`PendingUserOp::created_block`](crate::db::PendingUserOp)), no
    /// consensus decision reads it today.
    pub requested_block: u64,
}

#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct UnclaimedWithdrawalKey(pub OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnclaimedWithdrawalPrefix;

impl_db_record!(
    key = UnclaimedWithdrawalKey,
    value = UsdtWithdrawalV0,
    db_prefix = DbKeyPrefix::UnclaimedWithdrawal,
);
impl_db_lookup!(
    key = UnclaimedWithdrawalKey,
    query_prefix = UnclaimedWithdrawalPrefix
);

/// The consensus-agreed lifecycle stage of a queued withdrawal (Phase 8,
/// Task 1's `Queued`; Task 2 adds the `UserOp`-signing/submission
/// transitions).
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Serialize)]
pub enum WithdrawalState {
    /// Enqueued by `Usdt::process_output`, awaiting Task 2's batching logic
    /// to include it in a withdrawal `UserOp`.
    Queued,
    /// Included in a withdrawal `UserOp` (identified by its `op_hash`, the
    /// same key as the [`PendingUserOp`] it was enqueued alongside) whose
    /// federation MPC signing session is in progress (Task 2).
    Signing([u8; 32]),
    /// The withdrawal's `UserOp` has been federation-agreed-signed
    /// (identified by its `op_hash`) and is awaiting/undergoing guardian-
    /// local on-chain submission and confirmation (Task 2).
    Submitted([u8; 32]),
    /// The withdrawal's `UserOp` confirmed on-chain successfully at `block`
    /// (Task 2); terminal.
    Confirmed { block: u64 },
    /// The withdrawal's `UserOp` failed on-chain, or could not be
    /// completed, for `reason` (Task 2/3); terminal.
    Failed { reason: String },
}

#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct WithdrawalStateKey(pub OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct WithdrawalStatePrefix;

impl_db_record!(
    key = WithdrawalStateKey,
    value = WithdrawalState,
    db_prefix = DbKeyPrefix::WithdrawalState,
);
impl_db_lookup!(
    key = WithdrawalStateKey,
    query_prefix = WithdrawalStatePrefix
);

/// One peer's most recent readiness vote (Part C), mirroring [`FeeVoteKey`]
/// exactly: `process_consensus_item` overwrites this peer's entry on each new
/// vote, and `Usdt::bootstrap_state` range-scans every peer's entry (via
/// [`BootstrapVotePrefix`]) to tally the per-field threshold counts.
#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct BootstrapVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BootstrapVotePrefix;

impl_db_record!(
    key = BootstrapVoteKey,
    value = BootstrapObservation,
    db_prefix = DbKeyPrefix::BootstrapVote,
);
impl_db_lookup!(key = BootstrapVoteKey, query_prefix = BootstrapVotePrefix);

/// Module-wide singleton latch (Part C): present once the readiness tally has
/// reached `Ready` at least once. A unit-keyed, unit-valued singleton
/// (mirroring `fedimint-mint-server`'s `NonceKey`-style `value = ()` records),
/// queried directly via this key. Its presence is what lets
/// `Usdt::bootstrap_state` report `Degraded` (was `Ready`, now regressed)
/// distinctly from `AwaitingInfra` (never `Ready`).
#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct HasEverBeenReadyKey;

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct HasEverBeenReadyPrefix;

impl_db_record!(
    key = HasEverBeenReadyKey,
    value = (),
    db_prefix = DbKeyPrefix::HasEverBeenReady,
);
impl_db_lookup!(
    key = HasEverBeenReadyKey,
    query_prefix = HasEverBeenReadyPrefix
);

/// The maximum batch size the withdrawal at `OutPoint` may next be included
/// in (security finding 05, poisoned-batch isolation task). Absent is
/// equivalent to [`crate::BATCH_MAX_ITEMS`] (`Usdt`'s
/// `withdrawal_batch_cap` helper applies that default).
///
/// # Lifecycle
///
/// - Written by `Usdt::apply_withdraw_confirmed`'s `!obs.success` branch, ONLY
///   when the failed batch covered more than one withdrawal: every covered
///   outpoint's cap is set to `max(1, n / 2)` (`n` = the failed batch's size),
///   so the NEXT batch containing this withdrawal is at most half as large --
///   see `Usdt::maybe_trigger_withdrawal_batch`'s `effective_cap` computation,
///   which reads this record for every candidate in its sorted window.
/// - Removed once the withdrawal reaches a terminal state: `Confirmed` (the
///   success path) or `Failed` (a failed SINGLETON batch, i.e. `n == 1` -- the
///   isolated poison). Housekeeping only; a stray leftover entry for an
///   already-terminal withdrawal is harmless (never read again, since
///   `maybe_trigger_withdrawal_batch` only ever considers `Queued`
///   withdrawals), but removing it keeps the table from growing unbounded.
///
/// # Determinism
///
/// A brand-new prefix holding only new `u32` data -- no existing stored
/// value's shape changed, so this needed no `DatabaseVersion` migration (see
/// `Usdt::get_database_migrations`'s doc comment), only a
/// `MODULE_CONSENSUS_VERSION` bump (a new consensus-serialized DB record) and
/// `dump_database` coverage.
#[derive(Clone, Debug, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct WithdrawalBatchCapKey(pub OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct WithdrawalBatchCapPrefix;

impl_db_record!(
    key = WithdrawalBatchCapKey,
    value = u32,
    db_prefix = DbKeyPrefix::WithdrawalBatchCap,
);
impl_db_lookup!(
    key = WithdrawalBatchCapKey,
    query_prefix = WithdrawalBatchCapPrefix
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
            swept: UsdtAmount(0),
            nonce: 0,
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
            block_hash: [0u8; 32],
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
            purpose: SigningPurpose::UserOp([2; 32]),
            digest: [1; 32],
            signers: vec![PeerId::from(0), PeerId::from(1), PeerId::from(2)],
            round: 0,
            state: SessionState::InProgress,
            attempt: 0,
            last_progress_block: 7,
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

        // The whole-session prefix (all rounds, all peers) sees all 4 chunks
        // inserted above -- this is what GC on rotate/complete sweeps in one
        // shot.
        let all_session_chunks: Vec<_> = dbtx
            .find_by_prefix(&MpcRoundChunkSessionPrefix(id))
            .await
            .collect()
            .await;
        assert_eq!(all_session_chunks.len(), 4);
        assert!(all_session_chunks.iter().all(|(key, _)| key.0 == id));
    }

    fn sample_unsigned_user_op() -> UnsignedUserOp {
        UnsignedUserOp {
            sender: EvmAddress([0x21; 20]),
            nonce: alloy::primitives::U256::ZERO,
            init_code: vec![0xde, 0xad],
            call_data: vec![0xbe, 0xef],
            verification_gas_limit: 500_000,
            call_gas_limit: 200_000,
            pre_verification_gas: alloy::primitives::U256::from(100_000u64),
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 30_000_000_000,
            paymaster_and_data: vec![],
        }
    }

    #[tokio::test]
    async fn pending_user_op_round_trips() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let op_hash = [0x41; 32];
        let source = EvmAddress([0x51; 20]);
        let pending = PendingUserOp {
            op: sample_unsigned_user_op(),
            purpose: UserOpPurpose::DeployAndSweep { source },
            created_block: 42,
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&PendingUserOpKey(op_hash), &pending)
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            dbtx.get_value(&PendingUserOpKey(op_hash)).await,
            Some(pending)
        );
        assert_eq!(
            dbtx.find_by_prefix(&PendingUserOpPrefix)
                .await
                .count()
                .await,
            1
        );
    }

    #[tokio::test]
    async fn withdraw_purpose_pending_and_submitted_user_op_round_trip() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let op_hash = [0x43; 32];
        let outpoints = vec![test_out_point(0), test_out_point(1), test_out_point(2)];
        let purpose = UserOpPurpose::Withdraw {
            outpoints: outpoints.clone(),
        };

        let pending = PendingUserOp {
            op: sample_unsigned_user_op(),
            purpose: purpose.clone(),
            created_block: 7,
        };
        let submitted = SubmittedUserOp {
            signed: SignedUserOp {
                unsigned: sample_unsigned_user_op(),
                signature: vec![0xcc; 65],
            },
            purpose: purpose.clone(),
            submitted_block: 8,
            superseded: false,
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&PendingUserOpKey(op_hash), &pending)
            .await;
        dbtx.insert_new_entry(&SubmittedUserOpKey(op_hash), &submitted)
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        let fetched_pending = dbtx
            .get_value(&PendingUserOpKey(op_hash))
            .await
            .expect("PendingUserOp must round-trip");
        assert_eq!(fetched_pending.purpose, purpose);
        let fetched_submitted = dbtx
            .get_value(&SubmittedUserOpKey(op_hash))
            .await
            .expect("SubmittedUserOp must round-trip");
        assert_eq!(fetched_submitted.purpose, purpose);
        assert_eq!(
            fetched_submitted.purpose,
            UserOpPurpose::Withdraw { outpoints }
        );
    }

    #[tokio::test]
    async fn submitted_user_op_round_trips() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let op_hash = [0x42; 32];
        let submitted = SubmittedUserOp {
            signed: SignedUserOp {
                unsigned: sample_unsigned_user_op(),
                signature: vec![0xaa; 65],
            },
            purpose: UserOpPurpose::DeployAndSweep {
                source: EvmAddress([0x51; 20]),
            },
            submitted_block: 43,
            superseded: false,
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&SubmittedUserOpKey(op_hash), &submitted)
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            dbtx.get_value(&SubmittedUserOpKey(op_hash)).await,
            Some(submitted)
        );
    }

    #[tokio::test]
    async fn pool_state_round_trips_as_a_singleton() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let state = PoolState {
            account: EvmAddress([0x61; 20]),
            balance: UsdtAmount(9_000_000),
            nonce: 3,
        };

        let mut dbtx = db.begin_transaction().await;
        assert!(
            dbtx.get_value(&PoolStateKey).await.is_none(),
            "no PoolState until first written"
        );
        dbtx.insert_new_entry(&PoolStateKey, &state).await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(dbtx.get_value(&PoolStateKey).await, Some(state.clone()));
        // Exactly one record under the singleton's own prefix.
        assert_eq!(dbtx.find_by_prefix(&PoolStatePrefix).await.count().await, 1);
    }

    #[tokio::test]
    async fn user_op_confirmed_vote_round_trips_and_filters_by_op_hash_prefix() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let op_a = [0x71; 32];
        let op_b = [0x72; 32];

        let vote = |block: u64| UserOpConfirmedObservation {
            success: true,
            block,
            block_hash: [0u8; 32],
            swept: UsdtAmount(2_000_000),
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&UserOpConfirmedVoteKey(op_a, PeerId::from(0)), &vote(10))
            .await;
        dbtx.insert_new_entry(&UserOpConfirmedVoteKey(op_a, PeerId::from(1)), &vote(10))
            .await;
        dbtx.insert_new_entry(&UserOpConfirmedVoteKey(op_b, PeerId::from(0)), &vote(11))
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            dbtx.get_value(&UserOpConfirmedVoteKey(op_a, PeerId::from(0)))
                .await,
            Some(vote(10))
        );

        let op_a_votes: Vec<_> = dbtx
            .find_by_prefix(&UserOpConfirmedVoteOpPrefix(op_a))
            .await
            .collect()
            .await;
        assert_eq!(op_a_votes.len(), 2);
        assert!(op_a_votes.iter().all(|(key, _)| key.0 == op_a));
    }

    #[tokio::test]
    async fn fee_vote_round_trips() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let stored = StoredFeeVote {
            vote: fedimint_usdt_common::FeeVote {
                max_fee_per_gas_wei: 30_000_000_000,
                usdt_per_eth_e6: 3_000_000_000,
            },
            recorded_block: 42,
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&FeeVoteKey(PeerId::from(1)), &stored)
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            dbtx.get_value(&FeeVoteKey(PeerId::from(1))).await,
            Some(stored)
        );
        assert_eq!(dbtx.find_by_prefix(&FeeVotePrefix).await.count().await, 1);
    }

    fn test_out_point(idx: u64) -> OutPoint {
        use fedimint_core::BitcoinHash as _;
        OutPoint {
            txid: fedimint_core::TransactionId::all_zeros(),
            out_idx: idx,
        }
    }

    #[tokio::test]
    async fn unclaimed_withdrawal_round_trips() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let out_point = test_out_point(0);
        let withdrawal = UsdtWithdrawalV0 {
            recipient: EvmAddress([0x33; 20]),
            amount: UsdtAmount(5_000_000),
            max_fee: UsdtAmount(20_000),
            requested_block: 12,
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&UnclaimedWithdrawalKey(out_point), &withdrawal)
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            dbtx.get_value(&UnclaimedWithdrawalKey(out_point)).await,
            Some(withdrawal)
        );
        assert_eq!(
            dbtx.find_by_prefix(&UnclaimedWithdrawalPrefix)
                .await
                .count()
                .await,
            1
        );
    }

    #[tokio::test]
    async fn bootstrap_vote_round_trips_and_filters_by_prefix() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        let obs = |funded: bool| BootstrapObservation {
            entry_point_ok: true,
            factory_ok: true,
            impl_ok: true,
            broadcaster_funded: funded,
            rpc_healthy: true,
        };

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(&BootstrapVoteKey(PeerId::from(0)), &obs(true))
            .await;
        dbtx.insert_new_entry(&BootstrapVoteKey(PeerId::from(1)), &obs(false))
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            dbtx.get_value(&BootstrapVoteKey(PeerId::from(0))).await,
            Some(obs(true))
        );
        assert_eq!(
            dbtx.find_by_prefix(&BootstrapVotePrefix)
                .await
                .count()
                .await,
            2
        );
    }

    #[tokio::test]
    async fn has_ever_been_ready_round_trips_as_a_singleton() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

        let mut dbtx = db.begin_transaction().await;
        assert!(
            dbtx.get_value(&HasEverBeenReadyKey).await.is_none(),
            "latch absent until first set"
        );
        dbtx.insert_new_entry(&HasEverBeenReadyKey, &()).await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(dbtx.get_value(&HasEverBeenReadyKey).await, Some(()));
        assert_eq!(
            dbtx.find_by_prefix(&HasEverBeenReadyPrefix)
                .await
                .count()
                .await,
            1
        );
    }

    #[tokio::test]
    async fn withdrawal_state_round_trips_every_variant() {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

        let states = [
            WithdrawalState::Queued,
            WithdrawalState::Signing([1; 32]),
            WithdrawalState::Submitted([2; 32]),
            WithdrawalState::Confirmed { block: 99 },
            WithdrawalState::Failed {
                reason: "gas spike".to_string(),
            },
        ];

        let mut dbtx = db.begin_transaction().await;
        for (i, state) in states.iter().enumerate() {
            dbtx.insert_new_entry(&WithdrawalStateKey(test_out_point(i as u64)), state)
                .await;
        }
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        for (i, state) in states.iter().enumerate() {
            assert_eq!(
                dbtx.get_value(&WithdrawalStateKey(test_out_point(i as u64)))
                    .await
                    .as_ref(),
                Some(state)
            );
        }
    }
}
