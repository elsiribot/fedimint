/// Returns the federation's aggregate (group) threshold-ECDSA public key,
/// proving that DKG-produced config has been loaded and is queryable.
pub const GROUP_PUBLIC_KEY_ENDPOINT: &str = "group_public_key";

/// Enqueues this guardian's local deposit-checker task to start watching the
/// deposit address derived for a given claim key, returning that address.
pub const CHECK_DEPOSIT_ENDPOINT: &str = "check_deposit";

/// Reports the credited/claimed/claimable state of a claim key's deposit
/// account.
pub const DEPOSIT_STATUS_ENDPOINT: &str = "deposit_status";

/// Test-only (Phase 6a acceptance): pushes a digest into this guardian's
/// in-memory `pending_signing_starts` queue, to be proposed as a
/// `UsdtConsensusItem::StartSigning` consensus item on the guardian's next
/// `consensus_proposal`. Starting a signing session must go through
/// consensus (rather than being triggered on each guardian independently) so
/// every guardian starts it atomically in the same consensus order; calling
/// this on a single guardian is enough to reach every guardian via the
/// resulting consensus item. Phase-6a scaffolding: intentionally not
/// access-gated (the usdt module is experimental and opt-in via
/// `FM_ENABLE_MODULE_USDT`); Phase 7 replaces it with deterministic session
/// creation from pending sign-request records and removes this endpoint.
pub const DEBUG_START_SIGNING_ENDPOINT: &str = "debug_start_signing";

/// Reports the federation-agreed outcome of a threshold-ECDSA signing
/// session: `Some(compact 64-byte signature)` once a guardian's
/// `UsdtConsensusItem::MpcSignature` proposal has been verified and written
/// to the consensus `SigningSession.state` as `Completed` (Phase 6b), `None`
/// while the session is still in progress. Read from the consensus DB, so
/// ANY guardian — not just a signer — can answer, and every honest
/// guardian's answer is identical once the session has completed.
pub const SIGNING_SESSION_STATUS_ENDPOINT: &str = "signing_session_status";

/// Test-only (Phase 6b Task 4 degraded-federation acceptance harness):
/// toggles this guardian's LOCAL suppression of `MpcRound` proposals for
/// attempt-0 signing sessions. `fedimint-testing`'s degraded-federation
/// fixture always brings down the highest-numbered peer(s), which can never
/// be a member of the FIXED lowest-`t` attempt-0 signer subset, so it cannot
/// be used to make attempt 0 stall; this endpoint gives a test a way to force
/// exactly that (one signer in attempt 0's subset never contributes its
/// round payload, so the round can never reach 3-of-3 and the session times
/// out) without touching any production consensus-decision logic. Purely
/// guardian-local (an in-memory flag, never consensus state) and scoped to
/// attempt 0 only, so a rotated later attempt is unaffected. Not
/// access-gated, for the same reason as `DEBUG_START_SIGNING_ENDPOINT`.
pub const DEBUG_SUPPRESS_ATTEMPT0_ROUND_ENDPOINT: &str = "debug_suppress_attempt0_round";

/// Reports the consensus-agreed pool `SimpleAccount`'s derived address and
/// swept-in USDT balance (Phase 7, Task 5's `PoolState`). Read from
/// consensus DB, so any guardian answers identically.
pub const POOL_STATE_ENDPOINT: &str = "pool_state";

/// Reports the consensus-agreed lifecycle stage (`Pending`/`Submitted`/
/// `Unknown`) of a `UserOp`, identified by its `user_op_hash` (Phase 7, Task
/// 5). Read from consensus DB, so any guardian answers identically.
pub const USEROP_STATUS_ENDPOINT: &str = "userop_status";

/// Reports the current withdrawal fee quote (Phase 8, Task 1): the minimum
/// `max_fee` a `UsdtOutput::V0` must offer, derived from the federation's
/// consensus-agreed `FeeVote` median (see
/// `fedimint_usdt_common::withdrawal_fee_quote`). Read from consensus DB, so
/// any guardian answers identically (threshold-agreement, not just a
/// single-guardian estimate).
pub const WITHDRAW_FEE_QUOTE_ENDPOINT: &str = "withdraw_fee_quote";

/// Reports the consensus-agreed lifecycle stage (`Queued`/`Signing`/
/// `Submitted`/`Confirmed`/`Failed`/`Unknown`) of a queued withdrawal,
/// identified by the `OutPoint` of the `UsdtOutput::V0` that enqueued it
/// (Phase 8, Task 3). Read from consensus DB, so any guardian answers
/// identically (threshold-agreement via `request_current_consensus`,
/// mirroring [`DEPOSIT_STATUS_ENDPOINT`]/[`WITHDRAW_FEE_QUOTE_ENDPOINT`]).
pub const WITHDRAWAL_STATUS_ENDPOINT: &str = "withdrawal_status";

/// Reports the module's consensus-agreed readiness state (Part C):
/// `AwaitingInfra`/`Ready`/`Degraded`, plus the per-condition tally it was
/// derived from. Read from the threshold-aggregated `BootstrapObservation`
/// votes in consensus DB, so any guardian answers identically
/// (threshold-agreement via `request_current_consensus`, mirroring
/// [`POOL_STATE_ENDPOINT`]/[`DEPOSIT_STATUS_ENDPOINT`]). The client gates
/// deposit-address handout on this reporting `Ready`.
pub const USDT_STATUS_ENDPOINT: &str = "usdt_status";
