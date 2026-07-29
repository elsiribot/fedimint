/// Returns the federation's aggregate (group) threshold-ECDSA public key,
/// proving that DKG-produced config has been loaded and is queryable.
pub const GROUP_PUBLIC_KEY_ENDPOINT: &str = "group_public_key";

/// Reports the credited/claimed/claimable state of a claim key's deposit
/// account.
pub const DEPOSIT_STATUS_ENDPOINT: &str = "deposit_status";

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

/// Reports the current deposit fee quote: the minimum `fee` a
/// `UsdtInput::V0` claiming a credited deposit must offer, derived from the
/// federation's consensus-agreed `FeeVote` median (see
/// `fedimint_usdt_common::deposit_fee_quote`). Read from consensus DB, so
/// any guardian answers identically (threshold-agreement, not just a
/// single-guardian estimate), mirroring [`WITHDRAW_FEE_QUOTE_ENDPOINT`].
pub const DEPOSIT_FEE_QUOTE_ENDPOINT: &str = "deposit_fee_quote";

/// Reports the consensus-agreed lifecycle stage (`Queued`/`Signing`/
/// `Submitted`/`Confirmed`/`Failed`/`Unknown`) of a queued withdrawal,
/// identified by the `OutPoint` of the `UsdtOutput::V0` that enqueued it
/// (Phase 8, Task 3). Read from consensus DB, so any guardian answers
/// identically (threshold-agreement via `request_current_consensus`,
/// mirroring [`DEPOSIT_STATUS_ENDPOINT`]/[`WITHDRAW_FEE_QUOTE_ENDPOINT`]).
pub const WITHDRAWAL_STATUS_ENDPOINT: &str = "withdrawal_status";

/// Reports the live refund record of a terminally-failed withdrawal
/// (security finding 09): `(amount, reason)` for the reissued e-cash a
/// `UsdtInput::RefundV0` can claim, or `None` if none exists (never failed,
/// or already claimed), identified by the `OutPoint` of the `UsdtOutput::V0`
/// that enqueued it. Read from consensus DB, so any guardian answers
/// identically (threshold-agreement via `request_current_consensus`,
/// mirroring [`WITHDRAWAL_STATUS_ENDPOINT`]).
pub const REFUND_STATUS_ENDPOINT: &str = "refund_status";

/// Reports the module's consensus-agreed readiness state (Part C):
/// `AwaitingInfra`/`Ready`/`Degraded`, plus the per-condition tally it was
/// derived from. Read from the threshold-aggregated `BootstrapObservation`
/// votes in consensus DB, so any guardian answers identically
/// (threshold-agreement via `request_current_consensus`, mirroring
/// [`POOL_STATE_ENDPOINT`]/[`DEPOSIT_STATUS_ENDPOINT`]). The client gates
/// deposit-address handout on this reporting `Ready`.
pub const USDT_STATUS_ENDPOINT: &str = "usdt_status";

/// Reports the newest height currently anchored in the consensus-agreed
/// canonical block-hash ring (`BlockHashRingKey`, written by
/// `write_block_hash_ring`), plus the ring's retained window length
/// (`BLOCK_HASH_RING_LEN`). A deposit-by-proof client uses this to pick a
/// block to target its inclusion proof against: a proof for a height with no
/// ring entry (too new, or already pruned out of the window) is rejected as
/// not-yet-anchored. Read from consensus DB, so any guardian answers
/// identically, mirroring [`USDT_STATUS_ENDPOINT`]/[`POOL_STATE_ENDPOINT`].
pub const LATEST_ANCHORED_BLOCK_ENDPOINT: &str = "latest_anchored_block";
