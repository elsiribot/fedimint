# USDT Guardian Fee Withdrawal — Design

**Date:** 2026-08-04
**Module:** `fedimint-usdt-*`
**Status:** Approved design; implementation plan to follow.

## Problem

Guardians earn USDT fees on every deposit and withdrawal, but they front the
ETH gas for on-chain UserOps out of their **own** per-guardian broadcaster EOAs
(`broadcaster_private_key`, non-deterministic guardian-local config). There is
today **no path** for guardians to extract the accrued USDT fee revenue. It
accumulates permanently in the pool `SimpleAccount`'s on-chain USDT balance with
no exit door, so guardians cannot recoup the ETH gas they spend and cannot
replenish their gas budgets from fee income.

All ten existing USDT API endpoints are read-only diagnostics; no consensus item
or admin call moves fee value out.

## Goal

Give guardians a threshold-authorized way to withdraw accrued USDT fees from the
pool account to an EVM address of their choosing. Guardians handle any USDT→ETH
conversion and broadcaster reimbursement themselves off-band ("let the guardians
figure it out"). This design deliberately does **not** build automatic
USDT→ETH conversion or gas-pool top-up.

## Non-goals

- Automatic swapping of USDT fees to ETH.
- Automatic reimbursement of broadcaster EOAs.
- Any change to how fees are quoted or charged.
- Retroactive recovery of fees accrued before the upgrade (see Migration).

## Accounting model (the safety core)

The pool's on-chain USDT surplus is exactly the sum of all fees ever charged:

```
pool.balance − outstanding_ecash_liability
  = Σ(deposit_fee) + Σ(withdrawal_max_fee)
  = accrued fee surplus
```

Derivation: every deposit sweeps its **full** amount into `pool.balance`
(`claimed` advances by the full `input.amount`, so the deposit fee's USDT is
swept in as un-issued surplus), while the client only receives `amount − fee` of
e-cash. Every withdrawal burns `amount + max_fee` of e-cash but debits
`pool.balance` by only `amount`, leaving `max_fee` as surplus. The surplus is
**physically present** in the pool `SimpleAccount` as USDT, so it is directly
withdrawable via a pool UserOp.

### Tracking

Add a field to `PoolState` (`modules/fedimint-usdt-server/src/db.rs`):

```rust
pub struct PoolState {
    pub account: EvmAddress,
    pub balance: UsdtAmount,
    pub nonce: u64,
    pub accrued_fees: UsdtAmount,   // NEW
}
```

`accrued_fees` is incremented **only in deterministic consensus apply paths, at
the point where the fee's USDT is physically in the pool**, to preserve the
invariant `accrued_fees ≤ pool.balance`:

- **Deposit fee** — the deposit fee is charged in `process_input`
  (server lib.rs ~2334–2371) where `input.fee` is directly known, but its USDT
  is not yet in the pool at that moment (the sweep is still pending). So the fee
  is **accumulated onto the deposit record** in `process_input` (a new
  `fees_accrued: UsdtAmount` field on `DepositRecord`, incremented by
  `input.fee`) and **credited to `accrued_fees` only when that account's
  `DeployAndSweep` confirms** and credits `pool.balance`
  (`apply_user_op_confirmed`, DeployAndSweep success arm, server lib.rs
  ~5127–5143): `accrued_fees += record.fees_accrued`. This guarantees a deposit
  fee is counted only once its USDT has physically landed in the pool.
- **Withdrawal fee** — incremented at withdrawal **confirm**
  (`apply_withdraw_confirmed`), because how much fee is actually retained is only
  known at the terminal on-chain outcome, and it must match the existing `audit`
  accounting (`lib.rs:2525`, which already treats a successful withdrawal's
  `max_fee` as retained federation revenue):
  - **success** → `pool.accrued_fees += Σ max_fee` (read each `max_fee` from the
    `UnclaimedWithdrawal` record before it is removed);
  - **terminal failure (refund, batch size ≤ 1)** → `pool.accrued_fees +=
    incurred` (the actual gas charged, clamped to `amount + max_fee`); the rest
    of `max_fee` is refunded to the user, so only `incurred` is real revenue.
    Done inside `create_withdrawal_refund`, past its already-refunded guard, so
    it never double-counts;
  - **non-terminal failure (re-queue, batch size > 1)** → add nothing; the
    withdrawal is still live and no fee is realized yet.

All increment sites are inside consensus apply paths, so the counter is
identical across all honest guardians.

### Trigger-time physical guard

Because a fee's USDT can be briefly *in transit* (charged but its backing sweep
not yet landed), the trigger requires **both** `amount ≤ accrued_fees`
(economic: only realized fee revenue) **and** `amount ≤ pool.balance` (physical:
the pool actually holds the USDT to send). The second guard makes a fee-payout
UserOp that would revert on-chain for insufficient pool USDT simply wait a round
instead. Combined with the pool-op serialization below (a fee sweep never fires
while a user `Withdraw` is in flight), this keeps the payout safe under all
in-flight orderings.

`accrued_fees` is **decremented** by the sent amount when a fee-withdrawal
UserOp confirms (see flow below).

### Invariant

At all times `accrued_fees ≤ pool.balance`. A fee withdrawal may request at most
`accrued_fees`, so it can never dip into the USDT that backs outstanding e-cash.
The tally gate re-checks `amount ≤ accrued_fees` at trigger time, and the
threshold-ECDSA-signed UserOp transfers at most that amount out of the pool.

### Migration

Adding a field to `PoolState` and to `DepositRecord` changes their `Decodable`
shape, so — as with the existing `migrate_fee_vote` (server lib.rs ~1165) —
each needs a DB migration function, registered in the module's migration map and
bumping the DB version:

- **`PoolState`** is a singleton: the migration reads the old three-field record
  and rewrites it with `accrued_fees = UsdtAmount(0)`. Trivial (one record).
- **`DepositRecord`**: the migration rewrites each existing record with
  `fees_accrued = UsdtAmount(0)`. Mechanical prefix iteration.

Consequence: fees accrued **before** the upgrade are not retroactively
withdrawable — only fees charged after the upgrade accumulate into the counter.
This is acceptable (test federations, small values) and avoids a fragile
back-computation of historical surplus.

## Flow: vote → threshold → UserOp

This mirrors the existing `RecoverResidual` machinery one-to-one, with one
addition (an authenticated entry point, because a fee sweep is a deliberate
guardian action, not an automatic observer).

### 1. Guardian casts a vote (new authenticated endpoint)

New `ApiAuth`-guarded admin endpoint `withdraw_fees { recipient, amount }`
(`WITHDRAW_FEES_ENDPOINT`). It authenticates the caller as a specific guardian
and stores that guardian's intent in a guardian-local in-memory slot
(`Arc<Mutex<Option<{recipient, amount}>>>`, mirroring the existing
`fee_estimate` / `residual_recovery_proposals` state). Unlike `RecoverResidual`
— which is driven by an automatic observer task and needs no human trigger — a
fee withdrawal is a deliberate decision, so casting the vote **must** be
authenticated as that guardian. (Intent held only in memory means a guardian who
restarts before their vote is proposed simply re-casts; no value is at risk.)

Validation at the endpoint: reject a zero/placeholder `recipient` on non-dev
chains (reuse the `validate_usdt_params` `ensure!(field != placeholder, …)`
pattern, common lib.rs ~1455–1482); reject `amount == 0`.

### 2. Proposal

`consensus_proposal` (server lib.rs ~1698–1714, alongside the `RecoverResidual`
and `FeeVote` proposal blocks) emits the guardian's pending intent as
`UsdtConsensusItem::WithdrawFeesVote { recipient, amount }`, using the same
equality-based dedup: only propose when the guardian's own stored vote differs
from its current intent.

### 3. Apply

`process_consensus_item` (server lib.rs ~2205–2246, new arm) validates and
stores the vote per-peer under `WithdrawFeesVoteKey(peer_id)` (framework-supplied
`peer_id`, **not** `self.our_peer_id`), with an equality-based redundancy guard,
then calls `maybe_trigger_fee_withdrawal`.

### 4. Threshold gate → build UserOp

`maybe_trigger_fee_withdrawal`:

- Early-return guards (mirror `maybe_trigger_residual_recovery` ~4530–4581):
  a pool op already in flight (see Serialization), or no votes.
- Collect all peers' votes. Group by the exact `(recipient, amount)` pair.
- If some pair has `≥ self.num_peers.threshold()` (2f+1) agreeing votes **and**
  `amount ≤ pool.accrued_fees` **and** `amount ≤ pool.balance` → proceed;
  otherwise return.
- Build `UserOpPurpose::WithdrawFees { recipient, amount }` (new, appended last
  in the `UserOpPurpose` enum, db.rs ~404–428, to preserve wire tags). The
  UserOp is a single ERC-20 `transfer(recipient, amount)` from the pool
  `SimpleAccount` (a new `build_withdraw_fees_userop` in
  `fedimint-usdt-server/src/user_op.rs`, modeled on the batched-withdraw
  builder), using `PoolState.nonce`.
- Idempotency guard on `op_hash` (skip if already Pending/Submitted), insert
  `PendingUserOp`, `start_session` for threshold-ECDSA signing — identical to the
  residual path (~4626–4672).

### 5. Confirm

`apply_user_op_confirmed` (server lib.rs ~5122, new `WithdrawFees` arm):

- Bump `pool.nonce` unconditionally (mirrors `apply_withdraw_confirmed` ~5345).
- On success: `pool.balance -= amount` **and** `pool.accrued_fees -= amount`
  (both saturating).
- GC the votes (`remove_by_prefix` of the `WithdrawFeesVote` keyspace), so any
  subsequent sweep requires a fresh threshold — mirrors residual (~5207–5208).
- On revert: bump nonce, leave balances untouched, GC votes (a fresh vote can
  retry).

## Serialization with user withdrawals

The pool `SimpleAccount` has a **single shared nonce** (`PoolState.nonce`,
advanced only on confirm). A `WithdrawFees` op and a user `Withdraw` batch would
collide on that nonce if both were in flight. The existing guard
`withdraw_batch_in_flight` (server lib.rs ~4390–4427) currently blocks a new
batch only while a `UserOpPurpose::Withdraw` is Pending/Submitted.

Change: widen this guard (or introduce a shared `pool_op_in_flight` helper) to
treat **both** `Withdraw` and `WithdrawFees` as mutually exclusive — at most one
pool-account op of either purpose may be in flight. Both
`maybe_trigger_withdrawal_batch` and `maybe_trigger_fee_withdrawal` consult it.
Fee sweeps simply wait their turn behind user withdrawals (and vice-versa); the
threshold vote persists in the DB until a slot is free, so no vote is lost.

## Read surface

- Extend the existing `pool_state` endpoint response with the `accrued_fees`
  figure so guardians can see what is currently withdrawable.
- CLI: a command to cast a fee-withdrawal vote (calls the authenticated
  endpoint) and to read `accrued_fees` / current pool state.

## Config, validation, versioning

- **No new consensus-config field.** Recipient is per-request (in the vote), not
  fixed at DKG, so `UsdtConfigConsensus` is unchanged. (Contrast:
  `residual_recovery_recipient` is a config field because that flow is
  automatic.)
- **Recipient validation** happens at the endpoint and again structurally at the
  trigger (defense in depth): reject the zero/placeholder address on non-dev
  chains, allow it on dev chains (matching existing behavior).
- **`MODULE_CONSENSUS_VERSION`** bumps `0.11 → 0.12`
  (`fedimint-usdt-common/src/lib.rs:149`), with a new changelog paragraph above
  it noting: append-only `UserOpPurpose` variant, append-only
  `UsdtConsensusItem` variant, new `WithdrawFeesVote` keyspace, and the
  `PoolState.accrued_fees` / `DepositRecord.fees_accrued` field additions with
  their DB migrations (DB version bump).

## Trust / security notes

- The withdrawable pot is the **full** accrued surplus, including the portion
  that morally reimburses broadcasters' ETH gas. Guardians reconcile ETH
  reimbursement off-band. This is intentional.
- Value only moves on a 2f+1 threshold agreeing on the **exact** `(recipient,
  amount)` pair — a single malicious or compromised guardian cannot move funds,
  and cannot inflate the amount (unlike an auto-observer, there is no
  median-of-votes to skew; the pair must match exactly).
- The `amount ≤ accrued_fees` gate is enforced deterministically in consensus at
  trigger time, so the payout can never exceed real fee revenue even if guardians
  vote a larger number.
- The endpoint is `ApiAuth`-guarded, so only a guardian can register a vote for
  themselves.

## Testing

- **Accrued-fee counter:** deposit-fee increment on `DeployAndSweep` confirm;
  withdrawal-`max_fee` increment on output; decrement on `WithdrawFees` confirm;
  invariant `accrued_fees ≤ pool.balance` holds across a mixed sequence.
- **Threshold agreement:** votes on **mismatched** `(recipient, amount)` pairs do
  not tally; `threshold` identical votes do trigger; below-threshold does not.
- **Amount cap:** a vote with `amount > accrued_fees` does not trigger, even at
  threshold.
- **Serialization:** a fee sweep does not start while a user `Withdraw` is in
  flight, and vice-versa; the queued vote fires once the slot frees.
- **Confirm/revert:** success debits both `pool.balance` and `accrued_fees` and
  GCs votes; revert leaves balances intact, bumps nonce, GCs votes.
- **Validation:** zero recipient rejected on a non-dev chain, accepted on a dev
  chain.

## Decisions locked in

- **(a)** Vote is an **exact `(recipient, amount)` pair** (auditable; matches the
  per-request choice), not "sweep all accrued".
- **(b)** Withdrawable pot is the **full** fee surplus (deposit + withdrawal
  fees); broadcaster/ETH reconciliation is off-band.
- **(c)** Vote casting goes through a new **`ApiAuth` admin endpoint**, not an
  automatic trigger.
