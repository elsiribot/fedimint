# Phase 8 — Consolidation, withdrawal, fees (JIT plan)

Base: Phase-7 head (`66ee8b84b6a`, pending whole-branch review). Master plan §Phase 8 (line 327). **Draft — finalize after the Phase-7 whole-branch review clears.**

## Goal
User-facing withdrawals + automated pool management → the module is feature-complete. A user burns USDT e-cash to withdraw to any EVM address; the federation pays out from the pool `SimpleAccount` via an MPC-signed UserOp (reusing the Phase-7 pipeline), charging a USDT fee that covers gas.

## Reuses Phase 7
The pool is a `SimpleAccount` (owner = group key) that is deployed and holds swept USDT after the first Phase-7 sweep. A withdrawal is a UserOp **from the pool** (`pool.execute(usdt.transfer(recipient, amount))`, or `executeBatch` for a batch) — the same build → MPC-sign → `handleOps` → threshold-confirm machinery Phase 7 built. `UserOpPurpose` gains a `Withdraw { outpoints }` variant; the signing/submit/confirm lifecycle (Task-5 arms) is reused with minimal change.

## ⚠️ Economic-model decision (MAINTAINER SIGN-OFF — elsirion)
How gas is ultimately paid is a genuine product/trust fork. Two models:
- **(Default, chosen) Broadcaster-fronts-ETH + USDT-fee accounting.** The federation's broadcaster EOA fronts ETH gas (and keeps the pool's EntryPoint deposit prefunded); the user pays a USDT `max_fee`; the fee (minus actual gas cost) accrues to the federation as USDT; the operator periodically refills the broadcaster's ETH (converting accrued USDT→ETH off-protocol, or topping up). Simple, works on any chain, no oracle. **Downside:** requires operator ETH liquidity + a documented runbook; gas is not literally paid *in* USDT on-chain.
- **(Deferred/optional) On-chain token paymaster.** The v0.7 `TokenPaymaster` (arbitrary ERC-20 + price oracle) pays gas from USDT directly; the EntryPoint refunds the broadcaster from the paymaster's ETH stake; the paymaster collects USDT. True gas-in-USDT / ETH-net-zero. **Downside:** needs a Uniswap router + 2 price oracles standing up (complex on devnet; a real oracle dependency in prod).

**This plan implements the Default model** (broadcaster-fronts + USDT-fee accounting), matching the Phase-7 `depositTo` prefund groundwork, and treats the token paymaster as optional production hardening (a later phase / operator choice). The `usdt_per_eth_e6` field already in `FeeVote` is exactly the USDT/ETH price the fee model needs. **Flag for elsirion:** confirm the broadcaster-fronts economic model (+ operator ETH-refill runbook) is the intended v0 rather than requiring the on-chain token paymaster.

## Determinism rules (unchanged — every consensus arm is a pure fn of (ordered item, DB, config))
New consensus surface: `process_output` (debit + enqueue), `FeeVote` median (like block-count), the `Withdraw` UserOp trigger/batch, and `UserOpConfirmed` extended to settle withdrawals. Fee estimation reads (`get_fee_estimate`) are per-guardian VOTES aggregated by median — never a raw RPC value in a consensus write. Reuse the Phase-5 block-count-median + deposit-quorum patterns.

## DB additions (prefixes; 0x0B taken by UserOpConfirmedVoteKey in Phase 7)
- `FeeVoteKey(PeerId)` [0x02, reserved in Phase 5] → `FeeVote`
- `UnclaimedWithdrawalKey(OutPoint)` [**0x0C**] → `UsdtWithdrawalV0 { recipient, amount, max_fee, requested_block }` (queued for the next batch)
- `WithdrawalStateKey(OutPoint)` [0x0D] → `WithdrawalState { Queued | Signing(op_hash) | Submitted(op_hash) | Confirmed{block} | Failed{reason} }`
- extend `UserOpPurpose` with `Withdraw { outpoints: Vec<OutPoint> }`; `PoolState.balance` debited on withdrawal-confirm.

---

## Task 1 — `UsdtOutputV0` + `process_output` (withdrawal debit + queue) + FeeVote median
- Make `UsdtOutput` real: `enum UsdtOutput { V0(UsdtOutputV0 { recipient: EvmAddress, amount: UsdtAmount, max_fee: UsdtAmount }) }` (versioned, wasm-safe). Real `UsdtOutputOutcome`/`UsdtOutputError`.
- `FeeVote` median consensus: per-guardian poller proposes `FeeVote` from `evm_rpc.get_fee_estimate()` (mirror the block-count poller), `FeeVoteKey(PeerId)` per-peer with redundancy guard, median → the current fee quote. Per-guardian price-source config (devimint: static env, mirror the existing pattern).
- `process_output`: compute the required fee = `fee_quote(median FeeVote, amount)`; `ensure!(output.max_fee >= required_fee)`; return `TransactionItemAmounts` debiting `amount + max_fee` in USDT_UNIT (burns the user's e-cash); enqueue `UnclaimedWithdrawalKey(out_point)` + `WithdrawalStateKey = Queued`. `output_status`/`withdrawal_status` reads.
- **Acceptance:** hermetic — a withdrawal output debits the right e-cash, enqueues the withdrawal, rejects `max_fee < quote`; FeeVote median is deterministic across guardians (unit + 4-guardian test).

## Task 2 — Withdrawal batching → MPC-signed UserOp from the pool
- Batching policy: every N consensus blocks OR M queued items → build ONE `Withdraw` UserOp: `pool.executeBatch([usdt.transfer(r_i, a_i) for each queued withdrawal])` (v0.7 SimpleAccount `executeBatch(dest[], value[], func[])`); `UserOpPurpose::Withdraw{outpoints}`; deterministic trigger (block-count-driven, like the sweep). Pool nonce tracked (pool is long-lived — increments per UserOp; store `PoolState.nonce`).
- Reuse the Task-5 lifecycle: session signs → `SubmittedUserOp` → guardian-local submit → `UserOpConfirmed` quorum → on confirm, mark each `WithdrawalState = Confirmed`, debit `PoolState.balance`, remove `UnclaimedWithdrawal`.
- Consolidation: when `pool.balance < withdrawal demand`, the existing per-deposit sweeps already feed the pool; add a dust threshold skipping uneconomic sweeps. (Cross-account consolidation UserOps if needed — keep minimal for v0.)
- **Determinism:** the batch op is built from the ordered set of `UnclaimedWithdrawal`s (sorted by OutPoint) + `PoolState.nonce` + config — byte-identical across guardians. **Acceptance:** hermetic — queued withdrawals batch into one UserOp, sign (real MPC), confirm, pool debited, withdrawals Confirmed; all-guardian DB byte-identical.

## Task 3 — Fee accounting + overcharge + audit balance sheet
- Quote = `estimate × (1 + buffer)`; actual gas cost from `UserOpReceipt`; surplus (max_fee − actual) accrues to the federation (a `FeeSurplus`/`AccruedFees` counter, USDT). 
- **Audit (SOLVENCY):** extend the balance sheet to: `asset = sum(credited − swept) + pool.balance` (Phase 7) `− sum(queued withdrawal amounts)` (liability: owed to users, still backed by pool) `+ accrued_fees`. Confirm balanced before/after a withdrawal (e-cash burned = pool USDT owed out + fee). This is the trickiest accounting — the reviewer verifies no unit is lost or double-counted across deposit→claim→sweep→withdraw.
- **Acceptance:** audit balanced through a full deposit→claim→sweep→withdraw cycle; overcharge surplus accounted; fee-spike (`anvil_setNextBlockBaseFeePerGas`) handled (quote reflects it).

## Task 4 — Client withdraw operation + SM + fedimint-cli
- Client `withdraw(recipient, amount)`: fetch `withdraw_fee_quote`, submit an output tx (`UsdtOutput::V0`), track via `withdrawal_status` state machine (Queued→Signing→Submitted→Confirmed/Failed) with `OperationId`. fedimint-cli `module usdt withdraw`.
- **Acceptance:** client-driven withdrawal reaches Confirmed hermetically.

## Task 5 — Acceptance ★: devimint/anvil full loop (Phase-8 gate)
- Hermetic (skip-if-anvil-absent) e2e: fresh federation + full 4337 stack on anvil → deposit USDT → claim e-cash → **withdraw to a fresh EOA** → assert recipient's on-chain USDT correct, fee within quote, `audit` balanced before AND after, pool debited, `PoolState`/`WithdrawalState` consistent across guardians. Include a fee-spike + a paymaster/prefund-refusal→retry path.
- **This is the Phase-8 gate.** Real anvil + real MPC (the withdrawal UserOp signed by the group key from the pool account).

## Whole-branch review (opus) after Task 5
Determinism of `process_output` + FeeVote-median + Withdraw-batch + confirm-settlement; audit solvency across the full lifecycle; no Phase-5/6/7 regression; the pool-nonce tracking is deterministic + collision-free; WASM boundary; overcharge can't be gamed by a Byzantine guardian's FeeVote (median bounds it).

## Deferred to Phase 9
Reorg drills, restart-mid-session, client recovery/backup, DoS review, migration-test scaffolding, docs/runbook (incl. the broadcaster ETH-refill operational model + optional token-paymaster setup), the factory-config-validation setup guard, first-sweep-only→multi-sweep nonce handling, dangling-SubmittedUserOp GC, external-audit package.
