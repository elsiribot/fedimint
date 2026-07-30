# USDT Hardening — Findings A (stranded prefund) & B1 (over-ceiling double-pay) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close two adversarial-review findings in the USDT module: (B1) an over-ceiling withdrawal reprice that reissues an e-cash refund while the threshold-signed UserOp stays valid on-chain — enabling a double-pay + nonce desync; and (A) operator ETH stranded/over-fronted in single-use deposit-sweep accounts' EntryPoint gas deposits.

**Architecture:** Three independent commits, ordered by risk. A1 shrinks the over-provisioned prefund at the source (guardian-local, non-consensus). B1 removes the premature refund+purge in the over-ceiling branch so the stuck op stays live and settles exactly-once (consensus behavior change). A2 adds a batched pass that pulls residual EntryPoint deposits from fully-swept deposit accounts back to the broadcaster.

**Tech Stack:** Rust, fedimint module framework (`Encodable`/`Decodable`, `impl_db_record!`), alloy (`sol!` bindings, ERC-4337 v0.7 EntryPoint), threshold-ECDSA UserOp signing.

## Global Constraints

- **Determinism (consensus paths):** any code in `process_input`/`process_output`/`process_consensus_item`/`apply_*`/`process_replace_user_op` and the functions they call reads ONLY the ordered input, prior consensus DB, and `cfg.consensus`. NO RPC, NO wall-clock, NO `our_peer_id`, NO floats. Guardian-local observer tasks (`spawn_*`) may do RPC but MUST feed consensus only via a proposals queue drained by `consensus_proposal`.
- **Wire compatibility:** derived `Encodable`/`Decodable` enums are tagged by declaration order. NEW enum variants MUST be appended at the end (for `UsdtConsensusItem`/`UsdtInput`/`UsdtOutput`, immediately before the `#[encodable_default] Default` arm; for `UserOpPurpose`/`WithdrawalState`, which have no default arm, after the last variant). NEVER reorder or remove existing variants.
- **`MODULE_CONSENSUS_VERSION`** is the single constant at `modules/fedimint-usdt-common/src/lib.rs:95`. Any change to consensus wire types OR to deterministic consensus behavior requires a bump + a new changelog paragraph in the doc comment above it (lib.rs:26-94). Guardian-local (`rpc.rs` broadcaster) changes do NOT.
- **No `unwrap()` in non-test code** — use `expect()` with a succinct reason. Structured tracing (`field = value`), multi-line.
- **Run `just format` after edits; `just clippy` must pass with no warnings.** Each task's workspace must compile (`cargo check -q`) and the touched crate's tests must pass before the task is considered done.
- No DB migrations are required by any task (A1: none; B1: behavior-only; A2: append-only variants + a keyspace that starts empty).

---

### Task 1 — A1: Trim the EntryPoint prefund margin (1.5× → 1.05×)

**Files:**
- Modify: `modules/fedimint-usdt-server/src/rpc.rs:864-872` (the `need`/`need_with_margin` computation in `submit_user_ops`' per-op auto-prefund loop)
- Modify/verify test: `modules/fedimint-usdt-server/src/user_op.rs:1007-1027` (`with_median_fees_keeps_the_prefund_affordable_on_a_cheap_mainnet` — it recomputes the ×1.5 margin inline; keep it consistent) and any test in `rpc.rs` asserting the prefund top-up amount.

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing consumed by later tasks. Purely local to the broadcaster submission path.

**Rationale:** `need = total_gas × op.max_fee_per_gas` is already worst-case (worst-case gas *limits* × a `2×`-headroom price ceiling — see `GasBounds::with_median_fees`, `user_op.rs:180-188`). The EntryPoint only *requires* `need` (1×) to be present for validation. The extra `+ need/2` (0.5×) is redundant buffer on top of an already-worst-case figure and is guaranteed to strand in the single-use deposit account. This is guardian-local, non-consensus — different guardians could even run different margins without divergence (each funds its own `depositTo`), so NO consensus version bump.

- [ ] **Step 1: Add a named margin constant and apply it.** Replace the inline `need_with_margin = need + need / U256::from(2u8)` (rpc.rs:872) with a named constant `PREFUND_MARGIN_NUMERATOR`/`_DENOMINATOR` (or a single `PREFUND_MARGIN_PERCENT: u128 = 5`) so the margin is `need + need * 5 / 100` (i.e. 1.05×). Keep the `saturating_*` arithmetic and the `U256` types exactly as they are. Add a doc comment on the constant explaining: worst-case `need` already includes the gas-limit and 2× price headroom, so this is only a small drift cushion; the residual is recovered by the A2 batched sweep.

- [ ] **Step 2: Update the affordability comment/test.** The doc/test at `user_op.rs:1007-1027` recomputes `need_with_margin` with a hardcoded `×1.5` (`total_gas * priced.max_fee_per_gas`, then a margin). Update its inline margin to match 1.05× and re-assert the "well under 0.005 ETH on a cheap mainnet" bound still holds (it will, tighter). If any `rpc.rs` test asserts the exact top-up value, update it.

- [ ] **Step 3: Run tests.** `cargo test -q -p fedimint-usdt-server user_op` and any `rpc` prefund test. Expected: PASS.

- [ ] **Step 4: Lint + format.** `just clippy` (no warnings), `just format`.

- [ ] **Step 5: Commit.** `fix(usdt): trim EntryPoint prefund margin 1.5x->1.05x (finding A)`

---

### Task 2 — B1: Stop the over-ceiling withdrawal double-pay (stall, don't refund)

**Files:**
- Modify: `modules/fedimint-usdt-server/src/lib.rs:5801-5853` (the `over_ceiling` block inside the `UserOpPurpose::Withdraw` arm of `process_replace_user_op`)
- Modify: `modules/fedimint-usdt-common/src/lib.rs:95` (bump `MODULE_CONSENSUS_VERSION` to `ModuleConsensusVersion::new(0, 10)`) + append a `/// Bumped to 0.10 (...)` paragraph to the changelog doc (lib.rs:26-94)
- Modify/add tests: the existing tests around the over-ceiling refund behavior in `modules/fedimint-usdt-server/src/lib.rs` (search for `create_withdrawal_refund`, `gas exceeds committed max_fee`, and the over-ceiling reprice tests near line 17032 and in the reprice test module) — they assert the OLD refund+purge behavior and MUST be updated to the new stall behavior.

**Interfaces:**
- Consumes: existing `SubmittedUserOp { superseded: bool, ... }` (db.rs), `process_replace_user_op` gates.
- Produces: no new types. Behavior change only.

**The fix (minimal, option 3):** In the `if over_ceiling { ... }` block, DELETE the double-pay-causing actions:
- the `for &out_point in outpoints { self.create_withdrawal_refund(...) }` loop,
- `dbtx.remove_entry(&SubmittedUserOpKey(op_hash))`,
- `dbtx.remove_by_prefix(&UserOpConfirmedVoteOpPrefix(op_hash))`,
- `self.purge_user_op_nonce_chain(...)`.

Replace with: mark the op superseded so `propose_replace_user_ops` (which skips `superseded`, lib.rs:5662) stops re-proposing a reprice every timeout, and `return Ok(())`, leaving the `SubmittedUserOp` LIVE. Because the record stays, a later on-chain confirmation of the op is handled by the existing `apply_user_op_confirmed` path (finds the record → settles the withdrawals exactly-once, debits `PoolState.balance`, advances the pool nonce) — no refund is ever issued, so there is no second payment to double up. This also means the silent-ignore branch (lib.rs:4530) is never reached for this scenario.

**Invariant preserved / tradeoff (document in the code comment):** the withdrawal is neither paid nor refunded until the op eventually confirms (when gas falls to its fee level). Because the pool account is strictly one-batch-at-a-time (`withdraw_batch_in_flight` counts a superseded op, lib.rs:4087), a stuck over-ceiling op stalls all subsequent withdrawal batches until it confirms — an accepted, self-healing liveness cost bounded to the same rare gas-spike condition that triggered the over-ceiling. The only unbounded case (a permanent gas regime shift within the mempool window) is resolved by operator intervention; note this limitation in the comment. Funds are safe throughout: exactly one live obligation (the `UnclaimedWithdrawal`) per withdrawal, settled exactly once.

- [ ] **Step 1: Write/adjust the failing test — over-ceiling now stalls, does not refund.** In the reprice test module, add or convert a test `over_ceiling_reprice_stalls_op_without_refund`: set up a `SubmittedUserOp` (purpose `Withdraw`) whose reprice cost exceeds the covered withdrawals' committed `max_fee` sum; drive `process_replace_user_op`; assert (a) NO `RefundKey(out_point)` was written, (b) the `SubmittedUserOpKey(op_hash)` STILL EXISTS and is now `superseded == true`, (c) the `WithdrawalState` for each outpoint is UNCHANGED (still `Submitted`/`Signing`, NOT `Failed`), (d) `UnclaimedWithdrawalKey` still present. Run it; expected FAIL against current code (which refunds+purges).

- [ ] **Step 2: Apply the fix** as described above (delete the four actions, set `superseded = true`, `return Ok(())`, with a `warn!` that the batch is stalled — not refunded — until it confirms or gas drops, and a doc comment capturing the liveness tradeoff + operator-intervention escape hatch).

- [ ] **Step 3: Update the existing over-ceiling tests.** Find every test asserting the old refund/`Failed`/purge behavior for the over-ceiling *withdrawal* path and update them to the stall behavior. (Do NOT touch tests for the singleton-revert refund path in `apply_withdraw_confirmed` — that refund is legitimate and unchanged.) Re-run: expected PASS.

- [ ] **Step 4: Add the exactly-once late-confirm test.** Add `stalled_over_ceiling_op_settles_once_on_late_confirm`: after the stall (op live+superseded, no refund), feed a `UserOpConfirmed` observation for that op_hash and assert it settles normally (withdrawals → `Confirmed`, `PoolState.balance` debited by the swept amount, pool nonce advanced) and that NO refund exists. Run: expected PASS.

- [ ] **Step 5: Bump the consensus version.** Edit `common/lib.rs:95` to `ModuleConsensusVersion::new(0, 10)` and append a changelog paragraph: "0.10 — finding B1: over-ceiling withdrawal reprice no longer refunds+purges a still-live op (which double-paid on a late confirm); the op is kept live and superseded to settle exactly-once. Behavior-only; no wire/DB change, no migration." Confirm `cargo check -q` across the workspace (the version is read in three places, all off the one constant).

- [ ] **Step 6: Lint + format + full server test.** `just clippy`, `just format`, `cargo test -q -p fedimint-usdt-server`. Expected PASS.

- [ ] **Step 7: Commit.** `fix(usdt): stall over-ceiling withdrawal reprice instead of refunding a live op (finding B1)`

---

### Task 3 — A2: Batched recovery of stranded deposit-account gas deposits

**Files:**
- Modify: `modules/fedimint-usdt-common/src/lib.rs` — bump `MODULE_CONSENSUS_VERSION` to `new(0, 11)` + changelog; append `UsdtConsensusItem::RecoverResidual { account: EvmAddress, deposit_wei: u128 }` immediately before the `#[encodable_default] Default` arm (lib.rs:1577).
- Modify: `modules/fedimint-usdt-server/src/config.rs` — add `residual_recovery_recipient: EvmAddress` to `UsdtConfigConsensus` (the consensus config struct, ~config.rs:122), so every guardian builds the byte-identical recovery op. Wire it through config-gen: add the matching admin-supplied config-gen parameter alongside the other EVM addresses (`entry_point`/`account_factory`/`usdt_contract` — trace how one of those flows from the config-gen params into `UsdtConfigConsensus` during DKG, in `config.rs`/`dkg.rs`, and mirror it) and populate the new field there. Update EVERY constructor of `UsdtConfigConsensus` (tests, `trusted`/dummy config builders, devimint fixtures) to set the new field. **This is why the broadcaster can't be the recipient — `broadcaster_private_key` is per-guardian `UsdtConfigLocal` (config.rs:73), non-deterministic; the recipient MUST be this consensus field.**
- Modify: `modules/fedimint-usdt-server/src/db.rs:367-382` — append `UserOpPurpose::RecoverResidual { account: EvmAddress }` after `Withdraw`.
- Modify: `modules/fedimint-usdt-server/src/rpc.rs` — add `sol!` binding `IEntryPoint::withdrawTo(address payable withdrawAddress, uint256 amount)`; add a trait method `async fn get_entrypoint_deposit(&self, account: EvmAddress) -> anyhow::Result<u128>` wrapping `IEntryPoint::balanceOf(account)` (mirroring the inline read at rpc.rs:877-881), implemented on the concrete RPC type and any test/mock impl of the trait.
- Modify: `modules/fedimint-usdt-server/src/user_op.rs` — add `build_recover_residual_userop(params)` producing a UserOp on the deposit account with `callData = SimpleAccount.execute(entry_point, 0, IEntryPoint::withdrawTo(recipient, amount))` where `recipient = cfg.consensus.residual_recovery_recipient`, `needs_deploy = false` (a fully-swept account is already deployed), priced via `GasBounds::<recovery>.with_median_fees(...)`. Add a `RECOVER_RESIDUAL_GAS_UNITS` bound (small — one `execute`→`withdrawTo`).
- Modify: `modules/fedimint-usdt-server/src/lib.rs` — new observer `spawn_residual_recovery_observer`; drain in `consensus_proposal`; handle `RecoverResidual` in `process_consensus_item`; add `RecoverResidual` arms to `apply_user_op_confirmed`, `process_replace_user_op`, and every `UserOpPurpose` match the compiler flags; a `RESIDUAL_RECOVERY_MIN_WEI` threshold; a `residual_recovery_in_flight(account)` guard; a new `dump_database`/`Display` arm only if a new DB prefix is added (prefer NOT to — detect in-flight by scanning Pending/Submitted like `deploy_and_sweep_in_flight`, lib.rs:4140).

**Interfaces:**
- Consumes: `DepositRecordPrefix`/`DepositRecord` (db.rs:188), `fee_vote_median` (lib.rs:3506), `evm_address(group_public_key)`, `self.pool_account()`, `cfg.consensus.residual_recovery_recipient` (the deterministic `withdrawTo` recipient — new consensus field), `start_session` (lib.rs:6041), `user_op_hash`.
- Produces: nothing consumed by other tasks (final task).

**Design (mirror the sweep path):**
1. **Observer (guardian-local, RPC):** `spawn_residual_recovery_observer` ticks on `slow_poll_interval_secs()`; opens a non-committing dbtx; iterates `DepositRecordPrefix`; selects accounts that are fully swept (`record.credited.0 > 0 && record.swept == record.credited`) with no recovery already in-flight; reads each account's on-chain EntryPoint deposit via `get_entrypoint_deposit`; for deposits above `RESIDUAL_RECOVERY_MIN_WEI`, pushes `(account, deposit_wei)` into a new `residual_recovery_proposals` shared queue. Read-only; writes nothing to consensus directly.
2. **Proposal → consensus:** `consensus_proposal` drains the queue into `UsdtConsensusItem::RecoverResidual { account, deposit_wei }` items (batched — many accounts per round, each its own item, like `accelerate_sweeps_for_withdrawals` enqueues many independent ops).
3. **Aggregate + enqueue (deterministic):** `process_consensus_item`'s `RecoverResidual` arm collects threshold-agreed observations of `(account, deposit_wei)` (reuse the existing observation-vote aggregation pattern used for block/deposit observations — take the threshold-agreed value, e.g. the median/Nth deposit_wei so a byzantine reporter can't inflate it). Once at threshold: require a `fee_vote_median` (else defer); compute `amount = agreed_deposit_wei − need_with_margin(recovery_op)` (leave enough to pay the op's own gas — mirror `rpc.rs` `need`/margin, in wei; if `amount <= 0` skip); build the recovery op via `build_recover_residual_userop`, enqueue `PendingUserOp { purpose: RecoverResidual { account }, .. }` (idempotency-check Pending/Submitted first), and `start_session(SigningPurpose::UserOp(op_hash), ...)`. Per the framework warning (lib.rs:1768), a `RecoverResidual` item that reaches no threshold / makes no state change MUST return `Err` to avoid consensus-history bloat.
4. **Confirm:** `apply_user_op_confirmed`'s `RecoverResidual` arm advances the deposit `SimpleAccount` nonce (like the sweep) and does NOT touch `PoolState.balance`/`swept` (recovered ETH is broadcaster gas, not USDT pool balance); then the existing post-match nonce-chain purge runs as for any confirmed op.
5. **Reprice:** `process_replace_user_op`'s `RecoverResidual` arm: recovery is not urgent — mirror the `DeployAndSweep` arm (if the repriced fee exceeds the sweep gas ceiling, `bail!` and leave it stuck; funds are safe), so it never over-provisions.

- [ ] **Step 1: common — version bump + consensus item variant.** Bump to `new(0, 11)` + changelog paragraph ("0.11 — finding A: batched recovery of stranded EntryPoint gas deposits; adds a `residual_recovery_recipient` consensus config field, `UsdtConsensusItem::RecoverResidual` and `UserOpPurpose::RecoverResidual` (append-only). No DB migration; existing feds must be reconfigured to set the new consensus field."). Append the `RecoverResidual { account, deposit_wei }` variant before `Default`. `cargo check -q -p fedimint-usdt-common`.

- [ ] **Step 2: config — `residual_recovery_recipient` consensus field + config-gen.** Add the `EvmAddress` field to `UsdtConfigConsensus`; add the admin-supplied config-gen parameter and populate the field during DKG (mirror how `entry_point`/`account_factory` flow from config-gen params into the consensus config); update EVERY `UsdtConfigConsensus` constructor (unit tests, dummy/`trusted` builders, devimint fixtures) to set it. `cargo check -q --workspace`. NOTE: this is a consensus-config wire change — an already-configured fed can only pick it up via reconfiguration (accepted).

- [ ] **Step 3: db — `UserOpPurpose::RecoverResidual`.** Append the variant; add the `dump_database`/roundtrip coverage the compiler/tests demand. `cargo check -q -p fedimint-usdt-server` (will surface every non-exhaustive `UserOpPurpose` match — that list is your Step 6 worklist).

- [ ] **Step 4: rpc — `withdrawTo` binding + deposit read.** Add the `IEntryPoint::withdrawTo` `sol!` binding and the `get_entrypoint_deposit` trait method + impls (concrete + any mock). Unit-test the mock returns the expected value.

- [ ] **Step 5: user_op — recovery op builder.** Add `RECOVER_RESIDUAL_GAS_UNITS`, `RecoverResidualParams` (carrying the `recipient`), and `build_recover_residual_userop`. Write a unit test asserting the built op's `sender == deposit_account`, `needs_deploy == false` (no initCode), and `callData` decodes to `execute(entry_point, 0, withdrawTo(recipient, amount))`. Run: expected PASS.

- [ ] **Step 6: server — observer, aggregation, confirm, reprice, match arms.** Implement `spawn_residual_recovery_observer` (+ its handles struct, spawned in `Usdt::new`), the `consensus_proposal` drain, the `process_consensus_item` `RecoverResidual` aggregation→enqueue (recipient read from `cfg.consensus.residual_recovery_recipient`), the `apply_user_op_confirmed` arm, the `process_replace_user_op` arm, `residual_recovery_in_flight`, and the `RESIDUAL_RECOVERY_MIN_WEI` threshold. Fill every `UserOpPurpose` match arm the compiler flagged in Step 3. `cargo check -q`.

- [ ] **Step 7: server — deterministic tests.** Add: (a) `recover_residual_below_threshold_is_skipped`; (b) `recover_residual_at_threshold_enqueues_op_and_leaves_gas` (agreed deposit → enqueued `PendingUserOp` with `amount == deposit − need_with_margin`, purpose `RecoverResidual`, recipient == the config field, signing session started); (c) `recover_residual_confirm_advances_deposit_nonce_without_pool_change`. Run: expected PASS.

- [ ] **Step 8: Lint + format + full test + wasm check.** `just clippy`, `just format`, `cargo test -q -p fedimint-usdt-server -p fedimint-usdt-common`, and `just check-wasm` (the common crate change must stay wasm-safe). Expected PASS.

- [ ] **Step 9: Commit.** `feat(usdt): batched recovery of stranded deposit-account gas deposits via consensus recipient (finding A)`

---

## Self-Review notes (author)

- **Spec coverage:** A1 (margin) → Task 1; B1 (double-pay) → Task 2; A (stranding recovery) → Task 3. All three findings mapped.
- **Type consistency:** `RecoverResidual` named identically in `UsdtConsensusItem { account, deposit_wei }` (common) and `UserOpPurpose { account }` (server); `get_entrypoint_deposit` returns `u128` wei consistently with `deposit_wei: u128` and the `need`/margin wei arithmetic.
- **Ordering:** A1 first (no bump, lowest risk), B1 second (0.10), A2 third (0.11) — versions bump monotonically across commits; each commit compiles and tests green on its own. A2 is the largest surface and is last, so it can be deferred without disturbing A1/B1 if desired.
- **No migration** in any task; every enum change is append-only and every new keyspace (none added if in-flight is detected by scan) starts empty.
