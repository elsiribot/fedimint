# Phase 9 — Hardening + acceptance suite + audit prep (JIT plan)

Base: Phase-8 head (`fd00fe4c0e4`, pending whole-branch review). Master plan §Phase 9 (line 335). **Draft — finalize after the Phase-8 whole-branch review.** The FINAL phase: the module's core functionality (DKG → deposits → runtime MPC signing → resilience → sweep → withdrawals) is complete and proven on real anvil; Phase 9 makes it production-ready under adversarial conditions and prepares the external-audit package.

## Consolidated deferred items (from every phase's ledger) — Phase 9 addresses these
- **Reorg handling** (P5/P9): a reorged deposit must not credit / must not stay credited; a reorged submission must re-submit.
- **Restart mid-signing** (P6c/P9): a guardian restart loses the in-memory off-thread cggmp21 session; recovery is via the Phase-6b timeout+rotation — verify no key-share corruption + recovery works across restart.
- **Client recovery** (P9): `ClientModuleInit::recover` — rescan claim keys from seed, re-run `check_deposit`; backup coverage.
- **Liveness GC** (P7/P8): MpcRound/chunk + failed-session GC; dangling `SubmittedUserOp` GC; I2 (never-confirmed `Submitted` withdraw op wedges future batches — deterministic staleness/expiry).
- **Multi-sweep** (P7): first-sweep-only nonce=0 → handle a 2nd deposit after the 1st sweep confirms (nonce tracking / re-sweep).
- **Fee floor** (P8): degenerate zero-median → free withdrawal; floor the quote.
- **Factory-config validation** (P7/P9): a setup-time guard cross-checking the configured `account_factory.getAddress` against `derive_deposit_account` (else a mis-compiled factory ⇒ unspendable deposit addresses).
- **DoS** (P9): `check_deposit` spam → `deposit_check_fee` (config exists, may be 0) + per-connection rate limit; MpcRound payload-size caps (chunking bounds already; verify + document).
- **Byzantine chunk-count liveness** (P6a): inconsistent chunk counts stall a session (liveness) → timeout/retry already recovers; verify.
- **Minors:** unchecked `u64` adds → `saturating_add` sweep; audit `i64` saturation; per-`BlockCount` full-table scans (perf).

## ⚠️ Maintainer sign-off items (elsirion) — Phase 9 surfaces/defaults these
1. **Reorg credit-reversal policy:** does a credited-then-reorged-out deposit get *un-credited* (requires tracking + a reversal path, and interacts with already-claimed e-cash), or does the `confirmation_depth` simply need to be set conservatively enough that this can't happen in practice? (Default: rely on a well-chosen `confirmation_depth`; add reversal only if required. This is a real risk/UX decision.)
2. **Restart-mid-signing recovery:** timeout+rotation (current) vs true session-replay-from-DB (deferred as a bigger change). Default: verify timeout+rotation suffices; document the recovery window.
3. **DoS knobs:** `deposit_check_fee` default value + rate-limit policy.
4. **Docs/runbook + audit-package scope + threat model** — content review.
5. Carryover: ETH-net-zero via token paymaster (still deferred; broadcaster-fronts model + operator ETH-refill runbook); the gpg-unsigned Phase 6b–9 commits + wallet/walletv2 cargo-sort debt + rebase-onto-upstream (pre-PR cleanup).

## Determinism rules (unchanged) — any new consensus arm (e.g. reorg reversal, session GC) is a pure fn of (ordered item, DB, config).

---

## Task 1 — Reorg resilience (deposits + submissions)
- Deposit: confirm the deposit-checker only credits at `head − confirmation_depth`; add an `anvil_reorg` drill (reorg shallower than depth → no spurious credit; reorg a to-be-credited deposit out before it crosses depth → never credited). If credit-reversal is in scope (maintainer #1), add a deterministic reversal arm; else document the `confirmation_depth` reliance.
- Submission: confirm the guardian-local submitter re-submits when a submitted op yields no receipt (a reorged-out `handleOps` re-submits); `anvil_reorg` drill on a submitted UserOp.
- **Acceptance:** hermetic anvil reorg drills pass; determinism preserved (reorg observations are per-guardian reads aggregated by the existing quorum/confirmation logic).

## Task 2 — Restart-mid-signing + Byzantine-liveness resilience
- Drill: bring a guardian down mid-signing-session (or drop its off-thread session), confirm on restart the key share is intact (re-loadable, signs again) and the session recovers via Phase-6b timeout+rotation without manual intervention.
- Verify Byzantine inconsistent-chunk-count / withholding stalls recover via timeout+rotation.
- **Acceptance:** a `new_fed_degraded`-style restart/kill drill signs successfully after recovery; no key-share corruption.

## Task 3 — Client recovery + backup
- `ClientModuleInit::recover`: rescan claim keys derived from the client seed, re-run `check_deposit`, restore deposit/withdrawal tracking state. Backup coverage for the usdt client module state.
- **Acceptance:** a client recovered from seed re-discovers its deposits and can claim/track them.

## Task 4 — Liveness GC + deferred-fix sweep + DoS knobs
- Deterministic GC (consensus arms, pure): failed/old `SigningSession` + `MpcRoundChunk` cleanup; dangling `SubmittedUserOp` staleness/expiry (I2) — a `SubmittedUserOp` un-confirmed for N blocks reverts to allow progress (deterministic).
- Multi-sweep: handle a 2nd deposit after the 1st sweep confirms (track/advance the deposit-account nonce, or re-sweep on a fresh credit).
- Fee floor (a `MIN_WITHDRAWAL_FEE` or reject-zero-median).
- Factory-config setup-validation guard.
- `saturating_add` on the flagged `u64` consensus-path adds (N1).
- DoS: wire `deposit_check_fee` enforcement + document rate-limit expectations; verify MpcRound chunk-size caps.
- **Acceptance:** unit + a hermetic test per fix; determinism review (these add consensus surface).

## Task 5 — DB migrations + dump_database + wasm CI + lint
- `get_database_migrations` scaffolding + a snapshot/migration test (the module is greenfield/unreleased, but establish the pattern before v1). Confirm `dump_database` covers every key prefix (0x01–0x0D).
- Add `fedimint-usdt-client` to the CI wasm check set (`just check-wasm` package list).
- `just final-lint` / `just final-check` green; resolve the pre-existing wallet/walletv2 cargo-sort debt as part of pre-PR cleanup (or note it's upstream).

## Task 6 — Docs + external-audit package
- `docs/usdt-module.md`: architecture, the deposit→claim→sweep→withdraw flows, the deployment model (D8), and the **guardian ops runbook** (price-source config, broadcaster ETH funding + refill, pool/paymaster config, pool monitoring, `confirmation_depth` guidance).
- External-audit package: threat model, the consensus-determinism invariant + where it's enforced, the crypto-integration decision transcript (Phase-2/6 cggmp21 !Send off-thread driver, chunking, verify-before-trust, recovery-id assembly), the custody model (CREATE2 SimpleAccount owned by the group key), and the known-deferred/accepted risks.

## Task 7 — Final acceptance + pre-PR
- Full `test-ci-all`-style run of the usdt suites (`NEXTEST=1`); `just final-check`. Pre-PR cleanup checklist (read the `pr-submissions-checklist` skill): unsigned Phase-6b–9 commits (re-sign range if wanted), squash/atomicity pass, rebase onto upstream/master, the wallet cargo-sort debt.

## Phase 9 whole-branch review (opus) — determinism of any new arms (reorg reversal, GC, multi-sweep), no regression, audit still solvent, docs/audit-package accuracy.

## Note on scope
Several Phase-9 items are genuine product/security decisions (maintainer sign-offs above) rather than mechanical implementation. Where the module is already correct-and-safe under a reasonable operating assumption (e.g. a conservative `confirmation_depth`), Phase 9 documents that assumption and adds the drill, rather than building speculative machinery — flagging each such choice for elsirion. The autonomous run implements the concrete hardening (drills, GC, recovery, migrations, lint/wasm/docs) and defaults the policy questions with clear notes.
