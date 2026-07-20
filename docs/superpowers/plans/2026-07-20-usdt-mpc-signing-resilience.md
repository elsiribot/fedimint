# USDT Runtime MPC Signing — Resilience (Phase 6b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make runtime MPC signing (Phase 6a) resilient: the finished signature becomes a federation-wide agreed record (so non-signers also hold it, and Phase 7 can consume it), and a stalled signing subset is deterministically timed out and retried with a rotated signer subset until it succeeds — proven by a degraded-federation acceptance.

**Architecture:** Builds on Phase 6a's per-session off-thread signing driven over `MpcRound` (chunked) consensus items. Three additions, all consensus-deterministic: (1) a signer, on completing, proposes an `MpcSignature` consensus item; every guardian verifies it against the DKG group key and writes `SessionState::Completed(sig)` — a canonical, agreed record. (2) Each `SigningSession` tracks `last_progress_block`; when the consensus block count (already median-voted in Phase 5) advances past `last_progress_block + SIGNING_TIMEOUT_BLOCKS` while still `InProgress`, the session is *timed out* deterministically. (3) A guardian proposes `RotateSigning`; every guardian deterministically marks the old attempt `Failed` and starts the next attempt (`SigningSessionId = hash(digest ‖ attempt+1)`, signer subset rotated to the next lowest-`t` window). The status endpoint reads the agreed `Completed` state.

**Tech Stack:** Phase 6a's signing stack; the existing block-count median consensus (for the deterministic timeout clock); `secp256k1` `verify_ecdsa` (for the agreed-signature check); fedimint-testing degraded-federation fixtures.

## Global Constraints

- **Determinism is the whole game (Phase-5-CRITICAL class).** Every new `process_consensus_item` arm (`MpcSignature`, `RotateSigning`) must be a byte-identical pure function of `(ordered items, prior consensus-DB state, config)` on every guardian — signer or not. No dependence on `our_peer_id` for `Ok`/`Err` or any consensus-DB write; off-thread/in-memory state never gates a consensus write.
- **The agreed signature is verified before it is trusted.** `process_consensus_item(MpcSignature)` MUST `secp256k1::verify_ecdsa(sig, session.digest, group_public_key)` and reject an invalid one — a Byzantine signer cannot inject a bogus signature into the agreed record. The group key is `cfg.consensus.group_public_key` (consensus config).
- **The timeout clock is the consensus block count** (`consensus_block_count`, median of `BlockCountVoteKey` votes — Phase 5). It is identical on all guardians, so timeout detection is deterministic. Do NOT use wall-clock or per-guardian time. In `is_running_in_test_env()`, use a small `SIGNING_TIMEOUT_BLOCKS` so the degraded test is fast.
- **Subset rotation is deterministic:** attempt `a`'s subset = the `t` peer ids starting at offset `a mod n` in the sorted peer-id ring (wrapping), i.e. a rotated window of size `t`. `SigningSessionId(digest, attempt)` already folds `attempt` in (Phase 6a `signing_session_id`).
- **Unbounded-history rule:** every arm `Err`s when it changes no consensus state (an already-`Completed` session receiving another `MpcSignature`; a `RotateSigning` for a session already rotated/failed; etc.).
- **`-common`/`-client` stay WASM-safe** (the new `MpcSignature`/`RotateSigning` payloads are plain data — no cggmp21/gmp).
- **Preserve Phase 6a determinism + Phase 5.** The chunked-`MpcRound` flow, `completed_signatures` in-memory path, and all Phase-5 arms stay intact.
- After changes `just format`; `cargo clippy -p fedimint-usdt-server -p fedimint-usdt-common --all-targets` (NOT `just clippy -p`) 0 warnings. Commit with `git commit` (hook healthy; never `--no-verify`). Signing tests are SLOW (minutes) — run FOREGROUND, never background.

## Reference Map

- Phase 6a signing consensus code to extend: `modules/fedimint-usdt-server/src/lib.rs` (`consensus_proposal` drains, `process_consensus_item` `MpcRound`/`StartSigning` arms, `start_session`, `advance_local_signer`, the in-memory `signing_sessions`/`completed_signatures`/`pending_signing_starts`), `db.rs` (`SigningSessionKey`→`SigningSession{purpose,digest,signers,round,state}`, `MpcRoundChunkKey`), `common/src/lib.rs` (`UsdtConsensusItem`, `SigningSessionId`, `signing_session_id`, `SessionState`).
- Block-count median (the timeout clock): `consensus_block_count` in `lib.rs` (Phase 5, wallet-mirrored).
- Redundancy-guard idiom + deterministic arm structure: the Phase 6a `MpcRound`/`StartSigning` arms.
- Degraded-federation fixture: `grep -rn "new_fed_degraded\|degraded\|kill" fedimint-testing/src/` and the Phase-6a acceptance `federation_signs_a_digest_via_mpc` in `modules/fedimint-usdt-tests/tests/tests.rs` (mirror its trigger/poll/verify shape).

---

## Task 1: Federation-wide agreed signature (`MpcSignature` consensus item)

**Files:**
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (`UsdtConsensusItem::MpcSignature`)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`advance_local_signer` queues a proposal; `consensus_proposal` drains it; `process_consensus_item` `MpcSignature` arm; status endpoint reads consensus state; new in-memory `pending_signature_proposals` field)
- Test: inline unit test in `lib.rs`

**Interfaces:**
- Produces: `UsdtConsensusItem::MpcSignature { session_id: SigningSessionId, signature: Vec<u8> }` (compact 64-byte sig; plain data, before `#[encodable_default] Default`). New `Usdt` in-memory field `pending_signature_proposals: Arc<Mutex<Vec<(SigningSessionId, Vec<u8>)>>>` (init empty in `new`/`new_for_test`).

- [ ] **Step 1: Failing test.** In `lib.rs mod tests`: drive a signing session to completion (reuse the Task-3 unit-test harness that shuttles chunked `MpcRound` items across 4 in-process modules). Assert that after a signer proposes its `MpcSignature` (drained from `pending_signature_proposals` via `consensus_proposal`) and it is processed by ALL guardians, EVERY guardian's `SigningSessionKey(session_id)` has `state == SessionState::Completed(sig)` with the SAME `sig` bytes (including the non-signer, peer 3), and that `sig` verifies against the group key. Also assert a second identical `MpcSignature` is rejected (`Err`).

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.**
  - `advance_local_signer`: after storing the sig in `completed_signatures`, also push `(session_id, sig_bytes)` onto `pending_signature_proposals` (still guardian-local/in-memory — proposing is a later, deterministic consensus step).
  - `consensus_proposal`: drain `pending_signature_proposals` (via `mem::take`) into `UsdtConsensusItem::MpcSignature { session_id, signature }` items (only if the session isn't already `Completed` in the dbtx snapshot — cheap dedup).
  - `process_consensus_item` `MpcSignature` arm: load `SigningSession`; if missing ⇒ `Err`. If `state` is already `Completed` ⇒ `Err("redundant MpcSignature")` (unbounded-history). Verify: `secp256k1::ecdsa::Signature::from_compact(&signature)` then `verify_ecdsa(&Message::from_digest(session.digest), &sig, &self.cfg.consensus.group_public_key)`; on failure ⇒ `Err("MpcSignature does not verify against the group key")` (Byzantine guard). On success, write `state = Completed(signature)` back to `SigningSessionKey`. DETERMINISTIC: verify + write are pure functions of the item + config + digest — identical on all guardians; no `our_peer_id`.
  - `signing_session_status` endpoint: read `SigningSessionKey(session_id).state`; return `Some(sig)` iff `Completed(sig)`, else `None`. (Now every guardian — not just signers — can answer, so the client no longer needs to poll only signers; keep the per-peer client method but it can hit any guardian.)

- [ ] **Step 4: Run → PASS** (foreground). `just format`; clippy clean.
- [ ] **Step 5: Commit.** `feat(usdt): federation-wide agreed MPC signature via MpcSignature item`.

---

## Task 2: Session progress tracking + deterministic timeout detection

**Files:**
- Modify: `modules/fedimint-usdt-server/src/db.rs` (`SigningSession` gains `attempt: u32` and `last_progress_block: u64`)
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (a `SIGNING_TIMEOUT_BLOCKS` const, or put it server-side)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`start_session` sets the new fields; the `MpcRound` round-advance updates `last_progress_block`; a `timed_out(session, dbtx)` helper)
- Test: inline unit test

**Interfaces:**
- Produces: `SigningSession { purpose, digest, signers, round, state, attempt: u32, last_progress_block: u64 }`. `SIGNING_TIMEOUT_BLOCKS` (e.g. `50` prod; the code uses a smaller value under `is_running_in_test_env()` — define both). `async fn timed_out(&self, dbtx, session: &SigningSession) -> bool` = `session.state == InProgress && self.consensus_block_count(dbtx).await > session.last_progress_block + timeout_blocks()`.

- [ ] **Step 1: Failing test.** Seed a `SigningSession { state: InProgress, last_progress_block: 10, .. }`; seed block-count votes so `consensus_block_count` is 10 + timeout + 1; assert `timed_out()` is `true`; drop the block count below the threshold and assert `false`; set `state = Completed` and assert `false`.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** Add the two fields (update Task-1-era `SigningSession` construction sites incl. tests and the DB round-trip test). `start_session` sets `attempt` (from the caller — see Task 3; default 0) and `last_progress_block = consensus_block_count(dbtx)` at creation. In the `MpcRound` arm, when `session.round += 1` is written, also set `advanced.last_progress_block = self.consensus_block_count(dbtx).await` (progress = a round advanced). Implement `timed_out` + a `timeout_blocks()` (test-env-aware). All reads are consensus DB + config → deterministic.

- [ ] **Step 4: Run → PASS.** `just format`; clippy clean.
- [ ] **Step 5: Commit.** `feat(usdt): track signing-session progress and detect timeout via block count`.

---

## Task 3: Deterministic retry with rotated subset (`RotateSigning`)

**Files:**
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (`UsdtConsensusItem::RotateSigning`)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`consensus_proposal` proposes `RotateSigning` for timed-out sessions; `process_consensus_item` `RotateSigning` arm; `start_session` takes an `attempt`; a deterministic `rotated_subset(attempt)` helper)
- Test: inline unit test

**Interfaces:**
- Produces: `UsdtConsensusItem::RotateSigning { session_id: SigningSessionId }` (the timed-out attempt's id; plain data). `fn signer_subset(&self, attempt: u32) -> Vec<PeerId>` = the `t` peer ids starting at offset `attempt % n` in the sorted peer ring (wrapping). `start_session` signature gains `attempt: u32` (session id via `signing_session_id(&digest, attempt)`, subset via `signer_subset(attempt)`, `attempt` stored on the record).

- [ ] **Step 1: Failing test.** Simulate a stalled session across 4 in-process modules: `start_session` (attempt 0, subset {0,1,2}); advance block count past the timeout WITHOUT completing rounds; call `consensus_proposal` and assert it proposes `RotateSigning { session_id: id(digest,0) }`; feed it to every module's `process_consensus_item` and assert: the attempt-0 session is `state == Failed`, a NEW `SigningSession` exists at `signing_session_id(digest, 1)` with `attempt == 1`, `round == 0`, `state == InProgress`, and `signers == rotated {1,2,3}` (offset 1). Assert `signer_subset` wraps correctly (e.g. attempt 2 of 4 peers, t=3 → {2,3,0}).

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.**
  - `signer_subset(attempt)`: `let ids: Vec<PeerId> = self.num_peers.peer_ids().collect(); let n = ids.len(); let t = self.num_peers.threshold(); (0..t).map(|i| ids[(attempt as usize + i) % n]).collect()` (result is the rotated window; sort it for the canonical signer order used elsewhere — keep the SAME sorted-order convention `start_session`/`process_mpc_round` already use).
  - `consensus_proposal`: for each `SigningSession` that `timed_out()`, push `UsdtConsensusItem::RotateSigning { session_id }` (dedup: skip if that session is already `Failed`).
  - `process_consensus_item` `RotateSigning` arm: load the session; `ensure!(state == InProgress)` and `ensure!(timed_out(session))` (so a non-timed-out or already-rotated session ⇒ `Err`, deterministic + unbounded-history-safe — every guardian agrees on `timed_out` via the consensus block count); set the old session `state = Failed` and persist; then `start_session(dbtx, session.purpose, session.digest, session.attempt + 1)` (creates the next attempt deterministically; idempotent if it already exists). All consensus writes are pure functions of DB + config; the SM spawn inside `start_session` is the only `our_peer_id`-conditional (in-memory) part.
  - Update `StartSigning`'s arm + the `debug_start_signing` path to call `start_session(.., attempt = 0)`.

- [ ] **Step 4: Run → PASS.** `just format`; clippy clean.
- [ ] **Step 5: Commit.** `feat(usdt): time out and retry stalled signing with a rotated subset`.

---

## Task 4: Degraded-federation acceptance ★ — recover from a killed signer

**Files:**
- Modify: `modules/fedimint-usdt-tests/tests/tests.rs` (the acceptance)

**Interfaces:**
- Consumes: Tasks 1–3; a fedimint-testing degraded-federation fixture that can run with a guardian down (or bring one down) mid-session.

- [ ] **Step 1: Write the acceptance.** Mirror the Phase-6a `federation_signs_a_digest_via_mpc` shape, but arrange for the attempt-0 subset to be unable to complete (e.g. boot a federation where one of the lowest-`t` signers is absent/killed, per the fixture API — find it: `grep -rn "new_fed_degraded\|fn new_fed\|offline\|without_peer\|kill" fedimint-testing/src/`). Trigger signing; the attempt-0 session stalls; the block count advances past the timeout (drive it if the fixture needs blocks mined / the block-count poller); `RotateSigning` fires; attempt 1 (rotated subset that excludes the down guardian, or that the live quorum can complete) produces a signature. Poll `signing_session_status` on any live guardian until `Some(sig)`; verify it against the group key. Assert the final agreed session (`signing_session_id(digest, final_attempt)`) is `Completed`.
- [ ] If the exact degraded fixture can't force attempt-0 to fail cleanly, an acceptable variant is a full-federation run that *forces* a timeout+rotation via a test hook (e.g. a debug endpoint that suppresses one subset's proposals for attempt 0), then verifies attempt 1 completes — document the choice. Do NOT weaken the "a real signature verifies after rotation" assertion.

- [ ] **Step 2: Run FOREGROUND** (`cargo test -p fedimint-usdt-tests --test fedimint_usdt_tests <name> -- --nocapture`). Real MPC + a timeout cycle over a real federation — SLOW (several minutes). Do NOT background. It MUST pass (a verified signature produced by a rotated subset after the first stalled). This is Phase 6b's acceptance ★.
- [ ] If it stalls, instrument (temporary prints) to see whether the timeout fires and the rotated attempt starts; report findings; do NOT weaken assertions.

- [ ] **Step 3:** `just format`; clippy clean; commit. `test(usdt): degraded federation recovers signing via timeout and rotation`.

---

## Self-Review Checklist (run before dispatching Task 1)

- **Spec coverage** (master-plan Phase 6 resilience): federation-wide agreed signature ✓ (T1); deterministic block-count timeout ✓ (T2); rotated-subset retry ✓ (T3); degraded-federation recovery acceptance ✓ (T4). Still deferred (documented, not gaps): restart/replay of a live session (rely on timeout+rotation for v0), `MpcRound`/chunk + failed-session GC, Byzantine inconsistent-chunk-count hardening, the pre-drain-task pump optimization, and the Phase-7 real trigger — a Phase-6c/hardening or Phase-9 concern.
- **Determinism:** the two new arms (`MpcSignature`, `RotateSigning`) write consensus DB only as pure functions of the item + prior DB + config; `MpcSignature` verifies against the group key before trusting; `RotateSigning` gates on the deterministic `timed_out` (consensus block count). No `our_peer_id` in any `Ok`/`Err` or consensus write. The signature in the consensus `Completed` record is byte-identical across signers (threshold ECDSA + `normalize_s`).
- **Unbounded-history:** already-`Completed` ⇒ `MpcSignature` `Err`; already-`Failed`/not-timed-out ⇒ `RotateSigning` `Err`.
- **No regression:** Phase 6a chunked-`MpcRound` flow + `completed_signatures` + Phase-5 arms intact; `SigningSession`'s two new fields threaded through every construction site.
- **Type consistency:** `attempt`/`last_progress_block`, `signer_subset`, the `MpcSignature`/`RotateSigning` shapes used identically across T1–T4.
