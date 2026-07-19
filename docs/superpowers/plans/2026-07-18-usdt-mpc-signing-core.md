# USDT Runtime MPC Signing — Core Loop (Phase 6a) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Guardians co-sign an arbitrary 32-byte digest at runtime by advancing a `!Send` cggmp21 signing state machine across consensus rounds via `MpcRound` consensus items — the module-side realization of the design's threshold-signing primitive. Phase 6a delivers the core loop and a hermetic acceptance that signs one digest 3-of-4 over real consensus; timeout/rotation/restart are Phase 6b.

**Architecture:** Each in-flight signing session runs its `!Send` cggmp21 SM on a dedicated OS thread (Phase 3's `spawn_protocol`/`ProtocolHandle`, validated by the Phase-6 spike commit `ed5ccfcd942`). An in-memory, `SigningSessionId`-keyed session store on the `Usdt` module holds each session's `ProtocolHandle` plus its currently-pending outgoing round payload. A per-session driver keeps the "next outgoing payload" slot filled by calling `ProtocolHandle::next_outgoing`. `consensus_proposal` emits the current round's payload as `MpcRound{session_id, round, payload}`; `process_consensus_item` accumulates peers' payloads under `MpcRoundSeenKey` (redundancy-guarded) and, once all subset peers' round-`r` payloads are present, calls `ProtocolHandle::submit_round` and advances the session's `round`; when `next_outgoing` yields `None`, `into_output` produces the `secp256k1::ecdsa::Signature`, stored next to the session's purpose record.

**Tech Stack:** cggmp21 signing (`cggmp21::signing(eid, pos, &signers, &share).sign_sync`), the Phase-3 off-thread `ProtocolHandle::{next_outgoing, submit_round, into_output}` + `EncryptedRoundCodec` + `drive_over_exchange`, the module's existing block-count consensus, fedimint-testing.

## Global Constraints

- **Reuse the validated pump verbatim.** The off-thread `ProtocolHandle::{next_outgoing, submit_round, into_output}` from commit `ed5ccfcd942` (`crypto/threshold-ecdsa/src/transport/off_thread.rs`) is the ONLY sanctioned way to advance the `!Send` SM incrementally. Do not reintroduce `drive()` (continuous) for runtime signing, and do not attempt to move the SM off its thread.
- **Session storage is IN-MEMORY, never the consensus DB.** A live OS thread / `ProtocolHandle` is not serializable. The store is an `Arc<Mutex<BTreeMap<SigningSessionId, SessionSlot>>>` field on the `Usdt` module (mirrors the Phase-5 `deposit_proposals` in-memory queue). Only the session's *metadata* (`purpose`, `digest`, `signers`, `round`, per-round collected payloads, final signature) lives in the consensus DB.
- **`consensus_proposal` MUST NOT block** on `next_outgoing().await` (which blocks until the SM emits the round's payload). The per-session driver task pre-drains `next_outgoing` into the slot; `consensus_proposal` reads the ready slot non-blockingly (mirror Phase 5's checker→queue→drain).
- **Determinism of `process_consensus_item`.** Round-completeness (all subset peers' round-`r` items seen) and the payload ordering fed to `submit_round` (by party position `0..t`, ascending peer id) must be identical on every guardian. `submit_round` is called from the consensus handler only when the round is provably complete from consensus DB state alone. The redundancy guard: a duplicate `MpcRoundSeenKey(session, round, peer)` MUST return `Err`.
- **Fresh-per-signing `ExecutionId`.** Config-gen enc-pk-derived eids do NOT transfer to runtime signing (reuse is unsound). `SigningSessionId = hash(digest ‖ attempt)`; the cggmp21 `ExecutionId` is derived from the `SigningSessionId` bytes. Phase 6a uses `attempt = 0` (rotation is 6b).
- **Subset selection (Phase 6a):** the signer subset is the lowest-`t` peer ids (deterministic). `t = num_peers.threshold()`. Non-subset guardians do not drive an SM; they only observe `MpcRound` items (and in 6b verify liveness).
- **MPC transport keys** come from config: `UsdtConfigConsensus.mpc_encryption_pks` (all peers) and `UsdtConfigPrivate.mpc_encryption_sk` (this guardian) — already established in Phase 3. The `EncryptedRoundCodec` is keyed by the signer subset's enc pubkeys, indexed by subset position.
- **Server-only.** All of Phase 6 is `fedimint-usdt-server` + a `-common` wire type; `-common`/`-client` stay WASM-safe (the `MpcRound` item/`SigningSessionId` are plain data — no cggmp21/gmp; keep the SM/codec/handle in `-server`).
- After changes run `just format`; verify clippy via `cargo clippy -p fedimint-usdt-server -p fedimint-usdt-common --all-targets` (NOT `just clippy -p` — it drops `-D warnings`). Commit with `git commit` (hook healthy; never `--no-verify`). Foreground test runs only (signing is slow, ~minutes — do NOT background).

## Reference Map

- Validated pump + a working reference driver: `crypto/threshold-ecdsa/src/transport/off_thread.rs` — `ProtocolHandle::{next_outgoing, submit_round, into_output}` and the test `suspendable_pump_advances_offthread_signing_across_parked_rounds` (shows `spawn_protocol` + `cggmp21::signing(...).sign_sync` + `EncryptedRoundCodec::new(pos, sk, signer_pks, eid_bytes)` + `drive_over_exchange` inside the spawned closure, the poll-all/submit-all cadence, and `convert_signature` verification).
- Block-count consensus + in-memory queue + task spawning to mirror: `modules/fedimint-usdt-server/src/lib.rs` (`consensus_proposal` block-count vote + deposit drain; `process_consensus_item` arms + redundancy guards; `spawn_block_count_poller`/`spawn_deposit_checker` via `task_group.spawn_cancellable`; `deposit_proposals: Arc<Mutex<Vec<_>>>`; `consensus_block_count`).
- DB schema idiom: `modules/fedimint-usdt-server/src/db.rs` (`impl_db_record!`/`impl_db_lookup!`, `push_db_pair_items!` in `dump_database`).
- Config MPC keys: `modules/fedimint-usdt-server/src/config.rs` (`UsdtConfigConsensus.mpc_encryption_pks`, `UsdtConfigPrivate.mpc_encryption_sk`, `key_share`).
- Signature conversion / group key: `crypto/threshold-ecdsa/src/lib.rs` (`convert_signature`, `group_public_key`, `Curve`).

---

## Task 1: `MpcRound` wire type, `SigningSessionId`, and session DB schema

**Files:**
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (add `SigningSessionId`, `MpcRoundItem`, `UsdtConsensusItem::MpcRound` variant)
- Modify: `modules/fedimint-usdt-server/src/db.rs` (session + round-seen + signature records)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`dump_database` arms)
- Test: inline round-trip tests

**Interfaces:**
- Produces (in `-common`, wasm-safe — plain data, no cggmp21):
  - `pub struct SigningSessionId(pub [u8; 32]);` (`Encodable, Decodable, Serialize, Deserialize, Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd`)
  - `pub struct MpcRoundItem { pub session_id: SigningSessionId, pub round: u16, pub payload: Vec<u8> }`
  - Add `MpcRound(MpcRoundItem)` to `UsdtConsensusItem` (BEFORE the `#[encodable_default] Default` — new variant index is fine, consensus version 0.0, undeployed).
  - `pub fn signing_session_id(digest: &[u8; 32], attempt: u32) -> SigningSessionId` = `keccak256(DOMAIN ‖ digest ‖ attempt.to_be_bytes())` truncated/into `[u8;32]` (use the crate's `sha3::Keccak256`; add a `SIGNING_SESSION_DOMAIN` const).
- Produces (in `-server` `db.rs`, prefixes continuing the pinned map):
  - `SigningSessionKey(SigningSessionId)` → `SigningSession { purpose: SigningPurpose, digest: [u8;32], signers: Vec<PeerId>, round: u16, state: SessionState }` (prefix `0x06`)
  - `MpcRoundSeenKey(SigningSessionId, u16, PeerId)` → `Vec<u8>` (the peer's payload) + `MpcRoundSeenSessionRoundPrefix(SigningSessionId, u16)` for per-round lookup (prefix `0x07`)
  - where `pub enum SessionState { InProgress, Completed(Vec<u8> /* compact secp256k1 sig */), Failed }` and `pub enum SigningPurpose { Test([u8;32]) }` (Phase 6a has only a test purpose; Phase 7 adds `DeployAndSweep`/`Withdraw`).

- [ ] **Step 1: Write failing round-trip tests.** In `-common`: encode/decode `UsdtConsensusItem::MpcRound(MpcRoundItem{ session_id: SigningSessionId([7;32]), round: 3, payload: vec![1,2,3] })` and assert equality; assert `signing_session_id(&[9;32], 0)` is deterministic and differs for `attempt=1`. In `-server db.rs`: insert/read-back a `SigningSession` and two `MpcRoundSeenKey` entries, and a `find_by_prefix(&MpcRoundSeenSessionRoundPrefix(id, 2))` returning exactly that round's entries.

- [ ] **Step 2: Run to verify failure.** `cargo test -p fedimint-usdt-common mpc_round signing_session_id` and `cargo test -p fedimint-usdt-server -- db::tests` → FAIL (types absent).

- [ ] **Step 3: Implement the types.** Add the `-common` types (mirror the `DepositObservation`/`derive_deposit_account` style; `signing_session_id` mirrors `derive_deposit_account`'s keccak construction). Add the `-server` DB structs with `impl_db_record!`/`impl_db_lookup!` (mirror `DepositObservationVoteKey`'s dual-prefix pattern for `MpcRoundSeenKey`). Derive `Serialize` on the value structs for `dump_database`.

- [ ] **Step 4: `dump_database` arms** for the two new prefixes (mirror the existing `push_db_pair_items!` arms).

- [ ] **Step 5: Run tests → PASS.** `just format`; `cargo clippy -p fedimint-usdt-server -p fedimint-usdt-common --all-targets` clean; confirm `-common` wasm-safe (`cargo tree -p fedimint-usdt-common -i cggmp21` → not found).

- [ ] **Step 6: Commit.** `feat(usdt): MpcRound consensus item and signing-session DB schema`.

---

## Task 2: Off-thread signing session — spawn + in-memory store + driver slot

**Files:**
- Create: `modules/fedimint-usdt-server/src/signing.rs` (session spawn + slot types)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (module field + wiring)
- Test: inline unit test in `signing.rs`

**Interfaces:**
- Consumes: `ProtocolHandle`, `spawn_protocol`, `EncryptedRoundCodec`, `drive_over_exchange` (threshold-ecdsa); `cggmp21::{signing, DataToSign, ExecutionId, Signature}`; `KeyShare`, `Curve`; config MPC keys.
- Produces:
  - `pub struct SessionSlot { handle: ProtocolHandle<cggmp21::Signature<Curve>>, pending_outgoing: Option<Vec<u8>>, round: u16, done: bool }`
  - `pub type SessionStore = Arc<Mutex<BTreeMap<SigningSessionId, SessionSlot>>>;`
  - `pub fn spawn_signing_session(session_id, digest, signers: &[PeerId], our_peer_id, cfg: &UsdtConfig) -> Option<ProtocolHandle<cggmp21::Signature<Curve>>>` — returns `Some(handle)` if `our_peer_id ∈ signers` (build the `EncryptedRoundCodec` over the subset's enc pubkeys indexed by subset position, derive the fresh `ExecutionId` from `session_id`, `cggmp21::signing(eid, our_subset_pos, &subset_indices, &key_share).sign_sync(...)` inside the `spawn_protocol` closure driven by `drive_over_exchange`), else `None`.
  - `async fn pump_slot_outgoing(slot: &mut SessionSlot)` — if `pending_outgoing.is_none() && !done`, call `handle.next_outgoing().await`; `Some → pending_outgoing = Some(p)`, `None → done = true`.

  NOTE on `subset_indices`: cggmp21 `signing(eid, i, signers, share)` wants `signers: &[u16]` = the KEYGEN indices of the subset parties (their `PeerId`s as `u16`), and `i` = this party's POSITION within that slice. Mirror the spike (`signers = [0,1,3]`, `pos` is the slice index). Here `signers` (keygen indices) = the subset `PeerId`s as `u16` sorted; `our_subset_pos` = position of `our_peer_id` in that sorted subset.

- [ ] **Step 1: Write a failing off-thread-signing unit test.** Mirror the spike test but through `spawn_signing_session` + `pump_slot_outgoing` + a manual poll-all/submit-all pump over N=4/T=3 trusted-dealer shares wrapped in a minimal `UsdtConfig` (build the config via the existing `UsdtInit::trusted_dealer_gen` in tests, extracting each peer's `key_share`/`mpc_encryption_sk` and the shared `mpc_encryption_pks`). Assert the 3 produced signatures verify against the group key. (This proves the module-level wrapper reproduces the spike’s result with real config plumbing.)

- [ ] **Step 2: Run → FAIL.** (functions absent)

- [ ] **Step 3: Implement `signing.rs`** per the interfaces. The `spawn_signing_session` closure body mirrors the spike’s spawned closure but pulls `key_share` from `cfg.private.key_share`, `enc_sk` from `cfg.private.mpc_encryption_sk`, and the subset’s `enc_pks` from `cfg.consensus.mpc_encryption_pks` (indexed by subset position). Add `use` of the threshold-ecdsa items.

- [ ] **Step 4: Add the store to the module.** In `lib.rs`, add `signing_sessions: SessionStore` to `struct Usdt`, initialized empty in `new`/`new_for_test` (mirror `deposit_proposals`). No task spawned yet (the driver is Task 3’s consensus wiring — Phase 6a pumps the slot inline from `process_consensus_item`/`consensus_proposal`; a dedicated pre-drain task is a 6b optimization if needed).

- [ ] **Step 5: Run test → PASS** (foreground; slow). `just format`; clippy clean.

- [ ] **Step 6: Commit.** `feat(usdt): off-thread signing session spawn and in-memory store`.

---

## Task 3: Consensus wiring — propose rounds, collect, submit, complete

**Files:**
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`consensus_proposal`, `process_consensus_item`, a `start_session` helper)
- Test: inline unit test driving the arms directly

**Interfaces:**
- Consumes: Task 1 DB types, Task 2 `SessionStore`/`spawn_signing_session`/`pump_slot_outgoing`.
- Produces:
  - New IN-MEMORY `Usdt` field `completed_signatures: Arc<Mutex<BTreeMap<SigningSessionId, Vec<u8>>>>` (guardian-local; signer-only writes the compact 64-byte sig; read by Task 4's status endpoint). Initialize empty in `new`/`new_for_test`, mirroring `signing_sessions`.
  - `async fn start_session(&self, dbtx, purpose, digest)` — computes `session_id = signing_session_id(&digest, 0)`, subset = lowest-`t` peer ids, writes `SigningSessionKey(session_id) = SigningSession{ purpose, digest, signers: subset, round: 0, state: InProgress }`, and — if `our_peer_id ∈ subset` — `spawn_signing_session` into the store. Idempotent (no-op if the session already exists).
  - `consensus_proposal` addition: for each in-store session where `our_peer_id ∈ signers` and this guardian has NOT yet emitted an `MpcRoundSeenKey(session, round, our_peer_id)` for the current `round`: `pump_slot_outgoing`, and if `pending_outgoing` is ready, push `UsdtConsensusItem::MpcRound(MpcRoundItem{ session_id, round, payload })`.
  - `process_consensus_item` `MpcRound` arm: validate `peer ∈ session.signers` and `round == session.round` (stale/non-subset/duplicate ⇒ `Err`); `insert_new` into `MpcRoundSeenKey(session, round, peer)` (duplicate ⇒ `Err` "redundant MpcRound"); then **if all `session.signers` have a `MpcRoundSeenKey` for `(session, round)`:** bump `session.round += 1` on the `SigningSession` record (DETERMINISTIC — every guardian, signer or not, does exactly this); AND, **iff this guardian is a signer:** collect the round's payloads ordered by ascending subset position, `submit_round` into its slot, clear `pending_outgoing`, `pump_slot_outgoing`, and if the slot is now `done`, `into_output` → store the compact 64-byte signature in the IN-MEMORY `completed_signatures` map and remove the slot from the store.

  **DETERMINISM (this is the Phase-5-CRITICAL class — get it exactly right):** the ONLY consensus-DB writes in this arm are `insert_new(MpcRoundSeenKey)` and the `session.round += 1` bump — both pure functions of consensus-DB state (`MpcRoundSeenKey` presence) + config (`signers`), byte-identical on every guardian. The `!Send`-thread interactions (`submit_round`/`into_output`) and the `completed_signatures` write are guardian-LOCAL IN-MEMORY state that MUST NOT feed any consensus-DB write or the `Ok`/`Err` decision. **The signature is NEVER written to the consensus DB.** Non-signers cannot compute it; writing it (signers do, non-signers don't) would diverge the consensus DB — the exact bug the Phase-5 whole-branch review caught. The consensus `SigningSession` tracks only `round`; `state` stays `InProgress` in 6a. Federation-wide agreement on the final signature (so non-signers also hold it) is a Phase-6b concern (a `MpcSignature` consensus item proposed by a signer, or a read-threshold endpoint).

  **CONCURRENCY (Task-2 review finding):** the `SessionStore`/`completed_signatures` are `Arc<Mutex<..>>`. You call `next_outgoing`/`submit_round`/`into_output` (`.await`) while pumping — do NOT hold a `std::sync::Mutex` guard across those awaits. Since `consensus_proposal`/`process_consensus_item` are invoked SEQUENTIALLY by the consensus loop (never concurrently on the same module), the simplest correct fix is to switch the store to `tokio::sync::Mutex` (await the lock, hold across the pump await safely) — OR take the slot out of the map, drop the guard, pump on the owned slot, re-insert. Pick one and note it.

- [ ] **Step 1: Failing test** driving `start_session` + feeding `MpcRound` items through `process_consensus_item` across all subset peers for each round until completion. Simulate all `n` guardians in one test by holding `n` module instances (each with its own store), including at least one NON-signer (e.g. n=4, subset={0,1,2}, peer 3 is a non-signer), and shuttling every guardian's proposed `MpcRound` items to every other guardian's `process_consensus_item` round by round (the in-test analogue of consensus ordering). Assert: (a) each SIGNER's `completed_signatures[session_id]` holds a signature verifying against the group key; (b) EVERY guardian's `SigningSession.round` advanced to the same final value (signer and non-signer DBs identical) — the determinism guard; (c) the non-signer has NO entry in its `completed_signatures`.

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement** the three pieces. Reuse the block-count redundancy-guard idiom for the `MpcRound` arm. Keep `consensus_proposal`'s existing block-count + deposit drains intact; add the MpcRound drain after them.

- [ ] **Step 4: Run test → PASS** (foreground, slow). `just format`; clippy clean.

- [ ] **Step 5: Commit.** `feat(usdt): drive runtime signing sessions over MpcRound consensus items`.

---

## Task 4: Hermetic acceptance — sign one digest 3-of-4 over a real federation

**Files:**
- Modify: `modules/fedimint-usdt-common/src/endpoint_constants.rs` (a `signing_session_status` endpoint const)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (a test-only `start_session` trigger path + a `signing_session_status` read endpoint returning `Option<compact sig>`; a test-only API or direct `ServerModule` hook to start a session for a hardcoded digest)
- Modify: `modules/fedimint-usdt-tests/tests/tests.rs` (the acceptance test)

**Interfaces:**
- Consumes: Tasks 1–3; the existing shared-mock fixture plumbing (`UsdtInit::with_evm_rpc`) is not needed here (no EVM), but the usdt module + a fedimint-testing federation are.
- Produces: `signing_session_status { session_id } → Option<Vec<u8>>` — reads this guardian's IN-MEMORY `completed_signatures` map (so it returns `Some(sig)` only on a signer guardian that has finished; `None` on non-signers and before completion). NOT read from the consensus `SigningSession.state`. A test-only trigger to call `start_session(purpose = Test(digest), digest)` on every guardian — e.g. a debug API endpoint gated by `is_running_in_test_env()`, or a `pub` method the test invokes through a server hook. Keep it minimal and test-scoped. Because only signers hold the sig, the acceptance must poll the endpoint across guardians until ANY (a signer) returns `Some`.

- [ ] **Step 1: Write the acceptance test.**
```
#[tokio::test(flavor = "multi_thread")]
async fn federation_signs_a_digest_via_mpc() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await; // 4 guardians
    let client = fed.new_client().await;
    let digest = [0x11u8; 32];
    // trigger a signing session for `digest` on all guardians (test-only trigger)
    // ... start session ...
    let session_id = signing_session_id(&digest, 0);
    // poll signing_session_status until a signer returns Some(sig), with a generous deadline
    let sig = poll_until_some(...).await;
    // verify against the federation's group public key (from the group_public_key endpoint)
    let group_pk = client.api()...group_public_key().await?;
    verify_ecdsa(digest, sig, group_pk).expect("MPC signature verifies");
    Ok(())
}
```
The trigger must reach all 4 guardians so the 3 subset members spawn SMs and the consensus loop carries the rounds. If a clean test-only trigger is hard (starting a session isn't client-driven in 6a), use a consensus-item or a debug endpoint on every guardian; document the choice.

- [ ] **Step 2: Run it FOREGROUND** (`cargo test -p fedimint-usdt-tests --test fedimint_usdt_tests federation_signs_a_digest_via_mpc -- --nocapture`). Real MPC over a real federation is slow (minutes) — do NOT background. Iterate until the signature verifies. This is Phase 6a's acceptance ★.
- [ ] If real-timer consensus doesn't carry rounds fast enough within the test's default timeout, that's a genuine finding — report it (do NOT weaken the assertion); a session-driver pre-drain task or a raised timeout may be needed.

- [ ] **Step 3:** `just format`; clippy clean; commit. `test(usdt): federation signs a digest end-to-end via MPC over consensus`.

---

## Self-Review Checklist (run before dispatching Task 1)

- **Spec coverage** (master-plan Phase 6 core): MpcRound items ✓ (T1); off-thread session driven by the validated pump ✓ (T2); consensus_proposal emits / process_consensus_item collects+submits+completes with redundancy guard ✓ (T3); sign-a-known-digest acceptance over a real federation ✓ (T4). Deferred to Phase 6b (documented, not gaps): timeout+block-count-driven retry, deterministic subset ROTATION per attempt, restart/replay, federation-wide agreed signature record (non-signers), latency logging, MpcRound payload-size cap, the Phase-7 real purpose (`DeployAndSweep`/`Withdraw`) trigger.
- **Determinism:** the ONLY consensus-DB writes in the `MpcRound` arm are `insert_new(MpcRoundSeenKey)` and `session.round += 1` — pure functions of consensus DB + config, byte-identical on every guardian. The signature is guardian-LOCAL in-memory (`completed_signatures`, signer-only) and NEVER enters the consensus DB, so signer and non-signer DBs stay identical (the non-signer-can't-compute-the-sig subtlety resolved without divergence; federation-wide sig agreement is 6b). Task 3's test explicitly asserts a non-signer's DB round matches the signers'.
- **No pump reinvention:** Tasks reuse `ProtocolHandle::{next_outgoing, submit_round, into_output}` from `ed5ccfcd942`; no `drive()` for runtime signing.
- **Storage:** session `ProtocolHandle`s live only in the in-memory `SessionStore`; the DB holds metadata + collected payloads + final signature.
- **WASM:** `-common` gains only plain-data `SigningSessionId`/`MpcRoundItem` (no cggmp21); re-checked in T1.
- **Type consistency:** `SigningSessionId`, `MpcRoundItem` field names, `SessionState`/`SigningPurpose` are used identically across T1–T4.
