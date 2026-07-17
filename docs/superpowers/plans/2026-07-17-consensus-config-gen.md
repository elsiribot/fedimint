# Consensus-Coordinated Module Config Generation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement runtime module addition coordinated by consensus (design: `docs/superpowers/specs/2026-07-17-consensus-config-gen-design.md`) on the experimental branch `experimint` in `elsiribot/fedimint`.

**Architecture:** Consensus carries only lifecycle items (`Propose/Approve/Result/Ready/Abort`); DKG itself runs over runtime P2P. Generation state is a persisted, deterministic state machine in the server DB, driven by ordered consensus items. Admin API endpoints inject items via the existing `submission_sender`.

**Tech Stack:** Rust workspace; fedimint-core (wire types), fedimint-server (engine/state machine/API), existing G1/G2 DKG code, existing scheduled-shutdown mechanism.

## Global Constraints

- Branch: `experimint` on remote `elsiribot` (fork of fedimint/fedimint). Experimental: all peers are assumed to run this branch (old peers panic on the new `ConsensusItem` variant — engine.rs:1071; production landing requires `CoreConsensusVersion` gating, out of scope here).
- Never `unwrap()` outside tests; `expect()` with reason (CLAUDE.md).
- Structured tracing logging; `just clippy` and `just format` before every commit.
- Consensus-item processing MUST be deterministic: reject via `bail!` only on conditions all honest peers evaluate identically (no wall-clock, no I/O).
- New server DB prefix: `ConfigGeneration = 0x09` (0x03 is historically burned; 0x01–0x08 taken).
- One active generation at a time; `ModuleGenerationId`s are monotonic and single-use.

## Status (2026-07-17)

- **Phase 1: DONE** — `ConfigGen` consensus item (`Propose/Approve/Result/Abort`), persisted `GenerationLog` state machine (`Proposed → Approved → Generated | Aborted`), engine processing under db prefix 0x09, admin endpoints (`propose/approve/abort_module_generation`, `module_generations`) at api version 0.10.
- **Phase 2: DONE** — `P2PMessage::ConfigGen` variant, `GenerationTransport` (implements `IP2PConnections`, so `PeerHandle` + module `distributed_gen` run unchanged), aleph network loop forwards to a long-lived channel, `GenerationManager` runs DKGs on approval, stores private config locally (prefixes 0x0a/0x0b), submits `Result`, aborts crashed generations. Deviation from the design doc: `Result` does not yet carry the encrypted private config — that lands with root-secret derivation in Phase 3, keeping plaintext-adjacent material out of consensus in the meantime.
- **Phase 4: DONE** — activation via coordinated restart: `Activate` item deterministically assigns instance ids (above the static range) and an `active_from_session` (item session + 2); processing it schedules the existing shutdown-at-session mechanism on every guardian. Startup loads activated modules from the generation log + local outcome, extends db decoders (`Database::with_decoders`), and the engine rejects module items/txs before their activation session. `FederationTest::restart_all_peers` supports the restart in-process.
- **Acceptance suite** (run after every phase):
  - Unit: `cargo test -p fedimint-server config_gen` — state machine transitions (incl. activation/instance-id allocation), transport demultiplexing, encryption round-trip (17 tests)
  - E2E: `cargo nextest run -p fedimint-mint-tests --test fedimint_mint_config_gen_tests` — real in-process federations (AlephBFT + p2p + api): generation to `Generated` + recovery decryption, abort + retry, unsupported-kind abort, and full activation journey through coordinated restart with audit verification (4 tests, ~100s). **Must run under nextest**: `is_running_in_test_env()` is false under plain `cargo test` for integration binaries, which silently switches consensus to production session timing (15 min/session instead of 10 s).
  - Regression: `just clippy` and the existing suite via `just test-ci-all` (new tests are ordinary cargo test targets, so CI picks them up automatically)
- **Phase 3 (partial): DONE** — encrypted Result commitment: per-generation ChaCha20-Poly1305 keys derived from a domain-separated config-gen root (`consensus/config_gen/secrets.rs`), encrypted private configs carried in Result items (bounded at 40KB, below the 50KB aleph unit limit) and retained in `Generated` state for recovery; e2e test decrypts a peer's committed config from another peer's log. Root is derived from the broadcast secret key as a **placeholder for a guardian BIP39 mnemonic** — swapping the source only changes `config_gen_root()`. Still open from Phase 3: deterministic module-gen randomness (`ModuleConfigGenSecret` injected into `distributed_gen`, fixing wallet `OsRng` restart-sensitivity).
- **Phase 5: DONE** — client visibility: the served client config and advertised api-version summary cover dynamic modules; the client's additive refresh (already threshold-attested via `request_current_consensus`) stores the new config as pending and promotes it on next start, now also invalidating the cached api-version negotiation so the new instance initializes. E2E: client joins pre-activation-config, refreshes, reopens, and has the dynamic mint instance running.
- **Next:** guardian dashboard UI for the flow; hot (no-restart) activation; genesis commit for existing federations; bootstrap-only setup; guardian recovery flow. Phase 3 remainder (deterministic gen randomness) stays deferred — abort-and-retry makes it non-blocking. devimint exercise deferred — the in-process e2e covers the full stack except process boundaries.

## Phasing (master plan)

Deviation from the design's production sequence, deliberately: on this experimental branch we de-risk the novel protocol core first; the configs-to-DB refactor and client attestation (design steps 1–2) come after the protocol works end-to-end. The design doc's sequence remains the plan of record for production PRs.

- **Phase 1 (detailed below):** Core lifecycle over consensus — `ConfigGen` consensus item, persisted generation state machine (`Proposed → Approved → Aborted`), admin propose/approve/abort/status endpoints. No DKG yet.
- **Phase 2:** Runtime DKG transport — a `PeerHandleOps` implementation over the running federation's P2P connections, namespaced by `ModuleGenerationId`; generation worker task that starts on `Approved`, runs the module's unchanged `distributed_gen`, and submits `Result`. States `Running → Generated`.
- **Phase 3:** Guardian root secret derivation (`ModuleConfigGenSecret(root, generation_id)`), encrypted private config in `Result`, `Ready` with agreed config hash and `active_from_session`.
- **Phase 4:** DB-resident module configs + monotonic instance-ID allocator; activation via coordinated restart riding scheduled shutdown; server loads DB-resident modules alongside `consensus.json` genesis modules at startup.
- **Phase 5:** Client config revisions: regenerate client config on activation, wire the dormant additive-refresh path, threshold attestation.
- **Phase 6+:** Genesis commit for existing federations; bootstrap-only setup; hot activation; recovery flow (per design).

---

### Task 1: Wire types in fedimint-core

**Files:**
- Create: `fedimint-core/src/config_gen.rs`
- Modify: `fedimint-core/src/lib.rs` (add `pub mod config_gen;`)
- Modify: `fedimint-core/src/epoch.rs` (new `ConsensusItem` variant)

**Interfaces:**
- Produces: `ModuleGenerationId(pub u64)`; `ModuleConfigProposal { module_kind: ModuleKind, consensus_version: ModuleConsensusVersion, network: Network, disable_base_fees: bool }`; `ConfigGenAbortReason(pub String)`; `enum ConfigGenItem { Propose { generation_id, proposal }, Approve { generation_id }, Abort { generation_id, reason } }`; `ConsensusItem::ConfigGen(ConfigGenItem)`.

- [ ] **Step 1: Write encode/decode round-trip test** in `fedimint-core/src/config_gen.rs` `#[cfg(test)]`:

```rust
#[test]
fn config_gen_item_roundtrip() {
    let item = ConfigGenItem::Propose {
        generation_id: ModuleGenerationId(0),
        proposal: ModuleConfigProposal {
            module_kind: ModuleKind::from_static_str("mint"),
            consensus_version: ModuleConsensusVersion::new(2, 0),
            network: Network::Regtest,
            disable_base_fees: false,
        },
    };
    let bytes = item.consensus_encode_to_vec();
    let decoded = ConfigGenItem::consensus_decode_whole(&bytes, &Default::default()).expect("decodes");
    assert_eq!(item, decoded);
}
```

- [ ] **Step 2: Implement types** (derive `Encodable, Decodable, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize`; `ModuleGenerationId` also `Copy, Ord`). Add `ConfigGen(ConfigGenItem)` to `ConsensusItem` *before* the `#[encodable_default] Default` variant.

- [ ] **Step 3:** `cargo test -p fedimint-core config_gen` → PASS. Check `DebugConsensusItem`/any exhaustive matches on `ConsensusItem` across the workspace compile: `cargo check -q`.

- [ ] **Step 4:** Commit `feat(core): add ConfigGen consensus item wire types`.

### Task 2: Deterministic generation state machine (server, pure)

**Files:**
- Create: `fedimint-server/src/consensus/config_gen.rs`
- Modify: `fedimint-server/src/consensus/mod.rs` (declare module)

**Interfaces:**
- Consumes: Task 1 types.
- Produces:
  - `enum GenerationState { Proposed { proposal: ModuleConfigProposal, proposer: PeerId, approvals: BTreeSet<PeerId> }, Approved { proposal: ModuleConfigProposal }, Aborted { reason: ConfigGenAbortReason } }` (Encodable/Decodable for DB).
  - `struct GenerationLog { next_id: ModuleGenerationId, generations: BTreeMap<ModuleGenerationId, GenerationState> }` helpers.
  - Pure transition: `pub fn process_item(num_peers: NumPeers, log: &mut GenerationLog, item: ConfigGenItem, peer: PeerId) -> anyhow::Result<()>`.

Transition rules (each violation → `bail!`, deterministic):
- `Propose`: rejected unless `generation_id == log.next_id` and no generation is currently `Proposed`/`Approved`-but-unfinished (Phase 1: no generation in `Proposed` state; `Approved` is terminal-for-now and does not block — revisit in Phase 2 when `Approved` leads to `Running`). Proposer's approval is implicit (inserted on propose). On accept: `next_id += 1`.
- `Approve`: only for an existing generation in `Proposed`; duplicate approval from the same peer → `bail!`; when `approvals.len() == num_peers.total()` → `Approved`.
- `Abort`: any guardian, only while `Proposed`; → `Aborted`.

- [ ] **Step 1: Write unit tests first** covering: full propose→approve-by-all→`Approved`; duplicate approve rejected; approve for unknown id rejected; second propose while one is `Proposed` rejected; abort then re-propose with incremented id succeeds; propose with stale id rejected.
- [ ] **Step 2:** Implement; `cargo test -p fedimint-server config_gen` → PASS.
- [ ] **Step 3:** Commit `feat(server): config generation lifecycle state machine`.

### Task 3: DB persistence + engine wiring

**Files:**
- Modify: `fedimint-server/src/db.rs` (prefix `ConfigGeneration = 0x09`, `ConfigGenerationLogKey` → `GenerationLog`)
- Modify: `fedimint-server/src/consensus/engine.rs` (`process_consensus_item_with_db_transaction`: new match arm)

**Interfaces:**
- Consumes: `process_item` from Task 2.
- Produces: `ConsensusItem::ConfigGen` handled: load `GenerationLog` (default empty), apply `process_item`, persist on success, propagate `Err` to reject the item. Replaces the current fall-through-to-panic path for this variant.

- [ ] **Step 1:** Add DB key (follow `GuardianMetadata` pattern, `impl_db_record!`/`impl_db_lookup!`).
- [ ] **Step 2:** Add match arm; `cargo check -q`.
- [ ] **Step 3:** Commit `feat(server): persist config generation state from consensus items`.

### Task 4: Admin API endpoints

**Files:**
- Modify: `fedimint-core/src/endpoint_constants.rs` (add `PROPOSE_MODULE_GENERATION_ENDPOINT`, `APPROVE_MODULE_GENERATION_ENDPOINT`, `ABORT_MODULE_GENERATION_ENDPOINT`, `MODULE_GENERATIONS_ENDPOINT`)
- Modify: `fedimint-server/src/consensus/api.rs` (four endpoints in `server_endpoints()`)

**Interfaces:**
- Consumes: `submission_sender`, `check_auth` (follow `SHUTDOWN_ENDPOINT` pattern, api.rs:939), `GenerationLog` from DB.
- Produces:
  - `propose_module_generation(ModuleConfigProposal) -> ModuleGenerationId`: auth; reads `GenerationLog` to compute `next_id`; submits `ConfigGen(Propose)`.
  - `approve_module_generation(ModuleGenerationId) -> ()`: auth; submits `Approve`.
  - `abort_module_generation({ id, reason }) -> ()`: auth; submits `Abort`.
  - `module_generations() -> BTreeMap<ModuleGenerationId, GenerationStateSummary>`: auth; DB read (serde-serializable summary type, since `GenerationState` contains `PeerId` keys fine for serde).

- [ ] **Step 1:** Implement endpoints; `cargo check -q`.
- [ ] **Step 2:** `just clippy`; fix warnings.
- [ ] **Step 3:** Commit `feat(server): admin endpoints for module config generation`.

### Task 5: Phase-1 integration check & push

- [ ] **Step 1:** `just format`, `just clippy`, `cargo test -p fedimint-core -p fedimint-server` → PASS.
- [ ] **Step 2:** Optional smoke: `just devimint-env` boots a federation (no generation proposed) — confirms no regression from the new variant/arm.
- [ ] **Step 3:** Commit docs (`docs/superpowers/specs/...`, this plan), push `experimint` to `elsiribot`.

---

### Phase 2 sketch (next detailed plan)

Runtime `PeerHandleOps`: explore `fedimint-server/src/net/p2p*` `Message` enum; add a `ConfigGen(ModuleGenerationId, Vec<u8>)` message variant routed to a per-generation worker channel; implement `struct RuntimePeerHandle` wrapping it with the same round semantics as `fedimint-server/src/config/peer_handle.rs`; worker spawned from a `GenerationState::Approved` observer; on completion submit `ConfigGen(Result { .. })`. Exercise `exchange_bytes` peer-to-peer in a devimint test before wiring real module `distributed_gen`.
