# Hot Module Activation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Activate a dynamically generated module at its target session without restarting fedimintd.

**Architecture:** The consensus semantics stay exactly as they are: the `Activate` item pins
`active_from_session = S + ACTIVATION_SESSION_MARGIN` and the generation log is the source of
truth. What changes is the *executor*: instead of scheduling a shutdown at session
`active_from_session - 1`, the consensus engine initializes the module itself between sessions
(the only deterministic, single-threaded point in the process) and publishes a new module-set
snapshot on a watch channel. A refresher task rebuilds the API surface (`ConsensusApi`,
websocket `RpcModule`, iroh endpoint map, dashboard router) from each snapshot. The existing
startup init-from-log path is untouched and remains the crash/offline-guardian catch-up path —
hot activation must produce byte-identical state to a restart, which is the core invariant every
test asserts.

**Tech Stack:** tokio `watch` channel for snapshots, existing jsonrpsee/axum/iroh servers
(stopped and respawned in-process), existing `GenerationLog`/`ACTIVATION_SESSION_MARGIN`
machinery.

## Global Constraints

- **No wire changes.** `ConfigGenItem`, the generation state machine
  (`fedimint-server/src/consensus/config_gen/mod.rs`), and `ACTIVATION_SESSION_MARGIN = 2` are
  untouched. All 18 existing state machine unit tests must pass unmodified.
- **Startup path is the invariant check.** A guardian that was down during activation must
  arrive at the same state via the existing startup init-from-log path as a guardian that
  hot-activated. Never fork the module init logic — extract and share it.
- `ensure_module_active` session gating in `fedimint-server/src/consensus/engine.rs` stays: items
  for the new instance before `active_from_session` are rejected either way.
- Run `just format` after every task; `just clippy` must be clean before each commit.
- E2E tests run via `cargo nextest run` only (plain `cargo test` gets production session timing).
- Branch: `experimint` (worktree `~/experimint-wt`).

## Current State (what each task changes)

| Component | Today | After |
|---|---|---|
| `ConsensusEngine::modules`, `db` | fixed at construction | mutated between sessions by the engine itself |
| `Activate` processing (engine.rs ~1134) | `shutdown_sender.send_replace(Some(active_from_session - 1))` | record pending activation, no shutdown |
| Module init for dynamic modules | inline in startup (`fedimint-server/src/consensus/mod.rs`, the init-from-log block) | shared `DynModuleActivator` used by startup *and* engine |
| `ConsensusApi` | built once, cloned into ws/iroh/dashboard | rebuilt per snapshot by refresher task |
| ws API (`start_consensus_api`) | started once | stopped + respawned per snapshot (~sub-second blip) |
| iroh API (`run_iroh_api`) | builds `module_api` map once from `consensus_api` | rebuilds handler map on snapshot change, iroh `Endpoint` kept alive (no blip) |
| dashboard axum server | started once | stopped + respawned per snapshot |
| CI proposal submitters | spawned once at startup | additionally spawned by activator for new instance |

---

### Task 1: Extract shared dynamic-module initialization (`DynModuleActivator`)

**Files:**
- Create: `fedimint-server/src/consensus/config_gen/activation.rs`
- Modify: `fedimint-server/src/consensus/mod.rs` (startup init-from-log block and CI submitter loop)
- Modify: `fedimint-server/src/consensus/config_gen/mod.rs` (add `pub mod activation;`)

**Interfaces:**
- Produces: `pub struct DynModuleActivator` holding everything module init needs
  (`module_inits: ServerModuleInitRegistry`, `server_cfg` bits, `task_group: TaskGroup`,
  `submission_sender: Sender<ConsensusItem>`, `dyn_server_bitcoin_rpc`), with
  `pub async fn init_module(&self, db: &Database, active: &ActiveModule) -> anyhow::Result<(ModuleInstanceId, DynServerModule, Decoder)>`
  (runs DB migrations, builds `ServerModuleConfig` from the stored private/consensus configs,
  calls the module init — exactly the code currently inline at startup) and
  `pub fn spawn_ci_submitter(&self, db: Database, instance_id: ModuleInstanceId, kind: ModuleKind, module: DynServerModule)`
  (wraps the existing `submit_module_ci_proposals`).

- [ ] **Step 1:** Move the per-module body of the startup init-from-log loop into
  `DynModuleActivator::init_module`, and `submit_module_ci_proposals` invocation into
  `spawn_ci_submitter`. Startup constructs one activator and uses it for the loop; behaviour
  identical.
- [ ] **Step 2:** `cargo check -q`, then `cargo nextest run -p fedimint-server --lib` (all unit
  tests pass) and the existing e2e
  `cargo nextest run -E 'test(activated_module_runs_after_restart)'` to prove the startup path
  is unchanged.
- [ ] **Step 3:** `just format`, commit `refactor: extract dynamic module activator`.

### Task 2: Engine applies activations between sessions

**Files:**
- Modify: `fedimint-server/src/consensus/engine.rs`
- Modify: `fedimint-server/src/consensus/mod.rs` (pass activator + snapshot sender into engine)

**Interfaces:**
- Consumes: `DynModuleActivator` from Task 1.
- Produces: `pub struct ModuleSetSnapshot { pub modules: ServerModuleRegistry, pub db: Database, pub generation_log: GenerationLog }`
  published on `watch::Sender<ModuleSetSnapshot>` (new engine field `snapshot_sender`), with the
  initial value published before consensus starts.

- [ ] **Step 1:** Change `ConsensusEngine::run(self)` and the two session loops to `mut self`
  so `self.modules` / `self.db` can be replaced between sessions (no locking — the engine is the
  single writer, everyone else consumes snapshots).
- [ ] **Step 2:** In the `Activate` arm of `process_consensus_item_with_db_transaction`, replace
  the `shutdown_sender.send_replace(...)` with inserting into `self.dynamic_module_activation`
  only (which the arm already does for gating). Delete the restart scheduling and its comment.
- [ ] **Step 3:** Add `async fn apply_pending_activations(&mut self, next_session: u64)` called
  at the top of both `run_single_guardian` and `run_consensus` loop bodies, before
  `run_session`/the item loop: read `GenerationLog` from db; for every generation in state
  `Active` with `active_from_session <= next_session` whose `instance_id` is not in
  `self.modules`, call `activator.init_module`, insert into `self.modules`, extend decoders via
  `self.db = self.db.with_decoders(...)`, `activator.spawn_ci_submitter(...)`, and log
  `info!(target: LOG_CONSENSUS, %generation_id, instance_id, "Hot activated module")`. Then
  `snapshot_sender.send_replace(ModuleSetSnapshot { ... })` if anything changed.
  (`<=` not `==`: covers an engine that fell behind, e.g. long session recovery.)
- [ ] **Step 4:** `cargo nextest run -p fedimint-server --lib` — unit tests green.
- [ ] **Step 5:** `just format`, commit `feat: hot activate modules between consensus sessions`.

### Task 3: API refresher — rebuild ConsensusApi/ws/iroh/dashboard per snapshot

**Files:**
- Modify: `fedimint-server/src/consensus/mod.rs` (extract `build_consensus_api(snapshot, ...) -> ConsensusApi` from the current construction incl. the client-config/api-version extension code; add refresher task)
- Modify: `fedimint-server/src/net/api/mod.rs` only if `spawn` needs a rebuild-friendly signature (it should not)

**Interfaces:**
- Consumes: `watch::Receiver<ModuleSetSnapshot>` from Task 2.
- Produces: a `task_group` task `api-refresher`:
  ```rust
  loop {
      // (re)build api surface from the current snapshot
      let api = build_consensus_api(&snapshot_receiver.borrow().clone(), ...);
      let ws_handle = start_consensus_api(cfg, api.clone(), secrets.clone(), api_bind).await;
      let dashboard_handle = spawn_dashboard(api.clone().into_dyn(), ui_bind).await;
      iroh_handlers_tx.send_replace(build_iroh_handlers(&api)); // Step 3
      if snapshot_receiver.changed().await.is_err() { break; }
      ws_handle.stop()?; ws_handle.stopped().await;
      dashboard_handle.shutdown().await;
  }
  ```

- [ ] **Step 1:** Extract `build_consensus_api` so startup and refresher share one construction
  path (client config extension, `supported_api_versions_summary`, module registry, db handle
  all derived from the snapshot + static startup context).
- [ ] **Step 2:** Move the initial ws/dashboard spawn into the refresher's first iteration so
  there is exactly one code path. The dashboard axum server gets a shutdown trigger
  (`with_graceful_shutdown` on a oneshot/watch instead of the task-group handle) and rebinds its
  `TcpListener` each iteration.
- [ ] **Step 3:** Restructure `run_iroh_api`: instead of building `module_api` once at line
  ~614, hold a `watch::Receiver<Arc<IrohApiHandlers>>` (the `ConsensusApi` + endpoint map) and
  resolve per incoming request from `borrow().clone()`. The iroh `Endpoint` is created once and
  never dropped — no connectivity blip, no more ungraceful endpoint drops on activation.
- [ ] **Step 4:** Manual smoke: start a solo fed, propose+activate a module, confirm in the log
  that no `SUPERVISOR: fedimintd exited` line appears and the module card renders after refresh.
- [ ] **Step 5:** `just format`, `just clippy`, commit `feat: rebuild api surface on module activation`.

### Task 4: E2E tests (nextest)

**Files:**
- Modify: `modules/fedimint-mint-tests/tests/config_gen_tests.rs`

- [ ] **Step 1:** New test `activated_module_runs_without_restart`: propose → (auto/all)
  approve → activate → wait until sessions pass `active_from_session` **without calling
  `restart_all_peers`** → assert audit contains the instance, a client that joins afterwards
  sees and can use the module, and the module's `module_{id}_*` ws endpoints answer.
- [ ] **Step 2:** Repurpose `activated_module_runs_after_restart` as the offline-guardian
  catch-up test: stop one peer before the activation session, let the rest hot-activate,
  restart the stopped peer, assert it initializes the module via the startup path and rejoins
  consensus (state parity with the hot-activated peers via matching audit).
- [ ] **Step 3:** `cargo nextest run -E 'binary(fedimint_mint_config_gen_tests)'` green.
- [ ] **Step 4:** Commit `test: hot activation and offline guardian catch up`.

### Task 5: UI smoke + docs

**Files:**
- Modify: `scripts/dev/config-gen-ui-smoke.sh` (activate via dashboard; poll the dashboard every
  2s through the activation window and fail on any non-200 — proving no restart gap; assert the
  module row flips to `Active`)
- Modify: `docs/superpowers/specs/2026-07-17-consensus-config-gen-design.md` (activation section:
  restart → hot) and the master plan status section

- [ ] **Step 1:** Update + run the smoke script inside `just devimint-env`.
- [ ] **Step 2:** Update docs, commit `docs: hot module activation`.

## Explicitly out of scope

- Removing a module at runtime (deactivation) — separate design.
- Client-side changes — none needed; clients already refresh config additively (Phase 5).
- The supervisor loop for the demo fed stays (it now only matters for crashes/upgrades).

## Risks / watch-outs

- **ws blip visibility:** clients with open websockets get disconnected on the ws respawn;
  `fedimint-client` reconnects transparently. The e2e client-usage assertion in Task 4 covers it.
- **Snapshot vs. old `ConsensusApi` clones:** any component still holding a pre-activation
  `ConsensusApi` serves a stale module list until the refresher replaces it; the refresher is the
  only spawner of such components after Task 3 Step 2, which is why the initial spawn must move
  into it.
- **Engine `mut self`:** touching the engine loop signature ripples into `consensus/mod.rs`
  call sites only; keep the diff mechanical.
