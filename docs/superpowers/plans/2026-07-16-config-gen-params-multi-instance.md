# Phase 4.5: Config-Gen Params + Multi-Instance Modules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Reintroduce per-module typed config-gen params (removed by joschisan in `194b14e6e47`) and generalize config-gen so a federation can run **multiple instances of the same module kind** with different params — e.g. two mintv2 instances (Bitcoin-denominated + USDT-denominated). This is general infrastructure (elsirion wants it beyond USDT) and the prerequisite for Phase 5's USDT minting.

**Architecture:** Restore the pre-removal mechanism (the exact code is in git history at `194b14e6e47^`) and adapt it to the current tree, keeping joschisan's good additions. Design settled with elsirion:
- **Hybrid args + params:** keep `ConfigGenModuleArgs { network, disable_base_fees }` for federation-wide settings AND reintroduce `type Params` on `ServerModuleInit` for per-instance module settings. Config-gen methods become `(peers, args, params)`.
- **Instance-list subsumes `enabled_modules`:** the reintroduced `ServerModuleConfigGenParamsRegistry` (`BTreeMap<ModuleInstanceId, (ModuleKind, ConfigGenModuleParams)>`) is the source of truth for which instances exist and their params, replacing the `enabled_modules: BTreeSet<ModuleKind>` filter. Instance ids are assigned deterministically (by the registry's `append_module` auto-increment, or explicit `register_module`).

**Tech stack:** Rust edition 2024; `fedimint-core`, `fedimint-server-core`, `fedimint-server`, `fedimintd`, `fedimint-testing`, all module crates.

## Global Constraints

- **This touches core Fedimint infrastructure across ~36 files** (matching the scale of the removal commit). It is a cross-cutting trait-signature change, so the workspace only compiles once all impls are updated together — Task 1 is intentionally large and atomic. **Do NOT rebase onto upstream** (decision: current base; rebase pre-PR).
- **Reference the pre-removal code directly:** `git show 194b14e6e47^:<path>` shows the exact known-good mechanism to port. Prefer porting-and-adapting over reinventing. Key pre-removal files: `fedimint-server-core/src/init.rs` (trait), `fedimint-core/src/config.rs` (`ConfigGenModuleParams`, `ServerModuleConfigGenParamsRegistry`, attach methods), `fedimint-server/src/config/mod.rs` (the two config-gen loops iterating `modules.iter_modules()`), each `modules/fedimint-*-common/src/config.rs` (`*GenParams`) + `*-server/src/lib.rs` (`type Params`).
- **Keep joschisan's good additions:** `ConfigGenModuleArgs` (for the hybrid), `is_enabled_by_default()`, `iter_legacy_order()` / `FM_BACKWARDS_COMPATIBILITY_TEST`, the `FM_ENABLE_MODULE_*` env gates.
- **Preserve behavior for existing federations:** after Task 1, a default federation must config-gen identically (single instance per enabled-by-default kind, same instance ids under legacy order, same module configs). Existing tests must pass unchanged.
- **Never `unwrap()`/`panic!` in non-test code** — except the existing `attach_config_gen_params` panic-on-invalid-serialization (that's the pre-removal behavior; keep it or make it return Result — prefer keeping parity).
- `just format`; before each commit `cargo clippy -q --locked --offline -p <crate> --all-targets -- -D warnings` (NOT `just lint`; skip clippy on `*-tests` crates due to the pre-existing lnv2-client dead_code issue). `just cargo-sort-check`.
- Broad build check after the big task: `cargo check --workspace` must pass (this change touches the whole workspace, so a per-crate check is insufficient).

## Pinned interfaces (the target shape)

```rust
// fedimint-server-core/src/init.rs
#[derive(Debug, Clone, Copy)]
pub struct ConfigGenModuleArgs { pub network: Network, pub disable_base_fees: bool } // KEEP (joschisan)

pub trait ServerModuleInit: ModuleInit + Sized {
    type Module: ServerModule + Send + Sync;
    type Params: serde::de::DeserializeOwned;                          // REINTRODUCED
    // ...
    fn parse_params(&self, params: &ConfigGenModuleParams) -> anyhow::Result<Self::Params> {
        serde_json::from_value(params.clone()).context("Failed to parse module params")
    }
    fn trusted_dealer_gen(&self, peers: &[PeerId], args: &ConfigGenModuleArgs, params: &Self::Params)
        -> BTreeMap<PeerId, ServerModuleConfig>;                        // HYBRID: args + typed params
    async fn distributed_gen(&self, peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs, params: &Self::Params) -> anyhow::Result<ServerModuleConfig>;
    // validate_config, get_client_config, ... unchanged
}
// object-safe IServerModuleInit takes erased params + args; blanket impl parses then calls typed:
//   fn trusted_dealer_gen(&self, peers, args, params: &ConfigGenModuleParams) -> ... {
//       let typed = <Self as ServerModuleInit>::parse_params(self, params)?; // (make validate return Result)
//       <Self as ServerModuleInit>::trusted_dealer_gen(self, peers, args, &typed) }

// fedimint-core/src/config.rs (REINTRODUCED, port from 194b14e6e47^)
pub type ConfigGenModuleParams = serde_json::Value;
pub type ServerModuleConfigGenParamsRegistry = ModuleRegistry<ConfigGenModuleParams>;
impl ModuleRegistry<ConfigGenModuleParams> {
    pub fn attach_config_gen_params_by_id<T: Serialize>(&mut self, id: ModuleInstanceId, kind: ModuleKind, gen: T) -> &mut Self; // explicit id
    pub fn attach_config_gen_params<T: Serialize>(&mut self, kind: ModuleKind, gen: T) -> &mut Self;                              // auto id (append_module)
    /// NEW convenience: build from a Vec, auto-assigning ids by position.
    pub fn from_instances<T: Serialize>(instances: Vec<(ModuleKind, T)>) -> Self;
}
```

`ModuleRegistry::append_module` / `register_module` (in `fedimint-core/src/module/registry.rs`) already exist and support the `BTreeMap<ModuleInstanceId,(ModuleKind,M)>` model — no change needed there.

---

### Task 1: Reintroduce core params types + trait + all-module updates + config-gen + wiring

**This is the large atomic task.** Port the pre-removal mechanism forward, adapting to the current tree. The workspace won't compile until every `ServerModuleInit` impl and every config-gen call site is updated, so this is one task ending in a green `cargo check --workspace`.

**Files (mirrors the removal commit's 36-file footprint):**
- `fedimint-core/src/config.rs` — reintroduce `ConfigGenModuleParams`, `ServerModuleConfigGenParamsRegistry`, `attach_config_gen_params*`, `from_instances`; re-add the `ServerModuleConfigGenParamsRegistry` field to `ConfigGenSettings`/`ConfigGenParams` where the pre-removal code had it.
- `fedimint-server-core/src/init.rs` — reintroduce `type Params` + `parse_params` on `ServerModuleInit`; change `trusted_dealer_gen`/`distributed_gen` to `(peers, args, params)` (typed) and the object-safe mirror to erased params; update the blanket impl to `parse_params` then delegate. Keep `ConfigGenModuleArgs`, `is_enabled_by_default`, `default_modules()`.
- `fedimint-server/src/config/mod.rs` — change the two config-gen loops (`trusted_dealer_gen`/`distributed_gen`) to iterate the **params registry** (`modules.iter_modules()` → `(module_id, kind, params)`), look up the init by `kind` in the `ServerModuleInitRegistry`, take the instance id from the registry key, and pass `(args, params)`. This replaces the `.filter(enabled_modules).enumerate()` scheme. Preserve legacy ordering: the params registry built for a default federation must produce the same ids as before (see Step 5).
- `fedimint-server/src/config/setup.rs` — build the params registry (instead of the `enabled_modules` set) from defaults; keep the env/UI enable flow mapping onto "which instances are in the registry".
- `fedimintd/src/lib.rs` — `default_modules()` returns a params registry (each enabled-by-default module attached with its default params, as pre-removal did: e.g. `attach_config_gen_params(MintCommonInit::KIND, MintGenParams::new(...))`); update `run()`'s `modules_fn` signature; wire `ConfigGenSettings`.
- `fedimint-testing/src/fixtures.rs` + `fedimint-testing-core/src/config.rs` — `with_module`/`with_server_only_module`/`new_primary` take a `params: impl Serialize` again (port from `194b14e6e47^`); track the incrementing id.
- Every module `modules/fedimint-{mint,mintv2,wallet,ln,lnv2,meta,dummy,empty,unknown,usdt}-*`:
  - `*-common/src/config.rs`: reintroduce the module's `*GenParams` where it had one (mint: `MintGenParams { denomination_base, fee_consensus }`; ln/lnv2/wallet: port their pre-removal GenParams **minus** `network` which now comes from `args`). Modules with no per-instance params (empty, unknown, meta, dummy, usdt for now) use `type Params = ()`.
  - `*-server/src/lib.rs`: set `type Params = <that GenParams or ()>`; change `trusted_dealer_gen`/`distributed_gen` signatures to `(peers, args, params)`; use `params` where the pre-removal code did (e.g. mint's `params.gen_denominations()`), and keep using `args.network`/`args.disable_base_fees` for the federation-wide bits.
- `gateway/fedimint-gateway-server/tests/tests.rs`, module `*-tests/tests/tests.rs` — update fixture calls to pass params (port from `194b14e6e47^`).

- [ ] **Step 1: Study the pre-removal mechanism.** For each file above, diff current vs pre-removal: `git show 194b14e6e47^:<path>` and `git show 194b14e6e47:<path>` (the removal's after-state) to see exactly what changed. The reintroduction is largely the inverse, PLUS the hybrid adaptation (keep `args`, add typed `params`) and PLUS keeping joschisan's `enabled_modules`→instance-list, `is_enabled_by_default`, legacy-order additions. Write down the per-file adaptation before editing.

- [ ] **Step 2: Core types first.** Reintroduce `ConfigGenModuleParams` + `ServerModuleConfigGenParamsRegistry` + attach methods + `from_instances` in `fedimint-core/src/config.rs`. Then the trait change in `fedimint-server-core/src/init.rs` (type Params, parse_params, hybrid signatures, object-safe mirror + blanket impl). At this point the workspace will NOT compile (all module impls are stale) — that's expected; proceed to update all impls before checking.

- [ ] **Step 3: Update every module impl** to the new signature + `type Params`. For modules with real params, reintroduce the `*GenParams` (port, drop `network`). For paramless modules, `type Params = ()` and ignore `params`. Use `args.network`/`args.disable_base_fees` for the federation-wide values everywhere they were used post-removal.

- [ ] **Step 4: Update config-gen loops** in `fedimint-server/src/config/mod.rs` to iterate the params registry (port the pre-removal `modules.iter_modules().map(|(id, kind, params)| registry.get(kind).trusted_dealer_gen(peers, &args, params))` pattern), taking `args` from the current `ConfigGenModuleArgs` construction. Reconcile `distributed_gen` similarly.

- [ ] **Step 5: Wire fedimintd + setup + fixtures.** `default_modules()` → params registry with default params per enabled-by-default module. **Critical for behavior preservation:** the default params registry must assign the SAME instance ids as the current `.enumerate()` scheme did for a default federation (so existing DBs/tests don't break). Build the default registry by iterating the init registry in the SAME order the current code uses (legacy order when `FM_BACKWARDS_COMPATIBILITY_TEST`, else kind-sorted) and `append_module`-ing each — this reproduces the id assignment. Update `setup.rs` to carry the params registry, and `fixtures.rs` `with_module(params)`.

- [ ] **Step 6: Compile the whole workspace.** `cargo check --workspace` — must pass. Fix all impls until green. (This is the atomicity gate.)

- [ ] **Step 7: Run the existing config-gen + module tests** to prove behavior preserved: `cargo test --release -p fedimint-usdt-server` (our DKG test — uses the config-gen path), `cargo test --release -p fedimint-mint-tests` (or a lighter mint config test), and any `fedimint-server` config-gen unit tests. Existing federations must config-gen identically. Report which tests you ran + results.

- [ ] **Step 8: Format, lint, commit.** `just format`; `cargo clippy` on the core crates touched (`fedimint-core`, `fedimint-server-core`, `fedimint-server`, `fedimintd`, and each module server crate) `-- -D warnings`; `just cargo-sort-check`. Commit: `feat(config): reintroduce typed config-gen params (hybrid with args)`

---

### Task 2: Multi-instance capability + test

**Files:** a test crate (e.g. `fedimint-testing`'s federation tests, or `modules/fedimint-dummy-tests`) proving two instances of one kind; possibly `fedimint-testing/src/fixtures.rs` for a `with_module_instances`/`with_extra_module` helper.

**Interface:** the `from_instances(Vec<(ModuleKind, T)>)` convenience (added in Task 1) + fixtures support for attaching two instances of a kind with distinct params.

- [ ] **Step 1: Write the failing test.** Using the trusted-dealer config-gen path (like the fixtures use), build a params registry with TWO instances of the SAME kind (simplest: two `dummy` instances, or two `mint` instances with different `denomination_base`). Assert: (a) config-gen produces two distinct `ModuleInstanceId`s (e.g. deterministic 0 and 1 by append order); (b) each instance's config reflects its own params (e.g. different denominations); (c) both are decodable/loadable (the module registry has two entries of the same kind under different ids). If fixtures don't support two-of-a-kind yet, add a minimal `Fixtures` helper to attach an extra instance with params.

- [ ] **Step 2: Run to verify fail** (two-of-a-kind not expressible / helper missing).

- [ ] **Step 3: Implement.** Ensure the params-registry path (Task 1) genuinely supports duplicate kinds end-to-end (it should, being keyed by instance id) and add the fixtures helper if needed. The init registry stays keyed by kind (one init impl per kind, looked up by kind); only the params registry / instance list carries multiplicity.

- [ ] **Step 4: Run to verify pass.** Report the two instance ids + that their configs differ.

- [ ] **Step 5: Format, lint, commit.** Commit: `feat(config): support multiple instances of one module kind`

---

### Task 3: mintv2 `amount_unit` param (the Phase 5 enabler)

**Files:** `modules/fedimint-mintv2-common/src/config.rs` (a `MintGenParams` with `amount_unit`), `modules/fedimint-mintv2-server/src/lib.rs` (`type Params` + use `params.amount_unit` instead of the hardcoded `AmountUnit::BITCOIN`).

Note: mintv2 is the unit-parameterized mint (its `MintConfigConsensus` already carries `amount_unit`). Task 1 may have given mintv2 `type Params = ()`; this task upgrades it to a real params type carrying the unit.

- [ ] **Step 1: Write the failing test.** In `fedimint-mintv2-server` (or a test crate), config-gen a mintv2 instance via `trusted_dealer_gen` with a `MintGenParams { amount_unit: AmountUnit::new_custom(1), .. }` and assert the resulting `MintConfigConsensus.amount_unit == AmountUnit::new_custom(1)` (and that the default/omitted case is `AmountUnit::BITCOIN`).

- [ ] **Step 2: Run to verify fail** (amount_unit currently hardcoded to BITCOIN).

- [ ] **Step 3: Implement.** Add `MintGenParams` (mintv2-common) with at least `amount_unit: AmountUnit` (default via a `Default`/constructor giving `BITCOIN`; keep any existing fee/denomination fields mintv2 needs — check mintv2's current config-gen to see what else it derives). Set `type Params = MintGenParams` in mintv2-server; replace both `amount_unit: AmountUnit::BITCOIN` literals (lib.rs ~211/~267 region) with `params.amount_unit`. Keep `AmountUnit::BITCOIN` as the default when params are absent/default. Ensure `fedimintd::default_modules` attaches mintv2 with a default (Bitcoin-unit) `MintGenParams` so existing behavior is unchanged.

- [ ] **Step 4: Run to verify pass.** Both the custom-unit and default-Bitcoin cases.

- [ ] **Step 5: Format, lint, commit.** Commit: `feat(mintv2): configurable amount_unit via config-gen params`

---

### Task 4: Fixtures/devimint helper to stand up a dual-mint federation

**Goal:** the concrete capability Phase 5 needs — a test/dev federation with two mintv2 instances: the default Bitcoin mint (primary for Bitcoin) + a USDT-denominated mint (primary for the USDT unit). Proves the whole chain works before Phase 5 depends on it.

**Files:** `fedimint-testing/src/fixtures.rs` (a helper to add a second mintv2 with a chosen unit), a test asserting the federation boots with both mints and the client routes per-unit.

- [ ] **Step 1: Write the failing test.** Build a `Fixtures` federation with the standard Bitcoin mintv2 as primary PLUS a second mintv2 instance configured (via `MintGenParams { amount_unit: USDT_UNIT }`) for a USDT unit. Boot it. Assert: (a) two mint instances exist with distinct ids; (b) the client's `primary_module_for_unit(USDT_UNIT)` resolves to the USDT mint instance (per the `supports_being_primary`/`Selected{units}` routing); (c) `get_balance(USDT_UNIT)` returns zero (no deposits yet) without error. Define `USDT_UNIT` as a shared constant (e.g. `AmountUnit::new_custom(1)`) — document that this id must be coordinated with the USDT module (Phase 5 uses the same constant).

- [ ] **Step 2–4: Implement the fixtures helper + make the test pass.** Add a `Fixtures` method to attach an extra mintv2 instance with a unit. Run the boot test (release; federation boot is slow). Report result.

- [ ] **Step 5: Format, lint, commit.** Commit: `test(config): dual-mint federation (bitcoin + USDT unit) fixture`

---

## Self-review checklist (controller, before dispatching Task 1)

- Design matches what elsirion approved: hybrid `args + typed Params`; instance-list (params registry) subsumes `enabled_modules`; Vec convenience with deterministic ids. ✓
- Task 1 is atomic-by-necessity (trait signature change) and reference-guided (port from `194b14e6e47^`), with a `cargo check --workspace` gate + existing-tests-preserved gate. ✓
- Behavior preservation for existing federations is an explicit Task-1 Step-5 requirement (same instance ids for default federations). ✓
- The USDT enabler (mintv2 `amount_unit` + dual-mint fixture) is isolated in Tasks 3–4, so Phase 5 has a proven foundation. ✓
- **Open risk flagged for Task 1:** the `enabled_modules`→instance-list migration touches `setup.rs` and possibly `fedimint-server-ui` (setup UI). If the setup UI reads `enabled_modules`, that path must be updated to the params registry too — the implementer must grep `enabled_modules` across the workspace and handle every consumer, or the setup UI breaks. Called out inline; if the UI change is large, report DONE_WITH_CONCERNS and we scope it.
- **Coordination constant:** `USDT_UNIT` (`AmountUnit::new_custom(1)`) must be shared between the USDT mint config and the USDT module's `process_input` (Phase 5). Defined in Task 4, reused in Phase 5.
