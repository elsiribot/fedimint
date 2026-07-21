# Module Generation Params and Asset Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Guardians fill out module-specific params (e.g. asset/amount unit) when proposing a module generation, backed by a consensus-agreed asset registry (id → name/ticker).

**Architecture:** `ModuleConfigProposal` carries a stringly-typed params map into the `Propose` consensus item so every guardian runs the DKG with identical `ConfigGenModuleArgs`. A descriptor API on `ServerModuleInit` tells the dashboard which params a kind accepts. The asset registry is a new consensus item processed by the existing config-gen machinery and stored on the `GenerationLog`. The mint's per-instance `amount_unit` support is cherry-picked from `2026-07-sp-ecash`.

**Tech Stack:** Rust, maud (dashboard), existing config-gen consensus machinery, `cargo nextest`.

**Spec:** `docs/superpowers/specs/2026-07-21-module-params-asset-registry-design.md`

## Global Constraints

- Work in the worktree `~/experimint-wt` (branch `experimint`). NEVER build from the user's checkout at `/home/user/.local/share/workspaces/minimint/running-fed-dkg` (it is on a different branch).
- Build with `CARGO_BUILD_TARGET_DIR=/home/user/.local/share/workspaces/minimint/running-fed-dkg/target-nix`.
- E2e tests MUST run via `cargo nextest run` (plain `cargo test` gets production session timing and hangs).
- Run `just format` after code changes; `just clippy` before each commit.
- Wire/DB breaking changes to `ConfigGenItem`/`GenerationLog` are acceptable; the demo federation is recreated afterwards. No migrations.
- Never use `unwrap()` outside tests; `expect()` with a reason.

---

### Task 1: Params in the proposal and DKG args

**Files:**
- Modify: `fedimint-core/src/config_gen.rs:48-54` (`ModuleConfigProposal`)
- Modify: `fedimint-server-core/src/init.rs:49-54` (`ConfigGenModuleArgs`)
- Modify: `fedimint-server/src/consensus/config_gen/manager.rs:207` (args construction)
- Modify: `fedimint-server/src/config/mod.rs:484,644` (static-path args, empty map)
- Modify: `modules/fedimint-mint-server/src/test.rs:20`, `modules/fedimint-ln-server/src/lib.rs:1344`, `modules/fedimint-wallet-tests/tests/tests.rs:1402` (test args, empty map)
- Modify: `modules/fedimint-mint-tests/tests/config_gen_tests.rs` (`propose` helper)
- Test: `fedimint-server/src/consensus/config_gen/mod.rs` (unit tests module at bottom)

**Interfaces:**
- Produces: `ModuleConfigProposal.params: BTreeMap<String, String>` (serde `#[serde(default)]`), `ConfigGenModuleArgs.params: BTreeMap<String, String>`. Later tasks rely on `proposal.params` reaching `distributed_gen` via `args.params`.

- [ ] **Step 1: Write the failing unit test**

In the `tests` module of `fedimint-server/src/consensus/config_gen/mod.rs`, alongside the existing process-item tests (reuse their helper for building a proposal if one exists; otherwise construct inline):

```rust
#[test]
fn proposal_params_are_preserved_in_log() {
    let mut log = GenerationLog::default();

    let proposal = ModuleConfigProposal {
        module_kind: ModuleKind::from_static_str("mint"),
        consensus_version: ModuleConsensusVersion::new(2, 0),
        network: Network::Regtest,
        disable_base_fees: false,
        params: BTreeMap::from([("amount_unit".to_string(), "1".to_string())]),
    };

    process_item(
        test_ctx(),
        &mut log,
        ConfigGenItem::Propose {
            generation_id: ModuleGenerationId(0),
            proposal: proposal.clone(),
        },
        PeerId::from(0),
    )
    .expect("proposal accepted");

    let GenerationState::Proposed { proposal: stored, .. } =
        &log.generations()[&ModuleGenerationId(0)]
    else {
        panic!("expected proposed state");
    };

    assert_eq!(stored.params, proposal.params);
}
```

Use the same `ProcessItemContext` construction as the existing tests in that module (there is a context with `instance_id_base: 10`; name a small helper `test_ctx()` if none exists).

- [ ] **Step 2: Run test to verify it fails to compile**

Run: `cd ~/experimint-wt && CARGO_BUILD_TARGET_DIR=.../target-nix cargo nextest run -p fedimint-server proposal_params_are_preserved`
Expected: compile error — `ModuleConfigProposal` has no field `params`.

- [ ] **Step 3: Add the fields**

`fedimint-core/src/config_gen.rs` (add `BTreeMap` to the existing `use` list):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ModuleConfigProposal {
    pub module_kind: ModuleKind,
    pub consensus_version: ModuleConsensusVersion,
    pub network: Network,
    pub disable_base_fees: bool,
    /// Module-specific generation parameters, e.g. the mint's
    /// `amount_unit`. Stringly typed; each module parses and validates the
    /// keys it understands (see `ServerModuleInit::config_gen_param_docs`).
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}
```

`fedimint-server-core/src/init.rs`:

```rust
#[derive(Debug, Clone)]
pub struct ConfigGenModuleArgs {
    /// Bitcoin network for the federation
    pub network: Network,
    /// Whether to disable base fees for this federation
    pub disable_base_fees: bool,
    /// Module-instance-specific DKG/config-generation parameters
    pub params: BTreeMap<String, String>,
}
```

Note `ConfigGenModuleArgs` loses `Copy` — fix any call sites that relied on it (clone instead).

- [ ] **Step 4: Update all construction sites**

`fedimint-server/src/consensus/config_gen/manager.rs:207`:

```rust
let args = ConfigGenModuleArgs {
    network: proposal.network,
    disable_base_fees: proposal.disable_base_fees,
    params: proposal.params.clone(),
};
```

All other sites (`fedimint-server/src/config/mod.rs:484,644`, the three module test files) get `params: BTreeMap::new(),`. The `propose` helper in `modules/fedimint-mint-tests/tests/config_gen_tests.rs` gets `params: BTreeMap::new(),` in its `ModuleConfigProposal` literal (a later task adds a params-taking variant). Also update the api-side proposal literal in `fedimint-server/src/consensus/api.rs:982` with `params: BTreeMap::new(),` (replaced properly in Task 3).

- [ ] **Step 5: Run tests**

Run: `cargo nextest run -p fedimint-server` then `cargo check -q --workspace`
Expected: all pass, workspace compiles.

- [ ] **Step 6: Format, clippy, commit**

```bash
just format && just clippy
git add -A && git commit -m "feat(config-gen): carry module params in generation proposals"
```

---

### Task 2: Asset registry consensus item and endpoints

**Files:**
- Modify: `fedimint-core/src/config_gen.rs` (item variant, request struct, caps)
- Modify: `fedimint-core/src/endpoint_constants.rs` (new endpoint const)
- Modify: `fedimint-server/src/consensus/config_gen/mod.rs` (`AssetInfo`, `GenerationLog.assets`, processing arm, unit tests)
- Modify: `fedimint-server/src/consensus/api.rs` (`try_register_asset`, endpoint registration, dashboard impl)
- Modify: `fedimint-server-core/src/dashboard_ui.rs` (`AssetSummary`, trait methods)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `ConfigGenItem::RegisterAsset { name: String, ticker: String }`; `pub struct AssetInfo { pub name: String, pub ticker: String, pub registered_by: PeerId }`; `GenerationLog::assets(&self) -> &BTreeMap<u64, AssetInfo>`; endpoint const `REGISTER_ASSET_ENDPOINT = "register_asset"` with body `RegisterAssetRequest { name, ticker }`; dashboard api `async fn assets(&self) -> Vec<AssetSummary>` (`AssetSummary { pub id: u64, pub name: String, pub ticker: String }`) and `async fn register_asset(&self, name: String, ticker: String) -> anyhow::Result<()>`.

- [ ] **Step 1: Write the failing unit tests**

In the `tests` module of `fedimint-server/src/consensus/config_gen/mod.rs`:

```rust
#[test]
fn assets_get_monotonic_ids_starting_at_one() {
    let mut log = GenerationLog::default();

    for (i, (name, ticker)) in [("US Dollar", "USD"), ("Euro", "EUR")].iter().enumerate() {
        process_item(
            test_ctx(),
            &mut log,
            ConfigGenItem::RegisterAsset {
                name: (*name).to_string(),
                ticker: (*ticker).to_string(),
            },
            PeerId::from(0),
        )
        .expect("registration accepted");

        let id = (i + 1) as u64;
        assert_eq!(log.assets()[&id].ticker, *ticker);
        assert_eq!(log.assets()[&id].registered_by, PeerId::from(0));
    }
}

#[test]
fn duplicate_ticker_is_rejected_case_insensitively() {
    let mut log = GenerationLog::default();

    let register = |log: &mut GenerationLog, ticker: &str| {
        process_item(
            test_ctx(),
            log,
            ConfigGenItem::RegisterAsset {
                name: "Some Asset".to_string(),
                ticker: ticker.to_string(),
            },
            PeerId::from(0),
        )
    };

    register(&mut log, "USD").expect("first registration accepted");
    assert!(register(&mut log, "usd").is_err());
    assert_eq!(log.assets().len(), 1);
}

#[test]
fn asset_name_and_ticker_are_length_capped() {
    let mut log = GenerationLog::default();

    assert!(
        process_item(
            test_ctx(),
            &mut log,
            ConfigGenItem::RegisterAsset {
                name: "x".repeat(MAX_ASSET_NAME_LEN + 1),
                ticker: "OK".to_string(),
            },
            PeerId::from(0),
        )
        .is_err()
    );

    assert!(
        process_item(
            test_ctx(),
            &mut log,
            ConfigGenItem::RegisterAsset {
                name: "Ok".to_string(),
                ticker: "x".repeat(MAX_ASSET_TICKER_LEN + 1),
            },
            PeerId::from(0),
        )
        .is_err()
    );

    assert!(log.assets().is_empty());
}
```

- [ ] **Step 2: Run to verify compile failure**

Run: `cargo nextest run -p fedimint-server assets_get_monotonic`
Expected: compile error — no `RegisterAsset` variant.

- [ ] **Step 3: Implement wire types**

`fedimint-core/src/config_gen.rs` — add to `ConfigGenItem`:

```rust
    /// Register a human-readable name/ticker for the next free custom
    /// amount-unit id. Single-guardian: takes effect once processed, no
    /// approval flow — the module proposal referencing the asset is the
    /// unanimously approved step.
    RegisterAsset { name: String, ticker: String },
```

and below the existing consts:

```rust
/// Bounds on asset registry entries so registry state stays small.
pub const MAX_ASSET_NAME_LEN: usize = 64;
pub const MAX_ASSET_TICKER_LEN: usize = 12;

/// Request body of the register-asset admin endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAssetRequest {
    pub name: String,
    pub ticker: String,
}
```

`fedimint-core/src/endpoint_constants.rs` (next to the other config-gen endpoints):

```rust
pub const REGISTER_ASSET_ENDPOINT: &str = "register_asset";
```

- [ ] **Step 4: Implement log state and processing**

`fedimint-server/src/consensus/config_gen/mod.rs`:

```rust
/// A registered asset: human-readable metadata for a custom amount-unit id.
#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize)]
pub struct AssetInfo {
    pub name: String,
    pub ticker: String,
    pub registered_by: PeerId,
}
```

Extend `GenerationLog`:

```rust
pub struct GenerationLog {
    generations: BTreeMap<ModuleGenerationId, GenerationState>,
    /// Registered assets by custom amount-unit id. Id 0 is bitcoin,
    /// implicit and never stored.
    assets: BTreeMap<u64, AssetInfo>,
}
```

(Keep `Default` derive working; add accessor:)

```rust
    pub fn assets(&self) -> &BTreeMap<u64, AssetInfo> {
        &self.assets
    }
```

New arm in `process_item` (before the closing of the match):

```rust
        ConfigGenItem::RegisterAsset { name, ticker } => {
            anyhow::ensure!(
                !name.is_empty() && name.len() <= MAX_ASSET_NAME_LEN,
                "Asset name must be 1..={MAX_ASSET_NAME_LEN} bytes"
            );
            anyhow::ensure!(
                !ticker.is_empty() && ticker.len() <= MAX_ASSET_TICKER_LEN,
                "Asset ticker must be 1..={MAX_ASSET_TICKER_LEN} bytes"
            );
            anyhow::ensure!(
                !log.assets
                    .values()
                    .any(|asset| asset.ticker.eq_ignore_ascii_case(&ticker)),
                "Asset ticker {ticker} is already registered"
            );

            let id = 1 + log.assets.keys().next_back().copied().unwrap_or(0);

            log.assets.insert(
                id,
                AssetInfo {
                    name,
                    ticker,
                    registered_by: peer,
                },
            );
        }
```

- [ ] **Step 5: Run unit tests**

Run: `cargo nextest run -p fedimint-server -- config_gen`
Expected: new tests pass, existing tests pass.

- [ ] **Step 6: Admin endpoint and dashboard api**

`fedimint-server-core/src/dashboard_ui.rs` — next to `ModuleGenerationSummary`:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct AssetSummary {
    pub id: u64,
    pub name: String,
    pub ticker: String,
}
```

and on the dashboard api trait (same block as `module_generations`):

```rust
    /// All registered assets, id ascending
    async fn assets(&self) -> Vec<AssetSummary>;

    /// Register an asset name/ticker for the next free unit id
    async fn register_asset(&self, name: String, ticker: String) -> anyhow::Result<()>;
```

`fedimint-server/src/consensus/api.rs` — in the impl with `try_propose_module_generation`:

```rust
    async fn try_register_asset(&self, name: String, ticker: String) -> anyhow::Result<()> {
        anyhow::ensure!(
            !name.is_empty() && name.len() <= MAX_ASSET_NAME_LEN,
            "Asset name must be 1..={MAX_ASSET_NAME_LEN} bytes"
        );
        anyhow::ensure!(
            !ticker.is_empty() && ticker.len() <= MAX_ASSET_TICKER_LEN,
            "Asset ticker must be 1..={MAX_ASSET_TICKER_LEN} bytes"
        );

        let log = self.generation_log().await;

        anyhow::ensure!(
            !log.assets()
                .values()
                .any(|asset| asset.ticker.eq_ignore_ascii_case(&ticker)),
            "Asset ticker {ticker} is already registered"
        );

        self.submit_config_gen_item(ConfigGenItem::RegisterAsset { name, ticker })
            .await;

        Ok(())
    }
```

Register the ws endpoint in the admin endpoint list (same pattern as `PROPOSE_MODULE_GENERATION_ENDPOINT` at `api.rs:1280`, admin-auth'd), deserializing `RegisterAssetRequest` and calling `try_register_asset`. Implement the two dashboard trait methods in the dashboard impl block (near `propose_module_generation` at `api.rs:968`): `assets()` maps `generation_log().await.assets()` into `AssetSummary`s; `register_asset` delegates to `try_register_asset`. Note the existing `MODULE_GENERATIONS_ENDPOINT` returns the whole serialized `GenerationLog`, so `assets` is automatically visible there for tests.

- [ ] **Step 7: Format, clippy, run tests, commit**

```bash
just format && just clippy
cargo nextest run -p fedimint-server
git add -A && git commit -m "feat(config-gen): consensus asset registry with guardian registration"
```

---

### Task 3: Param descriptor API and proposal validation

**Files:**
- Modify: `fedimint-server-core/src/init.rs` (descriptor types, trait method, dyn plumbing)
- Modify: `fedimint-server/src/consensus/config_gen/mod.rs` (`validate_proposal_params`, unit tests)
- Modify: `fedimint-server/src/consensus/api.rs` (`propose_module_generation` signature + validation)
- Modify: `fedimint-server-core/src/dashboard_ui.rs` (trait: params on propose, param docs accessor)
- Modify: `fedimint-server-ui/src/dashboard/config_gen.rs` (call-site compile fix only; real UI in Task 5)

**Interfaces:**
- Consumes: `GenerationLog::assets()` (Task 2), `ModuleConfigProposal.params` (Task 1).
- Produces:

```rust
// fedimint-server-core/src/init.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ConfigGenParamType {
    Text,
    U64,
    /// A registered asset id (0 = bitcoin); rendered as a dropdown
    Asset,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigGenParamDoc {
    pub name: &'static str,
    pub description: &'static str,
    pub param_type: ConfigGenParamType,
    pub required: bool,
}
```

`ServerModuleInit::config_gen_param_docs(&self) -> Vec<ConfigGenParamDoc>` (default `vec![]`) with matching `IServerModuleInit` method; `pub fn validate_proposal_params(docs: &[ConfigGenParamDoc], params: &BTreeMap<String, String>, assets: &BTreeMap<u64, AssetInfo>) -> anyhow::Result<()>`; dashboard trait `propose_module_generation(&self, kind: ModuleKind, params: BTreeMap<String, String>)` and `module_param_docs(&self, kind: ModuleKind) -> Vec<ConfigGenParamDoc>`.

- [ ] **Step 1: Write the failing validation unit tests**

In `fedimint-server/src/consensus/config_gen/mod.rs` tests:

```rust
fn amount_unit_docs() -> Vec<ConfigGenParamDoc> {
    vec![ConfigGenParamDoc {
        name: "amount_unit",
        description: "Asset issued by this instance",
        param_type: ConfigGenParamType::Asset,
        required: false,
    }]
}

#[test]
fn validates_proposal_params() {
    let docs = amount_unit_docs();
    let assets = BTreeMap::from([(
        1,
        AssetInfo {
            name: "US Dollar".to_string(),
            ticker: "USD".to_string(),
            registered_by: PeerId::from(0),
        },
    )]);
    let params = |entries: &[(&str, &str)]| {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect::<BTreeMap<_, _>>()
    };

    // optional param may be omitted
    assert!(validate_proposal_params(&docs, &params(&[]), &assets).is_ok());
    // bitcoin (0) and registered asset accepted
    assert!(validate_proposal_params(&docs, &params(&[("amount_unit", "0")]), &assets).is_ok());
    assert!(validate_proposal_params(&docs, &params(&[("amount_unit", "1")]), &assets).is_ok());
    // unregistered asset, non-numeric value, unknown key rejected
    assert!(validate_proposal_params(&docs, &params(&[("amount_unit", "7")]), &assets).is_err());
    assert!(validate_proposal_params(&docs, &params(&[("amount_unit", "abc")]), &assets).is_err());
    assert!(validate_proposal_params(&docs, &params(&[("nonsense", "1")]), &assets).is_err());
}

#[test]
fn required_param_must_be_present() {
    let docs = vec![ConfigGenParamDoc {
        name: "flavor",
        description: "",
        param_type: ConfigGenParamType::Text,
        required: true,
    }];

    assert!(validate_proposal_params(&docs, &BTreeMap::new(), &BTreeMap::new()).is_err());
}
```

- [ ] **Step 2: Run to verify compile failure**

Run: `cargo nextest run -p fedimint-server validates_proposal_params`
Expected: compile error — types don't exist.

- [ ] **Step 3: Implement descriptor types and trait plumbing**

Add the types from the Interfaces block to `fedimint-server-core/src/init.rs`. Add to the typed trait (near `get_documented_env_vars` at `init.rs:116`):

```rust
    /// Params a guardian can set when proposing a generation of this
    /// module kind; rendered as a form by the dashboard and validated at
    /// proposal time.
    fn config_gen_param_docs(&self) -> Vec<ConfigGenParamDoc> {
        vec![]
    }
```

Mirror it on `IServerModuleInit` and the blanket/dyn impls exactly like `get_documented_env_vars` (both impl blocks around `init.rs:258` and `init.rs:360`).

- [ ] **Step 4: Implement `validate_proposal_params`**

In `fedimint-server/src/consensus/config_gen/mod.rs`:

```rust
/// Validates guardian-supplied proposal params against a module kind's
/// param descriptors and the asset registry. Called at proposal time for
/// immediate feedback; DKG-time parse failures still abort the generation
/// as a defensive layer.
pub fn validate_proposal_params(
    docs: &[ConfigGenParamDoc],
    params: &BTreeMap<String, String>,
    assets: &BTreeMap<u64, AssetInfo>,
) -> anyhow::Result<()> {
    for (name, value) in params {
        let doc = docs
            .iter()
            .find(|doc| doc.name == name)
            .with_context(|| format!("Unknown param {name}"))?;

        match doc.param_type {
            ConfigGenParamType::Text => {}
            ConfigGenParamType::U64 => {
                value
                    .parse::<u64>()
                    .with_context(|| format!("Param {name} must be an unsigned integer"))?;
            }
            ConfigGenParamType::Asset => {
                let id = value
                    .parse::<u64>()
                    .with_context(|| format!("Param {name} must be an asset id"))?;

                anyhow::ensure!(
                    id == 0 || assets.contains_key(&id),
                    "Param {name}: no registered asset with id {id}"
                );
            }
        }
    }

    for doc in docs {
        anyhow::ensure!(
            !doc.required || params.contains_key(doc.name),
            "Missing required param {}",
            doc.name
        );
    }

    Ok(())
}
```

- [ ] **Step 5: Run the unit tests**

Run: `cargo nextest run -p fedimint-server validate`
Expected: PASS.

- [ ] **Step 6: Wire validation into the propose endpoint**

`fedimint-server-core/src/dashboard_ui.rs`: change the trait method to
`async fn propose_module_generation(&self, kind: ModuleKind, params: BTreeMap<String, String>) -> anyhow::Result<()>;` and add
`async fn module_param_docs(&self, kind: ModuleKind) -> Vec<ConfigGenParamDoc>;`.

`fedimint-server/src/consensus/api.rs:968` becomes:

```rust
    async fn propose_module_generation(
        &self,
        kind: ModuleKind,
        params: BTreeMap<String, String>,
    ) -> anyhow::Result<()> {
        let module_init = self
            .module_inits
            .get(&kind)
            .with_context(|| format!("Unsupported module kind {kind}"))?;

        let log = self.generation_log().await;

        validate_proposal_params(&module_init.config_gen_param_docs(), &params, log.assets())?;

        let consensus_version = module_init.supported_api_versions().module_consensus;

        let network = self
            .bitcoin_rpc_connection
            .status()
            .context("Bitcoin backend is not connected yet")?
            .network;

        self.try_propose_module_generation(ModuleConfigProposal {
            module_kind: kind,
            consensus_version,
            network,
            disable_base_fees: false,
            params,
        })
        .await?;

        Ok(())
    }

    async fn module_param_docs(&self, kind: ModuleKind) -> Vec<ConfigGenParamDoc> {
        self.module_inits
            .get(&kind)
            .map(|init| init.config_gen_param_docs())
            .unwrap_or_default()
    }
```

Apply the same validation inside `try_propose_module_generation` for the raw ws admin endpoint path (`PROPOSE_MODULE_GENERATION_ENDPOINT` deserializes a full `ModuleConfigProposal`): look up the init by `proposal.module_kind` and call `validate_proposal_params` before submitting.

Fix the dashboard call site `fedimint-server-ui/src/dashboard/config_gen.rs:132` to pass `BTreeMap::new()` for now (Task 5 replaces it).

- [ ] **Step 7: Format, clippy, tests, commit**

```bash
just format && just clippy
cargo nextest run -p fedimint-server
git add -A && git commit -m "feat(config-gen): module param descriptors and proposal validation"
```

---

### Task 4: Mint per-instance amount unit (cherry-pick) and mint descriptor

**Files:**
- Cherry-pick: commit `2e30c285431` ("feat(mint): support per-instance amount units") from branch `2026-07-sp-ecash`
- Modify: `modules/fedimint-mint-server/src/lib.rs` (add `config_gen_param_docs`)

**Interfaces:**
- Consumes: `ConfigGenModuleArgs.params` (Task 1), `ConfigGenParamDoc`/`ConfigGenParamType::Asset` (Task 3).
- Produces: mint parses param `"amount_unit"` (u64 asset id, absent = bitcoin) in `distributed_gen`/`trusted_dealer_gen`; `MintConfigConsensus.amount_unit`/`MintClientConfig.amount_unit` (both `#[serde(default)]`); all mint transaction amounts use `Amounts::new_custom(unit, amount)`.

- [ ] **Step 1: Cherry-pick**

```bash
cd ~/experimint-wt && git cherry-pick 2e30c285431
```

Expected conflicts, if any, in `fedimint-testing-core/src/config.rs` (the sp-ecash commit touches setup params there — keep the experimint side, only take hunks needed to compile) and around `modules/fedimint-mint-server/src/lib.rs` imports. The commit's `parse_amount_unit` reads `args.params`, which exists since Task 1. Resolve, then `git cherry-pick --continue`.

- [ ] **Step 2: Build and run the mint tests that came with the commit**

Run: `cargo nextest run -p fedimint-mint-server && cargo check -q --workspace`
Expected: PASS (the commit includes `modules/fedimint-mint-server/src/test.rs` coverage for unit parsing and config gen).

- [ ] **Step 3: Declare the mint's param descriptor**

In `modules/fedimint-mint-server/src/lib.rs`, in the `ServerModuleInit` impl for `MintInit` (near `get_documented_env_vars`):

```rust
    fn config_gen_param_docs(&self) -> Vec<ConfigGenParamDoc> {
        vec![ConfigGenParamDoc {
            name: CONFIG_PARAM_AMOUNT_UNIT,
            description: "Asset issued by this mint instance (default: bitcoin)",
            param_type: ConfigGenParamType::Asset,
            required: false,
        }]
    }
```

(`CONFIG_PARAM_AMOUNT_UNIT` is the `"amount_unit"` const the cherry-pick introduced; import `ConfigGenParamDoc`/`ConfigGenParamType` from `fedimint_server_core`.)

- [ ] **Step 4: Format, clippy, tests, commit (amend the descriptor into its own commit)**

```bash
just format && just clippy
cargo nextest run -p fedimint-mint-server -p fedimint-server
git add -A && git commit -m "feat(mint): declare amount_unit generation param descriptor"
```

---

### Task 5: Dashboard UI — assets section and param form

**Files:**
- Create: `fedimint-server-ui/src/dashboard/assets.rs`
- Modify: `fedimint-server-ui/src/dashboard/config_gen.rs` (two-step propose, params display)
- Modify: `fedimint-server-ui/src/dashboard/mod.rs` (render + routes)
- Modify: `fedimint-server/src/consensus/api.rs` (`ModuleGenerationSummary.params` population)
- Modify: `fedimint-server-core/src/dashboard_ui.rs` (`ModuleGenerationSummary.params` field)

**Interfaces:**
- Consumes: `DynDashboardApi::{assets, register_asset, module_param_docs, propose_module_generation(kind, params)}` (Tasks 2-3).
- Produces: `ModuleGenerationSummary.params: Vec<(String, String)>` (display name → display value, assets resolved to `"TICKER (id N)"`); routes `/assets/register` (POST), `/config-gen/propose-form` (GET with `?kind=`), existing `/config-gen/propose` (POST, now accepts `param_<name>` fields).

- [ ] **Step 1: Add the summary params field**

`fedimint-server-core/src/dashboard_ui.rs`:

```rust
pub struct ModuleGenerationSummary {
    pub generation_id: u64,
    pub module_kind: ModuleKind,
    pub state: String,
    pub detail: String,
    /// Proposal params as display pairs, asset ids resolved to tickers
    pub params: Vec<(String, String)>,
    pub can_approve: bool,
    pub can_activate: bool,
    pub can_abort: bool,
}
```

In `fedimint-server/src/consensus/api.rs` (`module_generations` summary construction around line 955), populate it from the state's proposal — every `GenerationState` variant carries `proposal`; resolve `Asset`-typed params via `log.assets()`:

```rust
let params = proposal
    .params
    .iter()
    .map(|(name, value)| {
        let display_value = value
            .parse::<u64>()
            .ok()
            .and_then(|id| log.assets().get(&id))
            .map_or_else(|| value.clone(), |asset| format!("{} ({})", asset.ticker, value));
        (name.clone(), display_value)
    })
    .collect();
```

(Resolving every numeric param against the registry is a display-only heuristic that is fine for the prototype.)

- [ ] **Step 2: Assets dashboard section**

Create `fedimint-server-ui/src/dashboard/assets.rs`:

```rust
//! Dashboard section for the guardian asset registry.

use axum::extract::{Form, State};
use axum::response::{IntoResponse, Redirect};
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_server_core::dashboard_ui::DynDashboardApi;
use fedimint_ui_common::auth::UserAuth;
use fedimint_ui_common::{ROOT_ROUTE, UiState};
use maud::{Markup, html};
use serde::Deserialize;
use tracing::warn;

use crate::LOG_UI;

pub const ASSETS_REGISTER_ROUTE: &str = "/assets/register";

#[derive(Deserialize)]
pub struct RegisterAssetForm {
    pub name: String,
    pub ticker: String,
}

pub async fn render(api: &DynDashboardApi) -> Markup {
    let assets = api.assets().await;

    html! {
        div class="card h-100" {
            div class="card-header dashboard-header" { "Asset Registry" }
            div class="card-body" {
                p class="text-muted" {
                    "Human-readable names for custom amount units. Id 0 is "
                    "always bitcoin. Any guardian can register an asset; it "
                    "takes effect once the consensus item is processed."
                }

                @if assets.is_empty() {
                    div class="alert alert-secondary" { "No assets registered yet" }
                } @else {
                    div class="table-responsive" {
                        table class="table table-sm align-middle" {
                            thead { tr { th { "Id" } th { "Name" } th { "Ticker" } } }
                            tbody {
                                @for asset in &assets {
                                    tr {
                                        td { (asset.id) }
                                        td { (asset.name) }
                                        td { (asset.ticker) }
                                    }
                                }
                            }
                        }
                    }
                }

                form method="post" action=(ASSETS_REGISTER_ROUTE) class="d-flex gap-2 mt-3" {
                    input type="text" name="name" class="form-control w-auto" placeholder="Name" required;
                    input type="text" name="ticker" class="form-control w-auto" placeholder="Ticker" required;
                    button type="submit" class="btn btn-primary" { "Register Asset" }
                }
            }
        }
    }
}

pub async fn post_register(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<RegisterAssetForm>,
) -> impl IntoResponse {
    if let Err(err) = state.api.register_asset(form.name, form.ticker).await {
        warn!(target: LOG_UI, err = %err.fmt_compact_anyhow(), "Failed to register asset");
    }

    Redirect::to(ROOT_ROUTE).into_response()
}
```

Wire into `fedimint-server-ui/src/dashboard/mod.rs`: `mod assets;`, render the card next to the config-gen card (same grid row as the call at `mod.rs:157`), and add the route next to the config-gen routes (`mod.rs:252`):

```rust
        .route(assets::ASSETS_REGISTER_ROUTE, post(assets::post_register))
```

- [ ] **Step 3: Two-step propose with param form**

Rework `fedimint-server-ui/src/dashboard/config_gen.rs`:

Add route const and form types:

```rust
pub const CONFIG_GEN_PROPOSE_FORM_ROUTE: &str = "/config-gen/propose-form";

#[derive(Deserialize)]
pub struct ProposeFormQuery {
    pub kind: String,
}
```

`post_propose` now takes the whole form as a map and splits kind/params. Empty values are treated as unset:

```rust
pub async fn post_propose(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    Form(form): Form<BTreeMap<String, String>>,
) -> impl IntoResponse {
    let Some(kind) = form.get("kind").cloned() else {
        return Redirect::to(ROOT_ROUTE).into_response();
    };
    let kind = fedimint_core::core::ModuleKind::clone_from_str(&kind);

    let has_param_fields = form.keys().any(|key| key.starts_with("param_"));
    let docs = state.api.module_param_docs(kind.clone()).await;

    // Kind has params but the one-click form was used: show the param form
    if !docs.is_empty() && !has_param_fields {
        return Redirect::to(&format!("{CONFIG_GEN_PROPOSE_FORM_ROUTE}?kind={kind}"))
            .into_response();
    }

    let params: BTreeMap<String, String> = form
        .into_iter()
        .filter_map(|(key, value)| {
            let name = key.strip_prefix("param_")?;
            (!value.is_empty()).then(|| (name.to_string(), value))
        })
        .collect();

    if let Err(err) = state.api.propose_module_generation(kind, params).await {
        warn!(target: LOG_UI, err = %err.fmt_compact_anyhow(), "Failed to propose module generation");
    }

    Redirect::to(ROOT_ROUTE).into_response()
}
```

The param form page (GET handler) renders one field per descriptor; `Asset` params render as a dropdown of bitcoin + registered assets:

```rust
pub async fn get_propose_form(
    State(state): State<UiState<DynDashboardApi>>,
    _auth: UserAuth,
    axum::extract::Query(query): axum::extract::Query<ProposeFormQuery>,
) -> impl IntoResponse {
    let kind = fedimint_core::core::ModuleKind::clone_from_str(&query.kind);
    let docs = state.api.module_param_docs(kind.clone()).await;
    let assets = state.api.assets().await;

    let content = html! {
        div class="card" {
            div class="card-header dashboard-header" { "Propose " (kind) " Module" }
            div class="card-body" {
                form method="post" action=(CONFIG_GEN_PROPOSE_ROUTE) {
                    input type="hidden" name="kind" value=(kind);
                    @for doc in &docs {
                        div class="mb-3" {
                            label class="form-label" { (doc.name) }
                            @match doc.param_type {
                                ConfigGenParamType::Asset => {
                                    select name={ "param_" (doc.name) } class="form-select" {
                                        option value="" { "bitcoin (default)" }
                                        @for asset in &assets {
                                            option value=(asset.id) {
                                                (asset.ticker) " — " (asset.name)
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    input type="text" name={ "param_" (doc.name) }
                                        class="form-control" required[doc.required];
                                }
                            }
                            div class="form-text" { (doc.description) }
                        }
                    }
                    button type="submit" class="btn btn-primary" { "Propose" }
                    a href=(ROOT_ROUTE) class="btn btn-outline-secondary ms-2" { "Cancel" }
                }
            }
        }
    };

    fedimint_ui_common::layout::layout("Propose Module", content).into_response()
}
```

(Check how other standalone pages in `fedimint-server-ui` wrap content in the layout — follow that exact pattern; the helper name above is indicative. If no standalone-page pattern exists, render the form inline in the dashboard card instead: `render()` gains an optional `?propose=kind` mode.)

Register the GET route in `dashboard/mod.rs`:

```rust
        .route(config_gen::CONFIG_GEN_PROPOSE_FORM_ROUTE, get(config_gen::get_propose_form))
```

Display params in `render_generation_row` (detail cell):

```rust
            td {
                (generation.detail)
                @if !generation.params.is_empty() {
                    br;
                    small class="text-muted" {
                        @for (name, value) in &generation.params {
                            (name) "=" (value) " ";
                        }
                    }
                }
            }
```

- [ ] **Step 4: Build, manual smoke against a dev fed**

Run: `cargo check -q -p fedimint-server-ui && cargo build --bin fedimintd`
Then start a solo fed (or use the running demo fed's data-dir pattern) and via curl: login, POST `/assets/register` (name=US Dollar, ticker=USD), GET `/` shows the asset table, GET `/config-gen/propose-form?kind=mint` shows the dropdown containing USD, POST `/config-gen/propose` with `kind=mint&param_amount_unit=1` proposes.

- [ ] **Step 5: Format, clippy, commit**

```bash
just format && just clippy
git add -A && git commit -m "feat(ui): asset registry section and module param propose form"
```

---

### Task 6: E2e test, smoke script, docs

**Files:**
- Modify: `modules/fedimint-mint-tests/tests/config_gen_tests.rs`
- Modify: `scripts/dev/config-gen-ui-smoke.sh`
- Modify: `docs/superpowers/specs/2026-07-21-module-params-asset-registry-design.md` (status note)

**Interfaces:**
- Consumes: `REGISTER_ASSET_ENDPOINT`/`RegisterAssetRequest`, `MODULE_GENERATIONS_ENDPOINT` (log now serializes `assets`), `ModuleConfigProposal.params`, mint `amount_unit` (Tasks 1-4).

- [ ] **Step 1: Write the e2e test**

In `modules/fedimint-mint-tests/tests/config_gen_tests.rs`, add a params-taking propose helper (keep the existing `propose` delegating to it with empty params):

```rust
async fn propose_with_params(
    apis: &[DynGlobalApi],
    module_kind: &'static str,
    consensus_version: ModuleConsensusVersion,
    params: BTreeMap<String, String>,
) -> ModuleGenerationId {
    let proposal = ModuleConfigProposal {
        module_kind: ModuleKind::from_static_str(module_kind),
        consensus_version,
        network: bitcoin::Network::Regtest,
        disable_base_fees: false,
        params,
    };

    let generation_id: ModuleGenerationId = apis[0]
        .request_admin(
            PROPOSE_MODULE_GENERATION_ENDPOINT,
            ApiRequestErased::new(&proposal),
            auth(),
        )
        .await
        .expect("proposal accepted");

    info!(target: LOG_TEST, %generation_id, %module_kind, "Proposed generation");

    generation_id
}
```

New test:

```rust
#[tokio::test(flavor = "multi_thread")]
async fn mint_with_custom_asset_unit() -> anyhow::Result<()> {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);
    let fed = fixtures.new_fed_not_degraded().await;

    let mut apis = Vec::new();
    for peer in 0..NUM_PEERS {
        apis.push(fed.new_admin_api(PeerId::from(peer)).await?);
    }

    // Register an asset on peer 0; every peer sees it in its log
    apis[0]
        .request_admin::<()>(
            REGISTER_ASSET_ENDPOINT,
            ApiRequestErased::new(RegisterAssetRequest {
                name: "US Dollar".to_string(),
                ticker: "USD".to_string(),
            }),
            auth(),
        )
        .await?;

    for api in &apis {
        loop {
            let log: serde_json::Value = api
                .request_admin(MODULE_GENERATIONS_ENDPOINT, ApiRequestErased::default(), auth())
                .await?;
            if log["assets"]["1"]["ticker"] == "USD" {
                break;
            }
            sleep_in_test("Waiting for asset registration", Duration::from_millis(200)).await;
        }
    }

    // Propose a mint denominated in the registered asset and activate it
    let generation_id = propose_with_params(
        &apis,
        "mint",
        MODULE_CONSENSUS_VERSION,
        BTreeMap::from([("amount_unit".to_string(), "1".to_string())]),
    )
    .await;

    approve_all(&apis, generation_id).await;

    for api in &apis {
        await_state(api, generation_id, "Generated").await;
    }

    let (instance_id, active_from_session) = activate(&apis[0], generation_id).await;

    await_session_past(&apis[0], active_from_session).await?;
    await_module_in_audit(&apis[0], instance_id).await;

    // The activated instance's client config carries the custom unit
    let client = fed.new_client().await;
    let config = client.config().await;
    let mint_config = config
        .modules
        .get(&(instance_id as u16))
        .expect("dynamically added mint in client config")
        .cast::<fedimint_mint_common::config::MintClientConfig>()?;

    assert_eq!(
        mint_config.amount_unit,
        fedimint_core::module::AmountUnit::new_custom(1)
    );

    Ok(())
}
```

Note: the client fetches the refreshed config additively; if `config.modules` does not yet contain the instance, poll with `sleep_in_test` like `activated_module_runs_without_restart` does (reuse its pending-config wait pattern with `new_client_with_db` if the plain `new_client` joins with a pre-activation invite).

- [ ] **Step 2: Run the e2e test, verify it fails only at the endpoint gaps you expect**

Run: `cargo nextest run -p fedimint-mint-tests --test fedimint_mint_config_gen_tests mint_with_custom_asset_unit`
Expected: PASS (all pieces landed in Tasks 1-4). If it fails, the failure identifies the gap — fix it before proceeding.

- [ ] **Step 3: Run the whole config-gen e2e suite**

Run: `cargo nextest run -p fedimint-mint-tests --test fedimint_mint_config_gen_tests`
Expected: all tests pass.

- [ ] **Step 4: Extend the UI smoke script**

In `scripts/dev/config-gen-ui-smoke.sh`, before the propose step:

```bash
curl -sf -b "$(cookies 0)" -X POST -d "name=US Dollar&ticker=USD" \
  "http://127.0.0.1:$(port 0)/assets/register" >/dev/null
for _ in $(seq 30); do
  if curl -sf -b "$(cookies 0)" "http://127.0.0.1:$(port 0)/" | grep -q ">USD<"; then
    break
  fi
  sleep 2
done
curl -sf -b "$(cookies 0)" "http://127.0.0.1:$(port 0)/" | grep -q ">USD<"
echo "SMOKE: asset registered and visible"
```

and change the propose POST to go through the param path:

```bash
curl -sf -b "$(cookies 0)" "http://127.0.0.1:$(port 0)/config-gen/propose-form?kind=mint" \
  | grep -q "param_amount_unit"
curl -sf -b "$(cookies 0)" -X POST -d "kind=mint&param_amount_unit=1" \
  "http://127.0.0.1:$(port 0)/config-gen/propose" >/dev/null
echo "SMOKE: proposed mint with amount_unit param"
```

- [ ] **Step 5: Update docs status and commit**

Append to the spec doc: `Status (2026-07-21): implemented on branch experimint.` Then:

```bash
just format && just clippy
git add -A && git commit -m "test(config-gen): e2e for asset registry and mint amount unit param"
```

---

### Task 7: Recreate and verify the demo federation

**Files:** none (operational).

- [ ] **Step 1: Rebuild and reset**

```bash
cd ~/experimint-wt && CARGO_BUILD_TARGET_DIR=.../target-nix cargo build --bin fedimintd
pkill -x fedimintd || true
rm -rf ~/solo-fed-demo/fedimintd-data && mkdir -p ~/solo-fed-demo/fedimintd-data
```

Restart the supervisor loop (same env as before: `FM_IN_DEVIMINT=1 FM_ENABLE_IROH=1`, bitcoind regtest on 18443, UI on 8175, password `pass`) and re-run federation setup through the setup UI.

- [ ] **Step 2: Live verification**

Via the dashboard: register asset "US Dollar"/USD → propose mint with the USD asset selected → approve (solo: implicit) → activate → verify the instance hot-activates, the generation row shows `amount_unit=USD (1)`, and the log shows no WARN/ERROR. Re-arm the log monitor.
