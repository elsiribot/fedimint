# Module generation params and guardian asset registry

Extends consensus-coordinated module config generation (see
`2026-07-17-consensus-config-gen-design.md`) with per-proposal module
parameters and a guardian-managed asset registry, enabling e.g. a second
mint instance denominated in a custom asset ("stable ecash" pattern from
branch `2026-07-sp-ecash`).

## Motivation

The sp-ecash branch showed that module instances need per-instance DKG
parameters: a mint instance is bound to an `AmountUnit` at generation
time. Today the runtime proposal flow (`ModuleConfigProposal`) carries no
module-specific parameters, so every generated instance uses defaults.
Guardians also need a shared, human-readable mapping from custom unit ids
to names/tickers so the dashboard can render "USD" instead of "unit 1".

## Design decisions (settled)

- Dashboard learns module params via a **descriptor API** on
  `ServerModuleInit`, not hardcoded per-kind forms.
- The asset registry lives in the **config-gen consensus log**, not the
  meta module.
- Registering an asset is **single-guardian, immediate** (no approval
  flow); the module proposal referencing the asset remains the
  unanimously-approved step.
- Asset ids are **auto-incremented** by the registry, starting at 1
  (0 = bitcoin, implicit, never stored).

## Architecture

### 1. Params in the proposal

`ModuleConfigProposal` gains `params: BTreeMap<String, String>` —
stringly typed, each module parses and validates the keys it understands
(same shape as sp-ecash). The params ride in the `Propose` consensus item
so every guardian runs the DKG with identical arguments.

`ConfigGenModuleArgs` gains `params: BTreeMap<String, String>` (ported
from sp-ecash commit `3b8ca084ecc`, without the setup-code
`module_instances` changes, which the runtime flow does not need). The
generation manager copies `proposal.params` into the args passed to
`distributed_gen`. `trusted_dealer_gen` and static setup pass an empty
map.

Breaking change: the encoding of `ConfigGenItem::Propose` and the
generation log changes. No migration; prototype federations are
recreated.

### 2. Param descriptor API

```rust
pub struct ConfigGenParamDoc {
    pub name: &'static str,
    pub description: &'static str,
    pub param_type: ConfigGenParamType, // Text | U64 | Asset
    pub required: bool,
}
```

An absent optional param means the module's built-in default (e.g.
bitcoin for the mint's `amount_unit`); descriptors carry no default
value of their own.

`ServerModuleInit::config_gen_param_docs() -> Vec<ConfigGenParamDoc>`
(default: empty) plus the matching `IServerModuleInit` plumbing. The
mint declares `amount_unit` (type `Asset`, optional, default bitcoin).

The propose endpoint validates submitted params against the descriptors
(unknown keys rejected, required keys present, values parse per type,
`Asset` values resolve against the registry) before submitting the
consensus item. DKG-time failures still fall back to the existing abort
flow as a defensive layer.

### 3. Asset registry

New consensus item `ConfigGenItem::RegisterAsset { name, ticker }`.
Processing assigns the next free id (`1 + max existing`) and inserts into
the generation log:

```rust
pub struct AssetInfo {
    pub name: String,
    pub ticker: String,
    pub registered_by: PeerId,
}
// on ConfigGenerationLog:
pub assets: BTreeMap<u64, AssetInfo>,
```

Duplicate tickers (case-insensitive) are rejected deterministically at
processing time (item ignored with a log line) and pre-checked at the
endpoint for immediate feedback. Names are capped at 64 bytes and
tickers at 12 bytes to bound registry state.

Admin api: `register_asset` (auth), `list_assets` (auth). Dashboard: an
"Assets" section with the registered table (id, name, ticker,
registered-by) and an add form.

### 4. Dashboard propose flow

Propose becomes two steps: pick kind → param form rendered from the
kind's descriptors → submit. `Asset` params render as a dropdown of
bitcoin + registered assets. Kinds without descriptors keep the current
one-click propose. Pending/generated/active generation cards display the
proposal's params, resolving asset ids to tickers.

### 5. Mint per-instance units

Cherry-pick sp-ecash commit `2e30c285431` (mint `amount_unit` in
`MintConfigConsensus`/`MintClientConfig`, `Amounts::new_custom` in
input/output processing, client-side unit handling). The mint's
`parse_amount_unit` reads the `amount_unit` param supplied by the
proposal.

## Testing

- Unit: registry processing (auto-increment, duplicate ticker, determinism
  across item orderings), descriptor validation of proposals.
- E2e (`config_gen_tests.rs`): register an asset on peer 0, visible on
  all peers; propose a mint with `amount_unit` set; activate; the
  client config of the new instance carries the custom unit.
- UI smoke script: register an asset, propose a mint through the param
  form, activate.

## Out of scope

- Client-side display/UX for custom-unit balances beyond what the
  cherry-picked mint client changes provide.
- Asset de-registration or renaming.
- Non-guardian (public) visibility of the registry.
- Setup-time (day-0) module instances with params (`module_instances`
  in the setup code).

Status (2026-07-21): implemented on branch experimint.
