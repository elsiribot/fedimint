# Atomic Swap Module — Master Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan phase-by-phase. Each phase is executed from its own just-in-time detailed plan (written via superpowers:writing-plans) whose steps conform to the interfaces pinned here. Changing a pinned interface requires editing this document first. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Fedimint module that swaps any `AmountUnit` for any other *within one federation*: a maker locks a fixed amount of unit A and names the exact amount of unit B they want; a taker fills it; each party then withdraws the other's locked leg as fresh e-cash. Atomicity comes from consensus serialization, not an on-chain HTLC.

**Design spec:** `docs/superpowers/specs/2026-08-20-swap-module-design.md`

**Architecture:** On-consensus escrow. Each leg crosses the per-unit transaction balance equation *at par within a single unit* (paired with a mint input/output); the cross-unit relationship lives entirely in `Offer` state, never in the balance equation. Four operations — `MakeOffer`/`Fill` (outputs), `Claim`/`Reclaim` (inputs). Expiry is a peer-proposed **median consensus timestamp** (the USDT block-count pattern). No threshold keys, no DKG, no crypto — config is `dummy`-trivial.

**Tech stack:** Rust (edition 2024), Fedimint three-crate module pattern (`fedimint-swap-common|server|client` + `-tests`), `fedimint-testing` harness. Client + common are **wasm-safe**.

---

## Decision record (settled with elsirion, 2026-08-20)

| # | Decision | Choice | Key consequence |
|---|---|---|---|
| D1 | Asset scope | Generic: any `AmountUnit` ↔ any other, within one federation | Module hardcodes no unit; both legs are `(AmountUnit, Amount)` pairs |
| D2 | Order model | All-or-nothing single-fill offers | No partial fills, no ratio/rounding, no matching engine |
| D3 | Cancellation | Cancel anytime while `Open` + mandatory expiry backstop | `Reclaim` valid only while `Open`; a `Filled` offer is never cancellable |
| D4 | Atomicity | Consensus serialization over module state | `Fill`/`Reclaim` race resolves by ordering; no fund loss, taker only risks a rejected fill |
| D5 | Offer id | The `OutPoint` of the `MakeOffer` output | Unique, deterministic, no maker-chosen ids to squat/collide |
| D6 | Expiry clock | Peer-proposed **median unix timestamp**, monotonic | Byzantine-tolerant, chain-independent, wall-clock legible; costs one consensus item |
| D7 | Fees | None in v1 | Every leg moves value 1:1 within a unit; no solvency invariant to maintain |
| D8 | Privacy | Offers/fills visible in consensus state | Documented known property; not a defect |
| D9 | Config/DKG | Trivial (`dummy`-style empty config) | No threshold key, no secrets, no distributed gen |
| D10 | `Claim` disambiguation | Explicit `party` discriminant on the input | `process_input` *produces* the `pub_key` core verifies; side can't be inferred from the signature |

---

## Crate and file map

New crates (three-crate module pattern):

| Crate | Path | Purpose | wasm? |
|---|---|---|---|
| `fedimint-swap-common` | `modules/fedimint-swap-common` | Types (`SwapInput`/`SwapOutput`/`Offer`/errors), config, consensus item, `KIND`, encoding | **yes** |
| `fedimint-swap-server` | `modules/fedimint-swap-server` | `ServerModule`: offer lifecycle, timestamp clock, DB, audit, endpoints | no |
| `fedimint-swap-client` | `modules/fedimint-swap-client` | `ClientModule`: maker/taker state machines, `list_open_offers`, offer helpers | **yes** |
| `fedimint-swap-tests` | `modules/fedimint-swap-tests` | Integration tests (`fedimint-testing`), `publish = false` | no |

Modified existing files (integration points):

- `Cargo.toml` (root): four new workspace members + crate entries.
- `fedimintd/src/lib.rs`: `default_modules()` → `server_gens.attach(fedimint_swap_server::SwapInit);` (+ a `LEGACY_HARDCODED_INSTANCE_ID_SWAP` const if the codebase pins instance ids there — check neighbors).
- `fedimint-cli/src/lib.rs` (or wherever client modules attach): `client_module_inits.attach(fedimint_swap_client::SwapClientInit);`.
- `modules/fedimint-swap-tests/Cargo.toml` + `scripts/tests/`: CI wiring for the new test binary.

**Client wasm rule:** `fedimint-swap-client` and `-common` must not pull in tokio-native IO or any server-only crate. They need only: secp256k1 keys, `Amount`/`AmountUnit`, `OutPoint`, encoding, and guardian API calls.

---

## Pinned cross-phase interfaces

These are the contracts between phases. JIT phase plans implement against them verbatim; renames require editing this section first. Types are `fedimint_core` unless noted: `Amount`, `AmountUnit`, `Amounts` (`BTreeMap<AmountUnit, Amount>`, ctor `Amounts::new_custom(unit, amount)`), `TransactionItemAmounts { amounts: Amounts, fees: Amounts }`, `InputMeta { amount: TransactionItemAmounts, pub_key: secp256k1::PublicKey }`, `OutPoint`, `InPoint`, `PeerId`, `secp256k1::PublicKey`.

### A. `fedimint-swap-common`

```rust
pub const KIND: ModuleKind = ModuleKind::from_static_str("swap");
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

/// Which side of a filled offer a claim is for. Explicit because
/// `process_input` must produce the pubkey core verifies (D10).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum Party { Maker, Taker }

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum SwapOutput {
    MakeOffer {
        maker_unit: AmountUnit,
        maker_amount: Amount,
        taker_unit: AmountUnit,
        taker_amount: Amount,
        /// Consensus-timestamp seconds after which the offer can no longer be filled.
        expiry: u64,
        maker_pk: PublicKey,
    },
    Fill { offer_id: OutPoint, taker_pk: PublicKey },
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum SwapInput {
    Claim { offer_id: OutPoint, party: Party },
    Reclaim { offer_id: OutPoint },
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// `output_status` payload: `Some` once the output landed (offer created / fill accepted).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct SwapOutputOutcome;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum OfferState { Open, Filled { taker_pk: PublicKey } }

/// The full offer record (also the shape returned by `list_open_offers`).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Offer {
    pub maker_pk: PublicKey,
    pub maker_unit: AmountUnit,
    pub maker_amount: Amount,
    pub taker_unit: AmountUnit,
    pub taker_amount: Amount,
    pub expiry: u64,
    pub state: OfferState,
    pub maker_claimed: bool,  // maker has withdrawn the TAKER leg
    pub taker_claimed: bool,  // taker has withdrawn the MAKER leg
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum SwapInputError {
    UnknownOffer,
    OfferNotFilled,      // Claim on an Open offer
    OfferNotOpen,        // Reclaim on a Filled offer
    LegAlreadyClaimed,   // second Claim of the same party's leg
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum SwapOutputError {
    UnknownOffer,        // Fill references a missing offer
    OfferAlreadyFilled,  // Fill on a non-Open offer
    OfferExpired,        // Fill after expiry
    ExpiryInPast,        // MakeOffer with expiry <= now
    SameUnit,            // maker_unit == taker_unit
    ZeroAmount,          // maker_amount or taker_amount is zero
}

/// Consensus item: each guardian's proposed wall-clock time (D6).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct SwapConsensusItem { pub unix_secs: u64 }
```

`plugin_types_trait_impl_common!(KIND, SwapModuleTypes, SwapClientConfig, SwapInput, SwapOutput, SwapOutputOutcome, SwapConsensusItem, SwapInputError, SwapOutputError);` plus `Display` for each type. `SwapClientConfig` is a unit struct (D9).

### B. `fedimint-swap-server` — DB schema

```rust
#[repr(u8)] enum DbKeyPrefix { Offer = 0x01, ConsensusTs = 0x02 }

// Offer records, keyed by the MakeOffer output's OutPoint.
OfferKey(OutPoint) -> Offer            // OfferPrefix for range scans (list_open_offers)
// Per-peer latest proposed timestamp; median-of-values is the consensus clock.
ConsensusTsKey(PeerId) -> u64          // ConsensusTsPrefix
```

### C. `fedimint-swap-server` — pinned server helpers

```rust
/// Median of the latest per-peer proposed timestamps; 0 if none yet (pre-init).
/// Pure consensus-DB read — safe to call from process_input/process_output.
async fn consensus_timestamp(dbtx: &mut DatabaseTransaction<'_>) -> u64;

// process_output(MakeOffer) -> TransactionItemAmounts { amounts: {maker_unit: maker_amount}, fees: 0 }
// process_output(Fill)      -> TransactionItemAmounts { amounts: {taker_unit: taker_amount}, fees: 0 }
// process_input(Claim{Maker}) -> InputMeta { amount: {taker_unit: taker_amount}, pub_key: maker_pk }
// process_input(Claim{Taker}) -> InputMeta { amount: {maker_unit: maker_amount}, pub_key: taker_pk }
// process_input(Reclaim)      -> InputMeta { amount: {maker_unit: maker_amount}, pub_key: maker_pk }
```

### D. `fedimint-swap-client` — pinned client surface

```rust
impl SwapClientModule {
    /// Maker: lock `maker_amount`/`maker_unit`, want `taker_amount`/`taker_unit`, valid `ttl_secs`.
    /// Returns the offer id (the MakeOffer OutPoint) once accepted.
    pub async fn make_offer(&self, maker_unit, maker_amount, taker_unit, taker_amount, ttl_secs) -> anyhow::Result<OutPoint>;
    /// Taker: fill `offer_id`. Errors if already filled/expired (funds untouched).
    pub async fn fill_offer(&self, offer_id: OutPoint) -> anyhow::Result<()>;
    /// Maker: cancel/reclaim an Open offer.
    pub async fn reclaim(&self, offer_id: OutPoint) -> anyhow::Result<()>;
    /// Browse the public order board.
    pub async fn list_open_offers(&self) -> anyhow::Result<Vec<(OutPoint, Offer)>>;
}
```

Endpoint constants (`fedimint-swap-common`): `LIST_OPEN_OFFERS_ENDPOINT = "list_open_offers"`, `GET_OFFER_ENDPOINT = "get_offer"`.

---

## Phase breakdown

Each phase ends with an independently testable deliverable and is executed from its own JIT detailed plan. Template for all boilerplate: the `dummy` module (`modules/fedimint-dummy-*`).

### Phase 1 — `-common` crate (types + encoding)
**Deliverable:** `fedimint-swap-common` compiles; all types in interface **A** defined and `Display`-implemented; `plugin_types_trait_impl_common!` wired; `SwapClientConfig` unit struct + `config.rs`.
**Tests:** Encodable/Decodable round-trip for `SwapInput`, `SwapOutput`, `Offer`, `SwapConsensusItem` (including the `#[encodable_default]` unknown-variant path). `just clippy` clean.
**Template:** `fedimint-dummy-common/src/{lib.rs,config.rs}`; the versioned-enum + `#[encodable_default]` pattern from `fedimint-usdt-common`'s `UsdtInput`.

### Phase 2 — `-server` scaffolding (init, config, DB, registration)
**Deliverable:** `fedimint-swap-server` with `SwapInit` (`ModuleInit` + `ServerModuleInit`), trivial `trusted_dealer_gen`/`distributed_gen`/`get_client_config` (dummy-style), empty `get_database_migrations`, `db.rs` with the schema in **B**, and a `ServerModule` impl whose process fns are stubs returning `UnknownOffer`. Registered in `fedimintd/src/lib.rs`.
**Tests:** the module initializes inside a `fedimint-testing` federation; DB key encode/decode round-trips. `just clippy` clean.
**Template:** `fedimint-dummy-server/src/{lib.rs,db.rs}`.

### Phase 3 — offer lifecycle (the consensus heart)
**Deliverable:** real `process_output` (`MakeOffer` writes an `Open` offer keyed by `out_point`; `Fill` flips `Open`→`Filled` with all validations from **A**'s error enums) and `process_input` (`Claim{party}` pays the correct leg to the correct key and sets the matching `*_claimed` flag; `Reclaim` pays the maker leg while `Open` and deletes the offer). `audit()` counts locked legs as liabilities. `consensus_timestamp()` helper (median read; tests seed `ConsensusTsKey` directly — the *populating* proposal is Phase 4).
**Tests (unit, TDD):** every happy path; every rejection (`fill-not-open`, `fill-expired`, `reclaim-after-fill`, wrong-`party` claim → signature-key mismatch, double-claim → `LegAlreadyClaimed`, `same-unit`, `zero-amount`, `expiry-in-past`); the **Fill-vs-Reclaim** and **two-taker** races asserted order-independent; a **per-unit solvency invariant** (escrow released ≤ escrow locked, per unit, over an arbitrary op interleaving).
**Template:** `process_input`/`process_output` shape from `dummy`; single-claim-exactly-once and key-in-`InputMeta` from `fedimint-usdt-common`'s `UsdtInput::RefundV0` docs + `fedimint-usdt-server`'s `process_input`.

### Phase 4 — consensus-timestamp clock
**Deliverable:** `consensus_proposal` proposes `SwapConsensusItem { unix_secs: now() }` (throttled so it only proposes when its own last-proposed value is stale, mirroring USDT's block-count throttle); `process_consensus_item` writes `ConsensusTsKey(peer)` **monotonically** (never decreasing a peer's stored value) and returns `Err` when the item changes nothing (per the `process_consensus_item` history-size warning).
**Tests:** median-of-values correctness; monotonicity (a lower proposal from a peer is ignored); an offer created then expired purely by advancing proposals; `process_consensus_item` returns `Err` on a no-op.
**Template:** USDT block-count consensus (`spawn_block_count_poller` → `consensus_proposal` → `process_consensus_item` median write).

### Phase 5 — `-client` crate (maker + taker state machines)
**Deliverable:** `SwapClientInit` + `SwapClientModule` with the surface in **D**. Maker SM: `MakeOffer` → on `Filled`, `Claim{Maker}`; on cancel/expiry-while-`Open`, `Reclaim`. Taker SM: `Fill` → on accept, `Claim{Taker}`; on reject, terminal `FillRejected` (no funds moved). `maker_pk`/`taker_pk`/refund keys derived deterministically from the client seed. `list_open_offers` + `get_offer` endpoints (server side wired here too).
**Tests:** client-side SM transition unit tests; key-derivation determinism. wasm build check (`just check-wasm`).
**Template:** `fedimint-dummy-client/src/{lib.rs,input_sm.rs,output_sm.rs,db.rs}`.

### Phase 6 — integration tests + e2e
**Deliverable:** `fedimint-swap-tests` with a full round trip on a `fedimint-testing` federation carrying **two mint instances in different units**: maker offers unit-A for unit-B, taker fills, both claim, balances reflect the swap. Cancel path and expiry path covered. CI wiring for the new test binary.
**Tests:** happy-path swap; cancel-before-fill; expiry-then-reclaim; two-taker race (one wins, one gets funds back); fill-after-expiry rejected.
**Template:** `fedimint-*-tests` crates; multi-unit test federation setup.

### Phase 7 — rollout wiring (demo feds)
**Deliverable:** the config/consensus sequencing to register the new module instance across guardians (this is a config-changing upgrade, unlike the additive USDT v6/v7). Document the DKG/config-gen path for adding a module to the running demo feds, or the decision to stand up a fresh federation for it.
**Tests:** devimint spins a federation with the swap module attached; guardians agree the module into config.
**Note:** this phase is operational; sequence it only once Phases 1–6 are green.

---

## Global Constraints

- **Determinism (consensus-critical):** every value on the consensus path (`process_input`/`process_output`/`process_consensus_item`) must be a pure function of the ordered item + prior consensus DB + config. Read time **only** via `consensus_timestamp(dbtx)` (a consensus-DB read), never `SystemTime`/wall-clock/`our_peer_id`/RPC inside a process fn. `SystemTime::now()` appears **only** in `consensus_proposal` (a proposal, allowed to be non-deterministic).
- **Per-unit balance:** every `process_output`/`process_input` returns amounts in the leg's own `AmountUnit` via `Amounts::new_custom(unit, amount)`. Never mix units at par; never assume `AmountUnit::BITCOIN`.
- **Claim by produced key (D10):** `process_input` returns the `pub_key` to verify; it must never try to read a signature. Wrong-`party` claims fail by key mismatch, not by a special check.
- **Exactly-once legs:** guard every `Claim`/`Reclaim` against replay via `*_claimed` flags / offer deletion; a second attempt errors, never double-pays.
- **`process_consensus_item` must `Err` on no-ops** (history-size warning in the `dummy` template).
- **wasm:** `-client` and `-common` stay wasm-safe; verify with `just check-wasm`.
- **Style:** no `unwrap()` in non-test code — `expect()` with an invariant reason; structured `tracing` (field = value); `just clippy` (pedantic+nursery, `-D warnings`) and `just format` clean before every commit.
- **Pre-release module:** no wire/DB back-compat required across phases; ships at DB v0.

---

## Self-review — spec coverage

| Spec section | Covered by |
|---|---|
| Trust model / per-unit escrow | Architecture; Global Constraints (per-unit balance); Phase 3 |
| `Offer` state | Interface A; DB schema B; Phase 3 |
| Make / Fill / Claim / Reclaim | Interface A + C; Phase 3 |
| `Claim` `party` disambiguation (D10) | Interface A; Global Constraints; Phase 3 tests (wrong-party) |
| Median-timestamp expiry clock | Interface A/B/C; Phase 4 |
| Fill-vs-Reclaim & two-taker races | Phase 3 tests; Phase 6 e2e |
| No fees (v1) | D7; process fns return `fees: 0` |
| Privacy (visible offers) | D8; `list_open_offers` is intentional |
| Client SMs + discovery | Interface D; Phase 5 |
| Testing (solvency, monotonicity) | Phase 3 + Phase 4 tests |
| Rollout (new module) | Phase 7 |
