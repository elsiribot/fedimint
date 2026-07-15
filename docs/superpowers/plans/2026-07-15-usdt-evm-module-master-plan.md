# USDT-on-EVM Wallet Module — Master Implementation Plan

> **How to use this document:** This is the end-to-end master plan for the entire module. It pins every crate, cross-phase interface (types, traits, consensus items, DB schemas), and acceptance test. Each phase is executed from its own just-in-time detailed plan (written via superpowers:writing-plans, like `2026-07-15-threshold-ecdsa.md` for Phase 1) whose steps must conform to the interfaces pinned here. Changing a pinned interface requires updating this document first.

**Goal:** A production-grade Fedimint module custodying USDT on EVM chains: users deposit USDT to per-user addresses and receive USDT-denominated e-cash; the federation consolidates deposits and processes withdrawals via ERC-4337 with gas paid in USDT; custody is a t-of-n CGGMP21 threshold-ECDSA group key.

**Design spec:** `docs/superpowers/specs/2026-07-15-usdt-wallet-module-design.md`

**Tech stack:** Rust (edition 2024), `cggmp21` 0.6.x (audited, MIT/Apache), `alloy` (EVM RPC + types), ERC-4337 EntryPoint v0.7 + SimpleAccount (vendored bytecode), `anvil` (hermetic EVM devnet), devimint + fedimint-testing.

---

## Decision record (settled with elsirion, 2026-07-15)

| # | Decision | Choice | Key consequence |
|---|---|---|---|
| D1 | Target chain family | EVM (L1 + L2s), chain configurable | Tron/Liquid out of scope; adapters possible later |
| D2 | Custody | Threshold ECDSA via `cggmp21` (CGGMP21, Kudelski-audited) | No identifiable aborts → timeout + signer-subset rotation |
| D3 | Deposit addresses | Counterfactual ERC-4337 smart accounts, CREATE2 salt commits to claim key; all owned by the one group key | HD derivation NOT on critical path (kept for fallback Model C) |
| D4 | Gas model | ERC-20 paymaster pays gas, reimbursed in USDT (third-party primary, self-run fallback); tests self-bundle via `handleOps` | Federation custodies only USDT in steady state |
| D5 | Runtime MPC transport | **Consensus items, full-interactive** — signing rounds ride AlephBFT like peg-out sigs today; P2P round parts encrypted per-recipient | ~15–60 s per signing session; batch many withdrawals per UserOp; no core-framework changes; no presignature storage (reuse hazard avoided) |
| D6 | AA stack | **SimpleAccount + EntryPoint v0.7** (canonical addr `0x0000000071727De22E5E9d8BAf0edAc6f37da032`), vendored bytecode | Broadest bundler/paymaster support; single-owner ECDSA check = group key |
| D7 | Deposit watch model | **Claim-triggered verification** — no standing watch set; client requests a check after depositing; guardians verify balance and vote | Two-phase claim (check → claim input); minimal guardian state; bounded work |
| D8 | Denomination | **USDT-denominated federation**: 1 fedimint `Amount` unit ≡ 10⁻⁶ USDT (the on-chain unit). Module deployed alongside a mint issuing USDT e-cash; not mixed into a BTC federation | Single-asset-per-federation constraint documented; no core multi-asset work |
| D9 | Setup-time DKG transport | CGGMP21 keygen + aux-gen over `PeerHandleOps::exchange_bytes` broadcast rounds; P2P parts encrypted per-recipient and packed per round | No changes to `PeerHandleOps`; fail-stop (all peers online during DKG — same as today's config gen) |
| D10 | Fee pricing | Guardians vote `FeeVote { max_fee_per_gas, usdt_per_eth_e6 }` (per-guardian configurable price source); median-of-votes, buffer on quotes | Same trust model as today's bitcoin feerate votes; no single oracle |

---

## Crate and file map

New crates (three-crate module pattern + shared crypto):

| Crate | Path | Purpose | wasm? |
|---|---|---|---|
| `fedimint-threshold-ecdsa` | `crypto/threshold-ecdsa` | cggmp21 wrapper: DKG, signing, exchange-round transport adapter | no |
| `fedimint-usdt-common` | `modules/fedimint-usdt-common` | Types, config, consensus items, contract constants/artifacts, CREATE2 address derivation | **yes** |
| `fedimint-usdt-server` | `modules/fedimint-usdt-server` | ServerModule: consensus, MPC sessions, EVM watcher, UserOp pipeline | no |
| `fedimint-usdt-client` | `modules/fedimint-usdt-client` | ClientModule: deposit/claim/withdraw operations + state machines | **yes** |
| `fedimint-usdt-tests` | `modules/fedimint-usdt-tests` | Integration tests (fedimint-testing harness + mock EVM), `publish = false` | no |

Modified existing files (recurring integration points):

- `Cargo.toml` (root): members + workspace deps (`alloy`, `cggmp21`, `round-based`, crate entries)
- `fedimintd/src/lib.rs`: `default_modules()` → `server_gens.attach(fedimint_usdt_server::UsdtInit);`
- `devimint/src/{external.rs,util.rs,vars.rs,devfed.rs,cli.rs,tests.rs}`: `Anvil` daemon + contract-deploy fixtures + e2e test cmd
- `flake.nix` / `nix/`: package `anvil` (foundry) for dev shell + CI
- `fedimint-testing`: nothing (module-specific mock EVM lives in `fedimint-usdt-tests`)
- `scripts/tests/`: CI wiring for the new test binary + devimint e2e

**Client wasm rule:** `fedimint-usdt-client` and `-common` must not depend on `alloy` networking, tokio-native IO, or `fedimint-threshold-ecdsa`. The client needs only: CREATE2/keccak address math (via `sha3`), claim-key management, and guardian API calls. The client never talks to an EVM node.

---

## Pinned cross-phase interfaces

These are the contracts between phases. JIT phase plans implement against them verbatim; renames require editing this section first.

### A. `fedimint-threshold-ecdsa` (Phase 1 — plan exists; Phase 2 adds the transport adapter)

```rust
pub type Curve = cggmp21::supported_curves::Secp256k1;
pub type KeyShare = cggmp21::KeyShare<Curve>;

// Phase 1 (see docs/superpowers/plans/2026-07-15-threshold-ecdsa.md):
pub async fn run_keygen(eid, i, t, n, rng, party) -> anyhow::Result<cggmp21::IncompleteKeyShare<Curve>>;
pub async fn run_aux_gen(eid, i, n, primes, rng, party) -> anyhow::Result<cggmp21::key_share::AuxInfo>;
pub fn assemble_key_share(core, aux) -> anyhow::Result<KeyShare>;
pub async fn run_signing(eid, i, signers, share, derivation_path, digest, rng, party)
    -> anyhow::Result<secp256k1::ecdsa::Signature>;
pub fn group_public_key(share: &KeyShare) -> anyhow::Result<secp256k1::PublicKey>;
pub fn derived_public_key(share: &KeyShare, path: &[u32]) -> anyhow::Result<secp256k1::PublicKey>;
pub fn evm_address(pk: &secp256k1::PublicKey) -> [u8; 20];

// Phase 2 — exchange-round transport (both DKG-at-setup and runtime reuse this):
/// One synchronous all-to-all byte-exchange round. Implemented over
/// `PeerHandleOps::exchange_bytes` at setup, and over consensus items at runtime.
#[async_trait]
pub trait RoundExchange {
    /// Broadcast `ours`, receive every party's payload (own included), indexed 0..n.
    async fn exchange(&mut self, ours: Vec<u8>) -> anyhow::Result<Vec<Vec<u8>>>;
}

/// Per-recipient encryption for cggmp21's P2P round messages carried over
/// broadcast rounds: payload_i = ECIES(recipient_i static pubkey, msg_i).
/// Round packet = Encodable { broadcast: Option<Vec<u8>>, p2p: BTreeMap<u16, Vec<u8>> }.
pub struct EncryptedRoundCodec { /* our static secret, all parties' static pubkeys */ }

/// Drive any cggmp21 protocol (keygen / aux-gen / signing, via its
/// `state-machine`-feature sync driver) over a RoundExchange.
pub async fn drive_over_exchange<SM: round_based::state_machine::StateMachine>(
    sm: SM, codec: &EncryptedRoundCodec, exchange: &mut dyn RoundExchange,
) -> anyhow::Result<SM::Output>;
```

### B. `fedimint-usdt-common` — module types

```rust
pub const KIND: ModuleKind = ModuleKind::from_static_str("usdt");
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

/// 20-byte EVM address newtype, Encodable/Decodable, Display = EIP-55 hex.
pub struct EvmAddress(pub [u8; 20]);
/// USDT in on-chain units (10^-6 USDT). Converts 1:1 to fedimint Amount (D8).
pub struct UsdtAmount(pub u64);

pub enum UsdtConsensusItem {
    /// Guardian's view of chain head (median voted; confirmation depth applied on top).
    BlockCount(u64),
    /// Fee + FX vote (median-of-votes per D10).
    FeeVote(FeeVote),
    /// Deposit observation: balance of `account` at `block` (claim-triggered, D7).
    Deposit(DepositObservation),
    /// One MPC round payload of a signing session (D5).
    MpcRound(MpcRoundItem),
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

pub struct FeeVote { pub max_fee_per_gas_wei: u64, pub usdt_per_eth_e6: u64 }
pub struct DepositObservation { pub account: EvmAddress, pub balance: UsdtAmount, pub block: u64 }
pub struct MpcRoundItem { pub session_id: SigningSessionId, pub round: u16, pub payload: Vec<u8> }
/// Deterministic id: hash(digest-to-sign ‖ attempt-counter).
pub struct SigningSessionId(pub [u8; 32]);

pub enum UsdtInput {
    /// Claim credited deposit funds. Core verifies the fedimint transaction
    /// is signed by `InputMeta.pub_key` = the claim key committed in the
    /// account's CREATE2 salt — no extra signature inside the input.
    V0(UsdtInputV0),
}
pub struct UsdtInputV0 { pub account: EvmAddress, pub amount: UsdtAmount }

pub enum UsdtOutput { V0(UsdtOutputV0) }
pub struct UsdtOutputV0 {
    pub recipient: EvmAddress,
    pub amount: UsdtAmount,
    /// Max total fee (gas-in-USDT + module fee) the user accepts; quoted
    /// via the client from FeeVote medians + buffer.
    pub max_fee: UsdtAmount,
}
pub struct UsdtOutputOutcome; // outcome tracked via operation/api, kept unit for v0

/// Address derivation (client + server must agree bit-for-bit):
/// salt = keccak256("fedimint-usdt-deposit-v0" ‖ claim_pk_compressed)
/// account = CREATE2(SimpleAccountFactory, salt, initcode_hash(owner = group key EOA addr))
pub fn derive_deposit_account(cfg: &UsdtClientConfig, claim_pk: &secp256k1::PublicKey) -> EvmAddress;

pub struct UsdtClientConfig {
    pub chain_id: u64,
    pub usdt_contract: EvmAddress,
    pub entry_point: EvmAddress,
    pub account_factory: EvmAddress,
    pub group_pubkey: secp256k1::PublicKey,
    pub confirmation_depth: u64,
    pub deposit_check_fee: UsdtAmount, // anti-spam knob, may be 0
}
// Server config split (mirrors wallet): UsdtConfig { local: rpc url etc.,
// consensus: UsdtConfigConsensus (chain params, contracts, threshold, all
// peers' MPC static encryption pubkeys), private: UsdtConfigPrivate (cggmp21
// KeyShare serialized, MPC static encryption secret) }.
```

Vendored contract artifacts in `modules/fedimint-usdt-common/contracts/` (JSON: abi + creation/runtime bytecode; no Solidity toolchain in build or CI):
`EntryPoint-v0.7.json`, `SimpleAccountFactory-v0.7.json`, `SimpleAccount-v0.7.json`, `TetherToken.json` (mainnet USDT source, compiled once, committed), `TestTokenPaymaster.json` (eth-infinitism sample token paymaster, fixed-price oracle, **test/devnet only**).

### C. EVM adapter (defined in `fedimint-usdt-server/src/rpc.rs`)

```rust
#[async_trait]
pub trait IServerEvmRpc: Debug + Send + Sync + 'static {
    async fn get_chain_id(&self) -> anyhow::Result<u64>;
    async fn get_block_number(&self) -> anyhow::Result<u64>;
    async fn get_erc20_balance(&self, token: EvmAddress, holder: EvmAddress, at_block: u64)
        -> anyhow::Result<UsdtAmount>;
    async fn get_fee_estimate(&self) -> anyhow::Result<FeeVote>; // usdt_per_eth from configured source
    async fn get_code_len(&self, addr: EvmAddress) -> anyhow::Result<usize>; // deployed-or-counterfactual
    async fn get_user_op_receipt(&self, user_op_hash: [u8; 32])
        -> anyhow::Result<Option<UserOpReceipt>>;
    /// Submit a signed batch. Impl A (tests/self-run): wrap in
    /// EntryPoint.handleOps from the broadcaster EOA. Impl B (prod):
    /// eth_sendUserOperation to a bundler endpoint.
    async fn submit_user_ops(&self, ops: Vec<SignedUserOp>) -> anyhow::Result<()>;
}
pub struct UserOpReceipt { pub success: bool, pub block: u64, pub actual_cost_usdt: UsdtAmount }
```

Implementations: `AlloyEvmRpc` (alloy provider, self-bundling via broadcaster EOA — used by devimint/anvil and the self-run fallback) and `BundlerEvmRpc` (Phase 8, thin: same alloy provider for reads + bundler URL for submission). `fedimint-usdt-tests` provides `MockEvmRpc` (scripted balances/blocks/receipts).

### D. Server DB schema (prefix bytes pinned; all values Encodable)

| Prefix | Key | Value |
|---|---|---|
| 0x01 | `BlockCountVoteKey(PeerId)` | `u64` |
| 0x02 | `FeeVoteKey(PeerId)` | `FeeVote` |
| 0x03 | `DepositRecordKey(EvmAddress)` | `DepositRecord { claim_pk, credited: UsdtAmount, claimed: UsdtAmount, last_observed_block: u64 }` |
| 0x04 | `DepositObservationVoteKey(EvmAddress, PeerId)` | `DepositObservation` |
| 0x05 | `PendingCheckKey(EvmAddress)` | `PendingCheck { claim_pk, requested_at_block: u64 }` (local, guardian-only) |
| 0x06 | `SigningSessionKey(SigningSessionId)` | `SigningSession { purpose, digest, signers: Vec<PeerId>, state: SessionState }` |
| 0x07 | `MpcRoundSeenKey(SigningSessionId, u16 round, PeerId)` | `()` (redundancy guard — `process_consensus_item` MUST error on duplicates) |
| 0x08 | `PendingUserOpKey([u8;32] op_hash)` | `PendingUserOp { op: UnsignedUserOp, purpose: UserOpPurpose, created_block: u64 }` |
| 0x09 | `SubmittedUserOpKey([u8;32] op_hash)` | `SubmittedUserOp { signed: SignedUserOp, submitted_block: u64 }` |
| 0x0A | `PoolStateKey` | `PoolState { account: EvmAddress, balance: UsdtAmount }` |
| 0x0B | `UnclaimedWithdrawalKey(OutPoint)` | `UsdtOutputV0` (queued for next batch) |

`UserOpPurpose ∈ { DeployAndSweep { source: EvmAddress }, Withdraw { outpoints: Vec<OutPoint> } }`.

### E. Module API endpoints (server → client)

| Endpoint | Request | Response | Notes |
|---|---|---|---|
| `check_deposit` | `{ claim_pk }` | `{ account, enqueued: bool }` | Enqueues `PendingCheck` (D7); idempotent |
| `deposit_status` | `{ claim_pk }` | `{ account, credited, claimed, claimable }` | Client polls until claimable |
| `withdraw_fee_quote` | `{ amount }` | `{ max_fee: UsdtAmount, valid_blocks: u64 }` | From FeeVote medians + buffer |
| `withdrawal_status` | `{ outpoint }` | `{ state: Queued\|Signing\|Submitted{op_hash}\|Confirmed{block}\|Failed{reason} }` | Drives client SM |
| `module_consensus_block_count` | `{}` | `u64` | Diagnostics/tests |

---

## Phase sequence

Dependency graph (each phase = one JIT detailed plan; ★ = has hermetic acceptance test gating the next phase):

```
P1 threshold-ecdsa crate ★
P2 exchange transport + DKG harness ★
P3 module scaffolding + config-gen DKG ★        (needs P1, P2)
P4 EVM adapter + devimint anvil stack ★         (independent of P2/P3; parallelizable)
P5 deposit path: check → consensus → claim ★    (needs P3, P4)
P6 runtime MPC signing sessions ★               (needs P3; P2 transport reused)
P7 ERC-4337 UserOp pipeline ★                   (needs P4, P6)
P8 consolidation + withdrawal + fees ★          (needs P5, P7)
P9 hardening + full acceptance suite + audit prep ★ (needs all)
```

---

### Phase 1 — `fedimint-threshold-ecdsa` crate

**Status:** Detailed plan written and committed: `docs/superpowers/plans/2026-07-15-threshold-ecdsa.md` (6 tasks). One scope amendment from D3: HD derivation (its Task 5) now serves only fallback Model C — keep the task (it's small and already planned) but its acceptance is not on the module's critical path.

**Acceptance ★:** `cargo test --release -p fedimint-threshold-ecdsa` — DKG, signing, sub-threshold-fails, HD, EVM-address vector, all over in-memory transport. Est: 2–3 wks.

### Phase 2 — Exchange-round transport + DKG harness

**Goal:** The single abstraction (interface A, Phase-2 section) that lets any cggmp21 protocol run over synchronous all-to-all byte-exchange rounds — the only transport shape Fedimint offers at both setup (`PeerHandleOps::exchange_bytes`) and runtime (consensus items).

**Deviation from initial master plan (recorded 2026-07-15):** Phase 2 keeps `fedimint-threshold-ecdsa` free of any `fedimint-core` dependency (Phase 1 established this and the whole-branch review praised it). The `RoundExchange` trait and an in-memory implementation live in the crate and ARE the test harness; the `PeerHandleOps`-backed setup adapter and the consensus-item runtime adapter move to Phase 3/Phase 6 (the module crate, which already depends on fedimint-server-core). Net effect: same transport abstraction, cleaner dependency boundary, and the setup-DKG wiring is validated in Phase 3's acceptance rather than here.

**Tasks (summary; JIT plan expands):**
1. `EncryptedRoundCodec`: static x25519 or secp256k1-ECIES keypair per guardian (generated at config time, pubkeys in consensus config); pack/unpack `{broadcast, p2p: BTreeMap<u16, ciphertext>}` round packets. Property tests for codec round-trip + tamper rejection.
2. `drive_over_exchange`: pump a cggmp21 `state-machine`-feature sync state machine (`ProceedResult`) against a `RoundExchange`; map round_based `Outgoing`/`Incoming` (sender indexes, broadcast vs p2p) onto packets. This uses the **sync driver, not async Sink/Stream** — deterministic, no runtime coupling.
3. In-memory `RoundExchange` impl for tests; re-run Phase-1 keygen/aux/signing tests through `drive_over_exchange` (proves semantic equivalence with the native async transport).
4. Fake-p2p DKG harness: drive `run_keygen`+`run_aux_gen` over an `exchange_bytes`-shaped adapter using `fedimint_core::net::peers::fake` mesh — the coverage `fedimint-testing` cannot give (it always uses trusted-dealer config gen).

**Acceptance ★:** 4-of-4 keygen + 3-of-4 signing complete over the exchange-round transport with per-recipient encryption; corrupted/replayed round packets abort the session with a clear error and no panic. Est: 2–3 wks. **Risk:** message-shape mismatch between round_based rounds and lockstep exchange rounds (e.g. a protocol round that sends nothing for some parties) — retire early with a spike test in Task 2.

### Phase 3 — Module scaffolding + config-gen DKG

**Goal:** The three module crates exist, register in fedimintd, and a federation completes real DKG at setup, storing each guardian's `KeyShare`.

**Tasks:** clone `fedimint-empty-*` skeletons into interface-B types (all no-op consensus logic); `plugin_types_trait_impl_common!` wiring; `UsdtInit: ServerModuleInit` with `trusted_dealer_gen` (uses `cggmp21::trusted_dealer` — legitimate here: trusted-dealer config gen *is* a trusted setup; `spof` becomes a regular server-crate feature) and `distributed_gen` (Phase-2 `drive_over_exchange` over an adapter wrapping `PeerHandleOps::exchange_bytes`; keygen then aux-gen; group pubkey into consensus config, `KeyShare` into private config); `UsdtClientInit` skeleton; attach in `fedimintd/src/lib.rs`; `fedimint-usdt-tests` crate with `Fixtures::new_primary(...)`-pattern harness (mint primary + usdt module, `MockEvmRpc`).

**Acceptance ★:** (a) fedimint-testing federation with the module boots and answers `module_consensus_block_count`; (b) devimint 4-guardian real-DKG startup produces identical group pubkeys in all four configs (asserted via an admin endpoint); `just final-lint` green. Est: 3–4 wks. **Risk:** DKG wall-clock at setup (Paillier primes, ~minutes) — pregenerate primes concurrently with earlier setup steps; document expected setup time.

### Phase 4 — EVM adapter + devimint anvil stack (parallelizable with P2/P3)

**Goal:** Interface C implemented for real, plus the hermetic EVM test environment every later acceptance test uses.

**Tasks:** `alloy` workspace dep; `AlloyEvmRpc` (reads + `handleOps` self-bundling from a broadcaster EOA); `MockEvmRpc` in `fedimint-usdt-tests`; vendor contract artifacts (compile TetherToken 0.4.17 + fetch canonical EntryPoint/SimpleAccountFactory v0.7 artifacts, commit JSON); devimint `Anvil` daemon (`external.rs` Esplora-pattern: `FM_PORT_ANVIL` in vars.rs, `util.rs` binary alias `FM_ANVIL_BASE_EXECUTABLE_ENV`, nix packaging of foundry); deploy fixture: EntryPoint via `anvil_setCode` at its canonical address, factory + TetherToken + TestTokenPaymaster via funded-EOA deploys, paymaster staked/funded; `DevFed` integration + `devimint-env` exposure of addresses via env vars.

**Acceptance ★:** integration test (gated on anvil presence, CI-wired): spin anvil, deploy fixture, mint TetherToken to a test EOA, transfer, read balance via `AlloyEvmRpc` at a depth-confirmed block; submit a trivial self-bundled UserOp through EntryPoint successfully. Est: 3–4 wks. **Risk:** USDT-quirk handling in alloy contract bindings (no-return-value `transfer`) — covered by using the real TetherToken bytecode in every test from day one.

### Phase 5 — Deposit path: check → consensus → claim

**Goal:** End-to-end deposits: plain USDT transfer to a derived address becomes claimable e-cash. No MPC needed yet (nothing is swept).

**Flow pinned (D7, claim-triggered):**
1. Client generates claim keypair; `derive_deposit_account` (interface B) shows the address.
2. After the user's on-chain transfer, client calls `check_deposit { claim_pk }` on all guardians → each stores `PendingCheck` (local DB, expires after `check_ttl_blocks`).
3. Guardian background task (per consensus block-count tick): for each `PendingCheck`, read `get_erc20_balance(usdt, account, head − confirmation_depth)`; if balance > `DepositRecord.credited`, propose `UsdtConsensusItem::Deposit(observation)`.
4. `process_consensus_item`: store per-peer `DepositObservationVote`; when ≥ threshold peers submitted **identical** `(account, balance)` observations, set `credited = balance` (credit delta = balance − previous credited; balance is monotonic between sweeps since only the federation can move funds out). Clear votes + pending check.
5. Client polls `deposit_status`; submits a fedimint transaction with `UsdtInput::V0 { account, amount ≤ credited − claimed }`, signed by the claim key (`InputMeta.pub_key = claim_pk` — core verifies). `process_input` checks the DepositRecord, bumps `claimed`, mints.

**Tasks:** server consensus logic (block-count votes/median exactly like wallet; deposit votes; input processing + double-claim guard), background checker task, client deposit operation + state machine (derive → instruct → poll → claim → mint) with `OperationId` tracking, `fedimint-cli` subcommands (dev ergonomics), integration tests over `MockEvmRpc` (multi-deposit to same address, partial claims, sub-threshold disagreement, expiry/re-check), devimint e2e over anvil.

**Acceptance ★:** devimint test: fresh federation on anvil → derive address → TetherToken transfer → mine past depth → `check_deposit` → client claims → e-cash balance equals deposit (minus configured deposit fee); replay/double-claim rejected. Est: 3–5 wks.

### Phase 6 — Runtime MPC signing sessions

**Goal:** Guardians co-sign arbitrary 32-byte digests at runtime via `MpcRound` consensus items (D5) — the module-side realization of the design's `PegOutSignature` analog.

**Session state machine pinned:** sessions are created deterministically from DB state (pending UserOps, Phase 7); `SigningSessionId = hash(digest ‖ attempt)`; signer subset = lowest-t peer ids for attempt 0, rotated deterministically per retry attempt; each guardian in the subset drives its cggmp21 sync state machine, emitting its round packet via `consensus_proposal` and consuming peers' packets in `process_consensus_item` (an adapter implements Phase-2 `RoundExchange` semantics over items — a "round" completes when all subset members' packets for that round are processed); non-subset guardians verify liveness only. Timeout = consensus block-count ticks without progress → attempt += 1 (new session, rotated subset). Redundancy guard via `MpcRoundSeenKey` (duplicate rounds MUST return `Err` per `process_consensus_item` contract). Completed session writes the final `secp256k1::ecdsa::Signature` next to its purpose record.

**Tasks:** session manager (create/advance/timeout/retry), the consensus-item `RoundExchange` adapter, MPC static-encryption key distribution in config (from Phase 3), integration tests over fedimint-testing (sign a known digest 4-of-4; kill one guardian → session times out and retries with rotated subset in a `new_fed_degraded()` fixture; verify signature against group key), latency measurement logged.

**Acceptance ★:** in a 3-of-4 degraded federation, a digest gets signed and verified; a stalled subset recovers via rotation without manual intervention. Est: 4–6 wks. **Highest-risk phase** (interactive-MPC ↔ consensus integration — the risk the design doc calls #1); the JIT plan must start with a thin spike (one hardcoded digest through the full loop) before generalizing.

> **⚠️ Constraint discovered in Phase 2 (2026-07-16) — resolve in the Phase 6 spike FIRST:** cggmp21's sync state machines (`into_state_machine`/`sign_sync`) are **`!Send`** — internally `Rc<RefCell<..>>` — and not serializable mid-protocol. Phase 2 drives them to completion inside a single `LocalSet`/`spawn_local` task (fine for config-gen DKG in Phase 3, which runs to completion in one place). But Phase 6 advances signing **incrementally across consensus rounds**, where the in-flight state must survive suspension points controlled by external `process_consensus_item` calls and typically be parked in `Send + 'static` `OperationId`-keyed storage — which a `!Send`, non-serializable state machine cannot do. Phase 6 must therefore either (a) keep **one dedicated OS thread per in-flight signing session** alive for its whole multi-round lifetime, with the consensus loop communicating to it over channels (the `drive_over_exchange` `RoundExchange` becomes a channel-backed adapter bridging the thread and the consensus item flow), or (b) bypass the sync wrapper and drive cggmp21's lower-level round-based message API directly. Option (a) reuses all of Phase 2 as-is and is the likely path; the spike must validate it before the rest of Phase 6 is built.

### Phase 7 — ERC-4337 UserOp pipeline

**Goal:** From "signed digest" to "on-chain effect": construct EntryPoint-v0.7 packed UserOps, sign their `userOpHash` via Phase 6, submit via interface C, track receipts.

**Tasks:** UserOp builder (alloy types; initCode via factory for first-touch accounts; calldata = SimpleAccount `execute` → USDT `transfer`; paymaster fields for TestTokenPaymaster; gas estimation via adapter with conservative static bounds first); `userOpHash` digest computation (EIP-712-style packing per v0.7 — test vectors against the vendored EntryPoint via anvil `eth_call`); pending→signing→submitted→confirmed lifecycle over DB records (idempotent across restarts; re-submission on drop); pool smart account (same factory, salt = `"fedimint-usdt-pool-v0"`); integration tests: deploy-and-sweep a deposit account on anvil with gas paid by the token paymaster in USDT, assert pool received balance − paymaster fee.

**Acceptance ★:** on anvil: counterfactual deposit account with only USDT → one UserOp deploys it, sweeps to pool, paymaster reimbursed in USDT, federation ETH spent = 0 (broadcaster EOA spends, gets refunded by EntryPoint from paymaster stake). Est: 4–6 wks. **Risk:** v0.7 packing/hash subtleties — pin with on-chain `eth_call` test vectors early.

### Phase 8 — Consolidation, withdrawal, fees

**Goal:** User-facing withdrawals and automated pool management; the module is feature-complete.

**Tasks:** `process_output` (validate `max_fee` against FeeVote-median quote, debit, enqueue `UnclaimedWithdrawal`); batching policy (every N blocks or M queued items → one UserOp batching transfers, plus sweep-consolidation UserOps when pool balance < withdrawal demand; dust threshold skips uneconomic sweeps); FeeVote proposal/median logic + per-guardian price-source config (devimint: static env values); `withdraw_fee_quote`/`withdrawal_status` endpoints; client withdraw operation + SM; overcharge handling pinned: quote = estimate × (1 + buffer), actual cost from `UserOpReceipt`, surplus accrues to federation (audited via `ServerModule::audit` — module balance sheet must include credited-unclaimed deposits, queued withdrawals, pool balance); integration + devimint tests incl. fee-spike (anvil `anvil_setNextBlockBaseFeePerGas`) and paymaster-refusal → retry path.

**Acceptance ★:** devimint full loop — deposit → claim → e-cash → withdraw to fresh EOA → recipient USDT correct, fee within quote, `audit` balanced before and after. Est: 3–5 wks.

### Phase 9 — Hardening + acceptance suite + audit prep

**Goal:** Production-readiness: adversarial conditions, recovery, docs, audit package.

**Tasks:** reorg drills (`anvil_reorg` across confirmation depth: reorged deposit must not credit; reorged submission must re-submit); guardian restart mid-signing-session (resume-or-retry from DB, no key-share corruption); client recovery (`ClientModuleInit::recover`: rescan claim keys from seed, re-run `check_deposit`); backup coverage; DoS review (check_deposit spam → `deposit_check_fee` + per-connection rate limit; MpcRound payload size caps); wasm build check for client/common; DB migration test scaffolding + `dump_database`; module docs (`docs/usdt-module.md`: deployment model D8, guardian ops runbook: price-source config, paymaster config, pool monitoring); external-audit package (threat model, invariants, session-transcript of Phase-2/6 crypto integration decisions); `just final-check` + full `test-ci-all` green.

**Acceptance ★:** the complete hermetic suite (fedimint-testing + devimint/anvil incl. reorg, restart, degraded-federation, paymaster-failure drills) runs in CI; a scripted "acceptance scenario" devimint test executes the design doc's §3.4–3.6 flows end-to-end. Est: 4–6 wks (+ external audit calendar).

---

## Effort roll-up

| Phase | Weeks |
|---|---|
| P1 threshold-ecdsa | 2–3 |
| P2 exchange transport + DKG harness | 2–3 |
| P3 scaffolding + config-gen DKG | 3–4 |
| P4 EVM adapter + anvil stack | 3–4 (parallelizable with P2/P3) |
| P5 deposit path | 3–5 |
| P6 runtime MPC sessions | 4–6 |
| P7 ERC-4337 pipeline | 4–6 |
| P8 consolidation + withdrawal | 3–5 |
| P9 hardening + audit prep | 4–6 |
| **Total (serial)** | **28–42 wks ≈ 6.5–10 months** — consistent with the design doc's 7.5–10-month audited-mainnet estimate; testnet-MVP cut ≈ end of P8 low-path ≈ 5–6 months |

## Standing risks (tracked across phases)

1. **P6 MPC-over-consensus integration** — mitigated by P2's transport equivalence tests and a P6-opening spike.
2. **cggmp21 lacks identifiable aborts** — timeout + deterministic subset rotation is the containment; a griefing guardian degrades latency, not safety.
3. **ERC-4337 v0.7 hash/packing fidelity** — on-chain test vectors in P7 before anything signs real value.
4. **USDT contract quirks** — real TetherToken bytecode in every test from P4 onward.
5. **Fee/FX pricing** — median-of-guardian-votes (D10) inherits the existing feerate-vote trust model; quote buffers absorb volatility; audit tracks surplus.
6. **Single-asset federation constraint (D8)** — deployment documentation must be unambiguous that this module defines the federation's unit; no mixed BTC+USDT federation.
