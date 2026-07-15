# Phase 3: USDT Module Scaffolding + Config-Gen DKG — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** The three USDT module crates (`fedimint-usdt-common/-server/-client`) exist, register in fedimintd, and a federation completes real threshold-ECDSA DKG at config generation — each guardian storing its `KeyShare`, all agreeing on one group public key. Plus the reusable off-thread protocol driver that both this phase and Phase 6 need.

**Architecture:** Build the module on the empty-module skeleton (`modules/fedimint-empty-*`, read it as the boilerplate reference) but take the config-carrying + DKG pattern from lnv2 (`modules/fedimint-lnv2-*`). The `!Send` cggmp21 state machine is driven on a dedicated OS thread via a channel-bridged `RoundExchange` (`spawn_protocol`/`ProtocolHandle`), reusing the Phase 2 `drive_over_exchange` + codec stack unchanged; the async `distributed_gen` services each round via `PeerHandleOps::exchange_bytes` and stays `Send`.

**Tech stack:** Rust edition 2024; `fedimint-core`, `fedimint-server-core`, `fedimint-client-module`; `fedimint-threshold-ecdsa` (Phases 1–2); `cggmp21`; `secp256k1`; `tokio` (mpsc/oneshot + a per-thread current-thread runtime).

## Global Constraints

- **Crate layout:** `modules/fedimint-usdt-common`, `modules/fedimint-usdt-server`, `modules/fedimint-usdt-client`, `modules/fedimint-usdt-tests` (`publish = false`). Register each in the root `Cargo.toml` `members` (alphabetical) and `[workspace.dependencies]` (with `version = "=0.12.0-alpha"`). Package metadata all `{ workspace = true }` except `name`/`description`; `[lints] workspace = true`.
- **KIND** = `ModuleKind::from_static_str("usdt")`; `MODULE_CONSENSUS_VERSION = ModuleConsensusVersion::new(0, 0)`.
- **wasm / dependency boundary (critical, drives the config split):** `fedimint-usdt-common` and `-client` MUST NOT depend on `fedimint-threshold-ecdsa` or `cggmp21` — those pull native GMP (`gmp-mpfr-sys`) which is not wasm-friendly, and common/client are wasm-built. Therefore the **server-side config that holds the `KeyShare` lives in `fedimint-usdt-server`, not `-common`.** Only the client config + shared newtypes live in `-common`. (This is a deliberate deviation from the empty/wallet pattern of putting all config in `-common`, forced by the GMP-in-wasm constraint.)
- **Never `unwrap()`/`panic!` in non-test code** — `expect()` with a reason or return `Result`. (The `expect` in `spawn_protocol`'s runtime build is acceptable — a failed runtime build on a fresh thread is unrecoverable and not attacker-influenced; give it a clear message.)
- **cggmp21 `trusted_dealer` (`spof` feature) is test-and-trusted-setup only.** It is legitimate inside `trusted_dealer_gen` (that IS a trusted setup). Never use it in `distributed_gen`.
- **Config derive rule** (from `plugin_types_trait_impl_config!`): the top `Config` struct and the `...Private` struct derive **only** `Serialize, Deserialize`; the `...Consensus` and `...ClientConfig` structs **additionally** derive `Encodable, Decodable`.
- `just format` after changes; before each commit run `cargo clippy -q --locked --offline -p <crate> --all-targets -- -D warnings` (NOT `just lint` — its pre-commit hook is environmentally broken here) and `just cargo-sort-check`. If the semgrep pre-commit hook blocks `tokio::spawn`/`tokio::sleep` in this crate (no `fedimint-core` dep in threshold-ecdsa), use the existing `// nosemgrep: <rule>` one-line annotation pattern already in the crate.
- Tests that run real DKG/keygen are Paillier-heavy: run `--release`, minutes-long, use long timeouts. Not a hang.
- **Verbatim source references** (read these files; they are the boilerplate/pattern source): empty skeleton `modules/fedimint-empty-{common,server,client}/src/*`; config-carrying + real DKG `modules/fedimint-lnv2-{common,server}/src/*` and `modules/fedimint-wallet-server/src/lib.rs` (`distributed_gen` `exchange_encodable` usage); `PeerHandleOps` in `fedimint-server-core/src/config.rs`; config erasure in `fedimint-core/src/config.rs`; registration in `fedimintd/src/lib.rs` `default_modules()`.

## Deviations from the master plan (recorded here)

1. Server config (private/consensus with `KeyShare`) lives in `-server`, not `-common` (wasm/GMP constraint above).
2. The master plan's full `UsdtClientConfig` (chain_id, contract addresses, confirmation_depth, deposit_check_fee) is **not** fully populated here — Phase 3 only needs the DKG output. This plan defines `UsdtClientConfig { group_public_key, network }` and `UsdtConfigConsensus { group_public_key, mpc_encryption_pks, threshold, network }`. The EVM/contract fields are added by a later phase's config migration when the adapter exists. Define the module's identity + DKG config now; don't invent EVM values we can't populate.
3. Devimint real-DKG startup validation is **not** a gating task of this phase (Paillier aux-gen at config gen risks exceeding devimint's startup timeout — a real integration risk). Phase 3's gating acceptance is hermetic (Task 5's fake-`PeerHandleOps` DKG + Task 6's fedimint-testing boot). Devimint real-DKG is recorded as a validation checkpoint to run when the module is more complete (or in Phase 9), with the timeout mitigation (pregenerate primes / raise DKG timeout) noted.

---

### Task 1: Off-thread protocol driver (`fedimint-threshold-ecdsa`)

**Files:**
- Create: `crypto/threshold-ecdsa/src/transport/off_thread.rs`
- Modify: `crypto/threshold-ecdsa/src/transport/mod.rs` (declare + re-export), `Cargo.toml` (tokio `rt`/`macros` features if not already enabled)

**Interfaces produced:**
```rust
/// A RoundExchange whose rounds are serviced by an external async pump.
/// Lives on a dedicated thread; `exchange` sends the round payload out and
/// awaits the serviced result over async channels.
pub struct ChannelExchange { /* index, n, req_tx, resp_rx */ }

/// Handle (async side) to a protocol running on a dedicated thread.
pub struct ProtocolHandle<O> { /* req_rx, resp_tx, output_rx, join */ }

/// Spawn `f` (which builds and drives a !Send cggmp21 state machine over the
/// given ChannelExchange) on a dedicated thread with its own current-thread
/// runtime. Returns a handle whose `drive` services each round.
pub fn spawn_protocol<O, F, Fut>(index: PartyIndex, n: u16, f: F) -> ProtocolHandle<O>
where O: Send + 'static,
      F: FnOnce(ChannelExchange) -> Fut + Send + 'static,
      Fut: std::future::Future<Output = anyhow::Result<O>>; // Fut is NOT Send — runs on the thread

impl<O: Send + 'static> ProtocolHandle<O> {
    /// Drive the protocol to completion, fulfilling each all-to-all round via
    /// `service` (e.g. PeerHandleOps::exchange_bytes). Returns the protocol output.
    pub async fn drive<F, Fut>(self, service: F) -> anyhow::Result<O>
    where F: FnMut(Vec<u8>) -> Fut, Fut: std::future::Future<Output = anyhow::Result<Vec<Vec<u8>>>>;
}
```

**Design notes (load-bearing):**
- Two `tokio::sync::mpsc` channels (capacity 1) + one `tokio::sync::oneshot`. `req`: thread→async (payload to service). `resp`: async→thread (serviced `Vec<Vec<u8>>`). `output`: thread→async (final `O`).
- `ChannelExchange::exchange` is **fully async** (`req_tx.send(ours).await`, `resp_rx.recv().await`) — NO blocking calls — so it runs fine inside the thread's current-thread runtime `block_on`. (Do not use `blocking_send`/`blocking_recv`: those panic inside a runtime.)
- The thread closure builds a `new_current_thread` runtime and `block_on(f(chan))`; the `!Send` state machine is created *inside* `f` on this thread and never crosses the boundary. Only `Vec<u8>` and the final `O` (Send) cross.
- `drive`: `while let Some(payload) = req_rx.recv().await { let r = service(payload).await; if resp_tx.send(r).await.is_err() { break } }` then `output_rx.await`. When the thread's protocol finishes it drops `req_tx` (channel closes → loop ends) and sends the output.

- [ ] **Step 1: Write the failing acceptance test** (in `off_thread.rs` `#[cfg(test)]`): real N=4 threshold-3 keygen where each party runs via `spawn_protocol` and its `ProtocolHandle::drive` is serviced by an `in_memory_mesh(4)` endpoint. Assert all 4 returned `IncompleteKeyShare`s agree on `shared_public_key()`. Reuse the codec/mesh/keygen patterns from the Phase 2 acceptance test (`tests.rs::keygen_and_signing_over_exchange_transport`). Skeleton:

```rust
#[tokio::test(flavor = "multi_thread")]
async fn keygen_runs_off_thread_serviced_by_mesh() {
    use crate::transport::{in_memory_mesh, spawn_protocol, drive_over_exchange, EncryptedRoundCodec};
    const N: u16 = 4; const T: u16 = 3;
    let secp = secp256k1::Secp256k1::new();
    let enc_sks: Vec<_> = (0..N).map(|i| { let mut b=[3u8;32]; b[31]=(i+1) as u8; secp256k1::SecretKey::from_slice(&b).unwrap() }).collect();
    let enc_pks: Vec<_> = enc_sks.iter().map(|sk| sk.public_key(&secp)).collect();
    let eid_bytes = b"off-thread-keygen".to_vec();
    let meshes = in_memory_mesh(N);
    let mut tasks = Vec::new();
    for (i, mesh) in meshes.into_iter().enumerate() {
        let i = i as u16;
        let codec = EncryptedRoundCodec::new(i, enc_sks[i as usize], enc_pks.clone(), eid_bytes.clone());
        let eidb = eid_bytes.clone();
        let handle = spawn_protocol::<cggmp21::IncompleteKeyShare<crate::Curve>, _, _>(i, N, move |mut chan| async move {
            let mut rng = rand::rngs::OsRng;
            let eid = cggmp21::ExecutionId::new(&eidb);
            let sm = cggmp21::keygen::<crate::Curve>(eid, i, N).set_threshold(T).hd_wallet(true).into_state_machine(&mut rng);
            drive_over_exchange(sm, &codec, &mut chan).await?.map_err(|e| anyhow::anyhow!("keygen: {e}"))
        });
        let mut mesh = mesh;
        tasks.push(tokio::spawn(async move {
            handle.drive(move |payload| { /* service one round via the mesh */ 
                // NOTE: mesh is moved in; can't reborrow across iterations of an FnMut easily —
                // implementer resolves: wrap mesh so service can call it each round (e.g. Arc<Mutex> or
                // restructure drive to take &mut dyn). See Step 3 note.
                unimplemented!() }).await
        }));
    }
    // join, assert consistent shared_public_key across all 4
}
```
**Implementer must resolve the `service`/mesh ownership**: `ProtocolHandle::drive`'s `service: FnMut(Vec<u8>) -> Fut` is called once per round and must call `mesh.exchange(payload).await` each time, which needs `&mut mesh`. Options: (a) make `drive`'s bound `FnMut` and capture `&mut mesh` in the closure (lifetime-permitting), or (b) change the `service` closure to own the mesh and return a future borrowing it. Cleanest: `handle.drive(|payload| mesh.exchange(payload)).await` where `mesh` is captured by the closure by `&mut` — since `InMemoryMesh::exchange` takes `&mut self`, the closure is `FnMut`. Verify this composes; if the borrow checker fights, wrap `mesh` in the closure via a small helper that owns it. Do NOT change the round semantics.

- [ ] **Step 2: Run to verify fail** — `cargo test -q -p fedimint-threshold-ecdsa keygen_runs_off_thread` → compile-fail (`spawn_protocol` not found).

- [ ] **Step 3: Implement `off_thread.rs`.** `ChannelExchange` + `spawn_protocol` + `ProtocolHandle::drive` per the design notes. `spawn_protocol` uses `std::thread::spawn`; inside, `tokio::runtime::Builder::new_current_thread().enable_all().build().expect("current-thread runtime for MPC protocol")` then `rt.block_on(f(chan))`, send result via `output_tx`. Add `mod off_thread; pub use off_thread::{spawn_protocol, ProtocolHandle, ChannelExchange};` to `transport/mod.rs`.

- [ ] **Step 4: Run to verify pass** — `cargo test --release -p fedimint-threshold-ecdsa keygen_runs_off_thread -- --nocapture` → PASS. Report runtime.

- [ ] **Step 5: Format, lint, commit** — `git commit -m "feat(threshold-ecdsa): off-thread driver for !Send MPC state machines"`

---

### Task 2: `fedimint-usdt-common` crate

**Files:** create `modules/fedimint-usdt-common/{Cargo.toml, src/lib.rs, src/config.rs}`; modify root `Cargo.toml`.

**Interfaces produced:**
```rust
pub const KIND: ModuleKind = ModuleKind::from_static_str("usdt");
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

/// 20-byte EVM address. Encodable/Decodable; Display = "0x…" lowercase hex.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EvmAddress(pub [u8; 20]);
/// USDT in on-chain units (10^-6 USDT).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct UsdtAmount(pub u64);

// Minimal transaction/consensus types (no-op logic in Phase 3; shapes filled later phases).
// Follow the empty-module pattern exactly (structs + Display + plugin_types_trait_impl_common!):
pub struct UsdtConsensusItem;   pub struct UsdtInput;  pub struct UsdtOutput;  pub struct UsdtOutputOutcome;
pub enum UsdtInputError { NotSupported }   pub enum UsdtOutputError { NotSupported }
pub struct UsdtModuleTypes;  // plugin_types_trait_impl_common!(KIND, UsdtModuleTypes, UsdtClientConfig, ...)
pub struct UsdtCommonInit;   // impl CommonModuleInit

// Client config only (server private/consensus config lives in -server, Task 3).
pub struct UsdtClientConfig { pub group_public_key: secp256k1::PublicKey, pub network: Network }
```

- [ ] **Step 1: Scaffold** — clone `modules/fedimint-empty-common` structure. `Cargo.toml` deps: `anyhow, fedimint-core, secp256k1, serde, thiserror` (NO threshold-ecdsa/cggmp21). Root `Cargo.toml`: add member + workspace dep entry.
- [ ] **Step 2: Write failing test** (`src/config.rs` or `lib.rs` `#[cfg(test)]`): `EvmAddress` and `UsdtAmount` round-trip through `Encodable`/`Decodable` (`consensus_encode_to_vec` → `consensus_decode_whole`); `EvmAddress` Display renders `0x` + 40 lowercase hex; the module decoder builds (`UsdtModuleTypes::decoder_builder().build()`).
- [ ] **Step 3: Run to verify fail.**
- [ ] **Step 4: Implement** `lib.rs` (types, Display impls, `plugin_types_trait_impl_common!`, `UsdtCommonInit: CommonModuleInit`) and `config.rs` (`UsdtClientConfig` + its `Display`). Use `Network` from `fedimint_core` (check whether lnv2 uses bare `Network` or a wrapper — mirror lnv2's `LightningConfigConsensus.network` type). `secp256k1::PublicKey` is `Encodable` via fedimint-core; confirm the import path (`fedimint_core::secp256k1::PublicKey` or `bitcoin::secp256k1`).
- [ ] **Step 5: Run to verify pass.**
- [ ] **Step 6: Format, lint (`cargo clippy -p fedimint-usdt-common`), cargo-sort, commit** — `feat(usdt): common crate — module types and client config`

---

### Task 3: `fedimint-usdt-server` skeleton + `trusted_dealer_gen`

**Files:** create `modules/fedimint-usdt-server/{Cargo.toml, src/lib.rs, src/config.rs, src/db.rs}`; modify root `Cargo.toml`.

**Interfaces produced:**
```rust
// src/config.rs (server-only; can depend on threshold-ecdsa)
pub struct UsdtConfig { pub private: UsdtConfigPrivate, pub consensus: UsdtConfigConsensus } // Serialize/Deserialize only
pub struct UsdtConfigPrivate {                        // Serialize/Deserialize only
    pub key_share: fedimint_threshold_ecdsa::KeyShare, // cggmp21 KeyShare (serde)
    pub mpc_encryption_sk: secp256k1::SecretKey,
}
pub struct UsdtConfigConsensus {                     // + Encodable/Decodable
    pub group_public_key: secp256k1::PublicKey,
    pub mpc_encryption_pks: BTreeMap<PeerId, secp256k1::PublicKey>,
    pub threshold: u16,
    pub network: Network,
}
// plugin_types_trait_impl_config!(UsdtCommonInit, UsdtConfig, UsdtConfigPrivate, UsdtConfigConsensus, UsdtClientConfig)

pub struct UsdtInit;   // ServerModuleInit
pub struct Usdt { pub cfg: UsdtConfig }  // ServerModule (no-op runtime methods like empty)
```

- [ ] **Step 1: Scaffold** — clone `modules/fedimint-empty-server` structure (ModuleInit/ServerModuleInit/ServerModule stubs, db.rs). `Cargo.toml` deps: empty-server's set + `fedimint-usdt-common`, `fedimint-threshold-ecdsa`, `cggmp21` (features `curve-secp256k1`, `spof` — spof for trusted_dealer), `secp256k1`, `rand`, `bincode`/`serde_json` as needed. Root `Cargo.toml`: member + workspace dep.
- [ ] **Step 2: Write failing test** (`#[cfg(test)]` in lib.rs): `UsdtInit.trusted_dealer_gen(&[4 peers], &args)` returns 4 configs; `to_typed::<UsdtConfig>()` each; assert all 4 `consensus.group_public_key` equal; assert each peer's `private.key_share` produces `group_public_key(&share) == consensus.group_public_key` (via `fedimint_threshold_ecdsa::group_public_key`); `validate_config(peer, cfg)` returns Ok for each peer's own config. Use `NumPeers`/`PeerId` test helpers (see how lnv2/wallet server tests build `peers`).
- [ ] **Step 3: Run to verify fail.**
- [ ] **Step 4: Implement.** config.rs (the three structs + macro; `UsdtConfigConsensus` derives Encodable/Decodable; verify `secp256k1::PublicKey`/`BTreeMap<PeerId,PublicKey>` are Encodable). `trusted_dealer_gen`: use `cggmp21::trusted_dealer::builder::<Curve>(n).set_threshold(Some(t)).hd_wallet(true).generate_shares(&mut OsRng)` → `Vec<KeyShare>`; generate per-peer secp256k1 MPC enc keypairs; `group_public_key` from share[0]; build per-peer `UsdtConfig` (that peer's key_share + enc_sk in private; group pk + all enc pks + threshold + network in consensus) → `.to_erased()`. `validate_config`: check `group_public_key(&cfg.private.key_share) == cfg.consensus.group_public_key` and the peer's enc pk matches. `get_client_config`: `UsdtConfigConsensus::from_erased` → `UsdtClientConfig { group_public_key, network }`. `init`: `Usdt::new(args.cfg().to_typed()?)`. `distributed_gen`: **stub** `anyhow::bail!("usdt distributed_gen implemented in the next task")` for now. All `ServerModule` runtime methods no-op like empty (consensus_proposal empty, process_* return NotSupported/bail, api_endpoints empty for now).
- [ ] **Step 5: Run to verify pass.**
- [ ] **Step 6: Format, lint, cargo-sort, commit** — `feat(usdt): server skeleton and trusted-dealer config gen`

---

### Task 4: `fedimint-usdt-client` skeleton

**Files:** create `modules/fedimint-usdt-client/{Cargo.toml, src/lib.rs, src/db.rs, src/states.rs, src/api.rs}`; modify root `Cargo.toml`.

- [ ] **Step 1: Scaffold** — clone `modules/fedimint-empty-client` verbatim into `usdt` naming. `UsdtClientModule` holds `cfg: UsdtClientConfig`, `client_ctx`, `db`. No `fedimint-threshold-ecdsa`/`cggmp21` dep (wasm boundary). `UsdtClientInit: ClientModuleInit` no-op `init`, api version (0,0). Empty state machine enum, empty db prefixes.
- [ ] **Step 2: Verify compile + wasm-safety** — `cargo check -p fedimint-usdt-client`. Then confirm no GMP in its tree: `cargo tree -p fedimint-usdt-client | grep -i 'gmp\|cggmp\|threshold-ecdsa'` must be empty.
- [ ] **Step 3: Format, lint, cargo-sort, commit** — `feat(usdt): client module skeleton`

(No standalone unit test here — Task 6's fedimint-testing boot exercises the client init end-to-end.)

---

### Task 5: `distributed_gen` — real config-gen DKG

**Files:** modify `modules/fedimint-usdt-server/src/lib.rs` (implement `distributed_gen`, add a small `dkg` submodule if it helps); modify `modules/fedimint-usdt-server/Cargo.toml` (dev-deps for the fake PeerHandle test: `tokio`, `async-trait`).

**Implementation of `distributed_gen`:**
1. Order peers: `let peer_ids: Vec<PeerId> = peers.num_peers().peer_ids().collect()` (sorted); `my_index = position of our peer`. **Problem:** `distributed_gen` doesn't receive our own `PeerId` directly — obtain it: the trusted setup has each peer generate its enc keypair, and `exchange_encodable` returns a `BTreeMap<PeerId, _>` keyed by peer, and the map includes *our* entry under our PeerId. So: generate `(mpc_enc_sk, mpc_enc_pk)`; `let enc_pks: BTreeMap<PeerId, PublicKey> = peers.exchange_encodable(mpc_enc_pk).await?;` To learn our own PeerId, compare: our entry is the one whose value == `mpc_enc_pk`. (Verify there's no simpler accessor; if `PeerHandleOps` exposes identity, use it — check the concrete `PeerHandle` struct which has `identity: PeerId`, but the trait may not expose it. If the trait lacks it, the enc-pk-match trick works, or extend `PeerHandleOps` with an `identity()` method — prefer not to; use the match.)
2. Build `ordered_enc_pks: Vec<PublicKey>` indexed by the sorted `peer_ids`; `my_index = peer_ids.iter().position(|p| p == our_peer)`.
3. Derive execution ids deterministically from the exchanged enc pks so all peers agree and it's federation-unique: `eid_keygen = Sha256("usdt-dkg-keygen-v0" ‖ concat(ordered_enc_pks compressed))`, `eid_aux = Sha256("usdt-dkg-aux-v0" ‖ …)`. Use the 32-byte hashes as the `ExecutionId` bytes AND the codec `domain`.
4. **Keygen** via the off-thread driver:
   ```rust
   let codec = EncryptedRoundCodec::new(my_index, mpc_enc_sk, ordered_enc_pks.clone(), eid_keygen.to_vec());
   let handle = spawn_protocol::<IncompleteKeyShare<Curve>,_,_>(my_index, n, move |mut chan| async move {
       let mut rng = OsRng;
       let eid = ExecutionId::new(&eid_keygen);
       let sm = cggmp21::keygen::<Curve>(eid, my_index, n).set_threshold(threshold).hd_wallet(true).into_state_machine(&mut rng);
       drive_over_exchange(sm, &codec, &mut chan).await?.map_err(|e| anyhow!("keygen: {e}"))
   });
   let core = handle.drive(|payload| service_round(peers, &peer_ids, payload)).await?;
   ```
   where `service_round(peers, peer_ids, payload)` = `let map = peers.exchange_bytes(payload).await?; peer_ids.iter().map(|p| map.get(p).cloned().context("missing peer payload")).collect::<Result<Vec<_>>>()` (reorder `BTreeMap<PeerId,_>` → `Vec` by the sorted `peer_ids`, matching the party-index space the codec/driver use).
5. **Aux-gen** via a second off-thread driver (fresh codec with `eid_aux` domain; `PregeneratedPrimes::generate` inside the thread closure), same `service_round` servicer, second series of `exchange_bytes` rounds.
6. `let key_share = assemble_key_share(core, aux)?; let group_public_key = group_public_key(&key_share)?;`
7. Build `UsdtConfig` (key_share + mpc_enc_sk private; group pk + enc_pks map + threshold + network consensus) → `Ok(config.to_erased())`.

**Concurrency note:** two off-thread protocols run sequentially (keygen then aux), each fully serviced by its own `exchange_bytes` round sequence, before the next starts. That matches how a single shared `PeerHandle` is used sequentially across a module's `distributed_gen`.

- [ ] **Step 1: Write the failing hermetic acceptance test.** A `FakeDkgNetwork` implementing `PeerHandleOps` for N peers over in-memory all-to-all channels: `exchange_bytes(data)` broadcasts `data` to all peers and returns `BTreeMap<PeerId, Vec<u8>>` (including self); `num_peers()` returns the `NumPeers`; `run_dkg_g1`/`run_dkg_g2` → `unimplemented!()` (usdt DKG doesn't use them). Then: build N `FakeDkgNetwork` handles sharing one coordinator, call `UsdtInit.distributed_gen(&fake_i, &args)` for all N concurrently (these ARE `Send` futures — `tokio::spawn` each, or `join_all`), collect N `ServerModuleConfig`. Assert: (a) all N `to_typed()`.consensus.group_public_key are equal; (b) extract the N `key_share`s and run one **3-of-N threshold signature** over an `in_memory_mesh` (reuse Phase 2's `drive_over_exchange` signing pattern), verifying it against the group key with the `secp256k1` crate — proving the DKG output is valid signing material. This is the strongest possible acceptance: real distributed DKG → a working signature.
- [ ] **Step 2: Run to verify fail** (`distributed_gen` currently bails).
- [ ] **Step 3: Implement `distributed_gen`** + the `service_round` helper. Replace the stub.
- [ ] **Step 4: Run to verify pass** — `cargo test --release -p fedimint-usdt-server distributed_gen -- --nocapture`. Minutes-long (N× keygen + N× aux Paillier). Report runtime + "signature verified against group key: yes/no".
- [ ] **Step 5: Format, lint, cargo-sort, commit** — `feat(usdt): distributed key generation at config gen`

---

### Task 6: fedimintd registration + `fedimint-usdt-tests` boot test + diagnostic endpoint

**Files:** modify `fedimintd/src/lib.rs` (`default_modules`) + `fedimintd/Cargo.toml`; modify `modules/fedimint-usdt-server/src/lib.rs` (add a `group_public_key` API endpoint); create `modules/fedimint-usdt-tests/{Cargo.toml, tests/tests.rs}`; modify root `Cargo.toml`.

- [ ] **Step 1: Register** — add `server_gens.attach(fedimint_usdt_server::UsdtInit);` in `default_modules()`; add `fedimint-usdt-server = { workspace = true }` to `fedimintd/Cargo.toml`. `cargo check -p fedimintd`.
- [ ] **Step 2: Add a diagnostic API endpoint** to the `Usdt` `ServerModule::api_endpoints`: `group_public_key` returning the config's `consensus.group_public_key` (serialized). Follow an existing simple `api_endpoint!` example (grep another module's `api_endpoints` for the macro shape — e.g. wallet's block-count endpoint). This gives Phase 3 an observable proving DKG config loaded.
- [ ] **Step 3: Write the failing boot test** in `fedimint-usdt-tests/tests/tests.rs`: build `Fixtures::new_primary(MintClientInit, MintInit).with_module(UsdtClientInit, UsdtInit)` (mint as the fee-paying primary; usdt attached). Spin a federation (`fixtures.new_fed_not_degraded().await` or the standard builder — mirror `modules/fedimint-mint-tests/tests/tests.rs`). Assert: the federation boots (trusted-dealer config gen runs `UsdtInit.trusted_dealer_gen`), the usdt client module initializes, and the `group_public_key` admin/module API endpoint returns a valid non-identity `secp256k1::PublicKey` consistent across guardians. `Cargo.toml`: `publish = false`, dev-deps mirror `fedimint-mint-tests` + `fedimint-usdt-{common,server,client}`, `fedimint-testing`, mint crates.
- [ ] **Step 4: Run to verify fail** then implement/wire until green — `cargo test --release -p fedimint-usdt-tests -- --nocapture`. (fedimint-testing uses trusted-dealer, so this exercises Task 3's `trusted_dealer_gen`, the client init, and the endpoint — NOT `distributed_gen`, which Task 5 covers hermetically.)
- [ ] **Step 5: Format, lint, cargo-sort, `cargo check -p fedimintd`, commit** — `feat(usdt): register module in fedimintd and add boot integration test`

---

## Self-review checklist (controller, before dispatching Task 1)

- Off-thread driver (Task 1) keeps `distributed_gen` `Send` while the `!Send` SM stays on the thread — the whole reason for this phase's shape. ✓
- Config split respects the wasm boundary: `KeyShare` only in `-server`; `-common`/`-client` free of cggmp21/GMP (Task 4 Step 2 asserts it). ✓
- DKG execution ids are deterministic + federation-unique (derived from exchanged enc pks) so all peers agree. ✓
- Hermetic acceptance (Task 5 fake `PeerHandleOps` → real DKG → valid signature; Task 6 fedimint-testing boot) gates the phase; devimint real-DKG deferred with the timeout risk recorded. ✓
- Open item for Task 5 implementer: confirming how `distributed_gen` learns our own `PeerId` (enc-pk-match vs a trait accessor) — flagged inline; default to the enc-pk match.
