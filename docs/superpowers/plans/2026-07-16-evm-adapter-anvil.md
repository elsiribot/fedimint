# Phase 4: EVM Read Adapter + Anvil Hermetic Test Stack — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** An EVM chain-RPC read adapter (`IServerEvmRpc` + `AlloyEvmRpc`) that reads block height, ERC-20 balances at a confirmation depth, chain-id, and fee estimates from an EVM node; a scriptable `MockEvmRpc` for module unit tests; and a hermetic `anvil` test harness (nix-provided foundry, a direct-spawn Rust integration test, and a devimint `Anvil` daemon). This is the read-side foundation Phase 5 (deposits) builds on. ERC-4337/UserOp machinery is explicitly Phase 7.

**Architecture:** The adapter lives in `fedimint-usdt-server` (not core) — bitcoin RPC is special-cased in `fedimint-server-core` with no generic multi-chain injection, so the USDT module constructs its own `AlloyEvmRpc` in `init()` from an RPC URL carried in its config (mirroring the wallet *client*'s `create_esplora_rpc(&url)` fallback). No `fedimint-server-core` changes. `alloy` (provider/reqwest) is server/test-only; `-common` gains only `FeeVote` (two u64s) and stays wasm-safe.

**Tech stack:** Rust edition 2024; `alloy` 2.1.x (default-features=false, features `essentials` + `reqwest-rustls-tls`) in server/tests; `foundry`/`anvil` 1.7.x from nixpkgs; a vendored minimal test ERC-20 bytecode fixture.

## Global Constraints

- **Adapter location:** `modules/fedimint-usdt-server/src/rpc.rs`. Trait `IServerEvmRpc`, `DynServerEvmRpc = Arc<dyn IServerEvmRpc>`, `AlloyEvmRpc` impl. Do NOT modify `fedimint-server-core` or `fedimint-server`.
- **wasm boundary (unchanged from Phase 3):** `alloy` (provider/network) MUST stay out of `fedimint-usdt-common` and `fedimint-usdt-client`. `-common` may gain `alloy-primitives`/`alloy-sol-types` ONLY if genuinely needed for address/keccak math (it already has `secp256k1`; prefer NOT adding alloy to common unless a task requires it — `FeeVote` is plain u64s and needs nothing). Verify with `cargo tree -p fedimint-usdt-common | grep -iE 'alloy-(provider|transport|rpc|network|signer)'` = empty and the wasm build still passes.
- **`FeeVote`** goes in `-common`: `pub struct FeeVote { pub max_fee_per_gas_wei: u64, pub usdt_per_eth_e6: u64 }` deriving `Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable`.
- **`IServerEvmRpc` (Phase 4 read half):** exactly the signatures pinned in the master plan (`get_chain_id -> u64`, `get_block_number -> u64`, `get_erc20_balance(token, holder, at_block) -> UsdtAmount`, `get_fee_estimate -> FeeVote`, `get_code_len(addr) -> usize`, `send_raw_transaction(signed_tx) -> [u8;32]`, `into_dyn`). Types `EvmAddress`/`UsdtAmount`/`FeeVote` from `-common`. UserOp methods are Phase 7 — do NOT add them.
- **Never `unwrap()`/`panic!` in non-test code** — `expect()` with reason or return `Result`.
- **Anvil availability:** the hermetic Rust integration test MUST skip gracefully (print a skip line, return Ok) when the `anvil` binary is not resolvable — mirroring fedimint's `FM_TEST_USE_REAL_DAEMONS` gating — but MUST actually run and pass when anvil IS present. The implementer MUST verify GREEN against a real anvil (obtain it via the nix dev shell after Task 1 adds foundry, or `nix run nixpkgs#foundry -- anvil`, or a locally installed foundry). The anvil binary is resolved via `FM_ANVIL_BASE_EXECUTABLE` env override → `anvil` on PATH (same alias pattern devimint uses).
- `just format`; before each commit `cargo clippy -q --locked --offline -p <crate> --all-targets -- -D warnings` (NOT `just lint`) and `just cargo-sort-check`. Do NOT run clippy `-D warnings` on any `*-tests` crate combined-target — a pre-existing unrelated `fedimint-lnv2-client` dead_code issue trips it (confirmed on untouched crates); clippy the non-test crates.
- **Verbatim in-repo patterns to mirror** (read them): `fedimint-server-core/src/bitcoin_rpc.rs` (trait + dyn alias + `into_dyn` + monitor shape); `fedimint-server-bitcoin-rpc/src/esplora.rs` (a concrete async impl); `modules/fedimint-wallet-server/src/lib.rs` init RPC usage; devimint `Esplora` at `devimint/src/external.rs:815`, `devimint/src/util.rs:922`, `devimint/src/envs.rs:91`, `devimint/src/vars.rs:160/204`, `devimint/src/devfed.rs` (6 touch-points), `devimint/src/tests.rs` (`TestCmd`); nix `nix/flakebox.nix:255-283`; CI `scripts/tests/reconnect-test.sh` + `scripts/tests/test-ci-all.sh`.
- **alloy API note:** verified against alloy 2.1.x docs on 2026-07-16, but exact provider builder / `sol!` shapes may drift. On compile failure consult https://docs.rs/alloy and adjust names; keep semantics (read at a specific block number for confirmation depth; ERC-20 `balanceOf` via `sol!` binding).

## Deviations from the master plan (recorded here + in the master plan)

1. ERC-4337 (real USDT/EntryPoint/paymaster vendoring, UserOp packing/hashing/submit, `submit_user_ops`/`get_user_op_receipt`) deferred to Phase 7. Phase 4 ships the read half + `send_raw_transaction` only.
2. Phase 4 uses a **simple vendored test ERC-20** (deterministic committed bytecode), not the real TetherToken. The real quirky USDT lands in Phase 7.
3. No `ServerEvmRpcMonitor` background-poller in Phase 4 (the bitcoin one exists for consensus status). The module reads directly via the adapter; a monitor/caching layer is added only if a later phase needs it. Keep it simple: `AlloyEvmRpc` is a thin alloy-provider wrapper.

## File / edit map

- Root `Cargo.toml`: `alloy` workspace dep; `foundry` is nix not cargo.
- `modules/fedimint-usdt-common/src/lib.rs`: add `FeeVote`.
- `modules/fedimint-usdt-server/Cargo.toml` + `src/rpc.rs` (new) + `src/lib.rs` (add `mod rpc;`, add `evm_rpc_url` to local config + build `AlloyEvmRpc` in `init()`).
- `modules/fedimint-usdt-server/src/config.rs`: add an `evm_rpc_url` field to a `UsdtConfigLocal` (new, per-guardian local config) — see Task 2.
- `modules/fedimint-usdt-tests/`: `MockEvmRpc`, the anvil-harness helper, the integration test, vendored test-ERC-20 bytecode fixture.
- `nix/flakebox.nix`: add `foundry`.
- devimint: `external.rs`, `util.rs`, `envs.rs`, `vars.rs`, `devfed.rs`, `tests.rs`; `scripts/tests/anvil-smoke-test.sh`; `scripts/tests/test-ci-all.sh`.

---

### Task 1: alloy dep + `FeeVote` + nix foundry + vendored test ERC-20

**Files:** root `Cargo.toml`; `modules/fedimint-usdt-common/src/lib.rs`; `nix/flakebox.nix`; `modules/fedimint-usdt-tests/src/` (new lib for shared test fixtures) or a `tests/fixtures/` dir.

- [ ] **Step 1: Add `alloy` to `[workspace.dependencies]`** (root `Cargo.toml`, alphabetical): `alloy = { version = "2.1", default-features = false, features = ["essentials", "reqwest-rustls-tls"] }`. Run `cargo metadata` / a throwaway `cargo add --dry-run` is unnecessary — just add it; it's consumed in Task 2. Also confirm the version resolves: `cargo update -p alloy --dry-run` or a `cargo check` after a crate uses it (Task 2). If 2.1 doesn't resolve, pick the latest 2.x that does and note it.

- [ ] **Step 2: Add `foundry` to nix** — in `nix/flakebox.nix` `nativeBuildInputs` (the `with pkgs; [ ... ]` list around line 255, alongside `bitcoind`/`lnd`/`esplora-electrs`), add `foundry`. This puts `anvil`/`forge`/`cast` on PATH in the dev shell and CI. (No overlay needed — foundry is in nixpkgs.)

- [ ] **Step 3: Add `FeeVote` to `-common`** (`modules/fedimint-usdt-common/src/lib.rs`), with the derive set from Global Constraints and a `Display`. Add a unit test: `FeeVote { max_fee_per_gas_wei: 30_000_000_000, usdt_per_eth_e6: 3_000_000_000 }` round-trips through `consensus_encode_to_vec`/`consensus_decode_whole`. Run: `cargo test -p fedimint-usdt-common`. Confirm still wasm-safe: `cargo tree -p fedimint-usdt-common | grep -iE 'alloy' ` = empty.

- [ ] **Step 4: Vendor a minimal test ERC-20 bytecode fixture.** Goal: a deterministic, committed hex string for a minimal ERC-20 (functions needed: `balanceOf(address)->uint256`, `transfer(address,uint256)->bool`, a way to seed balances — either a public `mint(address,uint256)` or a constructor that mints to the deployer, and 6 decimals to match USDT units). Obtain the CREATION (deploy) bytecode + the ABI once and commit them as a fixture (e.g. `modules/fedimint-usdt-tests/tests/fixtures/test_erc20.json` with `{abi, bytecode}` or a `.rs` const hex string).
  - **Preferred method:** write `TestUsdt.sol` (a ~30-line minimal ERC-20 with `mint`), compile once with `forge build` (foundry now on PATH), extract `bytecode.object` + `abi` from `out/TestUsdt.sol/TestUsdt.json`, commit the extracted artifact. Keep the `.sol` in the repo under `modules/fedimint-usdt-tests/contracts/` for provenance, but tests consume the committed hex (no solc at test time).
  - **If `forge`/solc is unavailable in your session:** use a well-known minimal ERC-20's published compiled bytecode (e.g. a Solmate/OpenZeppelin ERC20 minimal deployment), committing it with a source comment. The token only needs `balanceOf`/`transfer`/`mint`/`decimals`.
  - Document in the fixture file where the bytecode came from and how to regenerate it.
  - **If genuinely blocked** obtaining deterministic bytecode, report BLOCKED with what you tried — do NOT invent random bytecode.

- [ ] **Step 5: Format, lint, commit** — `cargo clippy -q --locked --offline -p fedimint-usdt-common --all-targets -- -D warnings`; `just format`; `just cargo-sort-check`. Commit: `feat(usdt): alloy dep, FeeVote type, nix foundry, and test-ERC20 fixture`

---

### Task 2: `IServerEvmRpc` trait + `AlloyEvmRpc` + config wiring

**Files:** `modules/fedimint-usdt-server/src/rpc.rs` (new); `modules/fedimint-usdt-server/src/config.rs` (add `UsdtConfigLocal`); `modules/fedimint-usdt-server/src/lib.rs` (wire `mod rpc;`, build the RPC in `init`); `modules/fedimint-usdt-server/Cargo.toml`.

**Interfaces produced:**
```rust
// rpc.rs
pub type DynServerEvmRpc = Arc<dyn IServerEvmRpc>;
#[async_trait::async_trait]
pub trait IServerEvmRpc: std::fmt::Debug + Send + Sync + 'static {
    async fn get_chain_id(&self) -> anyhow::Result<u64>;
    async fn get_block_number(&self) -> anyhow::Result<u64>;
    async fn get_erc20_balance(&self, token: EvmAddress, holder: EvmAddress, at_block: u64) -> anyhow::Result<UsdtAmount>;
    async fn get_fee_estimate(&self) -> anyhow::Result<FeeVote>;
    async fn get_code_len(&self, addr: EvmAddress) -> anyhow::Result<usize>;
    async fn send_raw_transaction(&self, signed_tx: Vec<u8>) -> anyhow::Result<[u8; 32]>;
    fn into_dyn(self) -> DynServerEvmRpc where Self: Sized + 'static { Arc::new(self) }
}
pub struct AlloyEvmRpc { /* provider, url */ }
impl AlloyEvmRpc { pub fn new(rpc_url: &str) -> anyhow::Result<Self>; }
```

**Config note:** the module needs a per-guardian **local** RPC URL (not consensus — each guardian points at its own node). Phase 3 has `UsdtConfig { private, consensus }` with no `local`. Add a `UsdtConfigLocal { evm_rpc_url: String }` and extend `UsdtConfig` to `{ local, private, consensus }`. Check how wallet does this: `WalletConfig` has `WalletConfigLocal { bitcoin_rpc }` and the `plugin_types_trait_impl_config!` macro — VERIFY whether that macro takes a local param or whether local config is handled separately (wallet's `WalletConfigLocal` derives Encodable/Decodable and is threaded via a different mechanism than the 4-arg `plugin_types_trait_impl_config!`). Mirror wallet's exact local-config pattern (read `modules/fedimint-wallet-common/src/config.rs` + how `trusted_dealer_gen`/`distributed_gen` populate local). For trusted-dealer/dev, default `evm_rpc_url` to a localhost anvil default (e.g. `http://127.0.0.1:8545` or an env-derived value) — mirror `default_client_bitcoin_rpc`. In `distributed_gen`, the local URL is this guardian's own (from args/env, not exchanged).

- [ ] **Step 1: Write failing test** — a `#[cfg(test)]` in `rpc.rs` that constructs `AlloyEvmRpc::new("http://127.0.0.1:1")` and asserts it builds (the provider is lazy; construction shouldn't require a live node). This just forces the type into existence. (The real behavior test is Task 3 against anvil.)

- [ ] **Step 2: Run to verify fail** — `cargo test -q -p fedimint-usdt-server rpc::` → compile-fail.

- [ ] **Step 3: Implement `rpc.rs`.** `AlloyEvmRpc` wraps an alloy HTTP provider (`ProviderBuilder::new().on_http(url.parse()?)` or the 2.1 equivalent — check docs.rs). ERC-20 `balanceOf` via `sol! { function balanceOf(address) external view returns (uint256); }` and a contract call `.block(BlockId::number(at_block))`. `get_block_number` = `provider.get_block_number()`. `get_chain_id` = `provider.get_chain_id()`. `get_code_len` = `provider.get_code_at(addr).block_id(...).await?.len()`. `get_fee_estimate`: `max_fee_per_gas_wei` from `provider.get_gas_price()` (or `eth_feeHistory`/`estimate_eip1559_fees`); `usdt_per_eth_e6` — Phase 4 has no price oracle, so return a **fixed placeholder** (e.g. `3_000_000_000` = 3000 USDT/ETH) with a doc comment that Phase 8 wires a real price source. `send_raw_transaction` = `provider.send_raw_transaction(&signed_tx).await?` → return the tx hash bytes. Convert `EvmAddress([u8;20])` ↔ alloy `Address` (from/to `[u8;20]`). Convert `U256` balance → `UsdtAmount(u64)` via `u64::try_from` with an overflow error (USDT fits in u64 for realistic amounts; error if not). No unwrap in non-test code.

- [ ] **Step 4: Run to verify pass** — `cargo test --release -p fedimint-usdt-server rpc::` → PASS (construction only).

- [ ] **Step 5: Add `UsdtConfigLocal` + wire into `init()`.** Add the local config struct (mirror wallet), thread `evm_rpc_url` through `trusted_dealer_gen`/`distributed_gen` (default localhost for dev). In `UsdtInit::init`, build `let evm_rpc = AlloyEvmRpc::new(&cfg.local.evm_rpc_url)?.into_dyn();` and store it on `Usdt` (add a `evm_rpc: DynServerEvmRpc` field). `Usdt::new` gains the param. Keep the runtime ServerModule methods no-op (Phase 5 uses `evm_rpc`). Update the Phase 3 `trusted_dealer_gen` test if the config shape change breaks it (it constructs `UsdtConfig` — now needs `local`).

- [ ] **Step 6: Verify + commit** — `cargo check -p fedimint-usdt-server`; `cargo test --release -p fedimint-usdt-server` (the Phase 3 DKG + trusted-dealer tests must still pass with the new local config); clippy non-test; format; cargo-sort. Commit: `feat(usdt): IServerEvmRpc trait, AlloyEvmRpc, and per-guardian RPC config`

---

### Task 3: Anvil harness + hermetic read-adapter integration test + `MockEvmRpc`

**Files:** `modules/fedimint-usdt-tests/` — a test-support module (`src/lib.rs` or `tests/common/mod.rs`) with `spawn_anvil()` + `deploy_test_erc20()`; `tests/evm_adapter.rs` (the integration test); `MockEvmRpc` (in the test-support module, implementing `IServerEvmRpc` from scripted state); `modules/fedimint-usdt-tests/Cargo.toml` (dev-deps: `alloy`, `fedimint-usdt-server`, `tokio`, `anyhow`, `hex`; the vendored fixture).

- [ ] **Step 1: `spawn_anvil` helper.** Resolve the binary via `FM_ANVIL_BASE_EXECUTABLE` env else `"anvil"`; if `which`/spawn fails, return `Ok(None)` (→ test skips). Spawn `anvil --port <alloc'd> --chain-id 31337 --silent` (or default automine) as a child; poll `eth_chainId`/`eth_blockNumber` via an alloy provider until ready (bounded retries); return a handle `{ child, url, provider }` that kills anvil on drop. Use a random/OS-assigned free port (bind-and-release or a fixed test port; anvil `--port 0` picks a free port and prints it — parse stdout, OR allocate a port like devimint's `port_alloc`). Keep it self-contained (don't pull in devimint).

- [ ] **Step 2: `deploy_test_erc20` helper.** Using an alloy signer over one of anvil's deterministic funded accounts (default mnemonic accounts), deploy the vendored test-ERC-20 creation bytecode (send a create tx or use alloy's `sol!`-generated `deploy`), return its `Address`. Then `mint`/seed a chosen holder with a known balance (call `mint(holder, amount)` if the fixture has it, else transfer from the deployer's constructor-minted supply). Mine/confirm as needed (automine covers it).

- [ ] **Step 3: Write the failing integration test** `tests/evm_adapter.rs`:
```rust
#[tokio::test]
async fn alloy_evm_rpc_reads_chain_and_erc20_state() -> anyhow::Result<()> {
    let Some(anvil) = spawn_anvil().await? else {
        eprintln!("SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE or add foundry)");
        return Ok(());
    };
    let rpc = AlloyEvmRpc::new(&anvil.url)?;
    // chain id
    assert_eq!(rpc.get_chain_id().await?, 31337);
    // deploy token, seed a holder
    let holder = EvmAddress([0x11; 20]);
    let (token_addr, seeded) = deploy_test_erc20(&anvil, holder, UsdtAmount(1_000_000)).await?; // 1 USDT
    // block number advanced; read balance at a confirmed block
    let head = rpc.get_block_number().await?;
    let bal = rpc.get_erc20_balance(token_addr, holder, head).await?;
    assert_eq!(bal, UsdtAmount(1_000_000));
    // code present at token, absent at a random addr
    assert!(rpc.get_code_len(token_addr).await? > 0);
    assert_eq!(rpc.get_code_len(EvmAddress([0x22; 20])).await?, 0);
    // fee estimate returns a plausible non-zero max fee + the placeholder price
    let fee = rpc.get_fee_estimate().await?;
    assert!(fee.max_fee_per_gas_wei > 0);
    Ok(())
}
```
(Adjust `deploy_test_erc20`'s return shape to what Step 2 produces. The confirmation-depth read is exercised by reading at a specific historical block: additionally transfer, mine, then read balance at the PRE-transfer block and assert it shows the OLD balance — proving `at_block` addressing works, which is the property Phase 5's deposit detection depends on.)

- [ ] **Step 4: Run to verify** — with anvil available: `FM_ANVIL_BASE_EXECUTABLE=$(which anvil) cargo test --release -p fedimint-usdt-tests --test evm_adapter -- --nocapture` (or inside `nix develop`). MUST pass (not skip) for the GREEN. If anvil truly can't be obtained in your session, report DONE_WITH_CONCERNS with the skip output and exactly how to run it — but make a real effort (nix develop / nix run nixpkgs#foundry) first.

- [ ] **Step 5: `MockEvmRpc`.** A scriptable `IServerEvmRpc` impl backed by in-memory maps: `chain_id`, `block_number`, `balances: HashMap<(EvmAddress token, EvmAddress holder, u64 block), UsdtAmount>` (or a simpler current-balance map + a settable block), `code: HashMap<EvmAddress, usize>`, `fee: FeeVote`, and a record of `send_raw_transaction` calls. Constructor + setters so Phase 5's module unit tests can script deposits without a real chain. Add a unit test exercising the mock (set a balance, read it back; unknown holder → 0).

- [ ] **Step 6: Verify + commit** — clippy the server crate (mock lives in tests; don't `-D warnings` the tests crate due to the pre-existing lnv2 issue — but DO `cargo check -p fedimint-usdt-tests --tests`); format; cargo-sort. Commit: `test(usdt): anvil harness, hermetic EVM read-adapter test, and MockEvmRpc`

---

### Task 4: devimint `Anvil` daemon + smoke test + CI wiring

**Files:** `devimint/src/{external.rs, util.rs, envs.rs, vars.rs, devfed.rs, tests.rs}`; `scripts/tests/anvil-smoke-test.sh`; `scripts/tests/test-ci-all.sh`; `devimint/Cargo.toml` (alloy dev/dep if the smoke test reads via alloy).

This makes anvil a first-class devimint daemon so Phase 5+ full-federation-on-chain tests can use it. Mirror the `Esplora` pattern exactly (research gave verbatim shapes).

- [ ] **Step 1: Binary alias** — `devimint/src/envs.rs`: `pub const FM_ANVIL_BASE_EXECUTABLE_ENV: &str = "FM_ANVIL_BASE_EXECUTABLE";`. `devimint/src/util.rs`: `pub struct Anvil;` with `cmd()` → `to_command(get_command_str_for_alias(&[FM_ANVIL_BASE_EXECUTABLE_ENV], &[ANVIL_FALLBACK]))` and `const ANVIL_FALLBACK: &str = "anvil";`.

- [ ] **Step 2: Port** — `devimint/src/vars.rs`: add `FM_PORT_ANVIL: u16 = port_alloc(1)?; env: "FM_PORT_ANVIL";` in the `declare_vars!` block (near `FM_PORT_ESPLORA`).

- [ ] **Step 3: `Anvil` daemon** — `devimint/src/external.rs`: an `Anvil` struct (mirror `Esplora`) with `new(process_mgr) -> Result<Self>` spawning `cmd!(crate::util::Anvil, "--port={anvil_port}", "--chain-id=31337", "--silent")` via `process_mgr.spawn_daemon("anvil", cmd)`, and `wait_for_ready` polling `eth_chainId` over an alloy provider at `http://127.0.0.1:{FM_PORT_ANVIL}` using the `poll(...)` + `ControlFlow::Continue` pattern. Add an accessor `pub fn rpc_url(&self) -> String`. (Anvil needs no external dep like bitcoind — it's standalone.)

- [ ] **Step 4: `DevFed`/`DevJitFed` wiring** — mirror Esplora's 6 touch-points in `devimint/src/devfed.rs` (struct fields, JitArc construction, accessor `anvil()`, `finalize` force-ready, `to_dev_fed` copy, `fast_terminate` drop). Anvil has no dependency on bitcoind so its Jit closure needs no upstream await. Also add to `ExternalDaemons` + `external_daemons()` in external.rs if you want `just devimint-env` to include it.

- [ ] **Step 5: devimint smoke test** — `devimint/src/tests.rs`: add `TestCmd::AnvilSmokeTest` variant + a match arm that `setup`s, gets an anvil (via `external_daemons` or a standalone `Anvil::new`), and asserts `eth_chainId == 31337` and `eth_blockNumber` responds. Free fn `async fn anvil_smoke_test(...) -> Result<()>`.

- [ ] **Step 6: CI wiring** — `scripts/tests/anvil-smoke-test.sh` (clone `reconnect-test.sh`, call `devimint anvil-smoke-test`); in `scripts/tests/test-ci-all.sh` add `function anvil_smoke_test() { fm-run-test "${FUNCNAME[0]}" ./scripts/tests/anvil-smoke-test.sh; }`, `export -f anvil_smoke_test`, and `"anvil_smoke_test"` in the `tests_to_run_in_parallel` array.

- [ ] **Step 7: Verify + commit** — `cargo check -p devimint`. If anvil is available, run the smoke test: `nix develop -c ./scripts/tests/anvil-smoke-test.sh` (or `devimint anvil-smoke-test` with foundry on PATH) — report result; if not runnable in-session, `cargo check -p devimint` clean + a note. `just format`; clippy `-p devimint` (NOT -D warnings if it trips the lnv2 issue — check); cargo-sort. Commit: `feat(devimint): anvil EVM devnet daemon and smoke test`

---

## Self-review checklist (controller, before dispatching Task 1)

- Scope matches the settled decision: read half + `send_raw_transaction` + harness; NO UserOp/4337/real-USDT (that's Phase 7). ✓
- No `fedimint-server-core`/`fedimint-server` changes — adapter built in the module's `init()` from local config (research-confirmed lowest-friction path). ✓
- wasm boundary preserved: alloy stays out of `-common`/`-client`; `FeeVote` is plain u64s. ✓
- The acceptance test genuinely exercises `at_block` addressing (read balance at a pre-transfer block) — the property Phase 5 deposit detection needs — and skips-but-verifiable when anvil absent. ✓
- Open risk flagged for Task 1: obtaining deterministic test-ERC-20 bytecode (forge-compile-once-and-commit, or a vendored minimal artifact); BLOCKED path defined. ✓
- Open item for Task 2 implementer: mirror wallet's exact local-config mechanism (the `plugin_types_trait_impl_config!` macro may not take a `local` arg — local config is threaded differently; verify against wallet before assuming the 4-arg macro handles it). Flagged inline.
