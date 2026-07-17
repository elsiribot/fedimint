# USDT Deposit Path (Phase 5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A plain USDT (ERC-20) transfer to a per-user derived EVM address becomes claimable, USDT-denominated fedimint e-cash — end to end, with no MPC signing or sweeping (those are Phases 6/7).

**Architecture:** The client derives a deposit address from `(federation group key, user claim key)` with a wasm-safe additive tweak, and shows it to the user. After the user's on-chain transfer, the client calls `check_deposit` on every guardian, each of which stores a local `PendingCheck`. A background per-guardian task reads the confirmed ERC-20 balance of pending addresses and proposes `Deposit` consensus observations; when a threshold of guardians report the *identical* `(account, balance, block)` the federation credits a `DepositRecord`. The client then submits a fedimint transaction whose single `UsdtInput::V0` is authenticated by the claim key (core verifies the transaction signature against `InputMeta.pub_key`); `process_input` bumps the record's `claimed` and funds the transaction in `USDT_UNIT`, which the federation's USDT-denominated `mintv2` instance turns into e-cash notes.

**Tech Stack:** Rust; `fedimint-core` module framework (`ServerModule`/`ClientModule`); `secp256k1` (`add_exp_tweak`, wasm-safe); `sha3` Keccak-256 (wasm-safe, for EVM address derivation in `-common`); `alloy` (server-only, already wired in Phase 4) behind `IServerEvmRpc`; `fedimint-testing` for the hermetic acceptance; `devimint` + `anvil` for the (gated) real-chain e2e.

## Global Constraints

- **Deposit-address derivation is PROVISIONAL and detection-only (D7 + this-session decision).** Phase 5 uses an additive-tweak EOA: `account = evm_address(group_pk ⊕ H(domain ‖ group_pk ‖ claim_pk)·G)`. The federation never *signs for* these addresses in Phase 5 (nothing is swept). Signing-custody (SLIP-10 vs additive-tweak vs CREATE2 SimpleAccount) is reconciled in Phase 7. Every derivation site must carry a `// PROVISIONAL (Phase 5): detection-only; signing custody reconciled in Phase 7` comment.
- **`-common` and `-client` stay WASM-safe.** No `cggmp21`/`gmp`, no `alloy` *provider* (the lazy RPC stack), no `fedimint-usdt-server` in their dependency graph. Keccak in `-common` comes from `sha3` (pure Rust), NOT from `crypto/threshold-ecdsa` (which pulls `gmp`) and NOT from an `alloy` provider crate. Verify with `cargo tree` in the relevant task.
- **USDT unit is fixed.** Credited/claimed amounts are denominated in `fedimint_usdt_common::USDT_UNIT` (`AmountUnit::new_custom(1)`), converted `UsdtAmount(x) → Amount::from_msats(x)` (D8: 1 `Amount` ≡ 10⁻⁶ USDT). `process_input` MUST credit exactly `USDT_UNIT`, or the client's per-unit primary-module routing sends the funds to the wrong (or no) mint instance.
- **`process_consensus_item` MUST return `Err` for any item that does not change consensus state** (unbounded-history rule). Every handler ends in a redundancy guard, mirroring the wallet module.
- **Per-guardian EVM reads are votes, not shared truth.** Guardians may see different chain tips / balances; only threshold-agreed observations mutate consensus. Never treat one guardian's read as authoritative.
- **`at_block > node head` is a retry condition, not a failure.** A guardian whose node hasn't reached the requested confirmed block yet simply proposes nothing this round (logs at `debug`), it does not error.
- **Module stays env-gated OFF by default** (`FM_ENABLE_MODULE_USDT`), unchanged from Phase 3. The gated devimint e2e (Task 12) opts in explicitly.
- **Consensus version stays `(0,0)`; nothing is deployed.** Wire-format churn between phases is acceptable — do NOT pre-define Phase 6/8 consensus-item or output variants "for stability." Pin only what Phase 5 uses, plus the `#[encodable_default]` fallback.
- After code changes run `just format`; before committing a task run `just clippy` (workspace `-D warnings`; note the pre-existing `fedimint-core/tiered_multi.rs` pedantic lint and any `*-tests` `lnv2-client` dead-code lint are toolchain/pre-existing, not ours — confirm identical on unmodified HEAD before dismissing).

## Reference Map (existing code to mirror — read before implementing)

- Block-count vote / median / redundancy guard: `modules/fedimint-wallet-server/src/lib.rs:539-582` (propose), `:630-679` (process), `:1366-1385` (`consensus_block_count` median), `:1338-1348` (cached read). DB keys: `modules/fedimint-wallet-server/src/db.rs:158-170` (`impl_db_record!`/`impl_db_lookup!`).
- Module holding `our_peer_id`/`task_group`, spawning tasks: `modules/fedimint-wallet-server/src/lib.rs:1177-1229` (`Wallet` struct + `new`), `:1824-1870` (`spawn_cancellable`). `init` accessors: `fedimint-server-core/src/init.rs:153-171` (`cfg`/`db`/`num_peers`/`task_group`/`our_peer_id`).
- `Tweakable` / `add_exp_tweak`: `modules/fedimint-wallet-common/src/tweakable.rs:23-36`; clean tweak-a-pubkey example `modules/fedimint-walletv2-common/src/lib.rs:55-61` (`pk.add_exp_tweak(secp256k1::SECP256K1, &Scalar::from_be_bytes(...)?)`).
- `evm_address` reference impl (server-side, keccak-last-20): `crypto/threshold-ecdsa/src/lib.rs:200-206`.
- `api_endpoint!` with typed param touching `dbtx`: `modules/fedimint-lnv2-server/src/lib.rs:673-687` (read), `:710-720` (typed param + auth + write).
- Client claim input: `modules/fedimint-mintv2-client/src/lib.rs:634-675` (`ClientInput { input, keys, amounts }` + `ClientInputSM` + `ClientInputBundle::new`), server side it must match `InputMeta { amount, pub_key }` at `modules/fedimint-mintv2-server/src/lib.rs:435-441`.
- Client operation + `OperationId` + submit + event log: `modules/fedimint-mintv2-client/src/lib.rs:815-836` (output op), `:907-957` (input op with `operation_exists` guard + `log_event`).
- Config-gen params (Phase 4.5 mechanism): `modules/fedimint-mintv2-common/src/config.rs:12-28` (`MintGenParams` + `Default`), server wiring `modules/fedimint-mintv2-server/src/lib.rs` (`type Params = MintGenParams`, used in both `trusted_dealer_gen` and `distributed_gen`).
- devimint env injection: add one line to `devimint/src/vars.rs` `Fedimintd` block (`:291-316`) reading `globals.FM_PORT_ANVIL` (`:162`); anvil url accessor `devimint/src/external.rs:932-935`, devfed accessor `devimint/src/devfed.rs:424-425`.
- `Amounts`/`InputMeta`/`TransactionItemAmounts`: `fedimint-core/src/module/mod.rs:55-59`, `:138-144` (`Amounts::new_custom`), `:248-252`.

---

## Task 1: Common wire types + provisional deposit-address derivation

**Files:**
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (replace the placeholder `UsdtConsensusItem`/`UsdtInput` unit structs; add `DepositObservation`, `evm_address`, `derive_deposit_account`; real `UsdtInputError`)
- Modify: `modules/fedimint-usdt-common/Cargo.toml` (add `sha3` workspace dep)
- Test: inline `#[cfg(test)]` in `lib.rs`

**Interfaces:**
- Consumes: `EvmAddress`, `UsdtAmount`, `USDT_UNIT`, `FeeVote` (already in `-common`); `UsdtClientConfig` (extended in Task 2 — for Task 1 use the *current* shape with just `group_public_key`; Task 2 adds the fields `derive_deposit_account` needs, so Task 1 derives from `group_public_key` + a hardcoded domain tag only).
- Produces:
  - `pub enum UsdtConsensusItem { BlockCount(u64), Deposit(DepositObservation), #[encodable_default] Default { variant: u64, bytes: Vec<u8> } }`
  - `pub struct DepositObservation { pub account: EvmAddress, pub balance: UsdtAmount, pub block: u64 }`
  - `pub enum UsdtInput { V0(UsdtInputV0), #[encodable_default] Default { variant: u64, bytes: Vec<u8> } }`
  - `pub struct UsdtInputV0 { pub account: EvmAddress, pub amount: UsdtAmount }`
  - `pub enum UsdtInputError { UnknownDepositAccount, InsufficientCredit { available: UsdtAmount, requested: UsdtAmount } }`
  - `pub fn evm_address(pk: &secp256k1::PublicKey) -> EvmAddress`
  - `pub fn derive_deposit_account(group_public_key: &secp256k1::PublicKey, claim_pk: &secp256k1::PublicKey) -> EvmAddress` (Task 2 re-wraps this as `derive_deposit_account(cfg, claim_pk)`)
  - `pub const DEPOSIT_ADDRESS_DOMAIN: &[u8] = b"fedimint-usdt-deposit-v0";`

- [ ] **Step 1: Add the `sha3` dependency.** In `modules/fedimint-usdt-common/Cargo.toml` under `[dependencies]` add `sha3 = { workspace = true }` (the workspace already pins `sha3` for `crypto/threshold-ecdsa`; confirm with `grep '^sha3' Cargo.toml`). Do NOT add `alloy` to this crate.

- [ ] **Step 2: Write the failing derivation tests.** Add to `modules/fedimint-usdt-common/src/lib.rs` `#[cfg(test)] mod tests`:

```rust
#[test]
fn evm_address_matches_keccak_last_20_of_uncompressed() {
    // A fixed secp256k1 pubkey → its well-known Ethereum address.
    // Secret key = 0x0000...0001; address is the canonical test vector.
    let sk = secp256k1::SecretKey::from_slice(&{
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    })
    .expect("valid scalar");
    let pk = sk.public_key(secp256k1::SECP256K1);
    // keccak256(uncompressed[1..])[12..] for sk=1:
    let expected =
        EvmAddress(hex_20("7e5f4552091a69125d5dfcb7b8c2659029395bdf"));
    assert_eq!(evm_address(&pk), expected);
}

#[test]
fn derive_deposit_account_is_deterministic_and_claim_specific() {
    let group = secp256k1::SecretKey::from_slice(&[2u8; 32])
        .unwrap()
        .public_key(secp256k1::SECP256K1);
    let claim_a = secp256k1::SecretKey::from_slice(&[3u8; 32])
        .unwrap()
        .public_key(secp256k1::SECP256K1);
    let claim_b = secp256k1::SecretKey::from_slice(&[4u8; 32])
        .unwrap()
        .public_key(secp256k1::SECP256K1);

    // Deterministic
    assert_eq!(
        derive_deposit_account(&group, &claim_a),
        derive_deposit_account(&group, &claim_a)
    );
    // Distinct per claim key
    assert_ne!(
        derive_deposit_account(&group, &claim_a),
        derive_deposit_account(&group, &claim_b)
    );
    // Distinct from the untweaked group address (tweak is non-zero)
    assert_ne!(derive_deposit_account(&group, &claim_a), evm_address(&group));
}
```

Add a tiny hex helper next to the tests:

```rust
fn hex_20(s: &str) -> [u8; 20] {
    let bytes = (0..20)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect::<Vec<_>>();
    bytes.try_into().unwrap()
}
```

- [ ] **Step 3: Run to verify failure.** `cargo test -p fedimint-usdt-common evm_address_matches -- --nocapture` → FAIL (`evm_address` not defined).

- [ ] **Step 4: Implement `evm_address` and `derive_deposit_account`.** Add near the top of `lib.rs` (after imports; add `use fedimint_core::secp256k1; use sha3::{Digest, Keccak256};`):

```rust
/// Domain-separation tag mixed into the provisional deposit-address tweak.
pub const DEPOSIT_ADDRESS_DOMAIN: &[u8] = b"fedimint-usdt-deposit-v0";

/// The standard Ethereum address of a secp256k1 public key: last 20 bytes of
/// `keccak256` over the 64-byte uncompressed point (SEC1 with the `0x04`
/// prefix stripped). WASM-safe (pure-Rust `sha3`); mirrors
/// `fedimint_threshold_ecdsa::evm_address`, and a round-trip test keeps them
/// byte-identical.
#[must_use]
pub fn evm_address(pk: &secp256k1::PublicKey) -> EvmAddress {
    let uncompressed = pk.serialize_uncompressed();
    let hash = Keccak256::digest(&uncompressed[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    EvmAddress(address)
}

/// Derives the per-user deposit EOA from the federation group key and the
/// user's claim key via an additive tweak: `group_pk ⊕ t·G` where
/// `t = keccak256(DOMAIN ‖ group_pk ‖ claim_pk)`.
///
/// PROVISIONAL (Phase 5): detection-only. The federation does not sign for
/// this address in Phase 5; signing custody (SLIP-10 / additive-tweak /
/// CREATE2 SimpleAccount) is reconciled in Phase 7. Both the client (wasm)
/// and every guardian call this exact function so the address they watch is
/// bit-for-bit identical.
#[must_use]
pub fn derive_deposit_account(
    group_public_key: &secp256k1::PublicKey,
    claim_pk: &secp256k1::PublicKey,
) -> EvmAddress {
    let mut hasher = Keccak256::new();
    hasher.update(DEPOSIT_ADDRESS_DOMAIN);
    hasher.update(group_public_key.serialize()); // 33-byte compressed
    hasher.update(claim_pk.serialize());
    let tweak_bytes: [u8; 32] = hasher.finalize().into();

    // keccak output ≥ curve order only with negligible probability; mirror
    // the wallet's `tweak_public_key` which treats this as infallible.
    let tweak = secp256k1::Scalar::from_be_bytes(tweak_bytes)
        .expect("keccak digest is a valid secp256k1 scalar with overwhelming probability");
    let derived = group_public_key
        .add_exp_tweak(secp256k1::SECP256K1, &tweak)
        .expect("additive tweak of a valid point is a valid point");

    evm_address(&derived)
}
```

- [ ] **Step 5: Run derivation tests to verify pass.** `cargo test -p fedimint-usdt-common evm_address_matches derive_deposit_account -- --nocapture` → PASS. (If the `sk=1` vector fails, recompute it with `cast wallet address --private-key 0x0000...0001` using `.superpowers/sdd/tools/cast` and correct the literal.)

- [ ] **Step 6: Replace the placeholder consensus/input/error types.** In `lib.rs` replace `pub struct UsdtConsensusItem;`, `pub struct UsdtInput;`, and the `UsdtInputError` enum with:

```rust
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositObservation {
    pub account: EvmAddress,
    pub balance: UsdtAmount,
    pub block: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum UsdtConsensusItem {
    /// Guardian's view of the EVM chain head (median-voted, wallet-style).
    BlockCount(u64),
    /// Guardian's observation of a pending deposit account's confirmed
    /// balance (claim-triggered, D7).
    Deposit(DepositObservation),
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum UsdtInput {
    /// Claim credited deposit funds. Core verifies the fedimint transaction is
    /// signed by `InputMeta.pub_key` = the deposit's claim key; there is no
    /// extra signature inside the input.
    V0(UsdtInputV0),
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtInputV0 {
    pub account: EvmAddress,
    pub amount: UsdtAmount,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum UsdtInputError {
    #[error("No credited deposit record exists for this account")]
    UnknownDepositAccount,
    #[error("Claim of {requested} exceeds the {available} still claimable for this account")]
    InsufficientCredit {
        available: UsdtAmount,
        requested: UsdtAmount,
    },
}
```

Update the `Display for UsdtInput` / `Display for UsdtConsensusItem` impls to match the new enums (e.g. `write!(f, "{self:?}")`). Leave `UsdtOutput`, `UsdtOutputOutcome`, `UsdtOutputError` as their placeholder unit types (withdrawals are Phase 8).

- [ ] **Step 7: Add wire round-trip tests for the new enums.** In `mod tests` add encode/decode round-trips for `UsdtConsensusItem::BlockCount(7)`, `UsdtConsensusItem::Deposit(DepositObservation { .. })`, and `UsdtInput::V0(UsdtInputV0 { account: EvmAddress([9;20]), amount: UsdtAmount(1_000_000) })`, following the existing `test_*_round_trips_through_consensus_encoding` pattern (`consensus_encode_to_vec` → `consensus_decode_whole` → `assert_eq!`).

- [ ] **Step 8: Build, format, verify.** `cargo check -p fedimint-usdt-common && just format && cargo test -p fedimint-usdt-common`. Confirm WASM-safety: `cargo tree -p fedimint-usdt-common -i gmp-mpfr-sys` and `-i cggmp21` must both report "not found". All tests PASS.

- [ ] **Step 9: Commit.**
```bash
git add modules/fedimint-usdt-common
git commit -m "feat(usdt): deposit-address derivation and Phase 5 wire types"
```

---

## Task 2: Config-gen params → consensus + client config

**Files:**
- Modify: `modules/fedimint-usdt-common/src/config.rs` (extend `UsdtClientConfig`; re-export/wrap `derive_deposit_account`)
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (add `UsdtGenParams`)
- Modify: `modules/fedimint-usdt-server/src/config.rs` (extend `UsdtConfigConsensus`)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`type Params = UsdtGenParams`; thread through `trusted_dealer_gen`, `get_client_config`)
- Modify: `modules/fedimint-usdt-server/src/dkg.rs` (thread params through `distributed_gen`)
- Test: inline in server `lib.rs` (extend the existing `trusted_dealer_gen_produces_consistent_valid_configs`)

**Interfaces:**
- Consumes: Task 1's `derive_deposit_account(group_public_key, claim_pk)`, `EvmAddress`.
- Produces:
  - `pub struct UsdtGenParams { pub usdt_contract: EvmAddress, pub chain_id: u64, pub confirmation_depth: u64, pub check_ttl_blocks: u64 }` (with a `Default` matching a local-anvil dev federation).
  - `UsdtClientConfig` gains `pub usdt_contract: EvmAddress`, `pub confirmation_depth: u64`, `pub chain_id: u64`.
  - `UsdtConfigConsensus` gains the same three + `pub check_ttl_blocks: u64`.
  - `pub fn derive_deposit_account(cfg: &UsdtClientConfig, claim_pk: &secp256k1::PublicKey) -> EvmAddress` (the pinned Interface-B signature, wrapping Task 1's raw function).

- [ ] **Step 1: Add `UsdtGenParams`.** In `modules/fedimint-usdt-common/src/lib.rs` (or a small addition to `config.rs` — keep it in `lib.rs` next to the other pub types):

```rust
/// Per-instance config-gen params for the USDT module (Phase 4.5 mechanism).
///
/// `Default` targets a local `anvil` dev federation: chain id 31337, a fast
/// confirmation depth, and the test ERC-20 address deployed by the devimint
/// anvil harness. Real deployments override every field at config-gen time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsdtGenParams {
    pub usdt_contract: EvmAddress,
    pub chain_id: u64,
    pub confirmation_depth: u64,
    pub check_ttl_blocks: u64,
}

impl Default for UsdtGenParams {
    fn default() -> Self {
        Self {
            usdt_contract: EvmAddress([0u8; 20]),
            chain_id: 31337,
            confirmation_depth: 1,
            check_ttl_blocks: 10_000,
        }
    }
}
```

- [ ] **Step 2: Write the failing config-flow test.** In `modules/fedimint-usdt-server/src/lib.rs` `mod tests`, add:

```rust
#[test]
fn config_gen_params_flow_into_consensus_and_client_config() {
    let peers = (0..NUM_PEERS).map(PeerId::from).collect::<Vec<_>>();
    let args = ConfigGenModuleArgs {
        network: Network::Regtest,
        disable_base_fees: false,
    };
    let params = fedimint_usdt_common::UsdtGenParams {
        usdt_contract: fedimint_usdt_common::EvmAddress([0xab; 20]),
        chain_id: 1,
        confirmation_depth: 6,
        check_ttl_blocks: 500,
    };

    let cfgs = UsdtInit.trusted_dealer_gen(&peers, &args, &params);
    let cfg0 = cfgs[&peers[0]].clone().to_typed::<UsdtConfig>().unwrap();
    assert_eq!(cfg0.consensus.usdt_contract, params.usdt_contract);
    assert_eq!(cfg0.consensus.confirmation_depth, 6);
    assert_eq!(cfg0.consensus.check_ttl_blocks, 500);

    let client_cfg = UsdtInit
        .get_client_config(&cfg0.consensus.to_erased())
        .unwrap();
    assert_eq!(client_cfg.usdt_contract, params.usdt_contract);
    assert_eq!(client_cfg.confirmation_depth, 6);
    assert_eq!(client_cfg.chain_id, 1);
}
```

- [ ] **Step 3: Run to verify failure.** `cargo test -p fedimint-usdt-server config_gen_params_flow` → FAIL (fields/param type absent).

- [ ] **Step 4: Extend the config structs.** In `modules/fedimint-usdt-server/src/config.rs` add to `UsdtConfigConsensus`: `pub usdt_contract: EvmAddress`, `pub chain_id: u64`, `pub confirmation_depth: u64`, `pub check_ttl_blocks: u64` (import `EvmAddress`). In `modules/fedimint-usdt-common/src/config.rs` add to `UsdtClientConfig`: `pub usdt_contract: EvmAddress`, `pub chain_id: u64`, `pub confirmation_depth: u64` (import `EvmAddress` from the crate root).

- [ ] **Step 5: Wire params through config-gen.** In `modules/fedimint-usdt-server/src/lib.rs`:
  - Change `type Params = ();` → `type Params = fedimint_usdt_common::UsdtGenParams;`.
  - In `trusted_dealer_gen` change the `_params: &Self::Params` binding to `params` and set the four new `UsdtConfigConsensus` fields from `params.{usdt_contract, chain_id, confirmation_depth, check_ttl_blocks}`.
  - In `distributed_gen` change `_params` → `params` and pass it: `dkg::distributed_gen(peers, args, params).await`.
  - In `get_client_config` populate the three new `UsdtClientConfig` fields from `config.{usdt_contract, chain_id, confirmation_depth}`.
  - In `modules/fedimint-usdt-server/src/dkg.rs` change `distributed_gen(peers, args)` → `distributed_gen(peers, args, params: &UsdtGenParams)` and set the four consensus fields identically (import `UsdtGenParams`).

- [ ] **Step 6: Add the `cfg`-based `derive_deposit_account` wrapper.** In `modules/fedimint-usdt-common/src/config.rs`:

```rust
/// Interface B (pinned): the deposit address for `claim_pk` under this
/// federation's config. Thin wrapper over
/// [`crate::derive_deposit_account`] so client and server share one impl.
#[must_use]
pub fn derive_deposit_account(
    cfg: &UsdtClientConfig,
    claim_pk: &secp256k1::PublicKey,
) -> crate::EvmAddress {
    crate::derive_deposit_account(&cfg.group_public_key, claim_pk)
}
```

- [ ] **Step 7: Fix the two existing config-gen tests.** The Task-1-era `trusted_dealer_gen_produces_consistent_valid_configs` and the `distributed_gen_tests` helpers pass `&()`; change them to `&fedimint_usdt_common::UsdtGenParams::default()` (and `run_distributed_gen_for_all_peers`'s `distributed_gen(&net, &args, &())` → `&UsdtGenParams::default()`).

- [ ] **Step 8: Build, format, test.** `cargo check --workspace && just format && cargo test -p fedimint-usdt-server config_gen_params_flow trusted_dealer_gen_produces`. New test PASSES; the DKG acceptance test is unchanged behaviorally (run it too if time permits: `cargo test -p fedimint-usdt-server distributed_gen_produces_working -- --nocapture`). Re-confirm `-common` WASM-safety (`cargo tree -p fedimint-usdt-common -i cggmp21` → not found).

- [ ] **Step 9: Commit.**
```bash
git add modules/fedimint-usdt-common modules/fedimint-usdt-server
git commit -m "feat(usdt): config-gen params for contract/chain/confirmation-depth"
```

---

## Task 3: Server DB schema

**Files:**
- Modify: `modules/fedimint-usdt-server/src/db.rs` (real key/value structs + macros)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`dump_database` over the new prefixes)
- Test: inline in `db.rs`

**Interfaces:**
- Consumes: `EvmAddress`, `UsdtAmount`, `DepositObservation` (`-common`); `PeerId`, `secp256k1::PublicKey`.
- Produces (all `Encodable`/`Decodable`, `impl_db_record!`/`impl_db_lookup!`):
  - `BlockCountVoteKey(pub PeerId)` / `BlockCountVotePrefix` → `u64` (prefix `0x01`)
  - `DepositRecordKey(pub EvmAddress)` / `DepositRecordPrefix` → `DepositRecord { pub claim_pk: secp256k1::PublicKey, pub credited: UsdtAmount, pub claimed: UsdtAmount, pub last_observed_block: u64 }` (prefix `0x03`)
  - `DepositObservationVoteKey(pub EvmAddress, pub PeerId)` / `DepositObservationVotePrefix` / `DepositObservationVoteAccountPrefix(pub EvmAddress)` → `DepositObservation` (prefix `0x04`)
  - `PendingCheckKey(pub EvmAddress)` / `PendingCheckPrefix` → `PendingCheck { pub claim_pk: secp256k1::PublicKey, pub requested_at_block: u64 }` (prefix `0x05`, guardian-local)

- [ ] **Step 1: Write the failing DB round-trip test.** In `db.rs` add `#[cfg(test)] mod tests` that inserts each record into an in-memory `Database` (use `fedimint_core::db::mem_impl::MemDatabase` + `ModuleDecoderRegistry::default()` — mirror any existing module `db.rs` test, e.g. search `modules/fedimint-mintv2-server/src/db.rs` for a `MemDatabase` test) and reads it back with `assert_eq!`. Cover `DepositRecordKey` and `DepositObservationVoteKey`, plus a `find_by_prefix(&DepositObservationVoteAccountPrefix(account))` returning exactly the votes for that account.

- [ ] **Step 2: Run to verify failure.** `cargo test -p fedimint-usdt-server -- db::tests` → FAIL (types absent).

- [ ] **Step 3: Implement the schema.** Replace `db.rs` contents with the `DbKeyPrefix` enum (variants `BlockCountVote = 0x01`, `DepositRecord = 0x03`, `DepositObservationVote = 0x04`, `PendingCheck = 0x05`; keep `#[repr(u8)]`, `EnumIter`, `Display`), the four value structs, and the key structs with `impl_db_record!`/`impl_db_lookup!` mirroring `modules/fedimint-wallet-server/src/db.rs:158-170`. Example for the two-field lookup:

```rust
#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash)]
pub struct DepositObservationVoteKey(pub EvmAddress, pub PeerId);

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DepositObservationVotePrefix;

#[derive(Debug, Clone, Encodable, Decodable)]
pub struct DepositObservationVoteAccountPrefix(pub EvmAddress);

impl_db_record!(
    key = DepositObservationVoteKey,
    value = DepositObservation,
    db_prefix = DbKeyPrefix::DepositObservationVote,
);
impl_db_lookup!(
    key = DepositObservationVoteKey,
    query_prefix = DepositObservationVotePrefix,
    query_prefix = DepositObservationVoteAccountPrefix,
);
```

`DepositRecord` / `PendingCheck` derive `Debug, Clone, Encodable, Decodable, Eq, PartialEq` (+ `Serialize` if `dump_database` needs it — it does; add `Serialize`).

- [ ] **Step 4: Update `dump_database`.** In `lib.rs` replace the `DbKeyPrefix::Reserved => {}` arm with real arms that `find_by_prefix` each table into `items` (mirror `modules/fedimint-wallet-server/src/lib.rs` `dump_database`). Each arm pushes `(format!("{key:?}"), Box::new(value))`.

- [ ] **Step 5: Run tests to verify pass.** `cargo test -p fedimint-usdt-server -- db::tests` → PASS.

- [ ] **Step 6: Format, clippy, commit.** `just format && cargo clippy -p fedimint-usdt-server`.
```bash
git add modules/fedimint-usdt-server
git commit -m "feat(usdt): deposit-tracking database schema"
```

---

## Task 4: Block-aware `MockEvmRpc` (test harness upgrade)

**Files:**
- Modify: `modules/fedimint-usdt-tests/tests/common/mock.rs`
- Test: extend `mock.rs`'s inline tests

**Interfaces:**
- Produces: `MockEvmRpc::set_erc20_balance_at(token, holder, block, balance)` (script a balance effective *from* `block` onward) alongside the existing `set_erc20_balance` (now shorthand for "from block 0"). `get_erc20_balance(token, holder, at_block)` returns the balance for the greatest scripted block `≤ at_block` (else `UsdtAmount(0)`). Reading `at_block` greater than `set_block_number` returns `Err` ("header not found"), so deposit-scanner retry logic can be tested.

- [ ] **Step 1: Write the failing block-aware tests.** In `mock.rs mod tests`:

```rust
#[tokio::test]
async fn balance_is_read_as_of_block() {
    let mock = MockEvmRpc::new();
    let (t, h) = (EvmAddress([1; 20]), EvmAddress([2; 20]));
    mock.set_block_number(100);
    mock.set_erc20_balance_at(t, h, 10, UsdtAmount(0));
    mock.set_erc20_balance_at(t, h, 20, UsdtAmount(5_000_000));

    assert_eq!(mock.get_erc20_balance(t, h, 15).await.unwrap(), UsdtAmount(0));
    assert_eq!(mock.get_erc20_balance(t, h, 25).await.unwrap(), UsdtAmount(5_000_000));
}

#[tokio::test]
async fn reading_above_head_errors() {
    let mock = MockEvmRpc::new();
    mock.set_block_number(30);
    let err = mock
        .get_erc20_balance(EvmAddress([1; 20]), EvmAddress([2; 20]), 31)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("header not found"));
}
```

- [ ] **Step 2: Run to verify failure.** `cargo test -p fedimint-usdt-tests --test tests 2>/dev/null; cargo test -p fedimint-usdt-tests balance_is_read_as_of_block` → FAIL. (Note: `mock.rs` is under `tests/common`; it compiles as part of each integration test target. Run via the target that includes it.)

- [ ] **Step 3: Implement block-awareness.** Change `State::balances` to `HashMap<(EvmAddress, EvmAddress), BTreeMap<u64, UsdtAmount>>`. Keep `set_erc20_balance(token, holder, balance)` as `set_erc20_balance_at(token, holder, 0, balance)`. Add `set_erc20_balance_at`. Rewrite `get_erc20_balance`:

```rust
async fn get_erc20_balance(
    &self,
    token: EvmAddress,
    holder: EvmAddress,
    at_block: u64,
) -> anyhow::Result<UsdtAmount> {
    let state = self.lock();
    anyhow::ensure!(at_block <= state.block_number, "header not found");
    Ok(state
        .balances
        .get(&(token, holder))
        .and_then(|by_block| by_block.range(..=at_block).next_back().map(|(_, v)| *v))
        .unwrap_or(UsdtAmount(0)))
}
```

- [ ] **Step 4: Run tests to verify pass.** The two new tests PASS; the existing `set_and_read_back_a_balance` / `unknown_holder_reads_as_zero` still pass (set `set_block_number` high enough in those — update them to `mock.set_block_number(1)` before reading at block 0). `just format`.

- [ ] **Step 5: Commit.**
```bash
git add modules/fedimint-usdt-tests
git commit -m "test(usdt): block-aware MockEvmRpc for deposit-detection tests"
```

---

## Task 5: Block-count cache, poller task, and block-count consensus

**Files:**
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`Usdt` struct + `new` + `init`; `consensus_proposal`; `process_consensus_item`; `consensus_block_count`; poller task)
- Test: inline in `lib.rs`

**Interfaces:**
- Consumes: `args.{db,task_group,our_peer_id,num_peers}()`; `evm_rpc.get_block_number()`; `BlockCountVoteKey`/`BlockCountVotePrefix` (Task 3).
- Produces: `Usdt { cfg, evm_rpc, our_peer_id, num_peers, block_count: Arc<AtomicU64>, task_group: TaskGroup, deposit_proposals: Arc<Mutex<Vec<DepositObservation>>> }` (the `deposit_proposals` field is populated in Task 7; declare it now, initialized empty). `pub async fn consensus_block_count(&self, dbtx) -> u64` (median). `consensus_proposal` emits `UsdtConsensusItem::BlockCount`. `process_consensus_item` handles `BlockCount` with the wallet redundancy guard.

- [ ] **Step 1: Write failing median + redundancy-guard tests.** In `lib.rs mod tests` add a helper that builds a `Usdt` over `MemDatabase` and a `MockEvmRpc`, then:

```rust
#[tokio::test]
async fn block_count_median_and_redundancy_guard() {
    let module = test_module_with_block_count(4, 0).await; // 4 peers, cached head 0
    let mut dbtx = module.db_for_test().begin_transaction().await;

    // No votes → median 0.
    assert_eq!(module.consensus_block_count(&mut dbtx.to_ref_nc()).await, 0);

    // Three of four peers vote 100 → median (index 2 of sorted [0,100,100,100]) = 100.
    for p in [0u16, 1, 2] {
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::BlockCount(100),
                PeerId::from(p),
            )
            .await
            .unwrap();
    }
    assert_eq!(module.consensus_block_count(&mut dbtx.to_ref_nc()).await, 100);

    // Re-submitting the same or lower vote is rejected (unbounded-history rule).
    let err = module
        .process_consensus_item(
            &mut dbtx.to_ref_nc(),
            UsdtConsensusItem::BlockCount(100),
            PeerId::from(0),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("redundant"));
}
```

(Provide `test_module_with_block_count` + `db_for_test` test helpers in this step: construct `Usdt` directly via a test-only constructor that takes an explicit `Database`, `MockEvmRpc`, peer id, `NumPeers`, and a `TaskGroup::new()` without spawning the poller. Add `#[cfg(test)] pub fn new_for_test(...)` on `Usdt` if the normal `new` spawns tasks.)

- [ ] **Step 2: Run to verify failure.** `cargo test -p fedimint-usdt-server block_count_median` → FAIL.

- [ ] **Step 3: Extend the `Usdt` struct + constructor.** Add fields `our_peer_id: PeerId`, `num_peers: NumPeers`, `block_count: Arc<AtomicU64>`, `task_group: TaskGroup`, `deposit_proposals: Arc<Mutex<Vec<DepositObservation>>>`. In `ServerModuleInit::init`, build the module via a `Usdt::new(cfg, evm_rpc, args.db().clone(), args.task_group().clone(), args.our_peer_id(), args.num_peers())` that (a) creates `block_count: Arc::new(AtomicU64::new(0))`, (b) spawns the poller (Step 5), (c) returns the module. Provide `#[cfg(test)] fn new_for_test(...)` that skips the spawn.

- [ ] **Step 4: Implement `consensus_block_count`, proposal, and processing.** Mirror the wallet exactly, using `u64` and `self.num_peers.total()`:

```rust
pub async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
    let peer_count = self.num_peers.total();
    let mut counts = dbtx
        .find_by_prefix(&BlockCountVotePrefix)
        .await
        .map(|entry| entry.1)
        .collect::<Vec<u64>>()
        .await;
    while counts.len() < peer_count {
        counts.push(0);
    }
    counts.sort_unstable();
    counts[peer_count / 2]
}
```

In `consensus_proposal`, read the cached head and propose (clamped like the wallet to avoid huge catch-up in one tx):

```rust
let head = self.block_count.load(Ordering::Relaxed);
let current_consensus = self.consensus_block_count(dbtx).await;
let mut vote = head;
if current_consensus != 0 {
    vote = vote.min(current_consensus + if is_running_in_test_env() { 100 } else { 5 });
}
let current_vote = dbtx.get_value(&BlockCountVoteKey(self.our_peer_id)).await.unwrap_or(0);
if vote > current_vote {
    items.push(UsdtConsensusItem::BlockCount(vote));
}
```

In `process_consensus_item`, add the `BlockCount` arm with the wallet's guard (`ensure!(vote > current, "Block count vote is redundant")`, then `insert_entry`). Change the fallthrough `bail!` so only *unknown/default* items error; `BlockCount` and (Task 6) `Deposit` are handled.

- [ ] **Step 5: Implement the poller task.** In `Usdt::new`, spawn:

```rust
task_group.spawn_cancellable("usdt-block-count-poller", {
    let evm_rpc = evm_rpc.clone();
    let block_count = block_count.clone();
    async move {
        loop {
            match evm_rpc.get_block_number().await {
                Ok(n) => { block_count.store(n, Ordering::Relaxed); }
                Err(err) => warn!(target: "usdt", err = %err.fmt_compact_anyhow(), "block count poll failed"),
            }
            fedimint_core::runtime::sleep(Duration::from_secs(if is_running_in_test_env() { 1 } else { 10 })).await;
        }
    }
});
```

(Use `fedimint_core::runtime::sleep`, not `tokio::time::sleep` — the `ban-tokio-sleep` lint, as in Phase 4.)

- [ ] **Step 6: Run tests to verify pass.** `cargo test -p fedimint-usdt-server block_count_median` → PASS. `just format && cargo clippy -p fedimint-usdt-server`.

- [ ] **Step 7: Commit.**
```bash
git add modules/fedimint-usdt-server
git commit -m "feat(usdt): block-count poller and median consensus"
```

---

## Task 6: Deposit observation consensus + crediting

**Files:**
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`process_consensus_item` `Deposit` arm; a `credit_if_threshold` helper)
- Test: inline in `lib.rs`

**Interfaces:**
- Consumes: `DepositObservationVoteKey`/`DepositObservationVoteAccountPrefix`, `DepositRecordKey`, `PendingCheckKey` (Task 3); `self.num_peers.threshold()`.
- Produces: `Deposit(DepositObservation)` handling: stores the per-peer vote (redundancy-guarded); when `≥ threshold` peers submitted the *identical* `(account, balance, block)`, sets `DepositRecord.credited = balance` (creating the record from the `PendingCheck`'s `claim_pk` if absent), updates `last_observed_block`, and clears that account's votes + `PendingCheck`.

- [ ] **Step 1: Write failing threshold-crediting tests.** In `mod tests`:

```rust
#[tokio::test]
async fn deposit_credited_only_at_threshold_of_identical_observations() {
    let module = test_module_with_block_count(4, 0).await; // threshold = 3
    let db = module.db_for_test();
    let account = EvmAddress([7; 20]);
    let claim_pk = test_pubkey(0xaa);

    // A PendingCheck must exist so the credit knows the claim key.
    {
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(&PendingCheckKey(account), &PendingCheck { claim_pk, requested_at_block: 0 }).await;
        dbtx.commit_tx().await;
    }

    let obs = DepositObservation { account, balance: UsdtAmount(2_000_000), block: 50 };
    let mut dbtx = db.begin_transaction().await;

    // Two identical votes: no credit yet.
    for p in [0u16, 1] {
        module.process_consensus_item(&mut dbtx.to_ref_nc(), UsdtConsensusItem::Deposit(obs.clone()), PeerId::from(p)).await.unwrap();
    }
    assert!(dbtx.to_ref_nc().get_value(&DepositRecordKey(account)).await.is_none());

    // A DIFFERENT balance from peer 2 does not count toward the 2M quorum.
    module.process_consensus_item(&mut dbtx.to_ref_nc(), UsdtConsensusItem::Deposit(DepositObservation { balance: UsdtAmount(9), ..obs.clone() }), PeerId::from(2)).await.unwrap();
    assert!(dbtx.to_ref_nc().get_value(&DepositRecordKey(account)).await.is_none());

    // Third identical 2M vote reaches threshold → credited, votes + pending cleared.
    module.process_consensus_item(&mut dbtx.to_ref_nc(), UsdtConsensusItem::Deposit(obs.clone()), PeerId::from(3)).await.unwrap();
    let record = dbtx.to_ref_nc().get_value(&DepositRecordKey(account)).await.unwrap();
    assert_eq!(record.credited, UsdtAmount(2_000_000));
    assert_eq!(record.claimed, UsdtAmount(0));
    assert!(dbtx.to_ref_nc().get_value(&PendingCheckKey(account)).await.is_none());
    assert_eq!(dbtx.to_ref_nc().find_by_prefix(&DepositObservationVoteAccountPrefix(account)).await.count().await, 0);
}

#[tokio::test]
async fn redundant_deposit_vote_errors() {
    // Same peer submitting the same observation twice must Err.
    // (setup as above, one peer, second identical submit → unwrap_err contains "redundant")
}
```

Add a `test_pubkey(byte) -> secp256k1::PublicKey` helper.

- [ ] **Step 2: Run to verify failure.** `cargo test -p fedimint-usdt-server deposit_credited_only_at_threshold` → FAIL.

- [ ] **Step 3: Implement the `Deposit` arm.** In `process_consensus_item`:

```rust
UsdtConsensusItem::Deposit(obs) => {
    // Store this peer's vote; redundancy guard (unbounded-history rule).
    let key = DepositObservationVoteKey(obs.account, peer);
    if dbtx.insert_entry(&key, &obs).await.as_ref() == Some(&obs) {
        bail!("Deposit observation vote is redundant");
    }

    // Count identical observations for this account.
    let votes: Vec<DepositObservation> = dbtx
        .find_by_prefix(&DepositObservationVoteAccountPrefix(obs.account))
        .await
        .map(|(_, v)| v)
        .collect()
        .await;
    let agreeing = votes.iter().filter(|v| **v == obs).count();

    if agreeing >= self.num_peers.threshold() {
        self.credit_deposit(dbtx, &obs).await?;
    }
    Ok(())
}
```

And the helper (credits the delta, monotonic since only the federation can move funds out):

```rust
async fn credit_deposit(
    &self,
    dbtx: &mut DatabaseTransaction<'_>,
    obs: &DepositObservation,
) -> anyhow::Result<()> {
    let claim_pk = match dbtx.get_value(&PendingCheckKey(obs.account)).await {
        Some(p) => p.claim_pk,
        // No pending check (already credited & cleared, or unknown) → nothing to do.
        None => match dbtx.get_value(&DepositRecordKey(obs.account)).await {
            Some(r) => r.claim_pk,
            None => bail!("Deposit observation for an account with no pending check or record"),
        },
    };
    let mut record = dbtx
        .get_value(&DepositRecordKey(obs.account))
        .await
        .unwrap_or(DepositRecord { claim_pk, credited: UsdtAmount(0), claimed: UsdtAmount(0), last_observed_block: 0 });
    // Only credit forward; balance is monotonic between sweeps.
    if obs.balance.0 > record.credited.0 {
        record.credited = obs.balance;
    }
    record.last_observed_block = obs.block;
    dbtx.insert_entry(&DepositRecordKey(obs.account), &record).await;
    // Clear the round's votes + the pending check.
    dbtx.remove_by_prefix(&DepositObservationVoteAccountPrefix(obs.account)).await;
    dbtx.remove_entry(&PendingCheckKey(obs.account)).await;
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify pass.** `cargo test -p fedimint-usdt-server deposit_credited redundant_deposit_vote` → PASS. `just format`.

- [ ] **Step 5: Commit.**
```bash
git add modules/fedimint-usdt-server
git commit -m "feat(usdt): threshold deposit-observation consensus and crediting"
```

---

## Task 7: Deposit-checker task + consensus_proposal draining + TTL expiry

**Files:**
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (checker task; drain `deposit_proposals` in `consensus_proposal`)
- Test: inline in `lib.rs`

**Interfaces:**
- Consumes: `evm_rpc.get_erc20_balance`, `self.block_count`, `self.cfg.consensus.{usdt_contract, confirmation_depth, check_ttl_blocks}`, `PendingCheckPrefix`, `DepositRecordKey`; `consensus_block_count`.
- Produces: a background `usdt-deposit-checker` task that, per tick, for each `PendingCheck`: (a) drops it if `requested_at_block + check_ttl_blocks < consensus_block_count`; (b) else reads `get_erc20_balance(usdt_contract, account, consensus_block_count − confirmation_depth)` (skips silently if that block > cached head, or on RPC error); (c) if `balance > record.credited` pushes a `DepositObservation` into `deposit_proposals`. `consensus_proposal` drains `deposit_proposals` into `UsdtConsensusItem::Deposit` items (dedup against what this peer already has as an unchanged vote).

- [ ] **Step 1: Write a failing checker-logic test.** Extract the per-account check into a pure async method `async fn scan_pending_deposits(&self, dbtx) -> Vec<DepositObservation>` so it is testable without a running task. Test: seed a `PendingCheck` + a `MockEvmRpc` with `set_erc20_balance_at(usdt, account, depositblock, 3_000_000)`, set cached `block_count` and votes so `consensus_block_count = N`, `set_block_number(N)`, then assert `scan_pending_deposits` returns one `DepositObservation { account, balance: 3_000_000, block: N - confirmation_depth }`. Add a second case: `requested_at_block` older than TTL → the method removes the `PendingCheck` (assert it's gone) and returns nothing.

- [ ] **Step 2: Run to verify failure.** FAIL (method absent).

- [ ] **Step 3: Implement `scan_pending_deposits`** reading `at = consensus_block_count.saturating_sub(confirmation_depth)`, guarding `at <= self.block_count.load(..)` (else skip), swallowing `get_erc20_balance` errors as skips, and TTL-expiring stale pending checks (delete + skip). Return the observations whose `balance > existing credited`.

- [ ] **Step 4: Spawn the checker task in `Usdt::new`** (like the poller): each tick, open a dbtx, call `scan_pending_deposits`, commit (for TTL deletions), and extend `self.deposit_proposals` with the returned observations. Interval: `sleep(1s in test / 10s prod)`.

- [ ] **Step 5: Drain in `consensus_proposal`.** After the block-count vote, `let pending = std::mem::take(&mut *self.deposit_proposals.lock().expect("not poisoned"));` and for each observation that isn't already this peer's stored vote (`dbtx.get_value(&DepositObservationVoteKey(obs.account, self.our_peer_id)).await != Some(obs.clone())`), push `UsdtConsensusItem::Deposit(obs)`.

- [ ] **Step 6: Test pass, format, clippy, commit.**
```bash
git add modules/fedimint-usdt-server
git commit -m "feat(usdt): deposit-checker task and observation proposal"
```

---

## Task 8: `process_input` (claim) + double-claim guard

**Files:**
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`process_input`)
- Test: inline in `lib.rs`

**Interfaces:**
- Consumes: `DepositRecordKey` (Task 3); `USDT_UNIT`; `Amounts::new_custom`.
- Produces: `process_input` for `UsdtInput::V0 { account, amount }`: loads the `DepositRecord`; errors `UnknownDepositAccount` if absent; errors `InsufficientCredit` if `amount > credited − claimed`; else sets `claimed += amount`, persists, returns `InputMeta { amount: TransactionItemAmounts { amounts: Amounts::new_custom(USDT_UNIT, Amount::from_msats(amount.0)), fees: Amounts::ZERO }, pub_key: record.claim_pk }`. `Default` input errors.

- [ ] **Step 1: Write failing claim tests.** In `mod tests`: seed a `DepositRecord { credited: 5_000_000, claimed: 0, .. }`; assert:
  - a valid `UsdtInput::V0 { amount: 2_000_000 }` returns `InputMeta` whose `amount.amounts == Amounts::new_custom(USDT_UNIT, Amount::from_msats(2_000_000))` and `pub_key == claim_pk`, and bumps `claimed` to `2_000_000`;
  - a second claim of `2_000_000` succeeds (`claimed` → `4_000_000`);
  - a third claim of `2_000_000` fails `InsufficientCredit { available: 1_000_000, requested: 2_000_000 }` (double-spend / over-claim guard);
  - an unknown account fails `UnknownDepositAccount`.

- [ ] **Step 2: Run to verify failure.** FAIL (still returns `NotSupported`, which no longer exists — the test won't compile until Step 3; that's fine, it's the red state).

- [ ] **Step 3: Implement `process_input`:**

```rust
async fn process_input<'a, 'b, 'c>(
    &'a self,
    dbtx: &mut DatabaseTransaction<'c>,
    input: &'b UsdtInput,
    _in_point: InPoint,
) -> Result<InputMeta, UsdtInputError> {
    let UsdtInput::V0(input) = input else {
        return Err(UsdtInputError::UnknownDepositAccount); // unknown/default variant
    };
    let mut record = dbtx
        .get_value(&DepositRecordKey(input.account))
        .await
        .ok_or(UsdtInputError::UnknownDepositAccount)?;
    let available = record.credited.0.saturating_sub(record.claimed.0);
    if input.amount.0 > available {
        return Err(UsdtInputError::InsufficientCredit {
            available: UsdtAmount(available),
            requested: input.amount,
        });
    }
    record.claimed = UsdtAmount(record.claimed.0 + input.amount.0);
    dbtx.insert_entry(&DepositRecordKey(input.account), &record).await;

    Ok(InputMeta {
        amount: TransactionItemAmounts {
            amounts: Amounts::new_custom(USDT_UNIT, Amount::from_msats(input.amount.0)),
            fees: Amounts::ZERO,
        },
        pub_key: record.claim_pk,
    })
}
```

(Import `USDT_UNIT`, `Amount`, `Amounts`, `TransactionItemAmounts`.)

- [ ] **Step 4: Test pass, format, clippy, commit.**
```bash
git add modules/fedimint-usdt-server
git commit -m "feat(usdt): process_input claims credited deposits as USDT-unit funding"
```

---

## Task 9: `check_deposit` / `deposit_status` API endpoints

**Files:**
- Modify: `modules/fedimint-usdt-common/src/endpoint_constants.rs` (two constants)
- Create: request/response types in `modules/fedimint-usdt-common/src/lib.rs` (or a small `api_types` module)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`api_endpoints`)
- Test: inline server test hitting the endpoint logic via the module directly, plus assertion the endpoint enqueues a `PendingCheck`.

**Interfaces:**
- Produces:
  - `CHECK_DEPOSIT_ENDPOINT = "check_deposit"`, `DEPOSIT_STATUS_ENDPOINT = "deposit_status"`.
  - `pub struct CheckDepositRequest { pub claim_pk: secp256k1::PublicKey }` → `pub struct CheckDepositResponse { pub account: EvmAddress, pub enqueued: bool }`.
  - `pub struct DepositStatusRequest { pub claim_pk: secp256k1::PublicKey }` → `pub struct DepositStatusResponse { pub account: EvmAddress, pub credited: UsdtAmount, pub claimed: UsdtAmount, pub claimable: UsdtAmount }`.
  - Both request/response `Serialize/Deserialize/Encodable/Decodable`.

- [ ] **Step 1: Write failing endpoint tests.** Test the underlying handlers via helper methods `async fn handle_check_deposit(&self, dbtx, claim_pk) -> CheckDepositResponse` and `handle_deposit_status`: `check_deposit` derives the account (`derive_deposit_account(&self.get_client_config_for_test(), &claim_pk)` — or store `usdt_contract`/`group_public_key` on the module and derive directly), inserts a `PendingCheck { claim_pk, requested_at_block: consensus_block_count }`, and is idempotent (second call `enqueued: false`); `deposit_status` returns `claimable = credited − claimed`.

- [ ] **Step 2: Run to verify failure.** FAIL.

- [ ] **Step 3: Add the endpoint constants + request/response types.** Add to `endpoint_constants.rs` and `-common`.

- [ ] **Step 4: Implement the handlers + wire `api_endpoint!`.** In `api_endpoints`, add two blocks mirroring `modules/fedimint-lnv2-server/src/lib.rs:673-687`:

```rust
api_endpoint! {
    CHECK_DEPOSIT_ENDPOINT,
    ApiVersion::new(0, 0),
    async |module: &Usdt, context, req: CheckDepositRequest| -> CheckDepositResponse {
        let mut dbtx = context.dbtx();
        Ok(module.handle_check_deposit(&mut dbtx.to_ref_nc(), req.claim_pk).await)
    }
},
api_endpoint! {
    DEPOSIT_STATUS_ENDPOINT,
    ApiVersion::new(0, 0),
    async |module: &Usdt, context, req: DepositStatusRequest| -> DepositStatusResponse {
        let mut dbtx = context.dbtx();
        Ok(module.handle_deposit_status(&mut dbtx.to_ref_nc(), req.claim_pk).await)
    }
},
```

(Confirm the `context.dbtx()` accessor name against the lnv2 example — it may be `context.db().begin_transaction().await`; match whatever that file uses for a writing endpoint, since `check_deposit` writes.)

`handle_check_deposit` derives the account (the module needs `group_public_key` — it already has `cfg.consensus.group_public_key`), reads `consensus_block_count` for `requested_at_block`, and inserts the `PendingCheck` only if absent (returns `enqueued`).

- [ ] **Step 5: Test pass, format, clippy, commit.**
```bash
git add modules/fedimint-usdt-common modules/fedimint-usdt-server
git commit -m "feat(usdt): check_deposit and deposit_status API endpoints"
```

---

## Task 10: Client — deposit address, deposit operation, claim, client API

**Files:**
- Modify: `modules/fedimint-usdt-client/src/api.rs` (client methods for the two endpoints)
- Modify: `modules/fedimint-usdt-client/src/db.rs` (a `ClaimKeyKey(EvmAddress) → KeyPair`-style record, or store the claim keypair keyed by operation)
- Modify: `modules/fedimint-usdt-client/src/lib.rs` (`deposit_address`, `await_deposit`/`claim` operation, `get_balance`)
- Modify: `modules/fedimint-usdt-client/src/states.rs` (minimal claim state machine, or reuse the mint output SM via the primary module)
- Test: inline client unit tests for address derivation parity.

**Interfaces:**
- Consumes: `derive_deposit_account(cfg, claim_pk)` (Task 2); `CHECK_DEPOSIT_ENDPOINT`/`DEPOSIT_STATUS_ENDPOINT` + types (Task 9); `UsdtInput::V0`; `USDT_UNIT`.
- Produces (public `UsdtClientModule` methods):
  - `pub fn deposit_address(&self, claim_keypair: &Keypair) -> EvmAddress` (client-side derivation; PROVISIONAL comment).
  - `pub async fn allocate_deposit(&self) -> anyhow::Result<(OperationId, EvmAddress)>`: generates + stores a claim keypair, returns its address.
  - `pub async fn check_and_claim(&self, operation_id, claim_keypair) -> anyhow::Result<()>`: calls `check_deposit` on the federation, polls `deposit_status` until `claimable > 0`, then submits a fedimint tx with one `ClientInput { input: UsdtInput::V0 { account, amount: claimable }, keys: vec![claim_keypair], amounts: Amounts::new_custom(USDT_UNIT, Amount::from_msats(claimable.0)) }` via `finalize_and_submit_transaction` (the USDT-mintv2 primary module absorbs the funding into e-cash).

- [ ] **Step 1: Write a failing client/server derivation-parity test.** In `modules/fedimint-usdt-tests/tests/tests.rs` (or a client unit test) assert the client's `deposit_address(claim_pk)` equals the server-side `fedimint_usdt_common::derive_deposit_account(&client_cfg, &claim_pk)` for the same config — i.e. both call the same `-common` function; this test guards against divergence if either side is refactored.

- [ ] **Step 2: Implement client API methods.** In `api.rs` add `check_deposit(&self, claim_pk) -> FederationResult<CheckDepositResponse>` and `deposit_status(&self, claim_pk) -> FederationResult<DepositStatusResponse>` mirroring the existing `group_public_key` method (`request_current_consensus` with `ApiRequestErased::new(req)`).

- [ ] **Step 3: Implement `deposit_address` + `allocate_deposit`.** Generate a `Keypair` (`Keypair::new(secp256k1::SECP256K1, &mut rng)` via the client's rng), store `(account → keypair)` in the client DB (`ClaimKeyKey`), return the derived `EvmAddress`. Note in a comment: deterministic-from-seed derivation for recovery is deferred to Phase 9.

- [ ] **Step 4: Implement `check_and_claim`.** Call `check_deposit`, poll `deposit_status` (with `fedimint_core::runtime::sleep` backoff + a caller-supplied deadline), then build and submit the claim transaction. Mirror `modules/fedimint-mintv2-client/src/lib.rs:907-957` for `finalize_and_submit_transaction` + `TransactionBuilder::new().with_inputs(...)`. The `ClientInputSM` can be `new_no_sm` if no client-side state tracking beyond the tx is needed for Phase 5 (the primary mint module drives note issuance); otherwise a minimal `UsdtStateMachine` variant tracking `AwaitingClaim`.

- [ ] **Step 5: Implement `get_balance`.** Keep returning `Amount::ZERO` for now *unless* the unit is `USDT_UNIT` — USDT balance lives in the USDT-mintv2 module, not here, so `get_balance` staying `ZERO` is correct (document it). Confirm the client's `primary_module_for_unit(USDT_UNIT)` routes to the USDT mint (proven by the Phase 4.5 dual-mint fixture).

- [ ] **Step 6: Test pass (parity test), format, clippy, WASM-check.** `cargo tree -p fedimint-usdt-client -i cggmp21` → not found; `cargo tree -p fedimint-usdt-client -i gmp-mpfr-sys` → not found. Run `just check-wasm` if quick. Commit.
```bash
git add modules/fedimint-usdt-client modules/fedimint-usdt-tests
git commit -m "feat(usdt): client deposit address, check, and claim"
```

---

## Task 11: Hermetic acceptance — full deposit→claim→mint over fedimint-testing (GATING)

**Files:**
- Modify: `modules/fedimint-usdt-tests/tests/tests.rs` (the acceptance test)
- Modify: `modules/fedimint-usdt-server/src/lib.rs` if a test-only shared-RPC injection is needed (a `UsdtInit` carrying an `Option<DynServerEvmRpc>` override, default `None` → builds `AlloyEvmRpc`)
- Modify: `modules/fedimint-usdt-tests/tests/fixtures/` helper for a shared `MockEvmRpc` across guardians

**Interfaces:**
- Consumes: `Fixtures::with_extra_module_instance` (Phase 4.5), a shared `Arc<MockEvmRpc>`, the USDT-mintv2 instance (`MintGenParams { amount_unit: USDT_UNIT }`), and the full server + client stack from Tasks 1–10.

- [ ] **Step 1: Add a test-only shared-RPC injection.** Give `UsdtInit` a `#[cfg(...)]`-free field `evm_rpc_override: Option<DynServerEvmRpc>` (default `None`) and a `pub fn with_evm_rpc(rpc: DynServerEvmRpc) -> Self`. In `init`, use the override when present, else build `AlloyEvmRpc` as today. All guardians in the test share ONE `Arc<MockEvmRpc>` so their reads agree (deposit consensus needs identical observations).

- [ ] **Step 2: Build the fixtures.** A federation with: the default Bitcoin `mintv2` (primary), a second USDT `mintv2` (`with_extra_module_instance(MintV2Kind, MintGenParams { amount_unit: USDT_UNIT })`), and the `usdt` module (`UsdtInit::with_evm_rpc(shared_mock.clone())`, `UsdtGenParams { usdt_contract, confirmation_depth: 1, chain_id: 31337, check_ttl_blocks: 10_000 }`). Enable the module in the fixture (the env-gate is bypassed when explicitly `.with_module`'d — confirm; else set `FM_ENABLE_MODULE_USDT` in the test).

- [ ] **Step 3: Write the acceptance test.**

```rust
#[tokio::test(flavor = "multi_thread")]
async fn deposit_becomes_claimable_usdt_ecash() -> anyhow::Result<()> {
    let shared_mock = Arc::new(MockEvmRpc::new());
    let usdt_contract = EvmAddress([0xUS; 20]); // the test token
    shared_mock.set_chain_id(31337);
    shared_mock.set_block_number(100);

    let fed = fixtures(shared_mock.clone(), usdt_contract).new_fed_not_degraded().await;
    let client = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    // 1. Derive the deposit address.
    let (op, account) = usdt.allocate_deposit().await?;

    // 2. Simulate the on-chain USDT transfer, confirmed as of block 90.
    shared_mock.set_erc20_balance_at(usdt_contract, account, 90, UsdtAmount(2_500_000));

    // 3. Client checks + claims; guardians' checker task observes and credits at threshold.
    usdt.check_and_claim(op, /* claim keypair */).await?;

    // 4. The USDT-denominated e-cash balance equals the deposit.
    let usdt_balance = client.get_balance_for_unit(USDT_UNIT).await;
    assert_eq!(usdt_balance, Amount::from_msats(2_500_000));

    // 5. Replay/double-claim is rejected.
    let replay = usdt.check_and_claim(op, /* same keypair */).await;
    assert!(replay.is_err() || client.get_balance_for_unit(USDT_UNIT).await == Amount::from_msats(2_500_000));
    Ok(())
}
```

Drive consensus forward as needed (fedimint-testing advances sessions; the block-count poller + deposit-checker run on their 1s test interval). If the test needs to *force* progress deterministically rather than wait on timers, expose test hooks to (a) set the cached block count and (b) run one `scan_pending_deposits` + inject the resulting items — prefer real timers if they settle within the test's default timeout.

- [ ] **Step 4: Run the acceptance test.** `cargo test -p fedimint-usdt-tests deposit_becomes_claimable_usdt_ecash -- --nocapture`. Iterate until green. This is the **gating Phase 5 acceptance**.

- [ ] **Step 5: Format, clippy, commit.**
```bash
git add modules/fedimint-usdt-server modules/fedimint-usdt-tests
git commit -m "test(usdt): hermetic deposit→claim→USDT-ecash acceptance"
```

---

## Task 12: Gated devimint/anvil real-chain e2e + env wiring + CLI

**Files:**
- Modify: `devimint/src/vars.rs` (add `FM_USDT_EVM_RPC_URL` to the `Fedimintd` block)
- Create: `devimint/src/tests.rs` (or the appropriate test module) `#[ignore]` e2e OR a `devimint` cmd behind an opt-in flag
- Modify: `modules/fedimint-usdt-client/src/lib.rs` or `fedimint-cli` (minimal `usdt` subcommands: `deposit-address`, `check-deposit`, `deposit-status`, `claim`)
- Modify: `justfile`/CI notes documenting the opt-in lane

**Interfaces:**
- Consumes: the anvil daemon (`devimint/src/external.rs` `Anvil::rpc_url`, `FM_PORT_ANVIL`), the Phase-4 `deploy_test_erc20` helper, the full module stack.

- [ ] **Step 1: Plumb the per-guardian RPC url.** In `devimint/src/vars.rs` `Fedimintd` block (`:291-316`) add:
```rust
FM_USDT_EVM_RPC_URL: String = f!("http://127.0.0.1:{}", globals.FM_PORT_ANVIL); env: "FM_USDT_EVM_RPC_URL";
```
This reaches every guardian via the existing `env.vars()` pass at `devimint/src/federation.rs:1292-1312`. No other wiring needed.

- [ ] **Step 2: Write the `#[ignore]` e2e.** A devimint test that: starts a devfed with the usdt module enabled (`FM_ENABLE_MODULE_USDT=1`) and the USDT-mintv2 instance; deploys the test ERC-20 on anvil (`deploy_test_erc20`) and sets the usdt config `usdt_contract` to it; derives a deposit address via the client CLI; `cast send` (via `.superpowers/sdd/tools/cast`) an ERC-20 `transfer` to it; mines past `confirmation_depth`; runs `check-deposit` + `claim`; asserts the client's USDT e-cash balance equals the transfer; asserts a second claim fails. Mark `#[ignore = "slow: real cggmp21 DKG at startup; opt-in lane (see Phase 9 pregenerated-primes work)"]`.

- [ ] **Step 3: Minimal `fedimint-cli` `usdt` subcommands.** Add `deposit-address`, `check-deposit <claim-pk?>`, `deposit-status`, `claim` mapping to the Task 10 client methods (dev ergonomics; keep thin). If `fedimint-cli` wiring is heavy, gate this to what the e2e needs.

- [ ] **Step 4: Verify it can run (best-effort in this env).** In THIS session anvil is the patched binary at `.superpowers/sdd/tools/anvil` and nix-nested-sandbox blocks a full devimint run; document that the e2e is CI-only (real nix anvil) and, if feasible, run just the env-var plumbing + a `--help`/config-gen smoke. Do NOT block the task on a full local devimint run if the sandbox prevents it — the hermetic Task 11 test is the gating acceptance.

- [ ] **Step 5: Format, clippy, commit.**
```bash
git add devimint modules/fedimint-usdt-client fedimint-cli justfile
git commit -m "test(usdt): gated devimint/anvil deposit e2e and CLI ergonomics"
```

---

## Self-Review Checklist (run before dispatching Task 1)

- **Spec coverage** (master-plan Phase 5 §): derive address (T1/T2/T10 ✓), `check_deposit` enqueues `PendingCheck` (T9 ✓), background checker reads balance at `head−depth` (T7 ✓), threshold-identical crediting with delta (T6 ✓), `deposit_status` poll (T9/T10 ✓), `UsdtInput::V0` claim with `InputMeta.pub_key = claim_pk` (T8 ✓), double-claim guard (T6/T8 ✓), block-count votes/median like wallet (T5 ✓), unit tests: multi-deposit / partial claim / sub-threshold disagreement / expiry (T6/T7/T8 ✓), hermetic acceptance (T11 ✓), devimint/anvil e2e (T12, gated per user decision ✓).
- **Deviations from master-plan pins, all intentional & recorded:** deposit address is provisional additive-tweak EOA, NOT CREATE2/SimpleAccount (this-session decision; custody in P7); Phase 5 acceptance is hermetic-primary + `#[ignore]` devimint e2e (user decision, not the pinned devimint-only ★); `UsdtClientConfig` carries only the Phase-5 subset of the pinned fields (entry_point/account_factory/deposit_check_fee deferred to their phases).
- **No Phase 6/8 wire types pre-defined** (consensus version 0,0, nothing deployed — churn is free).
- **Type consistency:** `DepositObservation`/`DepositRecord`/`PendingCheck` field names are identical across T1/T3/T6/T7/T8; `derive_deposit_account` has the raw (T1) and `cfg`-wrapper (T2) forms, both used consistently; `Amounts`/`InputMeta`/`TransactionItemAmounts` shapes match `fedimint-core`.
- **WASM safety** re-checked in T1, T2, T10 (`-common`/`-client` free of `cggmp21`/`gmp`/alloy-provider).
