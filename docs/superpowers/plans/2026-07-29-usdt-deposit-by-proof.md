# USDT deposit-by-proof — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Replace federation `balanceOf` polling with client-supplied
`eth_getProof` state proofs, verified deterministically in consensus against an
agreed block-hash ring. Zero per-deposit federation RPC; clients use free no-key
public endpoints; closes sec-15's deposit facet; and removes the `PendingCheck`
machinery entirely (which fixes the sec-13 WriteConflict guardian-crash race).

**Architecture:** Client fetches `eth_getProof` for its deposit account's USDT
balance slot + the block header, submits them as a transaction **input**; the
module's `process_input` verifies `keccak(header)==agreed_ring_hash`, decodes
`state_root`, verifies the account + storage MPT proofs (alloy-trie), and credits
the high-water delta. A guardian-local task only *reads* the chain tip and
proposes the confirmation-depth block hash; the ring and all credits are written
**only** in the ordered consensus path.

**Tech Stack:** `alloy-trie` (MPT proof verify), `alloy-consensus` (block Header
decode → state_root, header hashing), `alloy-rlp`. All already in Cargo.lock.

## Global Constraints

- **Determinism:** `process_input`, proof verification, and every consensus-DB
  write read ONLY the ordered input + prior consensus DB + `cfg.consensus`. NO
  RPC, wall-clock, `our_peer_id`, `is_running_in_test_env`, or float in the
  apply/verify path.
- **Commit safety (the sec-13 lesson):** NO guardian-local task writes consensus
  state. The block-hash observer task is READ-ONLY (proposes an item). The ring
  and credits are written only in the ordered `process` path. Any task that must
  commit uses non-panicking `commit_tx_result` with retry — never `commit_tx()` /
  `.expect()` on a committable path that can conflict.
- **USDT balances slot = 2.** Storage key `= keccak256(pad32(account) ‖ pad32(2))`.
- **Proof size cap:** `MAX_DEPOSIT_PROOF_BYTES = 16_384`. Reject larger.
- **No `unwrap()`** in non-test; `expect()` with a justification; saturating arithmetic.
- **Consensus version:** bump `MODULE_CONSENSUS_VERSION`; add a DB migration + snapshot test.
- **Client is WASM-safe:** fetch proofs via the client's own HTTP (reqwest/ehttp
  as the crate already does), NOT the server RPC layer.
- **`just clippy` / `just format`** clean; commit each task through the pre-commit hook.

---

### Task 1: Common — DepositProof type, slot-key derivation, constants

**Files:**
- Modify: `modules/fedimint-usdt-common/src/lib.rs`
- Test: same file's `mod tests`

**Interfaces (Produces):**
- `pub const USDT_BALANCES_SLOT: u64 = 2;`
- `pub const MAX_DEPOSIT_PROOF_BYTES: usize = 16_384;`
- `pub const BLOCK_HASH_RING_LEN: u64 = 300;`
- `pub fn balances_storage_key(account: &EvmAddress) -> [u8; 32]` — `keccak256(pad32(account.0) ‖ pad32(USDT_BALANCES_SLOT))`.
- `pub struct DepositProof { pub block_number: u64, pub header_rlp: Vec<u8>, pub account_proof: Vec<Vec<u8>>, pub storage_proof: Vec<Vec<u8>> }` — derives `Encodable, Decodable, Clone, Debug, PartialEq, Eq`.
- `impl DepositProof { pub fn encoded_len_bytes(&self) -> usize }` — sum of header + all node lengths (for the size cap).

- [ ] **Step 1: failing test** — `balances_storage_key` for the empirically-verified account equals the known key.

```rust
#[test]
fn balances_storage_key_matches_mainnet() {
    // holder 0xF977…aceC, USDT slot 2 -> key verified against eth_getStorageAt
    let acct = EvmAddress(hex_lit::hex!("F977814e90dA44bFA03b6295A0616a897441aceC"));
    let key = balances_storage_key(&acct);
    assert_eq!(
        hex::encode(key),
        "0be16d71963429204d70543701f859c43526c316ac005c10114f4694ca405f36"
    );
}
```

- [ ] **Step 2: run, fail.** `cargo test -p fedimint-usdt-common balances_storage_key_matches_mainnet` → FAIL (fn missing).
- [ ] **Step 3: implement** the constants, `balances_storage_key` (keccak256 via `bitcoin_hashes`/`sha3` already used, or `alloy_primitives::keccak256`), and `DepositProof`. Use `alloy_primitives::keccak256` (add `alloy-primitives` to common if not present; it is transitively — make it a direct dep).
- [ ] **Step 4: run, pass.**
- [ ] **Step 5:** `DepositProof` Encodable/Decodable round-trip test.
- [ ] **Step 6: commit** `feat(usdt): DepositProof type + USDT balances-slot key derivation`.

---

### Task 2: Server — MPT proof verification module (`proof.rs`)

**Files:**
- Create: `modules/fedimint-usdt-server/src/proof.rs`
- Modify: `modules/fedimint-usdt-server/src/lib.rs` (`mod proof;`), `modules/fedimint-usdt-server/Cargo.toml` (add `alloy-trie`, `alloy-consensus`, `alloy-rlp`, `alloy-primitives` as direct deps — versions matching Cargo.lock)
- Test: `proof.rs` `mod tests` with captured real-mainnet fixtures in `modules/fedimint-usdt-tests/tests/fixtures/proofs/` (funded + empty account)

**Interfaces (Produces):**
```rust
/// Deterministic. Verifies `proof` proves `account`'s USDT balance at the block
/// whose header hashes to `expected_block_hash`; returns the proven balance
/// (proof-of-absence anywhere -> 0). No RPC, no wall-clock.
pub fn verify_deposit_proof(
    proof: &DepositProof,
    expected_block_hash: [u8; 32],
    usdt_contract: &EvmAddress,
    account: &EvmAddress,
) -> anyhow::Result<UsdtAmount>;
```

Verification steps (implement exactly):
1. `ensure!(proof.encoded_len_bytes() <= MAX_DEPOSIT_PROOF_BYTES)`.
2. `ensure!(keccak256(&proof.header_rlp)[..] == expected_block_hash)` — anchor.
3. Decode header: `alloy_consensus::Header::decode(&mut proof.header_rlp.as_slice())`; take `state_root`. (Uses the current mainnet header schema; extra fields are fine because the RLP must round-trip to match the hash.)
4. Account proof: `alloy_trie::proof::verify_proof(state_root, Nibbles::unpack(keccak256(usdt_contract.0)), account_rlp_opt, &proof.account_proof)`. On success extract `storage_root` from the account RLP (`[nonce, balance, storageRoot, codeHash]`); on proven absence, return `UsdtAmount(0)`.
5. Storage proof: `verify_proof(storage_root, Nibbles::unpack(keccak256(balances_storage_key(account))), value_opt, &proof.storage_proof)`; decode the RLP value word → `UsdtAmount`; absence → 0.

- [ ] **Step 1: capture fixtures** — a script/committed JSON: `eth_getProof` for a funded account and an empty (never-used) account at a known block, plus that block's header RLP + hash. Store under `tests/fixtures/proofs/`.
- [ ] **Step 2: failing test** — `verify_deposit_proof` on the funded fixture returns the fixture's known balance.
- [ ] **Step 3: run, fail.**
- [ ] **Step 4: implement** `proof.rs`.
- [ ] **Step 5: run, pass** + add negatives: header-hash mismatch → Err; wrong `expected_block_hash` → Err; empty-account fixture → 0; a storage proof for the wrong slot → 0/Err; oversize proof → Err.
- [ ] **Step 6: `just clippy` / `just format`; commit** `feat(usdt): deterministic eth_getProof MPT verification (alloy-trie)`.

---

### Task 3: Server DB — block-hash ring record + helpers

**Files:**
- Modify: `modules/fedimint-usdt-server/src/db.rs`, `modules/fedimint-usdt-server/src/lib.rs`
- Test: `db.rs`/`lib.rs` tests

**Interfaces (Produces):**
- `BlockHashRingKey(pub u64 /*height*/)` → `[u8;32]`; `BlockHashRingPrefix`; `impl_db_record!` / `impl_db_lookup!` with a new `DbKeyPrefix::BlockHashRing` variant.
- `async fn write_block_hash_ring(dbtx, height: u64, hash: [u8;32])` — inserts and prunes entries with `height + BLOCK_HASH_RING_LEN <= newest`.
- `async fn ring_hash_at(dbtx, height: u64) -> Option<[u8;32]>`.
- `async fn ring_latest_height(dbtx) -> Option<u64>`.

- [ ] Steps: failing test (write two heights, read back, prune drops the oldest beyond the window) → implement → pass → **commit** `feat(usdt): block-hash ring DB record + helpers`.

---

### Task 4: Server — populate the ring from agreed block-hash observations (consensus path only)

**Files:**
- Modify: `modules/fedimint-usdt-server/src/lib.rs`
- Test: `lib.rs` tests

**Interfaces (Consumes):** Task 3 ring helpers; the existing sec-12 block-hash observation/agreement machinery.
**Produces:** on agreement of a confirmation-depth `(height, hash)` observation in the ordered `process` path, `write_block_hash_ring(dbtx, height, hash)` is called. The guardian-local observer task remains READ-ONLY (it only reads the tip hash and proposes it) — **no local write to consensus state** (Global Constraint: commit safety).

- [ ] **Step 1: failing test** — feeding an agreed block-hash observation through the process path results in `ring_hash_at(height) == hash`, and old heights prune.
- [ ] **Step 2-4:** run/implement/pass. Ensure the observer task path does not write the ring.
- [ ] **Step 5: commit** `feat(usdt): persist agreed confirmation-depth block hashes into the ring`.

---

### Task 5: Common+Server — proof as a transaction input (verify + credit)

**Files:**
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (add `UsdtInput::DepositProofV0(DepositProof)`), `modules/fedimint-usdt-server/src/lib.rs` (`process_input`)
- Test: `lib.rs` tests (mock ring + fixture proof)

**Interfaces (Produces):**
- New input variant `UsdtInput::DepositProofV0(DepositProof)`.
- `process_input` for it: 
  1. `expected = ring_hash_at(dbtx, proof.block_number)` — `Err` (reject) if `None` (not anchored / too old / not yet confirmed).
  2. `proven = verify_deposit_proof(proof, expected, usdt_contract, &account)` where `account = derive_deposit_account(...)` from the input's claim binding (the proof input carries the `claim_pk`/account binding; see below).
  3. `credited = get DepositRecord(account).credited` (0 if none); `delta = proven.saturating_sub(credited)`; `ensure!(delta > 0)` (reject stale/duplicate).
  4. set `DepositRecord(account).credited = proven` (monotonic high-water); trigger the existing sweep bookkeeping exactly as `credit_deposit` does today.
  5. return `InputMeta { amount: delta_as_msat, .. }` so the client pairs it with a mint output (deposit + claim atomic).

Binding: the input must bind the `account` to the client's claim key so the minted e-cash is spendable only by the depositor — carry `claim_pk` in the input (or derive `account` from it) exactly as the current claim path binds. Reuse the existing claim-key/account derivation; do not invent a new one.

- [ ] **Step 1: failing test** — `process_input(DepositProofV0)` with a fixture proof + a ring seeded with the fixture block hash credits `delta` and sets `credited = proven`.
- [ ] **Step 2-4:** run/implement/pass.
- [ ] **Step 5: negatives** — proof for a block not in the ring → Err; second submit once `credited == proven` → Err (`delta == 0`); tampered proof → Err.
- [ ] **Step 6: `just clippy`/`just format`; commit** `feat(usdt): credit deposits from verified proof inputs (high-water mark)`.

---

### Task 6: Server — remove all PendingCheck machinery (fixes sec-13 WriteConflict)

**Files:**
- Modify: `modules/fedimint-usdt-server/src/lib.rs`, `modules/fedimint-usdt-server/src/db.rs`, `modules/fedimint-usdt-common/src/lib.rs`, `endpoint_constants.rs`

**Delete:** `handle_check_deposit`, `CHECK_DEPOSIT_ENDPOINT`, `CheckDepositRequest/Response`, `scan_pending_deposits`, `spawn_deposit_checker`, `gc_expired_pending_checks`, `PendingCheck`/`PendingCheckKey`/`PendingCheckPrefix`, `MAX_PENDING_CHECKS`, and the consensus `remove_entry(&PendingCheckKey(..))` at lib.rs:3536 (there is no PendingCheck to remove now — crediting is proof-driven). Remove the deposit-checker task spawn in `init`.

**Interfaces (Consumes):** nothing new — this is deletion. Depends on Task 5 (crediting no longer needs PendingCheck).

- [ ] **Step 1:** delete the above; fix all references.
- [ ] **Step 2:** `cargo check -p fedimint-usdt-server -p fedimint-usdt-common` → builds with zero `PendingCheck` references (`grep -r PendingCheck src/` empty).
- [ ] **Step 3:** confirm no guardian-local task remains that commits consensus state (grep for `commit_tx()` in spawned tasks; none should touch consensus DB).
- [ ] **Step 4: commit** `fix(usdt): remove PendingCheck polling/GC (proof-driven credit; fixes sec-13 WriteConflict race)`.

---

### Task 7: Server API — `latest_anchored_block` endpoint

**Files:** `modules/fedimint-usdt-common/src/endpoint_constants.rs` (`LATEST_ANCHORED_BLOCK_ENDPOINT = "latest_anchored_block"`), common response type `AnchoredBlockResponse { latest: u64, window: u64 }`, server `api_endpoint!`.

- [ ] Failing test → implement (returns `ring_latest_height` + `BLOCK_HASH_RING_LEN`) → pass → **commit** `feat(usdt): latest_anchored_block endpoint for proof targeting`.

---

### Task 8: Consensus version bump + DB migration

**Files:** `modules/fedimint-usdt-common/src/lib.rs` (`MODULE_CONSENSUS_VERSION`), `modules/fedimint-usdt-server/src/lib.rs` (migration), snapshot fixtures under `db/migrations/`.

**Migration v(N)→v(N+1):** delete any residual `PendingCheck` rows; the `BlockHashRing` keyspace starts empty. No re-credit needed (existing `DepositRecord`s keep their high-water marks).

- [ ] Failing snapshot **reader** test → write migration → pass. Do NOT run the snapshot **writer** test in a way that dirties committed fixtures. **Commit** `feat(usdt): bump consensus version + migrate out PendingCheck`.

---

### Task 9: Client — proof fetch + submit + claim; remove check-deposit

**Files:** `modules/fedimint-usdt-client/src/lib.rs`, `db.rs`, `cli.rs`

**Interfaces (Produces):**
- `async fn submit_deposit_proof(&self, index)` — derive account+claim key → GET `latest_anchored_block` → pick a block `B` in-window and ≥ `confirmation_depth` deep → client HTTP `eth_getProof(usdt_contract, [balances_storage_key(account)], B)` + `eth_getBlockByNumber(B)` (RLP header) → build `DepositProof` → submit a tx `{ input: DepositProofV0, output: mint }` → return op id.
- Configurable `evm_rpc_url` (client DB / arg), default a free no-key endpoint (`https://ethereum-rpc.publicnode.com`); may race a small fixed list.
- Remove the `check_deposit` client method.
- WASM-safe: use the crate's existing HTTP client, not the server RPC layer. Encoding of the block header to RLP: request `eth_getBlockByNumber` and RLP-encode via `alloy-consensus` `Header` (client-side, wasm-safe), OR fetch the raw header — pick whichever keeps wasm clean (prefer reconstructing the `Header` from the JSON and re-encoding, asserting `keccak==blockHash` client-side before submit so a bad header fails fast locally).

- [ ] Failing test (build a `DepositProof` from a captured proof; assert it verifies with the server verifier) → implement → pass. Integration: submitted input credits + mints. **Commit** `feat(usdt): client deposit-by-proof (eth_getProof, no-key RPC)`.

---

### Task 10: CLI — `submit-deposit-proof`; remove `check-deposit`

**Files:** `fedimint-cli` usdt subcommands (or the client `cli.rs`).

- [ ] Replace `check-deposit` with `submit-deposit-proof --index <n> [--rpc-url <url>]`; `deposit-address`/`claim`/`deposit-status` unchanged. Build test / help snapshot. **Commit** `feat(usdt): CLI submit-deposit-proof`.

---

### Task 11: Anvil e2e — full proof flow, no guardian poll

**Files:** `modules/fedimint-usdt-tests/` (extend `usdt_e2e` or a new proof e2e).

- [ ] Deploy stack on anvil → allocate deposit address → send USDT → mine past confirmation_depth → client `eth_getProof` **against anvil** → submit proof input → assert credit → claim e-cash → assert sweep — with **no `balanceOf` poll by guardians** in the loop (the scanner is gone). Run via the existing e2e harness. **Commit** `test(usdt): anvil e2e for deposit-by-proof`.

---

## Self-Review

- **Spec coverage:** ring anchor (T3,T4), client proof (T9), deterministic verify (T2,T5), USDT slot 2 (T1), replace polling (T6), free no-key client (T9), sec-15 closure (T2/T5 verify-not-trust), DoS cap (T1/T2/T5), migration (T8), e2e (T11). WriteConflict fix = T6 (removal) + Global commit-safety constraint. Covered.
- **Type consistency:** `DepositProof` (T1) consumed by `verify_deposit_proof` (T2), `UsdtInput::DepositProofV0` (T5), client builder (T9). `balances_storage_key` (T1) used in T2/T9. Ring helpers (T3) used in T4/T5/T7. Consistent.
- **Ambiguity resolved:** proof enters as a **tx input** (size < 10 KB, composes with claim) per the size check. Header handling: client reconstructs+RLP-encodes the `Header` and self-checks `keccak==blockHash` before submit.
- **Open risk flagged in T2/T9:** current-mainnet header schema — fixtures must be current-mainnet; anvil headers differ in fields but the same round-trip-hash rule holds (T11 covers anvil).

## Execution

REQUIRED SUB-SKILL: superpowers:subagent-driven-development — fresh implementer per task + task review, then a whole-branch review. Tasks 2 and 5 (crypto + consensus credit) are the highest-risk; review them hardest.
