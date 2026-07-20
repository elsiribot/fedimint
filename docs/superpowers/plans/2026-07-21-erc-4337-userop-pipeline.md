# Phase 7 — ERC-4337 UserOp pipeline (JIT plan)

Base: `838ebb3a617` (Phase 6b head). Master plan §Phase 7 (line 319) + interface C (line 167) + DB schema D (0x08–0x0B, line 201).

## Goal
From "the federation can MPC-sign a 32-byte digest" (Phase 6) to **on-chain effect**: build EntryPoint-v0.7 packed UserOps, sign their `userOpHash` via the Phase-6 signing loop, submit via interface C, track receipts — proven by a counterfactual USDT-only deposit account being **deployed and swept to the pool with gas paid in USDT by the token paymaster and net-zero federation ETH**.

## Central design reconciliation (maintainer sign-off item)
Phase 5 derived deposit addresses as a **provisional additive-tweak EOA** (detection-only; ledger line 101/128 explicitly: "signing custody reconciled in P7"). This phase switches derivation to the master-plan-pinned (D3) model:

> deposit address = `CREATE2(SimpleAccountFactory, salt, keccak256(initCode))`, `salt = keccak256("fedimint-usdt-deposit-v0" ‖ claim_pk_compressed)`, `initCode` = the factory's `ERC1967Proxy(SimpleAccountImpl, initialize(owner))` with **`owner` = the group-key EOA** (`evm_address(group_public_key)`).

Rationale (why this, not the EOA): one DKG group key owns *every* deposit account (differentiated only by `salt`), so a single MPC key signs all sweeps; the account is an ERC-4337 smart account, so the **token paymaster pays gas in USDT** and a deposit address never needs ETH — the entire point of a USDT wallet. An EOA sweep would require ETH in every deposit address. Module is `version(0,0)`, env-gated off, undeployed ⇒ derivation/wire churn is free. **Phase-5 deposit *detection* is unchanged** (ERC-20 balance credits a counterfactual address with no code); only the derived address value changes, and both client + server call the one `-common` function so they stay bit-identical.

## Environment / execution notes
- Autonomous run. Subagents CANNOT use git (main repo outside sandbox; git only works unsandboxed) → subagents **implement + test + report only**; controller commits each task unsandboxed `--no-verify` after in-sandbox clippy/cargo-sort/wasm-lint. CI re-validates the hook.
- anvil/forge/cast at `.superpowers/sdd/tools/` (Phase 4); set `FM_ANVIL_BASE_EXECUTABLE` to it. Network egress works in-sandbox (verified: unpkg HTTP 200) for artifact vendoring.
- Artifacts: `https://unpkg.com/@account-abstraction/contracts@0.7.0/artifacts/{EntryPoint,SimpleAccount,SimpleAccountFactory,LegacyTokenPaymaster}.json`. TetherToken: mainnet runtime bytecode via `eth_getCode` against a public RPC OR the committed Phase-4 approach; committed as hex fixture, `anvil_setCode` at `0xdAC17F958D2ee523a2206206994597C13D831ec7` + `anvil_setStorageAt` for balances/owner.
- v0.7 canonical addrs: EntryPoint `0x0000000071727De22E5E9d8BAf0edAc6f37da032`; SimpleAccountFactory `0x91E60e0613810449d098b0b5Ec8b51A0FE8c8985` (deploy fresh on anvil, don't assume the mainnet addr).
- **WASM boundary:** `-common` gets `alloy-sol-types` + `alloy-primitives` ONLY (both wasm-verified in Phase 4). No `alloy` provider into `-common`/`-client`. cargo-tree-check after every `-common` change.

## Determinism rules (unchanged from P5/P6, apply to every new consensus arm)
Only pure functions of `(ordered item, prior consensus-DB, config)` may write consensus DB or decide `Ok`/`Err`. No `our_peer_id`, no wall-clock, no RPC result in a consensus write. Every arm `Err`s when it changes no consensus state (unbounded-history rule). New consensus writes this phase: `PendingUserOpKey`, `SubmittedUserOpKey`, `PoolStateKey`, and the deterministic session-from-PendingUserOp trigger. RPC submission/receipt polling is guardian-local background work that NEVER gates a consensus write (mirrors the Phase-5 read-only checker + Phase-6 in-memory signer discipline).

---

## Task 1 — Vendor v0.7 artifacts + full 4337 anvil deploy harness + config surface
**Deliver:**
- `modules/fedimint-usdt-common/contracts/`: `EntryPoint-v0.7.json`, `SimpleAccount-v0.7.json`, `SimpleAccountFactory-v0.7.json`, `LegacyTokenPaymaster-v0.7.json` (abi+creation+runtime bytecode, fetched from unpkg, committed verbatim), plus the existing `TetherToken` fixture confirmed usable (real mainnet runtime bytecode for `setCode`).
- Config surface: add `entry_point: EvmAddress`, `account_factory: EvmAddress`, `simple_account_impl: EvmAddress` (needed for off-chain CREATE2 in Task 2), `pool_account: EvmAddress` (or derive deterministically from a fixed pool salt — see Task 5) to `UsdtClientConfig` + `UsdtConfigConsensus`; add the corresponding `UsdtGenParams` fields. Thread IDENTICALLY through `trusted_dealer_gen` + `distributed_gen` → `UsdtConfigConsensus`, and copy into `get_client_config`. Behavior-preserving all-zero placeholder defaults (like `usdt_contract`), doc'd "real deployments must override".
- Extend the Phase-4 anvil harness (`modules/fedimint-usdt-tests/src/…` spawn helpers): `deploy_4337_stack(anvil) -> Deployed4337 { entry_point, factory, simple_account_impl, paymaster, usdt }` — EntryPoint via `anvil_setCode` at canonical addr; SimpleAccountFactory deployed from a funded EOA (its constructor deploys the SimpleAccount impl — capture that addr); LegacyTokenPaymaster deployed, then **staked + deposit-funded** on the EntryPoint and pointed at the USDT token with a fixed price; TetherToken via `setCode`+`setStorageAt`. Reuse Phase-4 `deploy_test_erc20`/`spawn_anvil`.

**Acceptance:** a `#[ignore]`-free hermetic test (skip-if-anvil-absent) brings up the full stack and asserts: EntryPoint has code at the canonical addr; `factory.getAddress(owner, salt)` eth_call returns a 20-byte addr; paymaster `getDeposit()` > 0 and is staked; USDT `decimals()==6`. No consensus/determinism surface touched.

**Risk retired:** artifact vendoring + a reproducible full-stack anvil fixture every later task builds on.

---

## Task 2 — Reconcile deposit derivation to CREATE2 SimpleAccount (self-verified vs `factory.getAddress`)
**Deliver (all in `-common`, wasm-safe):**
- Vendor the `ERC1967Proxy` creation-code constant the factory uses (extract from the SimpleAccountFactory artifact / OZ; commit as a `&[u8]` const with a comment citing the source).
- Rewrite `derive_deposit_account(cfg, claim_pk)` → `CREATE2` per D3: `salt = keccak256(DEPOSIT_ADDRESS_DOMAIN ‖ claim_pk.serialize())`; `initCodeHash = keccak256(ERC1967Proxy_creationCode ‖ abi.encode(simple_account_impl, abi.encodeCall(SimpleAccount.initialize, (owner))))`, `owner = evm_address(group_public_key)`; `address = keccak256(0xff ‖ factory ‖ salt ‖ initCodeHash)[12..]`. Pure function, NO RPC, both client+server call it. `alloy-sol-types` for the abi-encode, `alloy-primitives` keccak256/Address.
- Update the Phase-5 parity test + `derive_deposit_account_is_deterministic_and_claim_specific`.

**Acceptance:** self-verifying anvil test — for ≥3 distinct claim keys, off-chain `derive_deposit_account` == `SimpleAccountFactory.getAddress(owner, salt)` eth_call byte-for-byte; plus a deposit-detection regression (USDT `transfer` to the CREATE2 addr is seen by `get_erc20_balance`). Phase-5 hermetic deposit acceptance still green (addresses now CREATE2 but derived dynamically).

**Risk retired:** off-chain CREATE2 address correctness (the fiddly ERC1967Proxy init-code-hash), pinned against the on-chain factory.

---

## Task 3 — UserOp types + v0.7 packing + `userOpHash` (self-verified vs `EntryPoint.getUserOpHash`)
**Deliver (all in `-common`, wasm-safe, `alloy-sol-types`):**
- `PackedUserOperation` (the v0.7 on-chain struct: `sender, nonce, initCode, callData, accountGasLimits: FixedBytes<32>, preVerificationGas, gasFees: FixedBytes<32>, paymasterAndData, signature`), plus an ergonomic `UnsignedUserOp` (unpacked gas fields) with `pack()` → `PackedUserOperation` (`accountGasLimits = hi128(verificationGasLimit)|lo128(callGasLimit)`, `gasFees = hi128(maxPriorityFeePerGas)|lo128(maxFeePerGas)`), and `SignedUserOp` (`packed + signature: Vec<u8>`). All `Encodable`/`Decodable` + serde, wasm-safe.
- `user_op_hash(op, entry_point, chain_id) -> [u8;32]` = `keccak256(abi.encode(op.hash(), entry_point, chain_id))`, `op.hash() = keccak256(abi.encode(sender, nonce, keccak256(initCode), keccak256(callData), accountGasLimits, preVerificationGas, gasFees, keccak256(paymasterAndData)))`. (v0.7 formula — NOT v0.8 EIP-712.)

**Acceptance:** self-verifying anvil test — a representative deploy-and-sweep `PackedUserOperation`'s off-chain `user_op_hash` == `EntryPoint.getUserOpHash(packedOp)` eth_call byte-for-byte. Plus unit tests for the 128-bit packing round-trip.

**Risk retired:** the master plan's #1 Phase-7 risk ("v0.7 packing/hash subtleties — pin with on-chain eth_call test vectors early").

---

## Task 4 — UserOp builder + adapter UserOp methods + signature assembly
**Deliver:**
- Server `build_deploy_and_sweep_userop(cfg, deposit_account, claim_pk, amount, pool, nonce, gas_bounds) -> UnsignedUserOp`: `sender = deposit_account`; `initCode = account_factory ‖ createAccount(owner, salt)` (empty if already deployed — Task 5 decides via `get_code_len`); `callData = SimpleAccount.execute(usdt_contract, 0, USDT.transfer(pool, amount))`; `paymasterAndData = paymaster ‖ v0.7 gas fields ‖ token config`; conservative **static** gas bounds first (document; gas estimation via adapter is a later refinement). alloy `sol!` for `execute`/`transfer`/`createAccount` calldata.
- Extend `IServerEvmRpc` (interface C) with `submit_user_ops(Vec<SignedUserOp>)` + `get_user_op_receipt([u8;32]) -> Option<UserOpReceipt>` (+ `UserOpReceipt { success, block, actual_cost_usdt }`, `SignedUserOp`). `AlloyEvmRpc`: `submit_user_ops` = `EntryPoint.handleOps(ops, beneficiary=broadcaster_eoa)` sent from the broadcaster EOA (self-bundling, Impl A); `get_user_op_receipt` via `eth_getLogs`/EntryPoint `UserOperationEvent`. `MockEvmRpc`: scriptable submit/receipt.
- Signature assembly: from the MPC compact `(r,s)` (64 bytes, low-S), build the 65-byte `r‖s‖v` Ethereum sig by brute-forcing `v ∈ {27,28}` and picking the one that `ecrecover`s to the group-key-EOA `owner` (deterministic; secp256k1 `RecoverableSignature`). The signed digest is `toEthSignedMessageHash(userOpHash)` (EIP-191) — SimpleAccount v0.7 `_validateSignature` wraps that way; confirm against the vendored SimpleAccount source in Task 4.

**Acceptance:** builder unit tests (calldata selectors cross-checked vs abi) + an adapter test that **hand-signs** a deploy-and-sweep op with a local key (owner = that key's EOA, not MPC yet) and submits via `handleOps` on real anvil → deposit account deployed (`get_code_len>0`) + pool received USDT. This isolates the 4337 mechanics from MPC before Task 6 combines them.

---

## Task 5 — Consensus lifecycle: pending → signing → submitted → confirmed (replaces `debug_start_signing`)
**Deliver:**
- DB (server): `PendingUserOpKey([u8;32] op_hash)[0x08] -> PendingUserOp { op: UnsignedUserOp, purpose: UserOpPurpose, created_block: u64 }`; `SubmittedUserOpKey([u8;32])[0x09] -> SubmittedUserOp { signed: SignedUserOp, submitted_block: u64 }`; `PoolStateKey[0x0A] -> PoolState { account: EvmAddress, balance: UsdtAmount }`. `UserOpPurpose ∈ { DeployAndSweep { source: EvmAddress } }` (Withdraw variant deferred to Phase 8).
- **Deterministic trigger** (replaces `debug_start_signing`): when a deposit is credited in `process_consensus_item` (Phase-5 Deposit arm), enqueue a `DeployAndSweep` `PendingUserOp` for that account (deterministic: op built from consensus-DB state + config; `op_hash` = its `user_op_hash`). A `PendingUserOp` with no live `SigningSession` deterministically **creates** the session (`digest = toEthSignedMessageHash(user_op_hash)`, `SigningPurpose::UserOp(op_hash)`) — same consensus-ordered `start_session` path as Phase 6, no per-guardian trigger. Remove `debug_start_signing` + `DEBUG_START_SIGNING_ENDPOINT` (keep `debug_suppress_attempt0_round` — test-only, still needed for degraded tests). Add `SigningPurpose::UserOp([u8;32])`.
- On session `Completed(sig)` (Phase-6b consensus state): a guardian-local background task assembles `SignedUserOp` (Task 4), writes `SubmittedUserOp` **via consensus item** (so all guardians agree it's submitted — a `SubmitUserOp` consensus item carrying the assembled sig, verified deterministically), submits via adapter (guardian-local, idempotent, only the broadcaster or any guardian may send — dedup on-chain by nonce), polls `get_user_op_receipt`; on confirmation proposes a `UserOpConfirmed` consensus item updating `PoolState.balance += swept` and clearing `PendingUserOp`. Idempotent across restarts (re-derive pending from DB; re-submit on drop). **Determinism care:** the *decision* to submit/confirm goes through consensus items verified against DB+config; the RPC calls are guardian-local side effects.
- `withdrawal_status`-style read endpoint deferred to Phase 8; add a minimal `pool_state`/`userop_status` diagnostic endpoint.

**Acceptance:** hermetic (MockEvmRpc) test — credit a deposit → a `DeployAndSweep` PendingUserOp appears deterministically on all guardians → session signs → `SubmitUserOp`/`UserOpConfirmed` items drive `PoolState`; assert all guardians' DBs byte-identical (signer + non-signer), replay-safe. No anvil (that's Task 6).

**Determinism review:** OPUS. This task adds the most consensus surface; every new arm gets the full pure-function audit.

---

## Task 6 — Acceptance ★: anvil deploy-and-sweep e2e (Phase-7 gating)
**Deliver:** a hermetic (skip-if-anvil-absent) `fedimint-testing` integration test wiring the real `AlloyEvmRpc` (not mock) to a shared anvil with the full 4337 stack (Task 1 harness):
1. Fresh federation (real DKG group key) + full 4337 stack on anvil; broadcaster EOA funded with ETH; paymaster staked/funded.
2. Compute a counterfactual deposit account (Task 2 derivation) for a claim key; fund it with **USDT only** (no ETH) via TetherToken transfer.
3. `check_deposit` → deposit credited → `DeployAndSweep` PendingUserOp → **real MPC signing** of the userOpHash digest → `handleOps` submitted from broadcaster → receipt confirmed.
4. **Assert:** deposit account now has code (`get_code_len>0`); pool account USDT balance == deposit − paymaster fee; broadcaster EOA ETH net change ≈ 0 (fronted gas refunded by EntryPoint from paymaster stake); federation guardians spent 0 ETH.

**Acceptance = the Phase-7 gate.** Slow (real anvil + real MPC ~2–4 min); FOREGROUND. This is the test that (like the Phase-6a 63KB stall) can surface integration bugs unit tests structurally cannot.

---

## Whole-branch review (opus) after Task 6
Base `838ebb3a617` .. Phase-7 head. Focus: determinism of the new consensus arms (PendingUserOp trigger, SubmitUserOp/UserOpConfirmed, PoolState); custody-model reconciliation soundness (CREATE2 owner = group key, MPC signs userOpHash, recovery-id assembly); no double-submit / double-sweep; idempotent-across-restart; audit balance sheet updated for swept-to-pool (asset moves from "credited deposit" to "pool balance"); WASM boundary (-common alloy-sol-types only); no Phase-5/6 regression. Triage accumulated Minors.

## Deferred to Phase 8/9 (not this phase)
Withdrawals (`process_output`, `UnclaimedWithdrawal` 0x0B, Withdraw UserOpPurpose), fee logic (FeeVote median, `withdraw_fee_quote`), batching/consolidation policy, gas *estimation* (Task 4 uses static bounds), reorg drills / restart-mid-session hardening, `BundlerEvmRpc` (Impl B), chunk/session GC.

## Maintainer sign-off items (log to ledger, for elsirion on wake)
1. **Deposit-derivation reconciliation** EOA→CREATE2 SimpleAccount (this phase's central change; master-plan-pinned, but confirms the custody model).
2. Static gas bounds (Task 4) — gas estimation deferred; confirm the conservative constants are acceptable for devnet.
3. `LegacyTokenPaymaster` as the devnet token paymaster (fixed-price oracle, test-only) — the master plan's `TestTokenPaymaster`; confirm this is the intended sample.
