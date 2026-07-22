# USDT module: self-bootstrapping + a readiness state machine (design draft)

**Status:** DRAFT for review. Not implemented. Target: consensus version `(0, 1)`
(the `(0, 0)` on-chain wire/config is unreleased, so additive config/DB changes
are free).

## Problem

Standing up a USDT federation today has manual, error-prone operator steps
(`docs/usdt-test-federation.md`): deploy + off-chain-*verify* the ERC-4337
factory/impl, prefund each account's EntryPoint gas deposit, and *know* by
convention when the module can actually honor deposits. Two consequences:

1. **A footgun:** if the on-chain factory's `initCodeHash` doesn't match the
   vendored proxy code, every derived deposit address is unspendable, and the
   module can only warn on the all-zero placeholder — it can't catch a
   wrong-but-nonzero factory.
2. **No readiness signal:** the module hands out a deposit address immediately,
   even before it can sweep or withdraw, so a user can be told to deposit into a
   federation that cannot yet pay them back.

## Goals / non-goals

**Goals.** Reduce the operator's job to *"fund the broadcaster EOA(s) with
ETH."* From there the module (a) deploys + verifies its own factory/impl, (b)
self-prefunds account gas, and (c) exposes a consensus-agreed **readiness** state
so the client only advertises deposit addresses once the full
deposit→claim→sweep→withdraw lifecycle is operational.

**Non-goals.** Deploying the EntryPoint (canonical per-chain; we verify, never
deploy). ETH-net-zero / token paymaster (separate, larger). Changing the
solvency/consensus accounting. Removing the *irreducible* external input: ETH
must enter the broadcaster from outside — you can't bootstrap gas from nothing.

## Architecture principle (unchanged)

Every new consensus-DB write stays a pure function of (ordered item, prior
consensus DB, config). All on-chain interaction (deploy, prefund, observe) is a
**guardian-local side effect** that influences consensus *only* by proposing
observations re-aggregated by threshold — exactly the existing deposit-checker /
UserOp-submitter pattern. The bootstrap actions are actions; the readiness state
is derived from *observations* of their on-chain result.

---

## Part A — deterministic factory/impl (kill the footgun)

**Config-gen computes the factory + impl addresses deterministically** instead
of the operator supplying them:

- `account_factory = CREATE2(deployer = canonical CREATE2 factory
  0x4e59…4956C, salt = fixed module constant, initCode = vendored
  SimpleAccountFactory creation code ‖ abi.encode(entry_point))`. Since
  `entry_point` is the canonical v0.7 address (identical across chains) and the
  creation code + salt are vendored constants, this address is deterministic and
  identical everywhere.
- `simple_account_impl` = the address the factory's constructor deploys the
  `SimpleAccount` at = `CREATE(factory_address, nonce=1)` — deterministic once
  the factory address is (verify by prediction, or read `accountImplementation()`
  post-deploy).

So `UsdtGenParams` no longer *needs* operator-supplied factory/impl (the env
overrides stay as an escape hatch for a nonstandard/pre-deployed stack). The
existing counterfactual deposit-address derivation is unchanged; it just consumes
the computed addresses.

**Bootstrap deploy (guardian-local).** On start, each guardian's bootstrap task
checks `get_code_len(account_factory)`. If empty, the **designated deployer**
(deterministic: the lowest `peer_id` whose broadcaster is funded) submits the
CREATE2 factory deploy via its broadcaster; the deterministic address means a
race is harmless (a second deploy no-ops / reverts). No consensus item is
written by the deploy itself.

**Verification (closes the footgun).** Every guardian, before it votes the
factory "ready," reads the on-chain runtime code at `account_factory` and checks
`keccak256(code) == VENDORED_FACTORY_RUNTIME_HASH` (a vendored constant), and
likewise for `simple_account_impl`. A mismatch → the guardian never votes the
factory ready (and logs loudly). This turns "operator must off-chain-verify" into
an automatic on-chain check.

---

## Part B — auto-prefund account gas (submitter, guardian-local)

Fold the EntryPoint prefund into the existing `submit_user_ops` path (already
guardian-local, non-consensus):

- Before `handleOps`, compute the op's max gas cost from its own bounds:
  `need = (verificationGasLimit + callGasLimit + preVerificationGas) *
  maxFeePerGas`.
- Read the sender's current EntryPoint deposit (`EntryPoint.balanceOf(sender)` /
  `getDepositInfo`); if `< need`, `EntryPoint.depositTo(sender, need − have +
  margin)` from the broadcaster, then `handleOps`.
- Idempotent + cheap: only tops up the shortfall, so a single-use deposit account
  gets ~one op's worth (not a parked 1 ETH); over-deposit is refundable. Multiple
  guardians topping up the same account is wasteful-but-harmless (refundable); to
  minimize, only the actually-submitting guardian tops up.

This removes the manual `depositTo` entirely and the per-account-dust problem.
The broadcaster fronts both the top-up and the L1 gas from its ETH.

---

## Part C — the readiness state machine (consensus-agreed)

### States (module-level, derived from consensus DB)

- **`AwaitingInfra`** — running (post-DKG; the group key is already in config),
  but not all readiness conditions met.
- **`Ready`** — full lifecycle operational.
- **`Degraded`** — was `Ready`, a condition regressed (e.g. broadcaster ETH low).

(DKG is a config-gen phase; by the time the module's API is reachable it is past
DKG, so `KeyGen` is not a runtime state the module reports.)

### Readiness conditions

| Condition | Kind | Source |
|---|---|---|
| EntryPoint deployed at configured address | federation fact | `get_code_len(entry_point) > 0`, threshold-agreed |
| Factory deployed + code hash matches vendored | federation fact | Part A verification, threshold-agreed |
| Impl deployed + code hash matches vendored | federation fact | Part A verification, threshold-agreed |
| ≥ `threshold` guardians have a funded broadcaster | quorum of self-facts | each guardian's `broadcaster ETH ≥ min` |
| ≥ `threshold` guardians have a healthy RPC | quorum of self-facts | each guardian's last RPC read succeeded |

`Ready = (all federation facts true) ∧ (funded_count ≥ threshold) ∧
(healthy_count ≥ threshold)`.

### Mechanism (mirrors the deposit-observation pattern)

- New consensus item `BootstrapObservation { entry_point_ok, factory_ok,
  impl_ok, broadcaster_funded, rpc_healthy }`, proposed **periodically** by each
  guardian's bootstrap task (a `consensus_proposal` drain, like FeeVote).
- New consensus DB `BootstrapVoteKey(peer) -> BootstrapObservation` (latest per
  guardian; overwritten on each new vote). `process_consensus_item` writes
  `BootstrapVote(ordered_item.peer)` — deterministic (keyed by the *ordered
  item's* origin peer, never `our_peer_id`).
- `bootstrap_state(dbtx)` derives the state as a **pure function** of the
  `BootstrapVote` table + `threshold`: count votes per condition, apply the
  table above. Federation facts (EntryPoint/factory/impl) use threshold-agreement
  on the on-chain observation; self-facts (broadcaster/RPC) count reporting
  guardians. No single guardian's RPC value gates the state.

### Determinism argument

Every input is a threshold-aggregated vote in consensus DB; the derivation is a
pure count. Identical on every guardian, signer or not. The bootstrap *actions*
(deploy, prefund) are guardian-local side effects that never write consensus —
they change on-chain state that guardians then *observe* and vote on. This is the
same shape already proven for deposits/sweeps.

### Client-facing readiness + gating

- New API endpoint `module usdt status` → `{ state, conditions: {...},
  funded_guardians, ... }`, answered from the consensus-agreed `bootstrap_state`
  (threshold-agreed, any guardian answers identically).
- **Primary gate (client-side):** `deposit-address` refuses (or hard-warns)
  unless `state == Ready`, so a user is never told to deposit into a federation
  that can't honor it. `pool-state`/`withdrawal-status` stay queryable always.
- **Optional server-side gate:** `process_input` (claim) and/or the deposit
  checker could refuse while not `Ready`. Deterministic (Ready is a pure fn of
  consensus DB), but stricter and riskier; propose leaving claims flowing (a
  credited deposit is already backed in its own account) and gating only the
  *advertisement* of new addresses. **Open question for review.**

---

## New consensus DB / wire (all additive; unreleased, no migration)

- `BootstrapVoteKey(PeerId) -> BootstrapObservation` (next free prefix after
  `0x0D`).
- `UsdtConsensusItem::BootstrapObservation(BootstrapObservation)`.
- `UsdtGenParams`: factory/impl become *derived-by-default* (env overrides
  retained). Vendored `VENDORED_FACTORY_RUNTIME_HASH` /
  `VENDORED_IMPL_RUNTIME_HASH` constants.
- Client API: `status` endpoint + `UsdtClientModule::status()`.

## Phasing (each independently shippable)

1. **Part B (auto-prefund).** Smallest, non-consensus, immediate win; validate by
   deleting the manual `depositTo` from the devimint e2e and re-running.
2. **Part A (deterministic deploy + verify).** Removes the footgun; validate by
   the e2e deploying its own factory instead of the harness.
3. **Part C (readiness state machine + `status` + client gate).** The
   consensus-visible bit; validate by asserting `AwaitingInfra` before the
   factory/broadcasters are up and `Ready` after.

## Validation outcome (reviewed against the code) — REVISIONS

**Verdict: soundly fixable.** Part C's determinism is correct and mirrors the
proven deposit-observation / `FeeVote` patterns; Part B is genuinely
non-consensus and independently shippable. Part A as originally drafted has a
load-bearing flaw. Revisions below supersede the affected text above.

**⚠ Part A — REVISED (two blockers).** "Compute the factory/impl addresses as a
config constant and verify by a single vendored runtime-code hash" is valid
**only on a canonical-stack chain** (mainnet/public testnets with the canonical
v0.7 EntryPoint *and* the Arachnid `0x4e59…` CREATE2 deployer present). It breaks
on anvil/devnet — where every acceptance test runs — for two reasons:
1. The factory's CREATE2 initCode embeds `abi.encode(entryPoint)`, and on a
   devnet the EntryPoint is freshly deployed at a **non-canonical** address
   (`anvil.rs:510-512`), so the factory address depends on a runtime-deployed
   value and is *not* knowable at config-gen. The `0x4e59…` deployer is also
   absent (must be deployed via its pre-signed tx first; a redundant CREATE2 to
   an existing address *reverts*, it does not cleanly no-op — harmless to
   consensus, but not "idempotent").
2. Both `SimpleAccountFactory` (immutable `accountImplementation`) and
   `SimpleAccount` (immutable `_entryPoint`) bake immutables into their **runtime
   code**, so a single vendored runtime-hash is not constant across chains.

**Revised Part A:** treat `account_factory`/`simple_account_impl` as **federation
facts observed post-deploy** on non-canonical chains — read `factory.getAddress`
/ `accountImplementation()` and vote them into consensus (folding into
`AwaitingInfra`; deposit-address handout blocks until observed). The env
overrides become the required input on such chains, not an escape hatch.
Compute-as-config-constant is a mainnet-only optimization gated by an explicit
per-chain "canonical stack present?" config switch. **Verify correctness NOT by a
runtime-code hash but by the immutable-invariant equivalence `factory.getAddress(
owner, salt) == derive_deposit_account(...)`** — the check that already runs
against live anvil (`common.rs:271-273`) and directly proves derived deposit
addresses are spendable. This replaces (and is strictly stronger than) the
all-zero placeholder guard.

**Part B — REVISED (nonce sequencing).** `submit_user_ops` bypasses the cached
nonce manager and sets an explicit pending nonce on `handleOps` to avoid the
known nonce-leak wedge (`rpc.rs:391-417`). The added `depositTo` is a *second*
broadcaster tx — do NOT let both auto-fill the nonce. Read `balanceOf(sender)`
first and top up only on a shortfall (keeps the common already-funded case off
the hot path); when a top-up is needed, either `await get_receipt()` on
`depositTo` before fetching the `handleOps` pending nonce, or fetch one pending
nonce and assign `n → depositTo`, `n+1 → handleOps` explicitly. Also: add a real
`get_code` (bytes) to `IServerEvmRpc` + `MockEvmRpc` — `get_code_len` (`rpc.rs:139`)
is insufficient for any code inspection Part A/C needs.

**Part C — REVISED (`Degraded` latch).** A pure count over the *current*
`BootstrapVote` table cannot distinguish `Degraded` from `AwaitingInfra` (both are
"not `Ready` now"). Add a deterministic latch `HasEverBeenReadyKey -> ()`, set
inside `process_consensus_item` the first time the tally reaches `Ready`; then
`Degraded = has_ever_been_ready ∧ ¬Ready`. Still a pure fn of (ordered item +
prior DB). DB prefix: `BootstrapVoteKey` is `0x0E` (`0x0D` is `WithdrawalState`).
Mixing federation-facts and self-facts in one `BootstrapObservation` is fine
(each field counted independently) — keep it combined. Leave `process_input`
(claim) UNGATED — a credited deposit is backed in its own account and claimable
pre-sweep; gate only new-address *advertisement*. The startup fee-refusal
(`init` `bail!`) stays as-is (pre-API, token-economics, not a runtime infra
condition).

### Open questions — RESOLVED

1. `simple_account_impl` is technically `CREATE(factory, 1)`, but the codebase
   deliberately reads it post-deploy (`anvil.rs:623-652`) and has no CREATE
   address helper — so treat it as a post-deploy federation fact (blocks
   address handout → `AwaitingInfra`). Pre-deploy prediction needs a new
   RLP-CREATE helper + a live-anvil pinning test if ever wanted.
2. `0x4e59…` is absent on anvil; redundant CREATE2 reverts (harmless to
   consensus). Deploy the Arachnid deployer first on devnet.
3. Deploy is a guardian-local side effect (writes no consensus item), so
   selecting a deployer may use `our_peer_id`/RPC freely. Let any funded
   guardian race with backoff; treat "factory has code" purely as an
   observation — avoids the single-designated-deployer liveness hole.
4. `Degraded` is advisory-only (and needs the latch first).
5. Prefund `need` is computable from the op's static bounds + a small margin;
   the broadcaster-funded `min` is genuinely per-chain → a config field, not a
   compiled constant.
6. No determinism trap — independent per-field counting. Keep one item.
7. Fee-refusal stays (pre-API). Placeholder guard is subsumed by the
   `getAddress`-equivalence check. Claims stay ungated.
