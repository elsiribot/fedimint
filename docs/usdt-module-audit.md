# USDT-on-EVM module — external-audit package

Companion to `docs/usdt-module.md`. Threat model, the invariants the module
depends on and where they are enforced, the record of crypto-integration
decisions, and the accepted/deferred risks. Scoped to consensus version
`(0, 0)` (experimental, opt-in, undeployed).

## Trust & threat model

- **Federation:** `n` guardians, Byzantine-fault-tolerant up to `t` faults
  (Fedimint/AlephBFT assumption). The threshold-ECDSA signer subset is
  `threshold`-of-`n`. Funds custody requires a signing quorum; no single
  guardian can move funds.
- **Adversaries considered:** a minority of Byzantine guardians (equivocation,
  withholding, forged proposals, outlier votes); a malicious client (double
  claim, over-withdraw, forged claim key); chain-level adversaries (reorgs);
  griefing (deposit-check spam, oversized signing payloads).
- **Out of scope:** a quorum of colluding guardians (can move funds — inherent
  to threshold custody); the security of the underlying chain, EntryPoint,
  factory, and USDT contracts (assumed correct — the canonical
  account-abstraction v0.7 contracts + the target chain's USDT).

## Core invariant: consensus determinism

**Every consensus-DB write and every `Ok`/`Err` returned from
`process_consensus_item` / `process_input` / `process_output` is a pure
function of `(the ordered item/tx, the prior consensus-DB state, the
config)`.** No `our_peer_id`, wall-clock, RPC result, floating point, or
map-iteration order may influence a consensus write or return. A violation
diverges guardians' databases and halts the federation.

Where it is enforced / how it is upheld:
- **Per-guardian observations are votes, aggregated by quorum/median.** EVM
  reads (balances, block count, gas price, UserOp receipts) are per-guardian
  RPC reads proposed as votes; consensus acts only on a threshold of
  **identical** observations (deposits, UserOp confirmations) or a **median**
  (block count, fee). A single guardian's RPC value never gates a consensus
  write.
- **Off-thread signing + RPC submission are guardian-local side effects.** The
  cggmp21 signer thread, the deposit checker, and the UserOp submitter run
  outside the consensus write path; they influence consensus only by proposing
  items that are re-validated deterministically.
- **Verify-before-trust.** A proposed `MpcSignature` is verified against the
  DKG group key over the session digest before being written as the agreed
  signature; a proposed UserOp confirmation's `swept`/paid total is decoded
  from the **federation-agreed op's own calldata**, never from an RPC field
  (only `success`/`block` are RPC-sourced, and they are threshold-voted).
- **Determinism of derived values.** Deposit/pool addresses (CREATE2),
  `userOpHash` (v0.7 formula, pinned on-chain against
  `EntryPoint.getUserOpHash`), the signer subset rotation, the batch
  construction (sorted by `OutPoint`, capped), the timeout (consensus
  block-count), and the fee median are all pure functions of config + consensus
  DB.

This invariant was independently reviewed at every consensus arm across
Phases 5–8; the integration tests assert **byte-identical module databases**
across all guardians (signer and non-signer) at terminal states.

## Solvency invariant

The module's `audit` balance sheet is
`asset = Σ(DepositRecord.credited − swept) + Σ PoolState.balance
         − Σ UnclaimedWithdrawal.amount`.

Every on-chain USDT unit is counted **exactly once** across its lifecycle:
credited-but-unswept (deposit account) → swept (pool) → queued-withdrawal
(obligation subtracted while the pool still holds the backing) → confirmed
(pool debited and the subtraction ceases, exactly offsetting). Withdrawal
`max_fee` is federation revenue and stays counted because it is backed by real
pooled USDT the recipient did not receive. Proven net-**constant** (not merely
non-negative) by `audit_net_assets_are_invariant_across_the_withdrawal_lifecycle`.
Reported as an asset with the Phase-5 convention (credited deposit = asset,
mirroring wallet UTXOs) so federation solvency (pool USDT ≥ outstanding e-cash
obligations) is auditable.

## Custody & signature safety

- **One DKG group key** owns every deposit account and the pool via distinct
  CREATE2 salts; the key is never reconstructed (threshold signing only).
  Shares live only in `UsdtConfigPrivate`, never in the in-memory signing
  session, so a guardian restart cannot corrupt them.
- **`SimpleAccount` validates** `owner == ecrecover(toEthSignedMessageHash(
  userOpHash), sig)`. The MPC produces a low-S `(r,s)`; the recovery id is
  brute-forced to the group-key EOA. This recovery is mathematically
  guaranteed to succeed for any signature that verifies against the group key
  (a verifying `(r,s)` with `r > ~2^128` forces the recovery id into `{0,1}`),
  and a Byzantine guardian cannot produce any signature passing the
  verify-before-trust check without the key.

## Crypto-integration decision record

- **cggmp21 over consensus rounds.** cggmp21's sync state machines are `!Send`
  (`Rc<RefCell>`) and non-serializable mid-protocol. Resolved (Phase-2/6
  spike) by driving each machine on a dedicated OS thread with a suspendable
  pump (`next_outgoing`/`submit_round`/`into_output`), bridging to the
  consensus-item flow. Session state is in-memory (not DB); recovery from loss
  is via timeout+rotation, not replay.
- **Round-payload chunking.** A signing round's payload (~63 KB for round 2)
  exceeds AlephBFT's 50 KB unit byte-limit, which silently never orders an
  oversized item. Resolved by chunking `MpcRound` payloads at 30 KB with
  deterministic reassembly (discovered by a real-federation acceptance; unit
  tests structurally could not see it).
- **Encrypted round transport.** Per-recipient AEAD binding
  `domain(eid)+round+sender+recipient` into the HKDF info (a Phase-2 review
  found and fixed a Byzantine box re-attribution when only the recipient was
  bound).
- **Deterministic timeout + rotation.** Timeout is consensus-block-count ticks
  without progress (never wall-clock); rotation is a deterministically rotated
  signer subset per attempt.
- **v0.7 UserOp hashing.** The v0.7 packed formula (NOT v0.8 EIP-712) pinned
  on-chain against `EntryPoint.getUserOpHash`; the CREATE2 deposit address
  pinned against `SimpleAccountFactory.getAddress`.

## Reorg handling (maintainer policy note)

Deposits are credited only at `head − confirmation_depth`, and credit is
monotonic. `confirmation_depth` is the primary defense: a reorg **shallower**
than it cannot affect a credit. A reorg **deeper** than `confirmation_depth`
after a credit (and possibly after the user already claimed e-cash) is **not**
currently reversed — the module relies on a conservatively chosen
`confirmation_depth` for the target chain. **Maintainer decision:** whether to
add a credit-reversal path (which must reconcile against already-minted e-cash)
or to rely on `confirmation_depth`. A reorged-out **submission** self-heals:
the guardian-local submitter re-submits UserOps that yield no receipt.

## Accepted / deferred risks (with rationale)

| Risk | Status | Rationale |
|---|---|---|
| Reorg deeper than `confirmation_depth` un-credit | **maintainer decision** | Rely on conservative depth; reversal reconciles vs minted e-cash. |
| ETH-net-zero via token paymaster | **deferred** | v0 uses broadcaster-fronts + USDT-fee revenue + operator ETH refill; the v0.7 sample `TokenPaymaster` needs a Uniswap router + 2 oracles. `usdt_per_eth_e6` in `FeeVote` supports the fee model today. |
| First-sweep-only (`nonce=0`); 2nd deposit to a swept account | **deferred** | Needs deposit-account nonce tracking / re-sweep; funds stay counted as `credited − swept` (solvent), just not re-swept. |
| Fee-charging token over-credits the pool → **cumulative insolvency** | **maintainer decision required before mainnet** | A confirmed sweep/withdraw credits/debits `swept` from the UserOp's **requested** transfer amount (`decode_transfer_amount` / `decode_batch_transfer_total`), NOT the actual on-chain `balanceOf` delta. If the target token charges a transfer fee — mainnet Tether ships a live-but-currently-0 `basisPointsRate`/`maximumFee` mechanism (exactly what the `NonStandardUsdt.sol` fixture models, though it is only ever exercised at fee=0) — every sweep credits `PoolState.balance` by the full amount while the pool actually receives `amount − fee`, so `PoolState.balance` drifts **above** real holdings: e-cash issued exceeds redeemable USDT (cumulative insolvency), and withdrawals additionally under-pay recipients by the fee. **Guard in place:** `init` REFUSES to start (`init` returns `Err`) if the configured token reports `basisPointsRate != 0` (`get_erc20_basis_points_rate`), so a fee-enabled token cannot be run against by mistake. Fail-open on any read error or timeout — a standard fee-less ERC-20 reverts the call (indistinguishable from an unreachable node), so it hard-fails only on a *confirmed* nonzero rate and otherwise proceeds with a warning (bounded by a 30s timeout so a hung node can't wedge startup). The residual accounting risk (a fee turned on *after* the federation is already running) still stands; the thorough remediation is to measure `swept` as a threshold-agreed `balanceOf`-delta observation instead of decoding the requested amount — deliberately unchanged here (a maintainer decision). |
| Dangling `SubmittedUserOp` / never-confirmed batch wedge | **deferred** | `BATCH_MAX_ITEMS` cap largely defuses; a deterministic staleness/expiry is the hardening. |
| Session/chunk/failed-session GC | **deferred** | Unbounded-history rule keeps consensus correct; GC is space hygiene. |
| Client recovery from seed (`ClientModuleInit::recover`) | **maintainer decision** | `allocate_deposit` currently generates a **random** claim key per deposit, persisted in the client DB — recoverable if that DB is retained, but NOT reconstructible from the seed alone. Seed-based recovery would require switching to **seed-indexed** claim keys (a client-key-model change) + a rescan state machine. Deferred pending the maintainer's choice of key model. Deposits remain fully spendable while the client DB is intact. |
| Recovery scope: uncredited deposits + reverted-sweep remainder | **known limitation** | `recover_deposits` rediscovers only deposits the federation has already **credited** (a `check_deposit` → observe → credit must have happened for the account); a funded-but-never-checked deposit at scan time is skipped (funds are not lost — a later `check-deposit` + re-scan finds them). Separately, the deliberate no-auto-retrigger on a **failed** sweep (`apply_user_op_confirmed`) leaves the solvent `credited − swept` remainder un-swept until a future deposit observation on that account, which may never arrive. Both are documented known limitations; restructuring recovery or the sweep-retry policy is a maintainer design item. |
| DoS: `check_deposit` spam | **partial** | `deposit_check_fee` config exists (may be 0); per-connection rate-limit is operator/infra-level. |
| Unchecked `u64` adds | **mitigated** | Flagged adds converted to `saturating_add`; overflow totals (>9.2e12 USDT) unreachable. |
| Factory misconfiguration → unspendable addresses | **mitigated** | Startup warns on placeholder factory; operator must configure a factory matching the vendored proxy init code (documented). |
| Bootstrap fee median (few votes) / degenerate zero median | **mitigated / deferred** | `MIN_WITHDRAWAL_FEE` floor prevents free withdrawals; transient early-vote skew is deterministic and within the honest range. |
| DB migrations | **n/a (greenfield)** | Unreleased module; a v1-migration pattern scaffold is documented. |
| Non-BITCOIN primary-module e-cash await (client) | **fixed** | `Client::await_primary_bitcoin_module_output` was hardcoded to `AmountUnit::BITCOIN`, so a USDT-denominated `mintv2` primary module's issued e-cash could not be awaited/observed. Added unit-aware `await_primary_module_output{,s}_for_unit(.., unit)` (bitcoin variants now specializations); the usdt `claim` awaits `..._for_unit(USDT_UNIT)`, so it returns only once the e-cash is issued. The real-chain devimint e2e now asserts the exact issued balance. |
| Withdrawal devimint e2e (real-chain) | **green (reliability caveat)** | The full deposit→sweep→claim→withdraw loop passes end to end through real `fedimintd` + real DKG + threshold MPC signing + anvil (4337 deploy + EntryPoint prefunding + broadcaster override + withdraw/verify), 4 consecutive runs. Two *earlier* runs stalled before the sweep funded the pool and were not reproducible afterward — likely a transient in the CPU-heavy MPC signing under load. Worth a soak test / load characterization before trusting the sweep timing under production load; not a correctness bug. |

## Test coverage (evidence)

- **Hermetic determinism:** 4-guardian (incl. non-signer) `fedimint-testing`
  tests over `MockEvmRpc` with real cggmp21 MPC, asserting byte-identical
  module DBs and replay-safety at each stage.
- **Anvil isolation:** hand-signed UserOps (deploy-and-sweep, withdrawal batch)
  on a real EntryPoint, isolating 4337 mechanics from MPC.
- **Real-MPC anvil e2e (the gates):** `deploy_and_sweep_e2e` and `withdraw_e2e`
  — a counterfactual account is deployed and swept, and a fresh EOA is paid,
  via real DKG + real MPC-signed UserOps on the real EntryPoint. These gates
  caught three production bugs no unit/mock test could (the 63 KB-round stall,
  the confirmation-depth/instant-mine race, and the broadcaster nonce-cache
  leak).
