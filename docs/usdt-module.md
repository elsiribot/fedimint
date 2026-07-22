# USDT-on-EVM Fedimint module

A Fedimint module that lets a federation custody USDT (or any ERC-20) on an
EVM chain and issue/redeem it as Chaumian e-cash. Deposits of on-chain USDT
become spendable e-cash; e-cash can be withdrawn back to any EVM address. The
federation holds the USDT in a smart-contract account it controls with a
threshold-ECDSA key produced by distributed key generation — no single
guardian can move funds.

> **Status:** experimental, opt-in (`FM_ENABLE_MODULE_USDT`), consensus
> version `(0, 0)`, not yet deployed. The crate set is
> `fedimint-usdt-{common,server,client}` + `fedimint-usdt-tests`.

## Architecture

Three-crate module (Fedimint convention):
- `fedimint-usdt-common` — wire types, config, address/hash derivation, UserOp
  types. **WASM-safe** (no `cggmp21`/`gmp`, no alloy provider — only
  `alloy-primitives`/`alloy-sol-types` for pure keccak/ABI).
- `fedimint-usdt-server` — consensus logic, threshold signing, the EVM adapter
  (`IServerEvmRpc`/`AlloyEvmRpc`), background tasks.
- `fedimint-usdt-client` — client operations (allocate/claim/withdraw), status
  tracking, CLI subcommands. WASM-safe.

Threshold ECDSA is provided by `fedimint-threshold-ecdsa` (a `cggmp21` wrapper)
over the `fedimint-exchange-transport` round-exchange abstraction. The EVM side
uses ERC-4337 (account abstraction) v0.7: deposit and pool accounts are
counterfactual `SimpleAccount`s; the federation moves funds by signing UserOps
whose `userOpHash` the DKG group key authorizes.

## The four flows

### 1. Deposit → credit
1. Client derives a **claim key** and shows the user the **deposit address** =
   `CREATE2(account_factory, salt = keccak256("fedimint-usdt-deposit-v0" ‖
   claim_pk), initCode(SimpleAccount owner = group-key EOA))`. Every deposit
   address is a distinct counterfactual `SimpleAccount` owned by the **one**
   DKG group key (differentiated only by salt).
2. User sends USDT to that address (a normal ERC-20 transfer; the account need
   not be deployed to hold ERC-20 balance).
3. Client calls `check_deposit`; each guardian records a local `PendingCheck`.
4. A guardian background task reads the USDT balance at
   `head − confirmation_depth` and, when it exceeds the recorded credit,
   proposes a `Deposit` observation. When a **threshold** of guardians submit
   **identical** observations, the module sets `DepositRecord.credited`
   (monotonic; balances are monotonic between sweeps since only the federation
   can move funds out).

### 2. Claim → e-cash
Client submits a fedimint transaction with a `UsdtInput` signed by the claim
key; `process_input` verifies the `DepositRecord`, bumps `claimed`, and mints
`USDT_UNIT`-denominated e-cash (via a `mintv2` instance the operator registers
for `USDT_UNIT`). Double-claims are rejected by the `claimed ≤ credited` guard.

### 3. Sweep → pool
When a deposit is credited, the module deterministically enqueues a
**deploy-and-sweep** UserOp: it deploys the deposit `SimpleAccount` (via the
factory `initCode`) and `execute`s a USDT transfer of the full balance to the
**pool** account (a fixed `SimpleAccount`, owner = group key, salt =
`keccak256("fedimint-usdt-pool-v0")`). The federation MPC-signs the UserOp's
`userOpHash`; a designated broadcaster submits it via `EntryPoint.handleOps`.
On confirmation (threshold-voted receipt observation), `PoolState.balance`
rises and `DepositRecord.swept` advances.

### 4. Withdraw → on-chain payout
1. Client `withdraw(recipient, amount, max_fee)` submits a `UsdtOutput`;
   `process_output` validates `max_fee ≥` the fee quote (from the median of
   guardians' `FeeVote`s, floored at `MIN_WITHDRAWAL_FEE`), burns
   `amount + max_fee` of e-cash, and enqueues an `UnclaimedWithdrawal`
   (`WithdrawalState::Queued`). The `max_fee` accrues to the federation as
   revenue (backed by real pooled USDT); the recipient receives exactly
   `amount`.
2. A block-count-driven trigger batches queued withdrawals (capped at
   `BATCH_MAX_ITEMS`, sorted deterministically) into one pool `executeBatch`
   UserOp, MPC-signed and submitted (the first withdrawal deploys the pool via
   its `initCode`).
3. On confirmation, `PoolState.balance` is debited and each withdrawal is
   `Confirmed`; a failed on-chain op reverts the withdrawals to `Queued` for
   retry (the pool nonce still advances, matching the EntryPoint).

The client tracks a withdrawal via `withdrawal_status` /
`await_withdrawal_confirmed`.

## Custody & signing

- **One key, many accounts.** DKG produces a single threshold-ECDSA group key
  whose EOA address owns every deposit account and the pool (differentiated by
  CREATE2 salt). A signing quorum (`threshold`-of-`n`) co-signs each UserOp's
  EIP-191-wrapped `userOpHash`; the recovery id is brute-forced so the 65-byte
  signature recovers to the group-key EOA, which the `SimpleAccount` validates
  on-chain.
- **Runtime signing over consensus.** cggmp21's signing state machines are
  `!Send` and non-serializable mid-protocol, so each signer drives its machine
  on a dedicated OS thread, exchanging round payloads as **chunked**
  `MpcRound` consensus items (a round's payload can exceed AlephBFT's 50 KB
  unit limit → chunked at 30 KB and deterministically reassembled). A finished
  signature is proposed as an `MpcSignature` item, **verified against the group
  key before it is trusted**, and written to consensus so every guardian
  (signer or not) holds the agreed signature.
- **Resilience.** A stalled session times out on a **consensus block-count**
  basis (never wall-clock) and retries with a **deterministically rotated**
  signer subset, recovering from a downed signer without manual intervention.

## Deployment & configuration

Config-gen produces (per D8 in the master plan):
- `UsdtConfigConsensus`: `group_public_key`, chain id, `usdt_contract`,
  `entry_point`, `account_factory`, `simple_account_impl`, `confirmation_depth`,
  all guardians' MPC static-encryption pubkeys.
- `UsdtConfigPrivate`: this guardian's cggmp21 `KeyShare` + MPC encryption
  secret + local `evm_rpc_url` + `broadcaster_private_key`.

`UsdtGenParams` (set at config-gen) carries the deployed contract addresses.
**A real deployment MUST configure an `account_factory` whose on-chain CREATE2
`initCodeHash` matches this build's vendored `ERC1967_PROXY_CREATION_CODE`**
(the canonical account-abstraction v0.7 `SimpleAccountFactory`, OZ 5.0.0, solc
0.8.23 `evmVersion=paris`) — otherwise derived deposit addresses will not match
what the factory deploys and deposits become unspendable. The module logs a
startup warning if the factory/impl are left at the all-zero placeholder.

## Guardian operations runbook

- **Broadcaster ETH.** The gas model is **broadcaster-fronts-ETH**: each
  guardian's broadcaster EOA fronts the gas for `handleOps` (and prefunds the
  deposit/pool accounts' EntryPoint deposits), reimbursed by the EntryPoint
  from the op's prefund. The user's USDT `max_fee` covers gas economically and
  accrues to the federation; the operator must **keep the broadcaster EOA
  funded with ETH** and periodically convert accrued USDT→ETH (off-protocol).
  *A true on-chain token paymaster (gas paid in USDT, ETH-net-zero) is a
  deferred production option — see the audit doc.*
- **Price source.** Each guardian votes a `FeeVote { max_fee_per_gas_wei,
  usdt_per_eth_e6 }` from its configured price source (devnet: static). The
  median sets withdrawal fee quotes; a Byzantine outlier vote can move the
  median only within the honest range.
- **`confirmation_depth`.** Choose conservatively for the target chain's reorg
  characteristics — it is the primary defense against reorged deposits (see
  the reorg note in the audit doc).
- **Pool monitoring.** Watch `PoolState.balance` vs. outstanding e-cash /
  queued withdrawals; the `audit` endpoint reports the module's balance sheet
  (`Σ(credited − swept) + pool.balance − Σ queued-withdrawals`).
- **Module enable.** Opt-in via `FM_ENABLE_MODULE_USDT`; the module runs a
  minutes-long DKG at setup (pregenerate Paillier primes / raise the DKG
  timeout for devnet).

## CLI

`fedimint-cli module usdt {deposit-address, check-deposit, deposit-status,
claim, fee-quote, withdraw, withdrawal-status, pool-state, userop-status}`.

## See also

- `docs/usdt-test-federation.md` — step-by-step runbook + operational
  requirements for standing up a minimal USDT-only test federation (usdt wallet
  + USDT-denominated `mintv2`).
- `docs/usdt-module-audit.md` — threat model, invariants, crypto-integration
  decisions, and accepted/deferred risks (external-audit package).
- `docs/superpowers/plans/2026-07-15-usdt-evm-module-master-plan.md` — the
  pinned design; per-phase JIT plans alongside it.
