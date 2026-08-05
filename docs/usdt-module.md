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
4. If a submitted batch times out and gas has risen enough that repricing it
   would cost more than the sum of its withdrawals' committed `max_fee` (the
   batch's "ceiling"), the module does **not** execute the batch over-ceiling
   and does **not** refund the burned e-cash. The already-signed op stays
   live and non-superseded at its `EntryPoint` `(sender, nonce)` — it can
   still confirm later if it lands on-chain — and the batch **stalls**:
   neither paid nor refunded. Every subsequent timeout, the module re-checks
   affordability against the current fee median and re-fires the reprice the
   moment the batch is priced back under the ceiling, so the stall
   **self-heals** with no operator action. Because the pool account is
   one-batch-at-a-time, a stalled batch also blocks later withdrawal batches
   until it reprices or confirms — so during a sustained gas spike above a
   batch's ceiling, its withdrawals can appear "stuck" in `Submitted` for
   longer than usual. See `docs/usdt-module-audit.md` for the accepted
   liveness tradeoff.

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
  usdt_per_eth_e6 }`; `usdt_per_eth_e6` comes from a Chainlink `AggregatorV3`
  `latestRoundData()` read of the configured `eth_usd_price_feed` (defaults to
  the canonical mainnet ETH/USD feed), guarded for staleness
  (`price_feed_max_staleness_secs`, default 4h), non-positive answers, and
  incomplete rounds. A bad/stale/unreachable reading makes that guardian
  **abstain** (skip its vote that poll cycle) rather than vote a wrong price.
  On a chain with no Chainlink deployment (e.g. local `anvil`/devnet),
  `eth_usd_price_feed` is set to the all-zero address, which falls back to a
  static `$3000.000000/ETH` price instead. The median (over whichever
  guardians voted that round) sets withdrawal fee quotes; a Byzantine outlier
  vote can move the median only within the honest range.
- **`confirmation_depth`.** Choose conservatively for the target chain's reorg
  characteristics — it is the primary defense against reorged deposits (see
  the reorg note in the audit doc).
- **Pool monitoring.** Watch `PoolState.balance` vs. outstanding e-cash /
  queued withdrawals; the `audit` endpoint reports the module's balance sheet
  (`Σ(credited − swept) + pool.balance − Σ queued-withdrawals`).
- **Module enable.** Opt-in via `FM_ENABLE_MODULE_USDT`; the module runs a
  minutes-long DKG at setup (pregenerate Paillier primes / raise the DKG
  timeout for devnet).

## Guardian fee withdrawal

The federation retains two sources of fee revenue in the pool, both tracked
in `PoolState.accrued_fees` (invariant: `accrued_fees ≤ balance` — realized
fee revenue can never exceed the USDT the pool physically holds):

- **Deposit fees.** The `max_fee`-equivalent quote a claim pays (see "2.
  Claim → e-cash" above) accrues onto the `DepositRecord` at claim time and is
  realized into `PoolState.accrued_fees` when that deposit's sweep confirms
  (so the fee is only counted once its USDT is actually in the pool).
- **Withdrawal fees.** On a **successful** withdrawal confirmation the
  federation keeps the FULL `max_fee` the client posted (the recipient is
  only ever paid `amount`). On a **refunded** (terminally failed) withdrawal
  the federation keeps only the `incurred` gas cost actually spent
  attempting it, not the full `max_fee`.

This accrued balance is guardian-only revenue and is never spent
automatically — a guardian must explicitly vote to pay it out to an EVM
address. Read the current figure via the `pool_state` endpoint
(`fedimint-cli module usdt pool-state`), whose response now includes
`accrued_fees` alongside `account`/`balance`.

### Casting a fee-withdrawal vote

Casting a vote is a **guardian action**, not a client operation — there is no
`fedimint-cli module usdt withdraw-fees` subcommand, because the module
*client* CLI talks to the federation's regular (unauthenticated) module API
and has no guardian credentials. Fee withdrawal instead goes through the
**admin API**, authenticated with each guardian's own password, against
**that guardian's own node**:

```bash
# each guardian, independently, against their own node:
fedimint-cli dev api \
  --peer-id <N> --module <usdt-module-id-or-kind> --password <guardian-pw> \
  withdraw_fees \
  '{"recipient":"0x…","amount":<usdt_e6>}'
```

(`dev api` is the generic authenticated JSON-RPC caller; `--password` requires
`--peer-id`, and `--module` selects the USDT module by its id or kind so the
method is the bare endpoint name `withdraw_fees`.)

`amount` is in raw USDT units (6 decimals, matching every other `UsdtAmount`
in this module). Operationally:

- **2f+1 threshold on the identical pair.** The vote is tallied by the exact
  `(recipient, amount)` pair — guardians must agree on both fields byte-for-
  byte before a payout is built; a guardian who votes a different amount (or
  recipient) simply doesn't count toward the same tally. Only once
  `threshold` guardians have cast the identical pair does the federation
  build and MPC-sign the payout `UserOp`.
- **Waits behind in-flight user activity.** A `WithdrawFees` payout shares
  the pool `SimpleAccount`'s nonce with ordinary user withdrawals, so it is
  never built while a `Withdraw`/`WithdrawFees` op is already
  `Pending`/`Submitted`; it is retried automatically once the pool is free.
- **Amount is bounded by both accrued fees and physical balance.** The
  federation refuses to build the payout — and simply keeps waiting — unless
  `amount` is within *both* `pool.accrued_fees` (never dips into user deposit
  principal) *and* `pool.balance` (never builds a transfer the pool can't
  fund on-chain). In practice, request `amount ≤ min(accrued_fees,
  pool_balance)`.
- Once threshold is reached and the payout confirms, ALL stored
  `WithdrawFeesVote`s are cleared (success or on-chain revert alike), so a
  subsequent fee withdrawal always needs a fresh round of votes.

## CLI

`fedimint-cli module usdt {deposit-address, check-deposit, deposit-status,
claim, fee-quote, withdraw, withdrawal-status, pool-state, userop-status,
status, recover}`.

`status` reports the module's consensus-agreed readiness state
(`AwaitingInfra`/`Ready`/`Degraded`) plus the per-condition tally, derived from
threshold-aggregated per-guardian readiness observations (EntryPoint/factory/impl
deployed and verified, plus a quorum of funded broadcasters and healthy RPC).
The client refuses `deposit-address` unless the federation reports `Ready`, so a
user is never told to deposit into a federation that cannot yet honor the full
deposit->claim->sweep->withdraw lifecycle; `claim`/`withdraw`/`pool-state` stay
queryable in every state.

## See also

- `docs/usdt-test-federation.md` — step-by-step runbook + operational
  requirements for standing up a minimal USDT-only test federation (usdt wallet
  + USDT-denominated `mintv2`).
- `docs/usdt-module-audit.md` — threat model, invariants, crypto-integration
  decisions, and accepted/deferred risks (external-audit package).
- `docs/superpowers/plans/2026-07-15-usdt-evm-module-master-plan.md` — the
  pinned design; per-phase JIT plans alongside it.
