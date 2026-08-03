# Deploying a USDT federation on a testnet (Sepolia)

How to stand up the USDT-on-EVM module on the **Sepolia** Ethereum testnet — the
recommended first real-network step before any mainnet consideration. This
builds on `docs/usdt-test-federation.md` (the local/anvil runbook); read that
for the module mechanics. This doc covers what changes for a real, shared
testnet.

> **Status:** experimental, opt-in, consensus version `(0, 0)`, undeployed.
> Testnet only. Do NOT point this at Ethereum mainnet — see
> `docs/usdt-module-audit.md` for the outstanding risks (no external audit, no
> real-network soak, etc.).

## First: do we run a chain daemon, or use an API?

**You do not need to run your own Ethereum node.** Unlike Bitcoin (where you'd
run `bitcoind` or trust an Electrum/Esplora server), the standard way to give
each guardian a view of the chain is a **hosted JSON-RPC endpoint** — an HTTPS
URL from a provider like Alchemy, Infura, QuickNode, Ankr, or a public Sepolia
endpoint. You point the guardian's `FM_USDT_EVM_RPC_URL` at that URL and it does
all its chain reads/writes (deposit detection, gas price, UserOp receipts, the
Chainlink price feed, broadcasting transactions) through it.

Key points:
- **One endpoint per guardian.** Each guardian reads the chain independently and
  votes; consensus aggregates (median / threshold). They can — and for
  decentralization *should* — use **different** providers. Don't make all
  guardians trust one company's endpoint.
- **A hosted RPC provider is a trusted data source** (like an Electrum server):
  it could lie to or censor a guardian. The per-guardian-read + threshold model
  limits the damage of one bad provider, but for mainnet the trust-minimizing
  option is guardians running their **own** execution node (geth/reth/nethermind).
  For testnet, hosted RPC is the easy, normal choice.
- **Running your own node is optional**, not required. A Sepolia full node is
  hundreds of GB and takes time to sync; only do it if you specifically want to
  practice the self-hosted-node setup.

## What you must source vs. what the module handles itself

| Ingredient | How to get it |
|---|---|
| **Sepolia RPC endpoint (per guardian)** | Free tier from Alchemy/Infura/etc., or your own node. |
| **Sepolia ETH (per guardian's broadcaster)** | Public faucets (Alchemy, Google Cloud Web3, Infura, PoW faucets). Needed to pay on-chain gas. |
| **A test USDT token** | Deploy `modules/fedimint-usdt-tests/contracts/NonStandardUsdt.sol` yourself; it has a public `mint()` faucet (see below). There is **no official Tether USDT on testnets**. |
| **EntryPoint (ERC-4337 v0.7)** | Already deployed at the canonical address on Sepolia — you just reference it. |
| **The `SimpleAccountFactory` + implementation** | **The module deploys these itself** (Part A). Do not deploy or configure them. |
| **EntryPoint gas prepayment for each account** | **The module funds these itself** from the broadcaster (Part B). |
| **Chainlink ETH/USD price feed** | Already deployed on Sepolia — you reference its address. |

So your real setup work is: **RPC endpoints, faucet ETH into each broadcaster,
and deploy + mint your test USDT.** The contract plumbing is self-deploying.

## Sepolia addresses

| What | Address | Notes |
|---|---|---|
| Chain id | `11155111` | Sepolia. |
| ERC-4337 EntryPoint v0.7 | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | Canonical, identical on every chain. |
| Arachnid CREATE2 deployer | `0x4e59b44847b379578588920cA78FbF26c0B4956C` | Present on Sepolia; if ever absent the module self-bootstraps it before deploying the factory. |
| Chainlink ETH/USD feed | `0x694AA1769357215DE4FAC081bf1f309aDC325306` | **VERIFY against Chainlink's official Sepolia data-feeds docs before use** — feed addresses must be exact. |
| Your test USDT | *(you deploy it — see below)* | |

## Step 1 — Get a Sepolia RPC endpoint per guardian

Sign up with one or more providers, create a Sepolia app, copy the HTTPS URL
(looks like `https://eth-sepolia.g.alchemy.com/v2/<key>`). Ideally a different
provider per guardian.

## Step 2 — Create and fund a broadcaster EOA per guardian

Each guardian needs one "broadcaster" account — a normal Ethereum keypair (EOA)
that fronts on-chain gas. For each guardian:

1. Generate a keypair (`cast wallet new`), keep the private key secret.
2. Fund its address with Sepolia ETH from faucets. Aim for **well above `0.05`
   ETH** (the module's default "funded" threshold) — say `0.2`–`0.5` ETH — so it
   can self-prefund accounts and run for a while. The module will not report
   `Ready` until at least a threshold of broadcasters are funded.

A single shared broadcaster key across guardians is acceptable for a test (the
EntryPoint dedups submissions), but separate keys are more realistic.

## Step 3 — Deploy your test USDT and mint yourself a balance

`NonStandardUsdt.sol` faithfully mimics real USDT: **6 decimals**, the quirk
where `transfer` returns nothing (which the module handles), and the dormant
owner-settable fee switch. Crucially it has a **public `mint(to, amount)`** —
your faucet.

```sh
# Compile (mirrors how the test fixture is produced):
forge build --root modules/fedimint-usdt-tests   # or a throwaway forge project

# Deploy from any funded Sepolia key:
cast send --rpc-url "$SEPOLIA_RPC" --private-key "$DEPLOYER_KEY" \
    --create "$(cat .../NonStandardUsdt.bytecode)"
# -> note the deployed contract address; this is your FM_USDT_CONTRACT.

# Mint yourself 1,000,000 test USDT (6 decimals => amount = 1_000_000_000000):
cast send --rpc-url "$SEPOLIA_RPC" --private-key "$YOUR_KEY" \
    <USDT_ADDRESS> "mint(address,uint256)" <YOUR_ADDRESS> 1000000000000
```

Verify with `cast call <USDT_ADDRESS> "decimals()"` → `6` and
`cast call <USDT_ADDRESS> "balanceOf(address)" <YOUR_ADDRESS>`.

## Step 4 — Configure the guardians (environment variables)

Set these on each guardian's `fedimintd` process (captured at process spawn).
**Only the config-gen leader's config-gen vars reach consensus**; the RPC URL and
broadcaster key are per-guardian runtime values.

Module set — USDT + a USDT-denominated `mintv2`, everything else off:

```sh
FM_ENABLE_MODULE_USDT=1
FM_ENABLE_MODULE_MINTV2=1
FM_ENABLE_MODULE_MINT=0
FM_ENABLE_MODULE_WALLET=0
FM_ENABLE_MODULE_WALLETV2=0
FM_ENABLE_MODULE_LNV1=0
FM_ENABLE_MODULE_LNV2=0
FM_MINTV2_AMOUNT_UNIT=1        # USDT_UNIT
FM_DISABLE_BASE_FEES=1         # optional: claimed e-cash == deposit exactly
```

Config-gen params (leader) — point at Sepolia:

```sh
FM_USDT_CONTRACT=0x<your deployed test USDT>
FM_USDT_ENTRY_POINT=0x0000000071727De22E5E9d8BAf0edAc6f37da032
FM_USDT_ETH_USD_PRICE_FEED=0x694AA1769357215DE4FAC081bf1f309aDC325306   # verify!
FM_USDT_CHAIN_ID=11155111          # REQUIRED — bound into signed userOpHash
FM_USDT_CONFIRMATION_DEPTH=3       # reorg cushion for testnet (raise for mainnet)
FM_USDT_RESIDUAL_RECOVERY_RECIPIENT=0x<your treasury/broadcaster-refill address>  # REQUIRED — see note below
# Do NOT set FM_USDT_ACCOUNT_FACTORY / FM_USDT_SIMPLE_ACCOUNT_IMPL:
#   the module derives them from the entry_point and self-deploys the factory.
```

Per-guardian runtime (may differ across guardians):

```sh
FM_USDT_EVM_RPC_URL=https://<this guardian's Sepolia RPC endpoint>
FM_USDT_BROADCASTER_PRIVATE_KEY=0x<this guardian's funded Sepolia EOA key>
```

> **`FM_USDT_CHAIN_ID` is not optional on Sepolia.** The chain id is baked into
> the ERC-4337 `userOpHash` the federation signs; left at the `31337` anvil
> default, every signature would be rejected on-chain. Likewise raise
> `FM_USDT_CONFIRMATION_DEPTH` above the `1` anvil default.

> **`FM_USDT_RESIDUAL_RECOVERY_RECIPIENT` is REQUIRED on Sepolia (and any
> non-dev chain).** It's the deterministic EVM address the federation
> withdraws stranded ERC-4337 `EntryPoint` gas deposits to when a deposit
> account's gas prefund goes unused (typically your treasury /
> broadcaster-refill address) — every guardian must build the
> byte-identical `EntryPoint.withdrawTo(recipient, amount)` recovery
> transaction, so it has to be a single consensus-agreed value, never a
> per-guardian broadcaster key. Config-gen (`validate_usdt_params` in
> `modules/fedimint-usdt-common/src/lib.rs`, enforced again at DKG in
> `modules/fedimint-usdt-server/src/dkg.rs`) **REJECTS** the all-zero
> placeholder address on any non-dev `chain_id` — leaving this env var unset
> (it defaults to the zero address) makes config-gen fail loudly with a clear
> error rather than silently configuring recovery to burn funds to `0x0`.
> Only the anvil/hardhat dev chain ids (`31337`/`1337`) are exempt from this
> check.

## Mainnet vs. testnet

This doc only walks through **Sepolia**. Nothing here should be pointed at
Ethereum mainnet without first reading `docs/usdt-module-audit.md` (no
external audit, no real-network soak, and the fee-charging-token risk in
particular). If/when that changes, mainnet needs a few parameters set
differently from the Sepolia values above; the module enforces the safety-
relevant ones at config-gen (`validate_usdt_params`), so getting them wrong
fails config-gen rather than silently deploying something unsafe:

- `FM_USDT_CHAIN_ID=1` (mainnet), not `11155111`.
- `FM_USDT_CONFIRMATION_DEPTH` must be **>= 6**
  (`MIN_PROD_CONFIRMATION_DEPTH` in `fedimint-usdt-common`) on any non-dev
  chain id. Config-gen **rejects** a lower value unless you also set
  `FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH=1` to explicitly acknowledge the
  reorg risk — don't set that on mainnet; raise the depth instead.
- `FM_USDT_CONTRACT` — the real Tether USDT mainnet contract address.
  **Verify the address yourself against Etherscan** before using it; don't
  trust it blindly from any single doc (fake "USDT" contracts are a common
  scam).
- `FM_USDT_ENTRY_POINT` — the same canonical ERC-4337 v0.7 address used above
  for Sepolia (`0x0000000071727De22E5E9d8BAf0edAc6f37da032`); it's identical
  on every chain.
- `FM_USDT_ACCOUNT_FACTORY` / `FM_USDT_SIMPLE_ACCOUNT_IMPL` — still leave
  unset. The module derives and self-deploys them exactly as on Sepolia.
- `FM_USDT_ETH_USD_PRICE_FEED` can be **omitted** on mainnet — it defaults to
  the canonical mainnet Chainlink ETH/USD feed, which is correct there
  (Sepolia is the chain that needs the explicit override used above).
- `FM_USDT_RESIDUAL_RECOVERY_RECIPIENT` — **required**, exactly as on
  Sepolia (see the note above); config-gen rejects the placeholder zero
  address on mainnet just as it does on Sepolia.

## Step 5 — Config-gen + DKG

Run the guardians through fedimint's normal setup/config-gen with the env above.
Every guardian then runs a threshold-ECDSA **distributed key generation**,
including a per-guardian Paillier safe-prime step that takes **a minute or more
each** — this is real production DKG, not the fast test primes. Raise your
setup/invite-code timeouts accordingly. DKG produces the single group key that
owns every deposit account and the pool.

## Step 6 — Wait for `Ready`

After config-gen, the module bootstraps itself (guardian-local, no operator
action): each funded guardian **self-deploys the `SimpleAccountFactory`** via
CREATE2, every guardian **verifies** it on-chain (`factory.getAddress ==` the
derived address), and readiness conditions are threshold-voted. Poll:

```sh
fedimint-cli module usdt status     # -> AwaitingInfra ... then Ready
```

Until it reports `Ready`, the client refuses to hand out deposit addresses (by
design — you can't be told to deposit into a federation that can't yet honor
it). If it stays `AwaitingInfra`, the `status` output shows which condition is
unmet (factory not verified, too few funded broadcasters, RPC unhealthy).

## Step 7 — Drive the flow

```sh
fedimint-cli module usdt deposit-address                 # -> { claim_pk, account }
# Send test USDT to `account`:
cast send --rpc-url "$SEPOLIA_RPC" --private-key "$YOUR_KEY" \
    <USDT_ADDRESS> "transfer(address,uint256)" <account> 2048000   # 512-aligned
fedimint-cli module usdt check-deposit <claim_pk>
fedimint-cli module usdt deposit-status <claim_pk>       # poll until credited
fedimint-cli module usdt claim <claim_pk>                # -> USDT e-cash
fedimint-cli module usdt pool-state                      # watch the auto-sweep
fedimint-cli module usdt fee-quote <amount>              # now driven by Chainlink
fedimint-cli module usdt withdraw <recipient> <amount>
fedimint-cli module usdt withdrawal-status <txid> <out_idx>
```

Use amounts that are multiples of **512** (the e-cash denomination granularity)
so nothing is lost to un-mintable dust, e.g. `2_048_000` (= 2.048 test USDT).

## What to watch (testnet gotchas)

- **Keep broadcasters funded.** They spend Sepolia ETH on every sweep/withdrawal
  and to prefund accounts. If they run low the module drops to `Degraded` and
  stops advertising deposit addresses. Top up from faucets.
- **Reorg depth.** `FM_USDT_CONFIRMATION_DEPTH=3` is a modest testnet cushion;
  Sepolia reorgs are usually shallow but the point is to practice a conservative
  value. Mainnet would use more.
- **Price feed is real here.** `fee-quote` now reflects the live Sepolia
  Chainlink ETH/USD price (± the 20% buffer). If the feed goes stale (> 4h) a
  guardian abstains from voting a price; quotes come from the healthy ones.
- **RPC trust / diversity.** Prefer a different provider per guardian. A single
  provider outage takes its guardian's votes offline (the rest carry on).
- **Your test USDT ≠ real Tether.** It reproduces the *mechanics* but not
  Tether-the-company's powers (freezing addresses, turning the fee on). To
  exercise those, later use mainnet-fork testing. Note the module **refuses to
  start** if the configured token reports a nonzero transfer fee — so leave your
  test token's fee at `0` (the default) unless you're specifically testing the
  refusal.
- **DKG is slow.** Minutes per guardian at setup; don't mistake it for a hang.

## Canonical reference

The `usdt-e2e-test` devimint binary
(`modules/fedimint-usdt-tests/bin/usdt_e2e.rs`) runs this whole lifecycle
automatically against a local `anvil` and is the ground truth for the flow. The
testnet deployment is the same flow with Sepolia's RPC, addresses, real DKG, and
real faucet ETH instead of anvil's free accounts.
