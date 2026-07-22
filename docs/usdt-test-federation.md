# Running a USDT-only test federation

How to stand up a minimal Fedimint federation whose **only** modules are the
USDT-on-EVM wallet and a USDT-denominated `mintv2` (e-cash) instance — no
Bitcoin wallet, no Bitcoin-denominated mint, no Lightning. This is the exact
shape proven end-to-end by the `usdt-e2e-test` devimint binary
(`modules/fedimint-usdt-tests/bin/usdt_e2e.rs`), which is the canonical,
automated version of everything below — read it alongside this doc.

> **Status:** experimental, opt-in, consensus version `(0, 0)`, undeployed. For
> testing against a devnet/testnet EVM chain, **never** mainnet — see
> `docs/usdt-module.md` and `docs/usdt-module-audit.md` for the risk register.

## What it is

- **Modules:** `usdt` (custodies USDT in ERC-4337 `SimpleAccount`s controlled by
  a threshold-ECDSA group key) + one `mintv2` instance denominated in
  `USDT_UNIT` (issues/redeems the custodied USDT as Chaumian e-cash). A Fedimint
  federation runs fine with **no Bitcoin wallet module** — verified.
- **Flow:** user sends USDT on-chain to a per-deposit address → guardians credit
  it → user `claim`s it as USDT e-cash → the federation auto-sweeps the deposit
  into a pool `SimpleAccount` → user `withdraw`s e-cash back to any EVM address.

## Operational prerequisites

Everything the federation needs beyond the fedimintd/fedimint-cli binaries:

1. **An EVM chain + a synced RPC endpoint per guardian.** Local: `anvil`
   (Foundry). Shared test: a testnet (e.g. Sepolia) node or provider URL. Each
   guardian reads/writes the chain independently through its own endpoint (they
   need not share one). USDT deposit detection, gas-price votes, and UserOp
   confirmations are all per-guardian RPC reads aggregated by consensus.

2. **The ERC-4337 v0.7 stack deployed on that chain**, and its addresses known:
   - **`EntryPoint`** (canonical `0x0000000071727De22E5E9d8BAf0edAc6f37da032`
     exists on mainnet/most testnets; on a fresh `anvil` you deploy it — see
     `modules/fedimint-usdt-tests/tests/common/anvil.rs::deploy_4337_infra`).
   - **`SimpleAccountFactory`** and the **`SimpleAccount` implementation** it
     proxies to. **CRITICAL:** the factory's on-chain CREATE2 `initCodeHash`
     MUST match this build's vendored `ERC1967_PROXY_CREATION_CODE` (canonical
     account-abstraction v0.7 `SimpleAccountFactory`, OZ 5.0.0, solc 0.8.23
     `evmVersion=paris`). If it doesn't, off-chain-derived deposit addresses
     disagree with what the factory deploys and **any USDT sent to a derived
     address becomes unspendable.** Verify this off-chain before funding
     anything; the module only startup-warns on the all-zero placeholder, it
     cannot detect a wrong-but-nonzero factory.

3. **A fee-less USDT (or test ERC-20) token.** The module **refuses to start**
   (`init` returns `Err`) if the configured token reports a nonzero
   `basisPointsRate` — because it credits the pool by the requested transfer
   amount, not the on-chain balance delta, so a fee-charging token would go
   insolvent (see the audit register). Mainnet USDT's fee is 0; a standard test
   ERC-20 has no fee mechanism at all (the check reverts and is skipped).

4. **A funded broadcaster EOA per guardian.** Each guardian's broadcaster fronts
   the native gas token (ETH) to submit `EntryPoint.handleOps` for sweeps and
   withdrawals. Fund it with enough ETH for ongoing operation; the user's USDT
   `max_fee` is the economic reimbursement (accrues to the federation; convert
   USDT→ETH off-protocol to refill). Any guardian's broadcaster may submit a
   given op (the EntryPoint dedups by `(sender, nonce)`), so a single shared key
   across guardians is acceptable for a test.

5. **EntryPoint gas deposits prefunded for the deposit and pool accounts.**
   There is **no paymaster**, so each *sender* `SimpleAccount` (every deposit
   account, and the pool account) must have its own `EntryPoint` deposit to pay
   for its UserOp — otherwise the op fails validation (`AA21 didn't pay
   prefund`). **The module does NOT auto-prefund this today.** For a test,
   prefund via `EntryPoint.depositTo(account)` from the broadcaster. This is a
   **refundable prepayment balance**, not a cost — the account draws its actual
   UserOp gas from it and any unused remainder stays withdrawable. Size it to a
   few ops' worth of gas: a deploy-and-sweep op is ~350–450k gas and a
   withdrawal batch similar, so on a testnet this is a small fraction of an ETH
   per account (the e2e parks a flat 1 ETH only because anvil ETH is free — do
   NOT read that as a sizing recommendation; each deposit account is single-use,
   so over-provisioning just strands refundable per-account dust). Prefund:
   - the **pool account** (its address is config-derived and known immediately
     after DKG — `fedimint-cli module usdt pool-state` returns it), and
   - each **deposit account** before/around funding it with USDT (its address
     comes from `fedimint-cli module usdt deposit-address`).
   Productionizing this (broadcaster auto-`depositTo` before submitting, or an
   operator sidecar that keeps deposits topped up) is an open item.

6. **Time and patience for DKG.** Every guardian runs a threshold-ECDSA
   distributed key generation at setup, including a per-guardian Paillier
   safe-prime aux-gen that takes **a minute or more per guardian**. Config-gen
   orchestration must allow for it (devimint: set
   `FM_DEVIMINT_CONFIG_GEN_TIMEOUT_SECS`; raise your own invite-code/setup
   timeouts accordingly). This is real production DKG — the fast pregenerated
   primes are trusted-dealer/test-only and do not apply here.

## Configuration (environment variables)

Set these on every guardian's `fedimintd` process (they are captured at
process-spawn time). Module-enable flags and `mintv2`/contract config-gen
params are read by the **config-gen leader**; the RPC URL and broadcaster key
are per-guardian runtime overrides.

Module set — enable only USDT + the USDT `mintv2`, disable everything else:

```sh
FM_ENABLE_MODULE_USDT=1
FM_ENABLE_MODULE_MINTV2=1
FM_ENABLE_MODULE_MINT=0        # no Bitcoin-denominated (v1) mint
FM_ENABLE_MODULE_WALLET=0      # no Bitcoin wallet
FM_ENABLE_MODULE_WALLETV2=0
FM_ENABLE_MODULE_LNV1=0        # no Lightning
FM_ENABLE_MODULE_LNV2=0
```

Make the single `mintv2` instance USDT-denominated (there is no devimint
mechanism yet to add a *second* mint instance of the same kind, so the sole
instance is repurposed):

```sh
FM_MINTV2_AMOUNT_UNIT=1        # USDT_UNIT == AmountUnit::new_custom(1)
FM_DISABLE_BASE_FEES=1         # optional: zero the mint issuance fee so claimed
                              #   e-cash equals the deposit exactly (test only)
```

Point config-gen at the deployed contracts (override the all-zero placeholders
in `UsdtGenParams`):

```sh
FM_USDT_CONTRACT=0x…              # the USDT / test ERC-20 token
FM_USDT_ENTRY_POINT=0x…           # deployed EntryPoint v0.7
FM_USDT_ACCOUNT_FACTORY=0x…       # deployed SimpleAccountFactory (verified hash!)
FM_USDT_SIMPLE_ACCOUNT_IMPL=0x…   # its SimpleAccount implementation
```

Per-guardian runtime (need not be identical across guardians):

```sh
FM_USDT_EVM_RPC_URL=http://127.0.0.1:8545        # this guardian's EVM node
FM_USDT_BROADCASTER_PRIVATE_KEY=0x…              # this guardian's funded EOA
```

`chain_id` (default 31337 = anvil), `confirmation_depth` (default 1 — raise for
a real chain's reorg characteristics), and `check_ttl_blocks` come from
`UsdtGenParams` at config-gen; set them appropriately for the target chain
(31337/1 are anvil-test values).

## Setup steps

1. **Start the EVM chain** (`anvil` locally, or point at a testnet node).
2. **Deploy the 4337 stack** (EntryPoint → SimpleAccountFactory → read back
   `accountImplementation()`) and **deploy/choose the token**; capture all four
   addresses. **Verify** the factory's `initCodeHash`.
3. **Fund the broadcaster EOA(s)** with the chain's native gas token.
4. **Config-gen + DKG:** start the guardians with the env above; the leader bakes
   the contract addresses and enable flags into config-gen; every guardian runs
   DKG (wait it out). The group public key that owns all accounts is produced
   here.
5. **Prefund EntryPoint deposits** for the pool account
   (`module usdt pool-state` → `account`) and for each deposit account you'll
   use, via `EntryPoint.depositTo(...)` from the broadcaster.
6. **Drive the flow** with `fedimint-cli` (below).

## Driving it with `fedimint-cli`

```sh
# 1. Get a fresh deposit address (a claim key is derived + stored client-side)
fedimint-cli module usdt deposit-address        # -> { claim_pk, account }

# 2. Send USDT to `account` on-chain (a normal ERC-20 transfer), then mine/wait
#    past confirmation_depth.

# 3. Ask the guardians to start watching the address
fedimint-cli module usdt check-deposit <claim_pk>

# 4. Poll until credited
fedimint-cli module usdt deposit-status <claim_pk>   # -> credited/claimed/claimable

# 5. Claim it into USDT e-cash (blocks until the notes are actually issued)
fedimint-cli module usdt claim <claim_pk>

# 6. (Automatic) the deposit is deploy-and-swept into the pool account.
fedimint-cli module usdt pool-state                  # watch balance rise

# 7. Withdraw e-cash back on-chain to any address
fedimint-cli module usdt fee-quote <amount>          # current min max_fee
fedimint-cli module usdt withdraw <recipient> <amount>   # -> out_point (txid:idx)
fedimint-cli module usdt withdrawal-status <txid> <out_idx>   # poll to Confirmed
```

Other subcommands: `userop-status`, and `recover --gap-limit N` (rescans the
federation from the seed to restore lost deposit claim keys).

## Notes, gotchas, and rough edges

- **512-msat denomination alignment.** `mintv2` issues e-cash in a fixed
  denomination granularity (512 of the smallest USDT unit). For claimed/withdrawn
  amounts to land exactly (no un-mintable dust), use multiples of 512 in tests
  (e.g. `2_048_000`); otherwise the remainder below 512 is not minted.
- **Withdrawal batching** waits a block-count interval before firing, and only
  builds a batch the **pool balance can cover** — so a `withdraw` issued before
  the backing deposit has swept will sit `Queued` until the sweep funds the pool.
  Advance the chain (mine blocks) to move the block-count-driven trigger.
- **Client recovery** uses seed-indexed claim keys, but is a manual
  `recover` subcommand (not wired into the global `recover()` flow yet); it
  rediscovers only deposits the federation has already credited.
- **Single broadcaster per guardian** is a submission-liveness single point of
  failure (mitigated by any guardian being able to submit + idempotent
  re-submission).
- **Price source** (`usdt_per_eth_e6` in `FeeVote`) is a static placeholder — the
  withdrawal fee quote is only economically meaningful once a real gas/price feed
  is wired per guardian.
- **No dual-mint yet.** This federation cannot also hold Bitcoin-denominated
  e-cash; the single `mintv2` is repurposed to USDT. A true dual-mint federation
  awaits the `instance-list` config-gen follow-up.

## Canonical reference

`modules/fedimint-usdt-tests/bin/usdt_e2e.rs` (the `usdt-e2e-test` devimint
binary) does all of the above automatically against a local `anvil`: deploys the
4337 stack + token, sets every env var listed here, spins up the real
multi-process federation with DKG, prefunds the EntryPoint deposits, and drives
`fedimint-cli` through deposit → claim → sweep → withdraw with on-chain
assertions. Run it via `scripts/tests/usdt-e2e-test.sh` / the `test-usdt-e2e`
`just` recipe (opt-in; slow — real DKG per guardian). It is the ground truth for
this runbook.
