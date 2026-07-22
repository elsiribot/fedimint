# USDT module: real ETH/USD price feed for withdrawal fee quotes (design)

**Status:** approved design, not yet implemented. Target: consensus version
`(0, 1)` additive config (the `(0, 0)` wire/config is unreleased, so a new
config-gen field needs no migration).

## Problem

A withdrawal's fee is quoted in USDT but paid (as on-chain gas) in ETH, so the
module must convert "this withdrawal costs *G* gas at *P* wei/gas" into a USDT
charge. That conversion needs the ETH price in USD. Today it is a **hardcoded
placeholder**: `AlloyEvmRpc::get_fee_estimate` returns
`usdt_per_eth_e6: 3_000_000_000` (== $3000.000000/ETH) with a code comment
flagging it as a Phase-8 stand-in (`rpc.rs`). On a real chain, a stale ETH
price makes every withdrawal systematically over- or under-charged; undercharging
**loses the federation money on every withdrawal** (it fronts more ETH gas than
the collected USDT `max_fee` covers). This is the top economic blocker for any
real-network deployment (see `docs/usdt-module-audit.md`).

The **gas price** half is already live (real `provider.get_gas_price()`), and
the whole consensus pipeline that turns per-guardian `FeeVote`s into a quote —
median (`fee_vote_median`), 20% movement buffer (`WITHDRAWAL_FEE_BUFFER_PERCENT`),
zero-median floor (`MIN_WITHDRAWAL_FEE`), overflow-safe pure arithmetic
(`withdrawal_fee_quote`) — is built, hardened, and unchanged by this work. The
*only* fake input is `usdt_per_eth_e6`.

## Goal / non-goals

**Goal.** Each guardian votes a **real, live ETH/USD price** read from an
on-chain **Chainlink** price feed, with staleness/sanity guards, feeding the
existing median → buffer → floor → quote pipeline unchanged. Reduce the residual
"federation loses money" risk from "ETH price is permanently stale" to "ETH price
is at most a feed-heartbeat + one poll-interval old, and can never be a bad
value."

**Non-goals (explicitly deferred, recorded as follow-ups).**
1. **EIP-1559 gas sharpening.** The gas price stays `get_gas_price()` (already
   live; adequate with the 20% buffer). Switching to base-fee + priority-fee
   estimation is a separate refinement.
2. **Gas-spike-vs-quote economics.** If gas rises more than the buffer between
   quoting a user and the batched withdrawal settling, the federation eats the
   difference. That is a batching-economics question (cap-spend / re-quote /
   defer-on-spike), not a price-feed one.
3. **Alternative price sources** (exchange API, DEX/Uniswap TWAP) — Chainlink was
   chosen (maintainer decision): on-chain read (same mechanism the module already
   uses), no external-internet/API-key dependency on guardians, decentralized
   operator set, tight cross-guardian convergence.

## Architecture principle (unchanged)

The ETH price is a **guardian-local vote input**, exactly like the gas price and
the deposit-balance reads: each guardian reads the feed from its own node and
proposes a `FeeVote`; consensus takes the median. Nothing here writes a value
directly into consensus — the only pure-consensus function, `withdrawal_fee_quote`,
still consumes only the agreed median. So per-guardian read divergence, feed
hiccups, and wall-clock are all confined to the vote and re-aggregated by the
existing threshold median. No determinism invariant is touched.

## Design

### 1. The price read (`AlloyEvmRpc`, server `rpc.rs`)

`get_fee_estimate` keeps reading gas via `get_gas_price()` (unchanged) and gains
a live ETH/USD read:

- **When a feed address is configured** (non-zero `eth_usd_price_feed`): call the
  Chainlink `AggregatorV3Interface` on it (same `sol!` + `eth_call` pattern as
  `factory_get_address` / `get_erc20_basis_points_rate`):
  - `latestRoundData()` → `(uint80 roundId, int256 answer, uint256 startedAt,
    uint256 updatedAt, uint80 answeredInRound)`.
  - `decimals()` → `uint8` (ETH/USD is 8; read it rather than assume, cache per
    `AlloyEvmRpc` after first read).
  - **Sanity guard:** reject `answer <= 0`, or `answeredInRound < roundId`
    (incomplete round). Bad → treat as unavailable (see §3).
  - **Staleness guard:** read the latest block timestamp; if
    `block_timestamp − updatedAt > price_feed_max_staleness_secs`, treat as
    unavailable. (Chain time on both sides — no wall-clock, no clock-skew.)
  - **Decimals conversion (pure, deterministic):**
    `usdt_per_eth_e6 = answer * 10^6 / 10^feed_decimals`, in `u128`/`checked_*`,
    then `u64::try_from` (an ETH price fits `u64` fixed-point with 6 decimals for
    any realistic value). Overflow/oversize → unavailable.
- **When no feed is configured** (zero address — local/anvil, no Chainlink):
  fall back to the existing static `usdt_per_eth_e6` constant so hermetic/anvil
  tests keep a plausible price. This is the ONLY place the static value survives.

`get_fee_estimate` returns `Err`/`None`-equivalent when a *configured* feed is
unavailable (bad/stale), so the caller abstains (§3). It returns `Ok(FeeVote)`
when it has a real price, or when no feed is configured (static fallback).

### 2. Configuration

Add to `UsdtGenParams` (threaded IDENTICALLY through **both** `trusted_dealer_gen`
and `distributed_gen` into `UsdtConfigConsensus`, mirroring `usdt_contract` /
`entry_point`; a mismatch between the two paths is a consensus split):
- `eth_usd_price_feed: EvmAddress` — the Chainlink ETH/USD aggregator. Default =
  the canonical mainnet ETH/USD feed `0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419`
  (8 decimals). Zero address = "no feed, use static fallback" (local testing).
  Overridable via a new `FM_USDT_ETH_USD_PRICE_FEED` env in
  `default_config_gen_params`, mirroring the existing `apply_address_override`
  closures.
- `price_feed_max_staleness_secs: u64` — staleness threshold. Default ~`14_400`
  (4h): comfortably above mainnet ETH/USD's ~1h heartbeat / 0.5%-deviation
  update cadence, tight enough that a truly wedged feed is caught.

`AlloyEvmRpc` is constructed with the feed + staleness (mirror
`.with_entry_point(cfg.consensus.entry_point)` at `lib.rs`; add
`.with_price_feed(cfg.consensus.eth_usd_price_feed, cfg.consensus.price_feed_max_staleness_secs)`).

### 3. Failure behavior — abstain (maintainer-approved)

When a *configured* feed read fails a guard (unavailable / stale / bad / RPC
error), the guardian **abstains**: the fee-estimate poller does **not** propose a
new `FeeVote` that cycle (it does not fall back to the static number on a real
chain). Mechanically this matches the existing patterns:
- The poller only refreshes/proposes a `FeeVote` when it obtains a valid estimate
  (like the deposit-checker skipping on RPC error).
- A guardian's last agreed `FeeVoteKey` persists in consensus (votes are sticky,
  like `BlockCount`/`BootstrapVote`), so a brief feed hiccup leaves the
  last-known-good vote in the median; the median forms from the guardians whose
  feed is healthy. A guardian that has *never* obtained a good read simply does
  not vote until it does.
- If so few guardians have a healthy feed that no median can be formed, the quote
  path already degrades safely: `withdrawal_fee_quote` floors at
  `MIN_WITHDRAWAL_FEE`, and a withdrawal whose `max_fee` cannot be validated
  stays `Queued` rather than settling underpriced.

This strictly removes the staleness bug (a stale/bad feed never injects a price)
rather than trading it for a quieter one (a static fallback would).

### 4. Testing

- **Deterministic/unit (mock):** extend the server + tests `MockEvmRpc` with a
  scriptable feed (answer, decimals, updatedAt, roundId). Cover: happy path
  (correct decimals conversion), stale → abstain, non-positive/incomplete-round →
  abstain, no-feed-configured → static fallback, RPC error → abstain. Assert the
  existing `withdrawal_fee_quote`/median determinism tests still pass with a
  voted (non-static) price.
- **Real read path (anvil e2e):** deploy a **minimal mock Chainlink aggregator**
  (a tiny contract returning scriptable `latestRoundData`/`decimals`) on the
  anvil harness, point `eth_usd_price_feed` at it, and assert a withdrawal's
  quoted `max_fee` reflects the fed price (not the static $3000). Reuse the
  existing e2e fee-quote assertions.
- Determinism argument to preserve in review: the read is a per-guardian vote;
  only `withdrawal_fee_quote(median)` is pure-consensus and is unchanged.

## Config / env summary

| Field (`UsdtGenParams` → `UsdtConfigConsensus`) | Default | Env override |
|---|---|---|
| `eth_usd_price_feed: EvmAddress` | mainnet ETH/USD `0x5f4e…8419` | `FM_USDT_ETH_USD_PRICE_FEED` |
| `price_feed_max_staleness_secs: u64` | `14_400` (4h) | (none; config-gen param) |

## Residual risks / documented follow-ups

- **Poll-interval + heartbeat lag.** The voted price is at most one feed heartbeat
  + one poll interval old. Acceptable; ETH rarely moves enough intra-heartbeat to
  break the 20% buffer.
- **Gas spike between quote and settlement** (non-goal 2) — unchanged by this
  work; still covered only by the 20% buffer. Record in the audit doc.
- **Chainlink trust.** We inherit Chainlink's operator-set assumptions and its
  own failure modes (feed deprecation, frozen aggregator) — the staleness/sanity
  guards + abstain are the mitigations; a feed swap is a config change.
- **EIP-1559 gas sharpening** (non-goal 1) — follow-up.

## Acceptance

Withdrawal fee quotes on a real (test) network reflect the live on-chain ETH/USD
price within one heartbeat+poll, a stale/bad feed causes abstention (never a bad
quote), and all existing fee-quote/median determinism tests stay green. Update
`docs/usdt-module.md` (price-source line) + `docs/usdt-module-audit.md` (retire
"static price placeholder" from the risk register; keep the gas-spike residual).
