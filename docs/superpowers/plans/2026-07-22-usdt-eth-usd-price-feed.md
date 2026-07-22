# ETH/USD Price Feed (Chainlink) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hardcoded `usdt_per_eth_e6 = $3000` placeholder in withdrawal fee quotes with a live, guarded Chainlink on-chain ETH/USD price each guardian votes into the existing `FeeVote` median pipeline.

**Architecture:** A pure `common` helper applies sanity/staleness guards + decimals conversion to a raw Chainlink `latestRoundData` reading (fully unit-testable). `AlloyEvmRpc::get_fee_estimate` reads the feed on-chain and calls that helper; a bad/stale/unconfigured-on-a-real-chain read makes the guardian **abstain** (the fee poller skips its vote that cycle). When no feed address is configured (local/anvil), a static fallback preserves today's behavior. The median → 20% buffer → `MIN_WITHDRAWAL_FEE` floor → `withdrawal_fee_quote` consensus pipeline is unchanged.

**Tech Stack:** Rust, `alloy` (sol!/eth_call), fedimint module config-gen, anvil + forge (e2e).

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-22-usdt-eth-usd-price-feed-design.md` (authoritative).
- NEVER `unwrap()` in non-test code — use `expect("why")`. (`CLAUDE.md`)
- `common` and `client` crates stay WASM-safe: no new deps beyond `alloy-primitives`; no `alloy` provider / `cggmp21` / `gmp`. The pure helper lives in `common` using only integer math.
- Structured `tracing` logging, `target: "usdt"`, field=value.
- New config field threaded **IDENTICALLY** through BOTH `trusted_dealer_gen` (`modules/fedimint-usdt-server/src/lib.rs:607`) AND `distributed_gen` (`modules/fedimint-usdt-server/src/dkg.rs:308`) — a mismatch is a consensus split.
- Determinism: the price read is a per-guardian **vote input** only; the sole pure-consensus function `withdrawal_fee_quote(median)` is unchanged. No consensus DB write is added.
- Run linters via `just clippy` / format via `just format` (NOT raw cargo) for final passes. (memory: use-just)
- Commits: `git commit --no-gpg-sign --no-verify`. Controller runs the anvil/devimint e2e; subagents compile + run unit/hermetic tests only.
- Config-address convention: contract addresses default to the all-zero placeholder EXCEPT this feed, which defaults to the canonical mainnet ETH/USD feed `0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419` (a stale-price footgun is worse than a loud "no quote" on a misconfigured non-mainnet chain — see spec §3). Test harnesses that run real `AlloyEvmRpc` against anvil MUST set it to the all-zero address (→ static fallback) or a deployed mock aggregator.

---

### Task 1: Pure Chainlink→`usdt_per_eth_e6` conversion helper (common)

**Files:**
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (add fn + `#[cfg(test)]` tests near `withdrawal_fee_quote`).

**Interfaces:**
- Produces: `pub fn chainlink_eth_usd_to_usdt_per_eth_e6(answer: i128, feed_decimals: u8, round_id: u128, answered_in_round: u128, updated_at: u64, chain_now: u64, max_staleness_secs: u64) -> Option<u64>` — used by Task 3.

- [ ] **Step 1: Write the failing tests**

Add to the `#[cfg(test)]` module in `modules/fedimint-usdt-common/src/lib.rs`:

```rust
#[test]
fn chainlink_price_happy_path_8_decimals() {
    // $3000.00 at 8 decimals, fresh, complete round -> 3000_000000 (1e-6 USDT)
    let v = chainlink_eth_usd_to_usdt_per_eth_e6(
        3000_00000000, 8, 42, 42, 1_000, 1_500, 14_400,
    );
    assert_eq!(v, Some(3_000_000_000));
}

#[test]
fn chainlink_price_rejects_non_positive_answer() {
    assert_eq!(chainlink_eth_usd_to_usdt_per_eth_e6(0, 8, 1, 1, 1_000, 1_000, 14_400), None);
    assert_eq!(chainlink_eth_usd_to_usdt_per_eth_e6(-1, 8, 1, 1, 1_000, 1_000, 14_400), None);
}

#[test]
fn chainlink_price_rejects_incomplete_round() {
    // answered_in_round < round_id -> carried-over/incomplete
    assert_eq!(chainlink_eth_usd_to_usdt_per_eth_e6(3000_00000000, 8, 42, 41, 1_000, 1_100, 14_400), None);
}

#[test]
fn chainlink_price_rejects_stale() {
    // chain_now - updated_at (20_000) > max_staleness (14_400)
    assert_eq!(chainlink_eth_usd_to_usdt_per_eth_e6(3000_00000000, 8, 1, 1, 1_000, 21_000, 14_400), None);
}

#[test]
fn chainlink_price_rejects_future_timestamp() {
    // updated_at > chain_now (clock/feed anomaly) -> abstain
    assert_eq!(chainlink_eth_usd_to_usdt_per_eth_e6(3000_00000000, 8, 1, 1, 2_000, 1_000, 14_400), None);
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p fedimint-usdt-common chainlink_price 2>&1 | tail -20`
Expected: FAIL — `cannot find function chainlink_eth_usd_to_usdt_per_eth_e6`.

- [ ] **Step 3: Implement the helper**

Add near `withdrawal_fee_quote` in `modules/fedimint-usdt-common/src/lib.rs`:

```rust
/// Converts a Chainlink ETH/USD `latestRoundData()` reading into
/// [`FeeVote::usdt_per_eth_e6`], applying sanity + staleness guards. Pure and
/// WASM-safe (integer math only). Returns `None` — meaning the guardian should
/// ABSTAIN from voting a price this cycle — when the reading is unusable:
/// non-positive `answer`, incomplete round (`answered_in_round < round_id`),
/// stale (`chain_now - updated_at > max_staleness_secs`, or `updated_at` in the
/// future), or the `answer * 1e6 / 10^feed_decimals` conversion overflows.
/// All inputs are read from the on-chain feed by the caller (see
/// `fedimint_usdt_server::rpc::AlloyEvmRpc::get_fee_estimate`).
#[must_use]
pub fn chainlink_eth_usd_to_usdt_per_eth_e6(
    answer: i128,
    feed_decimals: u8,
    round_id: u128,
    answered_in_round: u128,
    updated_at: u64,
    chain_now: u64,
    max_staleness_secs: u64,
) -> Option<u64> {
    if answer <= 0 || answered_in_round < round_id {
        return None;
    }
    // `checked_sub` returns None if `updated_at` is in the future.
    if chain_now.checked_sub(updated_at)? > max_staleness_secs {
        return None;
    }
    let answer = u128::try_from(answer).ok()?;
    let scaled = answer.checked_mul(1_000_000)?; // 1e6 USDT fixed-point
    let divisor = 10u128.checked_pow(u32::from(feed_decimals))?;
    u64::try_from(scaled.checked_div(divisor)?).ok()
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p fedimint-usdt-common chainlink_price 2>&1 | tail -20`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add modules/fedimint-usdt-common/src/lib.rs
git commit --no-gpg-sign --no-verify -m "feat(usdt): pure Chainlink ETH/USD -> usdt_per_eth_e6 helper with guards"
```

---

### Task 2: Config-gen fields + env override (common + server)

**Files:**
- Modify: `modules/fedimint-usdt-common/src/lib.rs` (`UsdtGenParams` struct + its `Default`).
- Modify: `modules/fedimint-usdt-server/src/config.rs:117` (`UsdtConfigConsensus` struct).
- Modify: `modules/fedimint-usdt-server/src/lib.rs:607` (`trusted_dealer_gen` UsdtConfigConsensus literal) + `default_config_gen_params` (~line 356, add env override).
- Modify: `modules/fedimint-usdt-server/src/dkg.rs:308` (`distributed_gen` UsdtConfigConsensus literal).
- Modify: `fedimint-core/src/envs.rs` (add `FM_USDT_ETH_USD_PRICE_FEED_ENV` const + register in `get_documented_env_vars`, mirroring `FM_USDT_ACCOUNT_FACTORY_ENV`).

**Interfaces:**
- Produces: `UsdtGenParams.eth_usd_price_feed: EvmAddress`, `UsdtGenParams.price_feed_max_staleness_secs: u64`; same two fields on `UsdtConfigConsensus`. Consumed by Task 3.

- [ ] **Step 1: Add the fields + defaults**

In `modules/fedimint-usdt-common/src/lib.rs`, add to `pub struct UsdtGenParams`:

```rust
    /// Chainlink ETH/USD aggregator address whose `latestRoundData()` each
    /// guardian reads to vote `FeeVote::usdt_per_eth_e6`. Defaults to the
    /// canonical mainnet ETH/USD feed; set to `EvmAddress([0; 20])` on a chain
    /// without Chainlink (e.g. anvil) to fall back to a static price. See
    /// `chainlink_eth_usd_to_usdt_per_eth_e6`.
    pub eth_usd_price_feed: EvmAddress,
    /// Max age (seconds, chain time) of a Chainlink reading before a guardian
    /// abstains. ~1h heartbeat feeds -> 4h default is comfortably above cadence.
    pub price_feed_max_staleness_secs: u64,
```

In its `Default` impl add:

```rust
            eth_usd_price_feed: EvmAddress(hex_literal::hex!(
                "5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"
            )),
            price_feed_max_staleness_secs: 14_400,
```

(If `hex_literal` is not already imported in this file, use the existing hex mechanism already used for addresses in this module — check the top of the file; `alloy_primitives::hex!` is available and returns a `[u8; N]`.)

In `modules/fedimint-usdt-server/src/config.rs`, add the same two fields to `pub struct UsdtConfigConsensus` (with brief doc comments referencing the gen params).

- [ ] **Step 2: Thread through BOTH gen paths (identically)**

In `modules/fedimint-usdt-server/src/lib.rs:607` (`trusted_dealer_gen`) and `modules/fedimint-usdt-server/src/dkg.rs:308` (`distributed_gen`), inside each `UsdtConfigConsensus { ... }` literal add:

```rust
                        eth_usd_price_feed: params.eth_usd_price_feed,
                        price_feed_max_staleness_secs: params.price_feed_max_staleness_secs,
```

(Match the exact field-access style already used for `entry_point`/`account_factory` in each literal.)

- [ ] **Step 3: Env override in `default_config_gen_params`**

In `modules/fedimint-usdt-server/src/lib.rs` `default_config_gen_params`, after the existing `apply_address_override`/`env_override` calls for `account_factory`, add (mirroring the exact helper used there):

```rust
        if let Some(feed) = env_override(FM_USDT_ETH_USD_PRICE_FEED_ENV) {
            params.eth_usd_price_feed = feed;
        }
```

In `fedimint-core/src/envs.rs`, add next to the other `FM_USDT_*` consts:

```rust
/// Overrides the ERC-4337 USDT module's Chainlink ETH/USD price-feed address
/// (a 0x-prefixed 20-byte hex EVM address) for the config-gen leader.
pub const FM_USDT_ETH_USD_PRICE_FEED_ENV: &str = "FM_USDT_ETH_USD_PRICE_FEED";
```

and add it to `get_documented_env_vars` where the other `FM_USDT_*` vars are listed.

- [ ] **Step 4: Verify it compiles**

Run: `cargo check --workspace 2>&1 | grep -E "^error" | head; echo EXIT ${PIPESTATUS[0]}`
Expected: no errors, EXIT 0.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit --no-gpg-sign --no-verify -m "feat(usdt): config-gen params for the ETH/USD price feed (address + staleness)"
```

---

### Task 3: `AlloyEvmRpc` reads the feed; poller abstains on error (server)

**Files:**
- Modify: `modules/fedimint-usdt-server/src/rpc.rs` (`AlloyEvmRpc` fields ~283, `new` ~315, add `with_price_feed`, add `IAggregatorV3` sol! interface, rewrite `get_fee_estimate`).
- Modify: `modules/fedimint-usdt-server/src/lib.rs:469` (construct `AlloyEvmRpc` with `.with_price_feed(...)`).
- Modify: `modules/fedimint-usdt-server/src/lib.rs` `spawn_fee_estimate_poller` (skip vote update on `Err`).

**Interfaces:**
- Consumes: `chainlink_eth_usd_to_usdt_per_eth_e6` (Task 1); `UsdtConfigConsensus.{eth_usd_price_feed, price_feed_max_staleness_secs}` (Task 2).
- Produces: `AlloyEvmRpc::with_price_feed(self, feed: EvmAddress, max_staleness_secs: u64) -> Self`.

- [ ] **Step 1: Add fields + builder + sol! interface**

In `modules/fedimint-usdt-server/src/rpc.rs`, add to the `AlloyEvmRpc` struct:

```rust
    /// Chainlink ETH/USD feed; `None` or all-zero -> static price fallback.
    eth_usd_price_feed: Option<EvmAddress>,
    price_feed_max_staleness_secs: u64,
```

Initialize both in `new` (`eth_usd_price_feed: None, price_feed_max_staleness_secs: 0`). Add the builder (mirror `with_entry_point`):

```rust
    /// Configure the Chainlink ETH/USD feed the fee poller reads. An all-zero
    /// address disables it (static fallback).
    #[must_use]
    pub fn with_price_feed(mut self, feed: EvmAddress, max_staleness_secs: u64) -> Self {
        self.eth_usd_price_feed = (feed.0 != [0u8; 20]).then_some(feed);
        self.price_feed_max_staleness_secs = max_staleness_secs;
        self
    }
```

Add the sol! interface near the others (`ISimpleAccountFactory`, `IERC20`):

```rust
    sol! {
        #[sol(rpc)]
        interface IAggregatorV3 {
            function decimals() external view returns (uint8);
            function latestRoundData() external view returns (
                uint80 roundId, int256 answer, uint256 startedAt,
                uint256 updatedAt, uint80 answeredInRound);
        }
    }
```

Add a named const for the fallback near the top of the impl:

```rust
/// Static ETH/USD fallback (== $3000.000000/ETH) used only when NO Chainlink
/// feed is configured (e.g. local anvil). A real deployment configures a feed.
const STATIC_USDT_PER_ETH_E6: u64 = 3_000_000_000;
```

- [ ] **Step 2: Rewrite `get_fee_estimate`**

Replace `AlloyEvmRpc::get_fee_estimate` with:

```rust
    async fn get_fee_estimate(&self) -> anyhow::Result<FeeVote> {
        let gas_price_wei: u128 = self.provider.get_gas_price().await?;
        let max_fee_per_gas_wei = u64::try_from(gas_price_wei)
            .with_context(|| format!("gas price {gas_price_wei} wei overflows u64"))?;

        let usdt_per_eth_e6 = match self.eth_usd_price_feed {
            Some(feed) => {
                let feed_addr = Address::from(feed.0);
                let aggregator = IAggregatorV3::new(feed_addr, &self.provider);
                let decimals = aggregator.decimals().call().await?;
                let round = aggregator.latestRoundData().call().await?;
                let block = self
                    .provider
                    .get_block(alloy::eips::BlockId::latest())
                    .await?
                    .context("latest block missing for price staleness check")?;
                let chain_now = block.header.timestamp;

                let answer: i128 = round.answer.try_into().ok().context(
                    "Chainlink answer does not fit i128",
                )?;
                fedimint_usdt_common::chainlink_eth_usd_to_usdt_per_eth_e6(
                    answer,
                    decimals,
                    u128::from(round.roundId),
                    u128::from(round.answeredInRound),
                    u64::try_from(round.updatedAt).unwrap_or(u64::MAX),
                    chain_now,
                    self.price_feed_max_staleness_secs,
                )
                .context(
                    "Chainlink ETH/USD reading unusable (stale/invalid); abstaining from FeeVote",
                )?
            }
            None => STATIC_USDT_PER_ETH_E6,
        };

        Ok(FeeVote {
            max_fee_per_gas_wei,
            usdt_per_eth_e6,
        })
    }
```

(Adjust `round.answer`/`round.roundId` field access + `BlockId`/`get_block` call to the exact alloy 2.x API already used elsewhere in this file — grep `get_block`/`try_into` usages; `U256`/`I256` conversions mirror the existing `get_erc20_balance` pattern.)

- [ ] **Step 3: Wire construction + poller abstain**

In `modules/fedimint-usdt-server/src/lib.rs:469`, extend the builder chain:

```rust
                AlloyEvmRpc::new(&evm_rpc_url)?
                    .with_entry_point(cfg.consensus.entry_point)
                    .with_price_feed(
                        cfg.consensus.eth_usd_price_feed,
                        cfg.consensus.price_feed_max_staleness_secs,
                    );
```

In `spawn_fee_estimate_poller`, ensure a `get_fee_estimate` `Err` does NOT overwrite `fee_estimate` (keep last good; abstain). If the current body does `if let Ok(vote) = evm_rpc.get_fee_estimate().await { *fee_estimate.lock()... = Some(vote) }` it already abstains — confirm and, on `Err`, add a `warn!(target: "usdt", ...)`. If it currently `?`-propagates or overwrites with a default, change it to the skip-on-`Err` shape:

```rust
                match evm_rpc.get_fee_estimate().await {
                    Ok(vote) => *fee_estimate.lock().expect("not poisoned") = Some(vote),
                    Err(err) => warn!(
                        target: "usdt",
                        err = %err.fmt_compact_anyhow(),
                        "fee estimate poll failed; keeping last vote (abstaining this cycle)"
                    ),
                }
```

- [ ] **Step 4: Verify compile + existing fee/hermetic behavior**

Run: `cargo check --workspace --all-targets 2>&1 | grep -E "^error" | head; echo EXIT ${PIPESTATUS[0]}`
Expected: EXIT 0.
Run: `cargo test -p fedimint-usdt-common withdrawal_fee_quote 2>&1 | tail -5`
Expected: PASS (median/quote determinism unaffected).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit --no-gpg-sign --no-verify -m "feat(usdt): read Chainlink ETH/USD in get_fee_estimate; abstain on bad feed"
```

---

### Task 4: Keep real-`AlloyEvmRpc` anvil harnesses green (static fallback)

The default feed is the mainnet address, which does not exist on anvil, so the three real-stack anvil e2e tests + the devimint binary must set the feed to the all-zero address (→ static fallback) to keep passing. (Hermetic tests use `MockEvmRpc`, which returns a scripted `FeeVote` and ignores the feed — no change needed there.)

**Files:**
- Modify: `modules/fedimint-usdt-tests/tests/deploy_and_sweep_e2e.rs`, `tests/withdraw_e2e.rs`, `tests/nonstandard_usdt_e2e.rs` (the `UsdtGenParams`/gen-params construction — set `eth_usd_price_feed: EvmAddress([0; 20])`, `price_feed_max_staleness_secs: 14_400`).
- Modify: `modules/fedimint-usdt-tests/bin/usdt_e2e.rs` (export `FM_USDT_ETH_USD_PRICE_FEED=0x0000000000000000000000000000000000000000` alongside the other `FM_USDT_*` env, so the leader's gen-params use the static fallback).

- [ ] **Step 1: Set the feed to zero in the three e2e gen-params**

In each of the three test files, where the gen params are built (grep `UsdtGenParams`/`derive_account_factory` from Part A), add the two fields set to `EvmAddress([0u8; 20])` / `14_400`. Follow the struct-literal style already present.

- [ ] **Step 2: Set the env in the devimint binary**

In `modules/fedimint-usdt-tests/bin/usdt_e2e.rs`, next to the existing `FM_USDT_ENTRY_POINT` env set, add setting `FM_USDT_ETH_USD_PRICE_FEED` to the all-zero address string (use the `fedimint_core::envs::FM_USDT_ETH_USD_PRICE_FEED_ENV` const for the key).

- [ ] **Step 3: Verify compile**

Run: `cargo check -p fedimint-usdt-tests --tests --bins 2>&1 | grep -E "^error" | head; echo EXIT ${PIPESTATUS[0]}`
Expected: EXIT 0.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit --no-gpg-sign --no-verify -m "test(usdt): pin anvil/devimint e2e to static ETH/USD fallback (no Chainlink on anvil)"
```

---

### Task 5: Anvil e2e — real read from a mock Chainlink aggregator (controller-run)

**Files:**
- Create: `modules/fedimint-usdt-tests/contracts/MockAggregatorV3.sol` + compiled fixture `modules/fedimint-usdt-tests/tests/fixtures/mock_aggregator_v3.json` (forge-compiled, like `NonStandardUsdt`).
- Modify: `modules/fedimint-usdt-tests/tests/common/anvil.rs` (a `deploy_mock_price_feed(anvil, answer_e8) -> EvmAddress` helper).
- Modify: `modules/fedimint-usdt-tests/tests/withdraw_e2e.rs` (deploy the mock feed, point `eth_usd_price_feed` at it, assert the quoted `max_fee` reflects the fed price, not `$3000`).

**Interfaces:**
- Consumes: config field (Task 2), read path (Task 3).

- [ ] **Step 1: Write the mock aggregator contract**

`modules/fedimint-usdt-tests/contracts/MockAggregatorV3.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

contract MockAggregatorV3 {
    int256 private _answer;
    uint8 private _decimals;
    uint256 private _updatedAt;
    uint80 private _roundId;

    constructor(int256 answer_, uint8 decimals_) {
        _answer = answer_;
        _decimals = decimals_;
        _updatedAt = block.timestamp;
        _roundId = 1;
    }

    function decimals() external view returns (uint8) { return _decimals; }

    function latestRoundData()
        external view
        returns (uint80, int256, uint256, uint256, uint80)
    {
        return (_roundId, _answer, _updatedAt, _updatedAt, _roundId);
    }
}
```

Compile it with the vendored forge (mirror how `NonStandardUsdt.sol` -> `nonstandard_usdt.json` is produced; document the exact `forge` invocation in a comment in the `.sol` file) and save the artifact JSON.

- [ ] **Step 2: Add the deploy helper**

In `modules/fedimint-usdt-tests/tests/common/anvil.rs`, add `deploy_mock_price_feed` mirroring `deploy_test_erc20` (constructor-encode `answer_e8: i256` + `decimals: u8`, send creation tx, return the deployed `EvmAddress`).

- [ ] **Step 3: Assert the fed price flows into the quote (in `withdraw_e2e`)**

In `withdraw_e2e.rs`: deploy the mock feed at e.g. `4000_00000000` (=$4000, 8 decimals), set `eth_usd_price_feed` to it (and a large staleness), and after readiness, assert the `fee-quote` for a fixed amount is **strictly greater** than the same quote computed at the static `$3000` (a $4000 ETH price => higher USDT gas cost). Reuse the existing `fee-quote` CLI/API assertion in that test; compute the expected relation with `withdrawal_fee_quote` rather than a magic number.

- [ ] **Step 4: (Controller) run it**

Run: `NEXTEST=1 cargo test -p fedimint-usdt-tests --test withdraw_e2e 2>&1 | tail -15`
Expected: PASS. **The controller runs this** (real anvil). Subagent: ensure it compiles (`cargo check -p fedimint-usdt-tests --tests`).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit --no-gpg-sign --no-verify -m "test(usdt): anvil e2e reads a live mock Chainlink feed into the withdrawal quote"
```

---

### Task 6: Docs

**Files:**
- Modify: `docs/usdt-module.md` (Price source bullet), `docs/usdt-module-audit.md` (retire the static-price row; keep the gas-spike residual), `docs/usdt-test-federation.md` (note `FM_USDT_ETH_USD_PRICE_FEED` + that anvil uses the static fallback).

- [ ] **Step 1: Update the three docs**

- `docs/usdt-module.md`: change the "Price source ... devnet: static" line to describe the Chainlink feed + per-guardian vote + abstain-on-stale.
- `docs/usdt-module-audit.md`: in the deferred/accepted table, replace the "static price placeholder" entry with "resolved (Chainlink feed, staleness-guarded, abstain)"; ADD/keep a "gas spike between quote and settlement" residual row and an "EIP-1559 gas sharpening" follow-up.
- `docs/usdt-test-federation.md`: add `FM_USDT_ETH_USD_PRICE_FEED` to the env list; note anvil has no Chainlink so the all-zero address / static fallback is used in tests.

- [ ] **Step 2: Verify + format**

Run: `just format >/dev/null 2>&1; echo done`

- [ ] **Step 3: Commit**

```bash
git add -A
git commit --no-gpg-sign --no-verify -m "docs(usdt): document the Chainlink ETH/USD price feed + retire static-price risk"
```

---

## Self-Review

**Spec coverage:** §1 price read → Task 3; guards/decimals → Task 1; §2 config/env → Task 2; §3 abstain → Task 3 (poller) + Task 1 (None); §4 testing → Tasks 1 (unit) + 5 (anvil real read); non-goals (gas) → untouched by design; docs/acceptance → Task 6 + Task 5 assertion. Static-fallback-preserves-existing-tests → Task 4. All covered.

**Placeholder scan:** all code steps carry real code; the two "adjust to exact alloy API" notes (Task 3) point at existing in-file patterns to copy, not vague TODOs. Acceptable (the alloy field/casing differs by version and must match the file).

**Type consistency:** `chainlink_eth_usd_to_usdt_per_eth_e6` signature identical in Task 1 (def) and Task 3 (call); `with_price_feed(feed, max_staleness_secs)` identical in Task 3 (def) and lib.rs wiring; `eth_usd_price_feed`/`price_feed_max_staleness_secs` field names identical across common/server/config/gen-paths/rpc.
