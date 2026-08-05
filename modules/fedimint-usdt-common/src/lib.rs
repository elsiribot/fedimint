#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::fmt;

use anyhow::{Context as _, ensure};
use config::UsdtClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{AmountUnit, CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{Amount, OutPoint, plugin_types_trait_impl_common, secp256k1};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

// Common contains types shared by both the client and server

// The client (and, in later phases, server) configuration
pub mod config;
pub mod endpoint_constants;
pub mod user_op;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("usdt");

/// Modules are non-compatible with older versions
///
/// Bumped to `0.1` (sec-01 hardening): the debug-signing-oracle consensus
/// item was removed from `UsdtConsensusItem` and `SigningPurpose` lost its
/// debug-only variant -- both consensus-encoded types changed shape, so old
/// and new binaries can no longer agree on the wire format.
///
/// Bumped to `0.2` (sec-13 hardening): the (since-removed) deposit-check API
/// response gained a `ready` field, changing its wire shape at the time. The
/// whole guardian-poll deposit path was later removed when deposit crediting
/// became proof-driven (see [`UsdtInput::DepositProofV0`]); this historical
/// note is retained only to explain the version number.
///
/// Bumped to `0.3` (sec-misc #4/06-facet): [`WithdrawFeeQuoteResponse`] and
/// [`DepositFeeQuoteResponse`] gained an `available` field (their wire shape
/// changed). Neither type is a stored consensus-DB record (they are computed
/// on the fly from the `FeeVote` table on every call), so no
/// `get_database_migrations` entry/snapshot is needed for this bump.
///
/// Bumped to `0.4` (sec-06 hardening): `FeeVoteKey`'s stored value changed
/// from a bare `FeeVote` to `StoredFeeVote` (adds a `recorded_block`
/// freshness stamp), a consensus-DB record shape change handled by
/// `migrate_db_v0`.
///
/// Bumped to `0.5` (sec-04/12/15 hardening): [`DepositObservation`],
/// [`UserOpReceipt`](user_op::UserOpReceipt), the server's
/// `UserOpConfirmedObservation`, and the [`UsdtConsensusItem::UserOpConfirmed`]
/// consensus item all gained a `block_hash` field binding an observation to a
/// canonical fork (so reorg-divergent votes no longer aggregate). The two
/// affected vote tables (`DepositObservationVote`, `UserOpConfirmedVote`) are
/// transient and re-formed every scan/submit tick, so `migrate_db_v1` DROPS
/// their old-shape rows rather than rewriting them (mirroring
/// `migrate_db_v0`).
///
/// Bumped to `0.7` (sec-05 hardening, poisoned-batch isolation): a brand-new
/// consensus-DB record, `WithdrawalBatchCapKey(OutPoint) -> u32`, was added
/// (server's `db.rs`). It is a new prefix holding only new data -- no
/// existing stored value's shape changed -- so no `get_database_migrations`
/// entry/snapshot was needed, only `dump_database` coverage.
///
/// Bumped to `0.8` (sec-09 hardening, terminal-withdrawal refund): several
/// consensus-serialized types changed shape to reissue e-cash for a
/// terminally-failed withdrawal. [`UsdtOutputV0`] gained a client-controlled
/// `refund_pubkey`; [`UsdtInput`] gained a `RefundV0 { out_point }` variant
/// (and [`UsdtInputError`] an `UnknownRefund`); the
/// [`UsdtConsensusItem::UserOpConfirmed`] item and the server's
/// `UserOpConfirmedObservation` gained `actual_gas_cost_wei` (so a failed
/// batch's on-chain gas can be deducted from the refund). Two new server
/// consensus-DB records were added -- `RefundKey(OutPoint) -> Refund` (the
/// reissuance obligation, subtracted by `audit` and cleared exactly once on
/// claim) and `WithdrawalIncurredFeeKey(OutPoint) -> UsdtAmount` (the
/// per-withdrawal accumulated incurred gas) -- and the persistent
/// `UsdtWithdrawalV0` record gained `refund_pubkey`. See `migrate_db_v3` for
/// how the persistent `UsdtWithdrawalV0` change is handled.
///
/// Bumped to `0.9` (deposit-by-proof feature): several consensus-serialized
/// types and DB keyspaces changed shape to make deposit crediting
/// proof-driven rather than guardian-poll-driven. On the wire,
/// [`UsdtConsensusItem`] gained a `BlockHash` variant (the canonical
/// block-hash anchor vote, Task 4) and [`UsdtInput`] gained a
/// `DepositProofV0` variant (with new [`UsdtInputError`] variants, Task 5).
/// In the consensus DB, two new prefixes were added -- `BlockHashRing`
/// (`0x13`, Task 3) and `BlockHashVote` (`0x14`, Task 4) -- and the old
/// guardian-poll `PendingCheck` table (prefix `0x05`) was removed (Task 6),
/// leaving `0x05` a permanent gap in `DbKeyPrefix`. The two new prefixes
/// start empty and fill at runtime (no migration needed for them); any
/// residual `PendingCheck` rows are dropped by `migrate_db_v4`. Existing
/// `DepositRecord`s are untouched (their `credited` high-water marks carry
/// forward). See `migrate_db_v4`.
///
/// Bumped to `0.10` (finding B1): the over-ceiling withdrawal-reprice path in
/// the server's `process_replace_user_op` no longer refunds-and-purges a
/// still-live, threshold-signed op. The old behavior reissued the covered
/// withdrawals' e-cash as a refund AND removed the op even though its
/// `(sender, nonce)` was still live on-chain with an unconsumed nonce, so a
/// later confirmation paid the recipient a SECOND time (double pay). The op is
/// now kept live so a later confirmation settles it exactly-once via
/// `apply_user_op_confirmed`.
///
/// Over-ceiling reprice re-evaluation (still `0.10`; refines unreleased
/// behavior, no version bump -- security review F4): a withdrawal whose reprice
/// would exceed the covered withdrawals' committed `max_fee` ceiling now STALLS
/// but stays eligible to reprice later. Previously the stall marked the op
/// `superseded`, which permanently removed it from `propose_replace_user_ops`'
/// re-evaluation, so it could only ever settle at its ORIGINAL fee even if gas
/// later fell to a level where the reprice would fit under the ceiling --
/// wedging the one-batch-at-a-time withdrawal queue for that whole window.
/// Instead the over-ceiling apply path is now a non-state-changing `Err` (no
/// DB write, no consensus-history bloat) that leaves the `SubmittedUserOp` LIVE
/// and NON-superseded, and `propose_replace_user_ops` gates a timed-out
/// `Withdraw` op on a shared, deterministic affordability check: it proposes a
/// reprice only when the current fee median prices the batch back UNDER the
/// committed ceiling. The stall thus self-heals -- the reprice fires the moment
/// fees fall under the ceiling -- while a late on-chain confirm still settles
/// the live op exactly-once (no double pay). This is a deterministic apply/
/// propose-path BEHAVIOR change only: no consensus-serialized type, wire shape,
/// or DB record layout changed, so there is no `get_database_migrations`
/// entry/snapshot for these bumps.
///
/// Bumped to `0.11` (finding A): batched recovery of stranded `EntryPoint` gas
/// deposits. Single-use deposit accounts are deployed and swept once and then
/// abandoned, but the ERC-4337 `EntryPoint` gas deposit funding that
/// deploy-and-sweep op is left stranded in the account's `EntryPoint` balance.
/// The federation now automatically recovers that residual by building a
/// threshold-signed op that calls `EntryPoint.withdrawTo(recipient, amount)`
/// and sends the residual to a DETERMINISTIC recipient. On the wire,
/// [`UsdtConsensusItem`] gained a `RecoverResidual` variant (a per-peer
/// observation vote of a swept account's on-chain `EntryPoint` deposit) and
/// `UserOpPurpose` gained a `RecoverResidual` variant (both append-only); the
/// consensus config gained a `residual_recovery_recipient` `EvmAddress` field
/// (the per-guardian broadcaster is non-deterministic and cannot be the
/// recipient of a threshold-signed op). No DB migration; the new enum variants
/// are append-only and no keyspace changed. Existing feds must be reconfigured
/// to set the new consensus field.
///
/// Residual-recovery vote hygiene (still `0.11`; refines unreleased behavior,
/// no version bump): a `RecoverResidual` vote is now VALIDATED before it is
/// stored -- rejected (non-state-changingly) unless its account exists and is
/// fully swept -- and ALL of an account's recovery votes are GARBAGE-COLLECTED
/// when a recovery op for it confirms (success or revert). Together this keeps
/// the vote table bounded and forces every recovery to re-cross a FRESH
/// threshold of votes, so stale post-recovery votes plus one byzantine
/// vote-flip can no longer re-trigger a bogus oversized recovery.
///
/// Bumped to `0.12`: guardian fee withdrawal. Appends two trailing
/// `UsdtAmount` fields (`DepositRecord.fees_accrued`, `PoolState.accrued_fees`,
/// migrated by `migrate_db_v5`), appends `UserOpPurpose::WithdrawFees` and
/// `UsdtConsensusItem::WithdrawFeesVote` (both append-only wire variants), and
/// adds the `WithdrawFeesVote` keyspace (`0x16`). Read-side:
/// `PoolStateResponse` gains an `accrued_fees` field.
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 12);

/// The [`AmountUnit`] that USDT-denominated ecash is issued in.
///
/// This is a coordination constant: it must be used both as the
/// `mintv2` config-gen param (`fedimint_mintv2_common::config::MintGenParams
/// { amount_unit: USDT_UNIT, .. }`) for the mint instance that issues
/// USDT-denominated notes, *and* by the usdt module's own consensus logic
/// (`process_input`/`process_output`, added in a later phase) when crediting
/// or debiting a guardian-observed USDT deposit/withdrawal. The client's
/// per-unit primary-module routing (`Client::primary_module_for_unit`) keys
/// off this exact value, so any mismatch between the mint instance's
/// configured unit and the value the usdt module credits would silently
/// route balance to the wrong (or no) mint instance.
pub const USDT_UNIT: AmountUnit = AmountUnit::new_custom(1);

/// A 20-byte EVM (Ethereum-style) address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EvmAddress(pub [u8; 20]);

impl fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;

        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl std::str::FromStr for EvmAddress {
    type Err = anyhow::Error;

    /// Parses the inverse of [`Self::fmt`]: an optionally `0x`-prefixed,
    /// 40-hex-character (20-byte) address.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_str = s.strip_prefix("0x").unwrap_or(s);
        anyhow::ensure!(
            hex_str.len() == 40,
            "EvmAddress must be a (optionally 0x-prefixed) 20-byte hex address, got {} hex chars in {s:?}",
            hex_str.len()
        );

        let mut bytes = [0u8; 20];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
                .with_context(|| format!("invalid hex byte at position {i} in {s:?}"))?;
        }

        Ok(Self(bytes))
    }
}

/// An amount of USDT expressed in its smallest on-chain unit (10^-6 USDT).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct UsdtAmount(pub u64);

impl fmt::Display for UsdtAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Moves a [`UsdtAmount`] through the core [`Amount`] API (custom
/// [`USDT_UNIT`](fedimint_core::module::AmountUnit) == this module's own
/// smallest on-chain unit, 10^-6 USDT -- NOT satoshis/msats). `Amount`'s
/// underlying representation happens to be called `from_msats`/`.msats`
/// (mirroring core Bitcoin usage elsewhere in Fedimint), but every value
/// flowing through it in this module is USDT, never millisatoshis. Centralize
/// the conversion here (misc #3) rather than spelling
/// `Amount::from_msats(x.0)` at each call site, where the "msats" name reads
/// as a unit mismatch to reviewers unfamiliar with the custom-unit
/// convention.
#[must_use]
pub fn usdt_amount(a: UsdtAmount) -> Amount {
    Amount::from_msats(a.0)
}

/// A federation member's vote on the current EVM fee market and USDT/ETH
/// exchange rate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeVote {
    pub max_fee_per_gas_wei: u64,
    pub usdt_per_eth_e6: u64,
}

impl fmt::Display for FeeVote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FeeVote(max_fee_per_gas_wei={}, usdt_per_eth_e6={})",
            self.max_fee_per_gas_wei, self.usdt_per_eth_e6
        )
    }
}

/// Sanity ceiling on an individual [`FeeVote::max_fee_per_gas_wei`] (security
/// finding 06's bounds facet): `10_000` gwei (`10^13` wei). Real EVM gas
/// prices sit many orders of magnitude below this even during extreme
/// congestion; a vote above it can only be a misconfigured/malicious
/// guardian, and letting it into the median risks
/// [`UsdtInputError::FeeQuoteOverflow`]/[`UsdtOutputError::FeeQuoteOverflow`]
/// turning into a federation-wide deposit/withdrawal `DoS` (the finding's
/// `FeeQuoteOverflow`-as-DoS path).
pub const MAX_SANE_MAX_FEE_PER_GAS_WEI: u64 = 10_000_000_000_000;

/// Sanity ceiling on an individual [`FeeVote::usdt_per_eth_e6`] (security
/// finding 06's bounds facet): `$1,000,000` per ETH, in the field's `10^-6`
/// USD fixed-point (`1_000_000 * 10^6 == 10^12`). Mirrors
/// [`MAX_SANE_MAX_FEE_PER_GAS_WEI`]'s rationale.
pub const MAX_SANE_USDT_PER_ETH_E6: u64 = 1_000_000_000_000;

/// Whether `vote`'s fields are both within the sane, non-zero ranges bounded
/// by [`MAX_SANE_MAX_FEE_PER_GAS_WEI`]/[`MAX_SANE_USDT_PER_ETH_E6`] (security
/// finding 06). `Usdt::process_consensus_item`'s `FeeVote` arm rejects (as a
/// non-state-changing `Err`, never stored) any vote failing this check --
/// pure function of `vote` alone, so every guardian rejects/accepts
/// identically.
#[must_use]
pub fn fee_vote_in_sane_range(vote: &FeeVote) -> bool {
    (1..=MAX_SANE_MAX_FEE_PER_GAS_WEI).contains(&vote.max_fee_per_gas_wei)
        && (1..=MAX_SANE_USDT_PER_ETH_E6).contains(&vote.usdt_per_eth_e6)
}

/// Total gas-unit estimate for a single-transfer withdrawal `UserOp` (pool
/// already deployed): the sum of the three ERC-4337 gas components the
/// builder provisions for a batch of one: `verification_gas_limit`
/// (`100_000`), `call_gas_limit` (`140_000`), and `pre_verification_gas`
/// (`120_000`).
///
/// A withdrawal is quoted per-item BEFORE its batch is composed, so the only
/// safe (never-undercharging) figure is this batch-of-1 total; larger
/// batches amortize the fixed per-batch overhead and over-collect slightly
/// (safe). Kept in lockstep with `GasBounds::withdrawal_batch(1, false)` by
/// `withdrawal_gas_units_matches_the_batch_of_one_builder_bound`.
pub const WITHDRAWAL_GAS_UNITS: u128 = 360_000;

/// Percentage buffer [`withdrawal_fee_quote`] applies on top of the raw
/// gas-cost estimate, covering fee-market movement between the quote being
/// given out and the withdrawal batch actually landing on-chain (Task 2's
/// batching delay), as well as [`WITHDRAWAL_GAS_UNITS`]'s own imprecision.
/// `20` == 20%.
pub const WITHDRAWAL_FEE_BUFFER_PERCENT: u128 = 20;

/// Floor applied by [`withdrawal_fee_quote`] on top of the computed
/// gas-cost-derived fee (Phase 9, Task 1 hardening; deferred from Phase 8).
///
/// Without a floor, a degenerate consensus [`FeeVote`] median -- e.g. every
/// guardian voting `max_fee_per_gas_wei: 0` or `usdt_per_eth_e6: 0` (whether
/// by misconfiguration, an EVM RPC that always reports a zero base fee such
/// as an idle `anvil` devnet, or a byzantine minority trying to zero out the
/// median) -- would make [`withdrawal_fee_quote`] return `Some(UsdtAmount(0))`,
/// letting `process_output` accept a withdrawal with `max_fee: 0`: a
/// completely free withdrawal that drains the pool with no fee revenue to
/// cover the guardians' real on-chain gas cost.
///
/// `10_000` raw units == `0.01` USDT (see [`UsdtAmount`]'s `10^-6` USDT
/// unit): large enough to guarantee the quote is never literally zero, but
/// negligible next to any realistic gas-market-derived quote (tens of
/// thousands to millions of raw units at normal EVM gas prices -- see
/// `withdrawal_fee_quote_computes_expected_value`'s `38_880_000`-unit
/// example), so it never distorts a real quote and only ever bites in the
/// degenerate zero-median edge case this const exists to close.
pub const MIN_WITHDRAWAL_FEE: UsdtAmount = UsdtAmount(10_000);

/// Total gas-unit estimate for a `DEPLOY_AND_SWEEP` `UserOp` -- verification
/// `500_000` (one-time `ERC1967Proxy` `CREATE2` deploy + `SimpleAccount.
/// initialize` + signature) + call `200_000` (execute-wrapped transfer) +
/// preVerification `100_000` = `800_000`.
///
/// Basis for [`deposit_fee_quote`]: every deposit lands in a fresh
/// counterfactual account the federation must deploy AND sweep to pull the
/// USDT into the pool, so the depositor is charged the full deploy+sweep
/// cost (never amortized or partially excluded). Kept in lockstep with
/// `GasBounds::DEPLOY_AND_SWEEP_DEVNET` by a drift-guard test in the server
/// crate.
pub const SWEEP_GAS_UNITS: u128 = 800_000;

/// Floor applied by [`deposit_fee_quote`] on top of the computed
/// gas-cost-derived fee, mirroring [`MIN_WITHDRAWAL_FEE`]: guarantees a
/// degenerate zero (or near-zero) `FeeVote` median can never yield a free
/// (or near-free) deposit.
pub const MIN_DEPOSIT_FEE: UsdtAmount = UsdtAmount(10_000);

/// Shared core of the gas-derived fee quotes ([`withdrawal_fee_quote`],
/// [`deposit_fee_quote`]): `max(floor_raw, gas_units *
/// median.max_fee_per_gas_wei (wei) * median.usdt_per_eth_e6 / 1e18 * (100 +
/// WITHDRAWAL_FEE_BUFFER_PERCENT) / 100)`, ceiling-rounded (`(numerator +
/// denominator - 1) / denominator`) so the federation is never left
/// undercharged by integer-division truncation, and floored at `floor_raw`
/// so a degenerate zero (or near-zero) `FeeVote` median can never yield a
/// free (or near-free) quote.
///
/// All arithmetic happens in `u128` via `checked_*` operations: two `u64`
/// fee-vote fields multiplied together (`max_fee_per_gas_wei *
/// usdt_per_eth_e6`) can already approach `u128::MAX`, and multiplying that
/// by `gas_units` and the buffer can overflow it outright for an extreme
/// (e.g. byzantine-voted) `FeeVote` -- this returns `None` rather than
/// panicking or silently wrapping in that case. A pure function of its args
/// alone (no RPC, no wall-clock, no `our_peer_id`), so every guardian
/// computes byte-identical output from the same consensus-agreed median.
fn gas_cost_fee_quote(gas_units: u128, median: &FeeVote, floor_raw: u64) -> Option<UsdtAmount> {
    const WEI_PER_ETH: u128 = 1_000_000_000_000_000_000;

    let gas_cost_wei = gas_units.checked_mul(u128::from(median.max_fee_per_gas_wei))?;
    let numerator = gas_cost_wei
        .checked_mul(u128::from(median.usdt_per_eth_e6))?
        .checked_mul(100 + WITHDRAWAL_FEE_BUFFER_PERCENT)?;
    let denominator = WEI_PER_ETH.checked_mul(100)?;
    let fee = numerator
        .checked_add(denominator - 1)?
        .checked_div(denominator)?
        .max(u128::from(floor_raw));

    u64::try_from(fee).ok().map(UsdtAmount)
}

/// Converts a raw wei gas cost (`total_gas_units * max_fee_per_gas_wei`) into
/// its USDT-equivalent (in [`UsdtAmount`]'s 1e-6-USDT unit) at the given
/// `usdt_per_eth_e6` exchange rate: `gas_cost_wei * usdt_per_eth_e6 / 1e18`,
/// ceiling-rounded so the caller is never left undercharged by integer
/// truncation. Returns `None` on `u128` overflow or a `u64`-overflowing
/// result (an extreme, e.g. byzantine-voted, median) rather than wrapping.
///
/// Used by the reprice/replacement path (security finding 03,
/// `fedimint_usdt_server::Usdt::process_replace_user_op`) to price a rebuilt
/// op's fronted `EntryPoint` prefund against the fee ceiling the covered
/// withdrawals committed (the sum of their `max_fee`s). Unlike
/// [`gas_cost_fee_quote`], it applies NO buffer and NO floor: it prices the
/// op's ACTUAL fronted cost (whose `max_fee_per_gas` already carries the
/// builders' 2x headroom) against an already-committed ceiling. A pure
/// function of its args alone (no RPC, no wall-clock, no `our_peer_id`), so
/// every guardian computes byte-identical output from the same
/// consensus-agreed median.
#[must_use]
pub fn wei_gas_cost_to_usdt(gas_cost_wei: u128, usdt_per_eth_e6: u64) -> Option<UsdtAmount> {
    const WEI_PER_ETH: u128 = 1_000_000_000_000_000_000;

    let numerator = gas_cost_wei.checked_mul(u128::from(usdt_per_eth_e6))?;
    let usdt = numerator
        .checked_add(WEI_PER_ETH - 1)?
        .checked_div(WEI_PER_ETH)?;
    u64::try_from(usdt).ok().map(UsdtAmount)
}

/// Computes the minimum USDT fee (in [`UsdtAmount`]'s smallest on-chain
/// unit) a withdrawal output must offer as `max_fee`, given the
/// federation's current [`FeeVote`] median (see
/// `fedimint_usdt_server::Usdt::fee_vote_median`).
///
/// See [`gas_cost_fee_quote`] for the shared formula; this instantiates it
/// with [`WITHDRAWAL_GAS_UNITS`] and floors at [`MIN_WITHDRAWAL_FEE`] so a
/// degenerate zero (or near-zero) `FeeVote` median can never yield a free
/// (or near-free) withdrawal (see [`MIN_WITHDRAWAL_FEE`]'s doc comment). A
/// pure function of `median` alone, so every guardian computes
/// byte-identical output from the same consensus-agreed median;
/// [`MIN_WITHDRAWAL_FEE`] is a compile-time const, so the `max` with it
/// stays just as deterministic.
#[must_use]
pub fn withdrawal_fee_quote(median: &FeeVote) -> Option<UsdtAmount> {
    gas_cost_fee_quote(WITHDRAWAL_GAS_UNITS, median, MIN_WITHDRAWAL_FEE.0)
}

/// Minimum USDT deposit fee given the current [`FeeVote`] median: the gas
/// cost of the depositor's deploy+sweep ([`SWEEP_GAS_UNITS`]) converted to
/// USDT with the standard buffer, floored at [`MIN_DEPOSIT_FEE`].
///
/// See [`gas_cost_fee_quote`] for the shared formula. Pure function of
/// `median` alone (no RPC, no wall-clock, no `our_peer_id`) -- deterministic
/// across guardians.
#[must_use]
pub fn deposit_fee_quote(median: &FeeVote) -> Option<UsdtAmount> {
    gas_cost_fee_quote(SWEEP_GAS_UNITS, median, MIN_DEPOSIT_FEE.0)
}

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

/// Domain-separation tag mixed into a deposit account's CREATE2 `salt` (see
/// [`derive_deposit_account`]).
pub const DEPOSIT_ADDRESS_DOMAIN: &[u8] = b"fedimint-usdt-deposit-v0";

/// Domain-separation tag whose `keccak256` IS the pool account's CREATE2
/// `salt` directly (see [`derive_pool_account`]) -- unlike
/// [`DEPOSIT_ADDRESS_DOMAIN`], which is only ever mixed with a `claim_pk`
/// (never used bare), the pool account is a single, fixed, well-known
/// address per federation, so its salt has nothing else to be
/// domain-separated against.
pub const POOL_ACCOUNT_DOMAIN: &[u8] = b"fedimint-usdt-pool-v0";

/// Domain-separation tag mixed into a signing session's id derivation (see
/// [`signing_session_id`]).
pub const SIGNING_SESSION_DOMAIN: &[u8] = b"fedimint-usdt-signing-v0";

/// The EVM storage slot for the USDT contract's token balances mapping.
pub const USDT_BALANCES_SLOT: u64 = 2;

/// Maximum size (in bytes) of a [`DepositProof`]'s encoded form.
pub const MAX_DEPOSIT_PROOF_BYTES: usize = 16_384;

/// Ring buffer size for canonical block-hash tracking (number of blocks to
/// retain).
pub const BLOCK_HASH_RING_LEN: u64 = 300;

/// Derives the EVM storage key for a USDT balance lookup: the keccak256 hash
/// of the left-padded (to 32 bytes) account address concatenated with the
/// left-padded (to 32 bytes) `USDT_BALANCES_SLOT` (2).
///
/// Mirrors the Solidity mapping storage key derivation for `mapping(address
/// => uint256) balances` at slot 2: `keccak256(pad32(account) ‖
/// pad32(slot))`.
#[must_use]
pub fn balances_storage_key(account: &EvmAddress) -> [u8; 32] {
    let mut padded_account = [0u8; 32];
    padded_account[12..].copy_from_slice(&account.0);

    let mut padded_slot = [0u8; 32];
    padded_slot[24..].copy_from_slice(&USDT_BALANCES_SLOT.to_be_bytes());

    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&padded_account);
    input[32..].copy_from_slice(&padded_slot);

    alloy_primitives::keccak256(input).into()
}

/// The standard Ethereum address of a secp256k1 public key: last 20 bytes of
/// `keccak256` over the 64-byte uncompressed point (SEC1 with the `0x04`
/// prefix stripped). WASM-safe (pure-Rust `sha3`); mirrors
/// `fedimint_threshold_ecdsa::evm_address`, and is independently verified
/// against the same canonical test vector as
/// `fedimint_threshold_ecdsa::evm_address`.
#[must_use]
pub fn evm_address(pk: &secp256k1::PublicKey) -> EvmAddress {
    let uncompressed = pk.serialize_uncompressed();
    let hash = Keccak256::digest(&uncompressed[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    EvmAddress(address)
}

/// The `CREATE` (nonce-based, non-CREATE2) contract address a `deployer`
/// account produces at a given `nonce`: `keccak256(rlp([deployer,
/// nonce]))[12..]` (the classic Ethereum contract-creation address rule,
/// EIP-161 §1).
///
/// Used by Part A to predict the `SimpleAccount` implementation the
/// `SimpleAccountFactory`'s constructor deploys as its first internal `CREATE`
/// (`new SimpleAccount(entryPoint)`, i.e. `create_address(factory, 1)`); kept
/// general over `nonce` even though the module only ever needs `1`.
///
/// Pure function, WASM-safe (pure-Rust `sha3`, no `alloy-rlp`): the two-item
/// RLP list `[20-byte address, nonce]` is short enough to hand-encode. For
/// `nonce == 1` this is exactly `keccak256(0xd6 ‖ 0x94 ‖ deployer ‖
/// 0x01)[12..]`. Verified against known Ethereum `CREATE` vectors in this
/// crate's tests and pinned against a real on-chain `accountImplementation()`
/// by `fedimint-usdt-tests`' live-anvil `factory_pinning` test.
#[must_use]
pub fn create_address(deployer: EvmAddress, nonce: u64) -> EvmAddress {
    // The nonce's minimal big-endian encoding (leading zero bytes stripped);
    // empty when `nonce == 0`. A `u64` has at most 8 significant bytes.
    let be = nonce.to_be_bytes();
    let significant = match be.iter().position(|&b| b != 0) {
        Some(first) => &be[first..],
        None => &[][..],
    };

    // RLP-encode the nonce (an integer): 0 -> empty string 0x80; a single byte
    // in `0x00..=0x7f` -> the byte itself; otherwise 0x80+len followed by the
    // significant bytes. `significant.len()` is at most 8, so the `0x80 + len`
    // byte never overflows (the `unwrap_or` branch is unreachable).
    let mut nonce_rlp = Vec::with_capacity(1 + significant.len());
    match significant {
        [] => nonce_rlp.push(0x80),
        [b] if *b < 0x80 => nonce_rlp.push(*b),
        _ => {
            nonce_rlp.push(0x80 + u8::try_from(significant.len()).unwrap_or(0));
            nonce_rlp.extend_from_slice(significant);
        }
    }

    // RLP-encode the 20-byte address as a string (0x80 + 20 == 0x94, then the
    // bytes), then wrap `[address, nonce]` in a list. The payload is always
    // well under 55 bytes (21 address bytes + at most 9 nonce bytes), so the
    // list header is a single `0xc0 + len` byte (the `unwrap_or` is
    // unreachable).
    let mut payload = Vec::with_capacity(1 + 20 + nonce_rlp.len());
    payload.push(0x94);
    payload.extend_from_slice(&deployer.0);
    payload.extend_from_slice(&nonce_rlp);

    let mut rlp = Vec::with_capacity(1 + payload.len());
    rlp.push(0xc0 + u8::try_from(payload.len()).unwrap_or(0));
    rlp.extend_from_slice(&payload);

    let hash = Keccak256::digest(&rlp);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    EvmAddress(address)
}

alloy_sol_types::sol! {
    /// Only the ABI signature is needed here (to produce `initialize`'s
    /// calldata for [`derive_deposit_account`]'s `initCode`); mirrors
    /// `SimpleAccount.initialize(address)` from the vendored
    /// `fedimint-usdt-tests/tests/fixtures/erc4337/SimpleAccount.json`
    /// (Phase 7 Task 1, `@account-abstraction/contracts@0.7.0`).
    interface ISimpleAccountInit {
        function initialize(address anOwner) external;
    }
}

/// The `ERC1967Proxy` creation (constructor) bytecode that
/// `SimpleAccountFactory.createAccount`/`getAddress` embed in the `initCode`
/// they `CREATE2` a counterfactual `SimpleAccount` proxy from (`new
/// ERC1967Proxy{salt: bytes32(salt)}(address(accountImplementation),
/// abi.encodeCall(SimpleAccount.initialize, (owner)))`).
///
/// Source: `eth-infinitism/account-abstraction` git tag `v0.7.0`'s own
/// `hardhat compile` output for
/// `artifacts/@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol/
/// ERC1967Proxy.json`'s `bytecode` field, committed here as this hex
/// literal.
///
/// NOTE: this is deliberately **not** `@openzeppelin/contracts@5.0.0`'s own
/// standalone-published artifact (`build/contracts/ERC1967Proxy.json` on
/// unpkg), even though that resolves to the identical Solidity source (the
/// exact version `@account-abstraction/contracts@0.7.0` pins via its
/// `yarn.lock` at this tag) compiled with the same solc `0.8.23` and
/// `optimizer.runs = 1000000` (`hardhat.config.ts`). The two artifacts'
/// bytecode differs anyway: `hardhat compile` (no explicit `evmVersion`
/// override) resolves solc 0.8.23's default target to `paris`, whereas a
/// bare `forge build` of the same source/solc/optimizer settings defaults
/// to `shanghai` (PUSH0-era codegen) -- a real, confirmed divergence, not a
/// hypothetical one (`derive_deposit_account_matches_factory_get_address`
/// below caught it during development). This constant was extracted by
/// actually cloning the tag, `npm install`-ing its declared dependencies
/// (resolving `@openzeppelin/contracts` to `5.0.0`, matching `yarn.lock`),
/// and running `npx hardhat compile`; the resulting `SimpleAccountFactory`
/// artifact byte-for-byte matches the one vendored in
/// `fedimint-usdt-tests/tests/fixtures/erc4337/SimpleAccountFactory.json`
/// (Phase 7 Task 1, fetched from unpkg), confirming this is the exact
/// toolchain/settings that produced it, and this exact `ERC1967Proxy`
/// bytecode is a literal contiguous substring of that artifact's
/// `deployedBytecode` (the `new ERC1967Proxy{salt}(...)` call embeds it
/// verbatim).
///
/// Pinned against the real on-chain factory (not just trusted as copied
/// correctly) by this module's self-verifying anvil test,
/// `fedimint-usdt-tests/tests/erc4337_harness.rs`'s
/// `derive_deposit_account_matches_factory_get_address`: if this constant
/// were wrong, off-chain [`derive_deposit_account`] would disagree with
/// `SimpleAccountFactory.getAddress` there.
const ERC1967_PROXY_CREATION_CODE: &[u8] = &alloy_primitives::hex!(
    "6080604052604051610417380380610417833981016040819052610022916102"
    "68565b61002c8282610033565b5050610352565b61003c82610092565b604051"
    "6001600160a01b038316907fbc7cd75a20ee27fd9adebab32041f755214dbc6b"
    "ffa90cc0225b39da2e5c2d3b90600090a280511561008657610081828261010e"
    "565b505050565b61008e610185565b5050565b806001600160a01b03163b6000"
    "036100cd57604051634c9c8ce360e01b81526001600160a01b03821660048201"
    "526024015b60405180910390fd5b7f360894a13ba1a3210667c828492db98dca"
    "3e2076cc3735a920a3ca505d382bbc80546001600160a01b0319166001600160"
    "a01b0392909216919091179055565b6060600080846001600160a01b03168460"
    "405161012b9190610336565b600060405180830381855af49150503d80600081"
    "14610166576040519150601f19603f3d011682016040523d82523d6000602084"
    "013e61016b565b606091505b50909250905061017c8583836101a6565b959450"
    "50505050565b34156101a45760405163b398979f60e01b815260040160405180"
    "910390fd5b565b6060826101bb576101b682610205565b6101fe565b81511580"
    "156101d257506001600160a01b0384163b155b156101fb57604051639996b315"
    "60e01b81526001600160a01b03851660048201526024016100c4565b50805b93"
    "92505050565b8051156102155780518082602001fd5b604051630a12f52160e1"
    "1b815260040160405180910390fd5b634e487b7160e01b600052604160045260"
    "246000fd5b60005b8381101561025f578181015183820152602001610247565b"
    "50506000910152565b6000806040838503121561027b57600080fd5b82516001"
    "600160a01b038116811461029257600080fd5b60208401519092506001600160"
    "401b03808211156102af57600080fd5b818501915085601f8301126102c35760"
    "0080fd5b8151818111156102d5576102d561022e565b604051601f8201601f19"
    "908116603f011681019083821181831017156102fd576102fd61022e565b8160"
    "405282815288602084870101111561031657600080fd5b610327836020830160"
    "208801610244565b80955050505050509250929050565b600082516103488184"
    "60208701610244565b9190910192915050565b60b7806103606000396000f3fe"
    "6080604052600a600c565b005b60186014601a565b605e565b565b600060597f"
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    "5473ffffffffffffffffffffffffffffffffffffffff1690565b905090565b36"
    "60008037600080366000845af43d6000803e808015607c573d6000f35b3d6000"
    "fdfea2646970667358221220d7f23a80daebb5531c9e4a18d87e812fca112e5d"
    "f7e56433218edcc12bbe415d64736f6c63430008170033"
);

/// The CREATE2 `salt` for `claim_pk`'s deposit account:
/// `keccak256(DEPOSIT_ADDRESS_DOMAIN ‖ claim_pk.serialize())` (compressed,
/// 33-byte). Extracted out of [`derive_deposit_account`] so
/// `fedimint-usdt-server`'s Phase-7 Task 4 `UserOp` builder can compute the
/// exact same salt for `SimpleAccountFactory.createAccount`'s `initCode`
/// without duplicating (and risking drifting from) this formula.
#[must_use]
pub fn deposit_salt(claim_pk: &secp256k1::PublicKey) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(DEPOSIT_ADDRESS_DOMAIN);
    hasher.update(claim_pk.serialize()); // 33-byte compressed
    hasher.finalize().into()
}

/// Derives the counterfactual CREATE2 address of the per-`claim_pk`
/// ERC-4337 v0.7 `SimpleAccount` deposit account (D3, Phase 7 Task 2's
/// reconciliation of Phase 5's provisional additive-tweak EOA):
///
/// - `owner = evm_address(group_public_key)` -- a single DKG group key owns
///   *every* deposit account (differentiated only by `salt`), so one MPC key
///   signs every sweep. No token paymaster is used (see
///   `security-review/22-low-broadcaster-eth-funding-no-reimbursement.md`): the
///   federation's broadcaster EOA fronts ETH to the `EntryPoint` to pay for
///   each deploy+sweep `UserOp`'s gas, so a deposit account itself never needs
///   to hold ETH -- but that ETH is never reimbursed on-chain from the USDT
///   fees the module collects; operators must keep the broadcaster funded out
///   of band.
/// - `salt = keccak256(DEPOSIT_ADDRESS_DOMAIN ‖ claim_pk.serialize())`
///   (compressed, 33-byte).
/// - `initCode = ERC1967Proxy_creationCode ‖ abi.encode(simple_account_impl,
///   SimpleAccount.initialize(owner))`, mirroring
///   `SimpleAccountFactory.createAccount`'s `new ERC1967Proxy{salt}(
///   address(accountImplementation), abi.encodeCall(SimpleAccount.initialize,
///   (owner)))`.
/// - `address = keccak256(0xff ‖ account_factory ‖ salt ‖
///   keccak256(initCode))[12..]` (EIP-1014), via
///   [`alloy_primitives::Address::create2_from_code`].
///
/// Pure function, no RPC -- both the client (wasm) and every guardian call
/// this exact function so the address they watch is bit-for-bit identical.
/// Self-verified against `SimpleAccountFactory.getAddress` on a real
/// anvil-deployed factory by
/// `fedimint-usdt-tests/tests/erc4337_harness.rs`.
#[must_use]
pub fn derive_deposit_account(
    group_public_key: &secp256k1::PublicKey,
    account_factory: EvmAddress,
    simple_account_impl: EvmAddress,
    claim_pk: &secp256k1::PublicKey,
) -> EvmAddress {
    let owner = evm_address(group_public_key);
    let salt = deposit_salt(claim_pk);
    create2_simple_account(account_factory, simple_account_impl, owner, salt)
}

/// The CREATE2 `salt` for the federation's fixed pool `SimpleAccount`:
/// `keccak256(POOL_ACCOUNT_DOMAIN)` (a single fixed salt, not mixed with any
/// claim key -- there is only ever one pool account per federation). Extracted
/// out of [`derive_pool_account`] (mirroring [`deposit_salt`]'s own
/// extraction out of [`derive_deposit_account`]) so
/// `fedimint-usdt-server`'s withdrawal-batch `UserOp` builder (Phase 8, Task
/// 2) can compute the exact same salt for `SimpleAccountFactory.
/// createAccount`'s `initCode` without duplicating (and risking drifting
/// from) this formula.
#[must_use]
pub fn pool_salt() -> [u8; 32] {
    Keccak256::digest(POOL_ACCOUNT_DOMAIN).into()
}

/// Derives the CREATE2 address of this federation's fixed pool `SimpleAccount`
/// -- the swept-to destination of every deploy-and-sweep `UserOp` (Phase 7
/// Task 5), and the `sender` of every withdrawal-batch `UserOp` (Phase 8,
/// Task 2): `owner = evm_address(group_public_key)` (the same group key that
/// owns every deposit account), `salt = `[`pool_salt`]`()`.
///
/// Pure function, no RPC -- every guardian (and, if a client ever needs it,
/// the client too) calls this exact function so the pool address is
/// bit-for-bit identical everywhere. Mirrors [`derive_deposit_account`]'s
/// CREATE2 construction via the shared [`create2_simple_account`] helper.
#[must_use]
pub fn derive_pool_account(
    group_public_key: &secp256k1::PublicKey,
    account_factory: EvmAddress,
    simple_account_impl: EvmAddress,
) -> EvmAddress {
    let owner = evm_address(group_public_key);
    create2_simple_account(account_factory, simple_account_impl, owner, pool_salt())
}

/// Shared CREATE2 computation behind [`derive_deposit_account`] and
/// [`derive_pool_account`]: `address = keccak256(0xff ‖ account_factory ‖
/// salt ‖ keccak256(initCode))[12..]` (EIP-1014), where `initCode =
/// ERC1967Proxy_creationCode ‖ abi.encode(simple_account_impl,
/// SimpleAccount.initialize(owner))`, mirroring
/// `SimpleAccountFactory.createAccount`'s `new ERC1967Proxy{salt}(
/// address(accountImplementation), abi.encodeCall(SimpleAccount.initialize,
/// (owner)))`. Pure function, no RPC.
fn create2_simple_account(
    account_factory: EvmAddress,
    simple_account_impl: EvmAddress,
    owner: EvmAddress,
    salt: [u8; 32],
) -> EvmAddress {
    use alloy_sol_types::{SolCall as _, SolValue as _};

    let initialize_calldata = ISimpleAccountInit::initializeCall {
        anOwner: alloy_primitives::Address::from(owner.0),
    }
    .abi_encode();
    // `abi.encode(address, bytes)`, matching `ERC1967Proxy`'s
    // `constructor(address implementation, bytes memory _data)`.
    let ctor_args = (
        alloy_primitives::Address::from(simple_account_impl.0),
        alloy_primitives::Bytes::from(initialize_calldata),
    )
        .abi_encode_params();

    let mut init_code = ERC1967_PROXY_CREATION_CODE.to_vec();
    init_code.extend_from_slice(&ctor_args);

    let factory_address = alloy_primitives::Address::from(account_factory.0);
    let derived = factory_address.create2_from_code(salt, init_code);

    EvmAddress(derived.into_array())
}

/// Identifies one instance of the guardians co-signing a single 32-byte
/// digest (see [`signing_session_id`]). Plain data — wasm-safe, carries no
/// cggmp21 state.
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Hash,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct SigningSessionId(pub [u8; 32]);

/// Derives the id of the signing session for `digest` on its `attempt`'th
/// retry: `keccak256(SIGNING_SESSION_DOMAIN ‖ digest ‖ attempt.to_be_bytes())`.
///
/// Mirrors [`derive_deposit_account`]'s keccak-construction style. Including
/// `attempt` lets the federation restart signing for the same digest (e.g.
/// after a failed round) under a fresh session id, without colliding with the
/// abandoned attempt's DB records.
#[must_use]
pub fn signing_session_id(digest: &[u8; 32], attempt: u32) -> SigningSessionId {
    let mut hasher = Keccak256::new();
    hasher.update(SIGNING_SESSION_DOMAIN);
    hasher.update(digest);
    hasher.update(attempt.to_be_bytes());
    SigningSessionId(hasher.finalize().into())
}

/// Maximum size, in bytes, of a single [`MpcRoundItem`] chunk's `payload`.
///
/// A cggmp21 signing round's full per-peer message can be tens of kilobytes
/// (round 2 is ≈63 KB), but Fedimint's `AlephBFT` unit byte limit
/// (`ALEPH_BFT_UNIT_BYTE_LIMIT = 50_000`) silently refuses to pack any
/// consensus item that does not fit under it into an ordered unit — so a
/// single oversized `MpcRound` item would never be ordered and the signing
/// session would stall forever. Each round's payload is therefore split into
/// chunks of at most this many bytes, each carried as its own `MpcRound`
/// consensus item and reassembled deterministically before being fed to the
/// signer. 30 KB leaves ample room under the 50 KB limit for the consensus
/// item envelope and encoding overhead.
pub const MPC_ROUND_CHUNK_SIZE: usize = 30_000;

/// Ceiling, in bytes, on one signer's reassembled per-round payload (the sum
/// of ALL of that signer's chunks for one `(session, round)`) that
/// `process_mpc_round` will accept before rejecting further chunks from that
/// peer (security finding 11: an unbounded chunk count/size otherwise lets a
/// Byzantine selected signer bloat the consensus DB with up to `u16::MAX`
/// accepted chunks per round). Real cggmp21 rounds top out at roughly 63 KB
/// (round 2's per-peer message; see [`MPC_ROUND_CHUNK_SIZE`]'s doc comment),
/// so 512 KiB leaves generous headroom for protocol/party-count growth while
/// still bounding a malicious peer's worst-case per-round contribution to a
/// modest, fixed amount of consensus-DB growth. Pinned against a real signing
/// round's actual size by
/// `fedimint_usdt_server::real_signing_round_fits_chunk_budget` (a drift
/// guard: if that test fails, this constant is too small and must be raised,
/// not the test loosened).
pub const MAX_MPC_ROUND_BYTES: usize = 512 * 1024;

/// Maximum number of [`MPC_ROUND_CHUNK_SIZE`]-sized chunks a single `(session,
/// round, peer)` may be split into: `ceil(MAX_MPC_ROUND_BYTES /
/// MPC_ROUND_CHUNK_SIZE)`. Bounding `chunk_count` itself (not just each
/// chunk's `payload` length) is what actually caps a Byzantine peer's chunk
/// count -- `MpcRoundItem.chunk`/`chunk_count` are `u16`, so without this a
/// peer could otherwise propose up to `u16::MAX` distinct chunk indices for
/// one round.
///
/// Written as a literal (18 at the current 30 KB chunk size / 512 KiB
/// ceiling) rather than a `const fn` -- primitive `usize -> u16` conversion
/// is not yet usable in a `const` context on stable Rust (`TryFrom` is not a
/// const trait) -- but the `const _: ()` assertion immediately below
/// recomputes the same value with `usize` arithmetic and fails to compile if
/// [`MAX_MPC_ROUND_BYTES`] or [`MPC_ROUND_CHUNK_SIZE`] change without this
/// constant being updated to match, so the two can never silently drift.
pub const MAX_MPC_CHUNKS: u16 = 18;

const _: () = assert!(
    MAX_MPC_CHUNKS as usize == MAX_MPC_ROUND_BYTES.div_ceil(MPC_ROUND_CHUNK_SIZE),
    "MAX_MPC_CHUNKS is out of sync with MAX_MPC_ROUND_BYTES / MPC_ROUND_CHUNK_SIZE -- update the \
     literal above to match"
);

/// One chunk of one guardian's message for a single round of a signing
/// session's cggmp21 state machine. A round's full per-peer payload can
/// exceed Fedimint's `AlephBFT` unit byte limit, so it is split into
/// [`MPC_ROUND_CHUNK_SIZE`]-byte chunks, each carried as its own `MpcRound`
/// consensus item and reassembled (by concatenating chunks `0..chunk_count`
/// in ascending index) before being interpreted. `payload` is THIS chunk's
/// opaque bytes; this module's consensus logic is the only thing that
/// interprets the reassembled whole.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct MpcRoundItem {
    pub session_id: SigningSessionId,
    pub round: u16,
    /// This chunk's index in `0..chunk_count`.
    pub chunk: u16,
    /// Total number of chunks for this `(round, peer)`'s full payload (always
    /// `>= 1`; a zero-length payload is a single empty chunk).
    pub chunk_count: u16,
    /// THIS chunk's bytes (not the whole round payload).
    pub payload: Vec<u8>,
}

/// Merkle proof of a USDT balance at a specific block height (Phase 9, Task 1,
/// "deposit-by-proof" feature). Contains the block header and state proof
/// trees needed to verify an account's balance on-chain without reading from
/// an RPC at proof-verification time. Created by the client or off-chain
/// indexer via `eth_getProof` at a canonical block; verified deterministically
/// by the server/guardians (no RPC dependency).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositProof {
    /// Block number at which the balance was observed.
    pub block_number: u64,
    /// RLP-encoded EVM block header (contains state root, timestamp, etc.).
    pub header_rlp: Vec<u8>,
    /// Account proof: sequence of RLP-encoded Merkle trie nodes from the
    /// state root to the account's leaf.
    pub account_proof: Vec<Vec<u8>>,
    /// Storage proof: sequence of RLP-encoded Merkle trie nodes from the
    /// account's storage root to the USDT balance's leaf.
    pub storage_proof: Vec<Vec<u8>>,
}

impl DepositProof {
    /// Returns the total byte count of this proof's encoded form, used for
    /// size-cap validation (must not exceed [`MAX_DEPOSIT_PROOF_BYTES`]).
    #[must_use]
    pub fn encoded_len_bytes(&self) -> usize {
        // Approximate: header_rlp + all account_proof nodes + all storage_proof nodes.
        // For precise accounting, sum the lengths of all components.
        self.header_rlp.len()
            + self.account_proof.iter().map(Vec::len).sum::<usize>()
            + self.storage_proof.iter().map(Vec::len).sum::<usize>()
    }
}

/// Payload of a `UsdtConsensusItem::Deposit` observation.
///
/// # Legacy (proof-driven crediting superseded this)
///
/// This was the payload of the guardian-polling deposit-observation quorum.
/// That whole path -- the deposit-check endpoint, the guardian-local
/// poll/GC tasks, and the scanner that produced these observations -- was
/// removed when deposit crediting became proof-driven
/// (see [`UsdtInput::DepositProofV0`]). No honest guardian proposes a
/// `UsdtConsensusItem::Deposit` any more. The variant and this type are kept
/// (not deleted) purely for consensus wire-format stability: the derived enum
/// tag of `UsdtConsensusItem` is positional, so removing the `Deposit` variant
/// would shift every later variant's tag and corrupt decode of existing
/// consensus history. `fedimint_usdt_server::Usdt::credit_deposit` still
/// handles a replayed item deterministically (see its doc comment).
///
/// `claim_pk` is carried in the observation itself (rather than recovered from
/// guardian-local state when the item is processed) so that crediting a
/// deposit is a pure function of consensus data: `process_consensus_item` must
/// be byte-identical across every honest guardian.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositObservation {
    pub account: EvmAddress,
    pub balance: UsdtAmount,
    pub block: u64,
    /// The canonical hash of [`Self::block`] (security findings 04/12/15):
    /// bound the observation to a specific fork so the vote tally counts only
    /// FULLY-equal observations, so two guardians observing the same
    /// account/balance/height on DIFFERENT forks produce non-equal votes that
    /// never aggregate to a threshold credit -- closing the "stale pre-reorg
    /// vote completes a threshold on a non-canonical fork" gap.
    pub block_hash: [u8; 32],
    pub claim_pk: secp256k1::PublicKey,
}

/// Payload of a [`UsdtConsensusItem::BlockHash`] (deposit-by-proof anchor):
/// one guardian's observation of the canonical hash of a confirmation-depth
/// EVM block `height`, read via `IServerEvmRpc::get_block_hash`. Mirrors
/// [`DepositObservation`]'s `(block, block_hash)` binding, reduced to just the
/// height+hash: `fedimint_usdt_server`'s block-hash observer proposes it and
/// `process_consensus_item` tallies FULLY-equal observations, writing the
/// agreed `(height, block_hash)` into the block-hash ring only once at least a
/// threshold of guardians propose the identical pair (so two guardians
/// observing the same height on DIFFERENT forks produce non-equal votes that
/// never aggregate). Kept whole in the vote so the tally is a pure function of
/// consensus data.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct BlockHashObservation {
    /// The confirmation-depth block height whose canonical hash this
    /// guardian observed (`consensus_block_count - confirmation_depth`).
    pub height: u64,
    /// The canonical hash of [`Self::height`].
    pub block_hash: [u8; 32],
}

/// Payload of a `UsdtConsensusItem::BootstrapObservation` (Part C): one
/// guardian's periodic view of whether the module's on-chain infrastructure
/// is ready to honor the full deposit->claim->sweep->withdraw lifecycle.
///
/// The first three fields are *federation facts* (the same on-chain reality
/// every honest guardian observes -- EntryPoint/factory/impl deployed and,
/// for the factory, its `getAddress` matching this build's off-chain
/// [`derive_deposit_account`] CREATE2 math); the last two are *self-facts*
/// (this guardian's own broadcaster funding and RPC health). All five are
/// counted independently and threshold-aggregated by
/// `fedimint_usdt_server::Usdt::bootstrap_state` -- no single guardian's
/// observation gates the federation's readiness (see that method's
/// determinism argument). Mirrors [`DepositObservation`]'s role in the
/// deposit-observation quorum: carried whole in the vote so the readiness
/// tally is a pure function of consensus data.
// Five independent on-chain readiness conditions, each counted separately by
// the threshold tally -- deliberately flat booleans (not a state machine), so
// `struct_excessive_bools` does not apply.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct BootstrapObservation {
    /// The configured `EntryPoint` has contract code deployed.
    pub entry_point_ok: bool,
    /// The configured `account_factory` has code AND its on-chain
    /// `getAddress(owner, salt)` matches this build's off-chain
    /// [`derive_pool_account`] CREATE2 derivation for the fixed `pool_salt`
    /// AND for one deterministic claim-key-derived sample salt (against
    /// [`derive_deposit_account`]) AND its `accountImplementation()` matches
    /// the configured `simple_account_impl` (sec-16 readiness deepening,
    /// finding 16) -- the immutable-invariant check that proves derived
    /// deposit addresses are spendable -- the footgun-killer.
    pub factory_ok: bool,
    /// The configured `simple_account_impl` has contract code deployed.
    pub impl_ok: bool,
    /// This guardian's broadcaster EOA holds at least the per-chain
    /// configured minimum ETH balance to front `UserOp` gas.
    pub broadcaster_funded: bool,
    /// This guardian's last round of readiness RPC reads succeeded.
    pub rpc_healthy: bool,
}

impl fmt::Display for BootstrapObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BootstrapObservation(entry_point_ok={}, factory_ok={}, impl_ok={}, \
             broadcaster_funded={}, rpc_healthy={})",
            self.entry_point_ok,
            self.factory_ok,
            self.impl_ok,
            self.broadcaster_funded,
            self.rpc_healthy
        )
    }
}

/// The module-level readiness state (Part C), derived by
/// `fedimint_usdt_server::Usdt::bootstrap_state` as a pure function of the
/// threshold-aggregated [`BootstrapObservation`] votes plus a persisted
/// "has ever been ready" latch.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum BootstrapState {
    /// The module is running (post-DKG) but not all readiness conditions are
    /// met yet, and it has never been `Ready`. Deposit-address handout is
    /// blocked.
    AwaitingInfra,
    /// The full deposit->claim->sweep->withdraw lifecycle is operational.
    Ready,
    /// The module was `Ready` at some point but a condition has since
    /// regressed (e.g. a broadcaster's ETH ran low). Advisory; distinguished
    /// from [`Self::AwaitingInfra`] only by the persisted latch.
    Degraded,
}

impl fmt::Display for BootstrapState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Response to the `usdt_status` endpoint (Part C): the consensus-agreed
/// [`BootstrapState`] plus the per-condition tally it was derived from. Read
/// directly from consensus DB (the threshold-aggregated
/// [`BootstrapObservation`] votes + the readiness latch), so any guardian
/// answers identically (threshold-agreement via `request_current_consensus`,
/// mirroring [`PoolStateResponse`]/[`DepositStatusResponse`]).
///
/// `entry_point_ok`/`factory_ok`/`impl_ok` are the *federation facts* (each
/// `true` once at least `threshold` guardians vote it); `funded_guardians`/
/// `healthy_guardians` are the raw counts of guardians currently reporting a
/// funded broadcaster / healthy RPC (each must reach `threshold` for
/// `Ready`).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct StatusResponse {
    pub state: BootstrapState,
    pub entry_point_ok: bool,
    pub factory_ok: bool,
    pub impl_ok: bool,
    pub funded_guardians: u16,
    pub healthy_guardians: u16,
    pub threshold: u16,
}

/// Request for the current credited/claimed/claimable state of `claim_pk`'s
/// deposit account.
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositStatusRequest {
    pub claim_pk: secp256k1::PublicKey,
}

/// Response to [`DepositStatusRequest`]. `claimable` is `credited − claimed`
/// (saturating). If no deposit has been credited yet (or observed at all),
/// `credited`/`claimed`/`claimable` are all zero, with `account` still set to
/// the derived deposit address so the client can poll this endpoint before
/// any credit lands.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositStatusResponse {
    pub account: EvmAddress,
    pub credited: UsdtAmount,
    pub claimed: UsdtAmount,
    pub claimable: UsdtAmount,
}

/// Response to the `pool_state` diagnostic endpoint (Phase 7, Task 5):
/// the pool `SimpleAccount`'s derived address (see [`derive_pool_account`])
/// and the consensus-agreed USDT balance swept into it so far. Read directly
/// from consensus DB, so any guardian answers identically once
/// `UsdtConsensusItem::UserOpConfirmed` has reached threshold agreement for
/// a sweep; `balance` is `0` (with `account` still populated) before the
/// first successful sweep, mirroring [`DepositStatusResponse`]'s
/// pre-credit-zeros shape.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct PoolStateResponse {
    pub account: EvmAddress,
    pub balance: UsdtAmount,
}

/// Response to the `latest_anchored_block` endpoint: the newest height
/// currently anchored in the consensus-agreed canonical block-hash ring
/// (`latest`, `0` if the ring is empty -- i.e. before the first
/// `UsdtConsensusItem::BlockHash` has reached threshold agreement) and the
/// ring's retained window length (`window`, always [`BLOCK_HASH_RING_LEN`]).
/// A deposit-by-proof client targets its inclusion proof at a height in
/// `[latest - window + 1, latest]` so the guardian ring still holds the
/// canonical hash to check the proof against. Read directly from consensus
/// DB, so any guardian answers identically, mirroring
/// [`PoolStateResponse`]/[`StatusResponse`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct AnchoredBlockResponse {
    pub latest: u64,
    pub window: u64,
}

/// Request for the [`UserOpStatus`] of a specific `UserOp`, identified by its
/// [`user_op::user_op_hash`].
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct UserOpStatusRequest {
    pub op_hash: [u8; 32],
}

/// The consensus-agreed lifecycle stage of a `UserOp` (Phase 7, Task 5):
/// `Pending` while awaiting/undergoing MPC signing (a `PendingUserOp`
/// consensus record exists), `Submitted` once federation-agreed-signed and
/// awaiting/undergoing on-chain confirmation (a `SubmittedUserOp` consensus
/// record exists), `Unknown` once confirmed (both records cleared -- see
/// [`PoolStateResponse`] for the confirmed sweep's effect) or if `op_hash`
/// was never seen at all. Read directly from consensus DB, so any guardian
/// answers identically.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub enum UserOpStatus {
    Pending,
    Submitted,
    Unknown,
}

/// Response to the `userop_status` diagnostic endpoint (Phase 7, Task 5).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct UserOpStatusResponse {
    pub status: UserOpStatus,
}

/// Request for the current withdrawal fee quote (Phase 8, Task 1).
/// `amount` is carried for forward-compatibility with a future
/// amount-dependent fee model (e.g. a batching-size-aware quote); the
/// current [`withdrawal_fee_quote`] formula does not use it.
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct WithdrawFeeQuoteRequest {
    pub amount: UsdtAmount,
}

/// Response to the `withdraw_fee_quote` endpoint (Phase 8, Task 1):
/// `max_fee` is the minimum fee a `UsdtOutput::V0` withdrawing `amount` must
/// offer right now; `valid_blocks` is how many further guardian-observed EVM
/// blocks the quote should be treated as valid for before re-querying
/// (fee-vote-median-derived quotes can move as guardians' `FeeVote`s
/// change), a fixed, non-consensus advisory hint rather than an enforced
/// on-chain expiry.
///
/// `available` (misc #4, finding 06's client-confusion facet) is `false`
/// when the federation has no fee-vote median yet (or the quote overflows):
/// in that case `max_fee` is `UsdtAmount(0)`, a placeholder that MUST NOT be
/// treated as a real quote -- do not submit a withdrawal against it. When
/// `available` is `true`, `max_fee` is the real fee-vote-median-derived
/// quote, byte-identical to what this endpoint returned before `available`
/// existed.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct WithdrawFeeQuoteResponse {
    pub max_fee: UsdtAmount,
    pub valid_blocks: u64,
    pub available: bool,
}

/// Request for the current deposit fee quote, mirroring
/// [`WithdrawFeeQuoteRequest`]. Unit-like: [`deposit_fee_quote`] does not
/// (yet) depend on the amount being claimed, but the request is kept as a
/// struct for forward-compatibility with a future amount-dependent fee
/// model, mirroring the withdraw side.
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositFeeQuoteRequest;

/// Response to the `deposit_fee_quote` endpoint, mirroring
/// [`WithdrawFeeQuoteResponse`]: `fee` is the minimum fee a `UsdtInput::V0`
/// claiming a credited deposit must offer right now; `valid_blocks` is how
/// many further guardian-observed EVM blocks the quote should be treated as
/// valid for before re-querying (fee-vote-median-derived quotes can move as
/// guardians' `FeeVote`s change), a fixed, non-consensus advisory hint
/// rather than an enforced on-chain expiry.
///
/// `available` (misc #4, finding 06's client-confusion facet) mirrors
/// [`WithdrawFeeQuoteResponse::available`]: `false` when there is no fee-vote
/// median yet (or the quote overflows), in which case `fee` is a
/// non-authoritative `UsdtAmount(0)` placeholder -- do not submit a claim
/// against it.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositFeeQuoteResponse {
    pub fee: UsdtAmount,
    pub valid_blocks: u64,
    pub available: bool,
}

/// Request for the current [`WithdrawalStatus`] of a withdrawal, identified
/// by the `OutPoint` of the `UsdtOutput::V0` that enqueued it (Phase 8, Task
/// 3).
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct WithdrawalStatusRequest {
    pub out_point: OutPoint,
}

/// Wasm-safe mirror of `fedimint_usdt_server::db::WithdrawalState` (Phase 8,
/// Task 3): the server-only type carries no cggmp21/EVM-RPC state itself
/// (it's already plain consensus-DB data), but it lives in `-server` and is
/// not reachable from a wasm client, so this is a plain-data duplicate
/// exposed over the `withdrawal_status` endpoint, mirroring how
/// [`PoolStateResponse`]/[`DepositStatusResponse`] expose other server
/// consensus-DB state to `-common`/client. Adds `Unknown` (absent from
/// `WithdrawalState` itself) for an `out_point` no `WithdrawalStateKey`
/// record exists for at all -- e.g. a typo'd or not-yet-processed
/// `OutPoint` -- mirroring [`UserOpStatus::Unknown`]'s equivalent
/// not-found sentinel.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub enum WithdrawalStatus {
    /// No `WithdrawalStateKey` record exists for the requested `OutPoint`.
    Unknown,
    /// Enqueued, awaiting the next withdrawal batch.
    Queued,
    /// Included in a withdrawal `UserOp` (`op_hash`) whose federation MPC
    /// signing session is in progress.
    Signing { op_hash: [u8; 32] },
    /// The withdrawal's `UserOp` (`op_hash`) has been federation-agreed-
    /// signed and is awaiting/undergoing guardian-local on-chain submission
    /// and confirmation.
    Submitted { op_hash: [u8; 32] },
    /// The withdrawal's `UserOp` confirmed on-chain successfully at `block`;
    /// terminal.
    Confirmed { block: u64 },
    /// The withdrawal's `UserOp` failed on-chain, or could not be
    /// completed, for `reason`; terminal.
    Failed { reason: String },
}

/// Response to the `withdrawal_status` endpoint (Phase 8, Task 3). Read
/// directly from consensus DB, so any guardian answers identically
/// (threshold-agreement via `request_current_consensus`, mirroring
/// `deposit_status`/`withdraw_fee_quote`).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct WithdrawalStatusResponse {
    pub status: WithdrawalStatus,
}

/// Request for the live refund record of a terminally-failed withdrawal
/// (security finding 09), identified by the `OutPoint` of the
/// `UsdtOutput::V0` that enqueued it.
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct RefundStatusRequest {
    pub out_point: OutPoint,
}

/// A terminally-failed withdrawal's reissued-e-cash refund (security finding
/// 09), as surfaced to the client. Wasm-safe mirror of the server-only
/// `fedimint_usdt_server::db::Refund` record: present from the moment the
/// withdrawal goes terminal-`Failed` until its `RefundV0` claim removes it
/// (claimed exactly once). `amount` is `(amount + max_fee)` minus the gas
/// already incurred on-chain; a client builds a [`UsdtInput::RefundV0`] with
/// its `ClientInput.amounts` set to exactly this so the reissued e-cash mints
/// and the transaction balances.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct RefundInfo {
    pub amount: UsdtAmount,
    pub reason: String,
}

/// Response to the `refund_status` endpoint (security finding 09): the live
/// [`RefundInfo`] for `out_point`, or `None` if no refund record exists (the
/// withdrawal never failed, or its refund was already claimed). Read directly
/// from consensus DB, so any guardian answers identically (threshold-
/// agreement via `request_current_consensus`, mirroring
/// [`WithdrawalStatusResponse`]).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct RefundStatusResponse {
    pub refund: Option<RefundInfo>,
}

/// Per-instance config-gen params for the USDT module (Phase 4.5 mechanism).
///
/// `Default` targets a local `anvil` dev federation: chain id 31337 and a
/// fast confirmation depth. `usdt_contract`, `entry_point`,
/// `account_factory`, and `simple_account_impl` are placeholders — real
/// deployments (and the devimint e2e) must override these with the deployed
/// contract addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsdtGenParams {
    pub usdt_contract: EvmAddress,
    pub chain_id: u64,
    pub confirmation_depth: u64,
    /// The deployed ERC-4337 v0.7 `EntryPoint` contract address (Phase 7).
    /// Placeholder; real deployments/tests must override.
    pub entry_point: EvmAddress,
    /// The deployed `SimpleAccountFactory` contract address (Phase 7).
    /// Placeholder; real deployments/tests must override.
    pub account_factory: EvmAddress,
    /// The deployed `SimpleAccount` implementation contract address (Phase
    /// 7). Placeholder; real deployments/tests must override.
    pub simple_account_impl: EvmAddress,
    pub check_ttl_blocks: u64,
    /// The minimum ETH balance (in wei) a guardian's broadcaster EOA must
    /// hold to count as "funded" for the Part C readiness state machine (see
    /// `BootstrapObservation::broadcaster_funded`). Genuinely per-chain (gas
    /// costs vary), so a config field rather than a compiled constant. A
    /// `u64` holds up to ~18 ETH of wei -- far above any sane per-guardian gas
    /// float, and (unlike `u128`) `fedimint_core`-`Encodable` for the
    /// consensus config it is threaded into.
    pub broadcaster_min_balance_wei: u64,
    /// Chainlink ETH/USD aggregator address whose `latestRoundData()` each
    /// guardian reads to vote `FeeVote::usdt_per_eth_e6`. Defaults to the
    /// canonical mainnet ETH/USD feed; set to `EvmAddress([0; 20])` on a chain
    /// without Chainlink (e.g. anvil) to fall back to a static price. See
    /// `chainlink_eth_usd_to_usdt_per_eth_e6`.
    pub eth_usd_price_feed: EvmAddress,
    /// Max age (seconds, chain time) of a Chainlink reading before a guardian
    /// abstains. ~1h heartbeat feeds -> 4h default is comfortably above
    /// cadence.
    pub price_feed_max_staleness_secs: u64,
    /// The DETERMINISTIC recipient EVM address the federation withdraws
    /// stranded deposit-account `EntryPoint` gas deposits to (finding A).
    /// Every guardian builds the byte-identical
    /// `EntryPoint.withdrawTo(recipient, amount)` recovery op, so the
    /// recipient MUST be a consensus-agreed value; the per-guardian
    /// broadcaster EOA (`UsdtConfigLocal::broadcaster_private_key`)
    /// is non-deterministic and cannot be used. Typically set to the
    /// federation's broadcaster-refill/treasury address. Placeholder (zero
    /// address) on dev chains; real deployments must override.
    pub residual_recovery_recipient: EvmAddress,
}

impl Default for UsdtGenParams {
    fn default() -> Self {
        Self {
            usdt_contract: EvmAddress([0u8; 20]),
            chain_id: 31337,
            confirmation_depth: 1,
            entry_point: EvmAddress([0u8; 20]),
            account_factory: EvmAddress([0u8; 20]),
            simple_account_impl: EvmAddress([0u8; 20]),
            check_ttl_blocks: 10_000,
            // 0.05 ETH: enough to front many UserOps' L1 gas on a typical
            // chain, negligible to top up on a devnet.
            broadcaster_min_balance_wei: 50_000_000_000_000_000,
            eth_usd_price_feed: EvmAddress(alloy_primitives::hex!(
                "5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"
            )),
            price_feed_max_staleness_secs: 14_400,
            residual_recovery_recipient: EvmAddress([0u8; 20]),
        }
    }
}

/// EVM chain ids treated as local/dev/test networks (anvil, hardhat,
/// ganache). Params targeting these chains skip the production-only safety
/// checks in [`validate_usdt_params`] (minimum confirmation depth,
/// non-placeholder contract addresses) since a dev federation intentionally
/// runs with the compiled-in placeholder/fast-confirmation defaults.
fn is_dev_chain(chain_id: u64) -> bool {
    matches!(chain_id, 31337 | 1337)
}

/// Minimum `confirmation_depth` required on a non-dev chain unless the
/// operator explicitly acknowledges the risk via
/// [`FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV`]. Chosen conservatively
/// (comparable to an hour of Ethereum mainnet blocks); operators of other
/// chains should override the env acknowledgement per their own chain's
/// reorg characteristics.
pub const MIN_PROD_CONFIRMATION_DEPTH: u64 = 6;

/// Sanity ceiling for `broadcaster_min_balance_wei`: 10 ETH. Far above any
/// sane per-guardian gas float; guards against a fat-fingered config value
/// that would make the broadcaster-funded readiness condition unreachable.
pub const MAX_BROADCASTER_MIN_BALANCE_WEI: u64 = 10_000_000_000_000_000_000;

/// Validates a [`UsdtGenParams`] for safety before it is baked into consensus
/// config. Called from both config-gen paths
/// ([`crate`]-external: `trusted_dealer_gen`/`dkg::distributed_gen` in
/// `fedimint-usdt-server`) *and* from every guardian's `validate_config`, so
/// an unsafe config is rejected both at generation time and defensively by
/// every guardian thereafter.
///
/// Deliberately permissive of the compiled-in anvil/hardhat dev defaults
/// ([`is_dev_chain`]) so dev/test federations are never broken by this
/// check; strict for any other `chain_id`. `confirmation_depth == 0` is
/// rejected unconditionally, even on dev chains, since it provides no
/// protection against chain reorgs whatsoever.
///
/// # Errors
///
/// Returns `Err` with a human-readable reason if `confirmation_depth` is
/// `0`; if `chain_id` is not a known dev chain and `confirmation_depth` is
/// below [`MIN_PROD_CONFIRMATION_DEPTH`] without the unsafe-ack env var set;
/// if `chain_id` is not a known dev chain and any of `usdt_contract`,
/// `entry_point`, `account_factory`, `simple_account_impl`, or
/// `residual_recovery_recipient` is the placeholder zero address; if
/// `price_feed_max_staleness_secs` is outside
/// `1..=86_400`; or if `broadcaster_min_balance_wei` is `0` or exceeds
/// [`MAX_BROADCASTER_MIN_BALANCE_WEI`].
pub fn validate_usdt_params(p: &UsdtGenParams) -> anyhow::Result<()> {
    ensure!(
        p.confirmation_depth >= 1,
        "confirmation_depth must be >= 1 (0 provides no protection against chain reorgs)"
    );

    if !is_dev_chain(p.chain_id) {
        let unsafe_low_depth_ack =
            std::env::var(fedimint_core::envs::FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV)
                .as_deref()
                == Ok("1");
        ensure!(
            p.confirmation_depth >= MIN_PROD_CONFIRMATION_DEPTH || unsafe_low_depth_ack,
            "confirmation_depth ({}) is below the minimum safe depth ({MIN_PROD_CONFIRMATION_DEPTH}) \
             for non-dev chain_id {}; set \
             {}=1 to acknowledge and override",
            p.confirmation_depth,
            p.chain_id,
            fedimint_core::envs::FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV,
        );

        let placeholder = EvmAddress([0u8; 20]);
        ensure!(
            p.usdt_contract != placeholder,
            "usdt_contract must not be the placeholder zero address on non-dev chain_id {}",
            p.chain_id
        );
        ensure!(
            p.entry_point != placeholder,
            "entry_point must not be the placeholder zero address on non-dev chain_id {}",
            p.chain_id
        );
        ensure!(
            p.account_factory != placeholder,
            "account_factory must not be the placeholder zero address on non-dev chain_id {}",
            p.chain_id
        );
        ensure!(
            p.simple_account_impl != placeholder,
            "simple_account_impl must not be the placeholder zero address on non-dev chain_id {}",
            p.chain_id
        );
        ensure!(
            p.residual_recovery_recipient != placeholder,
            "residual_recovery_recipient must not be the placeholder zero address on non-dev \
             chain_id {} (stranded EntryPoint gas deposits would be withdrawn to the zero \
             address and burned)",
            p.chain_id
        );
    }

    ensure!(
        (1..=86_400).contains(&p.price_feed_max_staleness_secs),
        "price_feed_max_staleness_secs ({}) must be between 1 and 86400",
        p.price_feed_max_staleness_secs
    );

    ensure!(
        p.broadcaster_min_balance_wei > 0,
        "broadcaster_min_balance_wei must be > 0 (0 would make every broadcaster read as \
         \"funded\" regardless of its actual on-chain balance)"
    );
    ensure!(
        p.broadcaster_min_balance_wei <= MAX_BROADCASTER_MIN_BALANCE_WEI,
        "broadcaster_min_balance_wei ({}) exceeds the sanity ceiling ({MAX_BROADCASTER_MIN_BALANCE_WEI})",
        p.broadcaster_min_balance_wei
    );

    Ok(())
}

/// Non-transaction items that will be submitted to consensus
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum UsdtConsensusItem {
    /// Guardian's view of the EVM chain head (median-voted, wallet-style).
    BlockCount(u64),
    /// LEGACY (deposit crediting is now proof-driven; see
    /// [`UsdtInput::DepositProofV0`]). Formerly a guardian's observation of a
    /// pending deposit account's confirmed balance, produced by the
    /// now-removed guardian-poll deposit path. No honest
    /// guardian proposes this any more; it is retained ONLY so the positional
    /// wire tags of the later variants do not shift (removing it would corrupt
    /// decode of existing consensus history). See [`DepositObservation`].
    Deposit(DepositObservation),
    /// One guardian's message for a single round of a signing session's
    /// cggmp21 state machine (Phase 6a).
    MpcRound(MpcRoundItem),
    /// A signer's federation-agreed signature for a signing session (Phase
    /// 6b). Proposed by a signer once its off-thread cggmp21 state machine
    /// finishes (see `Usdt::advance_local_signer`'s
    /// `pending_signature_proposals` queue in `fedimint-usdt-server`); every
    /// guardian — signer or not — verifies `signature` against the DKG group
    /// key and the session's digest before writing
    /// `SessionState::Completed(signature)` to the consensus `SigningSession`
    /// (see `Usdt::process_mpc_signature`). This is what makes the finished
    /// signature a federation-wide agreed record instead of guardian-local,
    /// signer-only state. `signature` is the compact 64-byte secp256k1
    /// signature.
    MpcSignature {
        session_id: SigningSessionId,
        signature: Vec<u8>,
    },
    /// Fails a stalled signing session and retries the same digest under a
    /// rotated signer subset (Phase 6b, Task 3). `session_id` is the
    /// TIMED-OUT attempt's id. Proposed by `consensus_proposal` for any
    /// `InProgress` session whose `last_progress_block` has fallen more than
    /// the timeout behind the consensus block count (a deterministic,
    /// consensus-DB-only judgement — never wall-clock — so every guardian
    /// agrees). Processing it is a pure function of the item, prior consensus
    /// DB state, and config: every guardian — signer or not — marks the
    /// timed-out `SigningSession` `Failed` and starts the next attempt
    /// (`attempt + 1`) under a rotated subset (see `Usdt::signer_subset` /
    /// `Usdt::start_session`), performing the identical consensus-DB writes.
    RotateSigning { session_id: SigningSessionId },
    /// One guardian's threshold-voted observation that `op_hash`'s
    /// `UserOp` has landed on-chain (Phase 7, Task 5) -- mirrors
    /// [`Self::Deposit`]'s observation-quorum shape exactly (dual-prefix
    /// per-peer vote, full-field `PartialEq` tally, unbounded-history
    /// `Err`-on-redundant). `success`/`block` come from the guardian-local
    /// deposit-checker-style background task's read of
    /// `IServerEvmRpc::get_user_op_receipt` (a guardian-local RPC result,
    /// never itself a consensus write); `swept` is the amount actually
    /// moved (self-contained in the vote so the applying guardian need not
    /// re-derive it). Processing this item (`fedimint_usdt_server::Usdt::
    /// process_consensus_item`'s `UserOpConfirmed` arm) is a pure function
    /// of the item, prior consensus DB state (the per-peer vote tally and
    /// the `SubmittedUserOp`/`PoolState`/`DepositRecord` records it updates
    /// at threshold), and config -- byte-identical on every guardian,
    /// signer or not.
    UserOpConfirmed {
        op_hash: [u8; 32],
        success: bool,
        block: u64,
        /// The canonical hash of `block` (security findings 04/15), read from
        /// the authoritative `EntryPoint` `UserOperationEvent` log via
        /// `IServerEvmRpc::get_user_op_receipt`. Part of the full-field
        /// equality tally, so two guardians observing the same op on
        /// different forks at the same height produce non-equal votes that
        /// never aggregate toward the confirmation threshold.
        block_hash: [u8; 32],
        swept: UsdtAmount,
        /// The op's on-chain gas cost in wei (security finding 09), read
        /// verbatim from the authoritative `EntryPoint` `UserOperationEvent`
        /// log's `actualGasCost` via `IServerEvmRpc::get_user_op_receipt`
        /// (a `UsdtAmount` reused only as a convenient `u64` newtype -- this
        /// carries WEI, not USDT; see
        /// [`user_op::UserOpReceipt::actual_gas_cost_wei`]). Part of the
        /// full-field equality tally like `swept`, so guardians only ever
        /// deduct a threshold-agreed gas figure. Used by
        /// `apply_withdraw_confirmed`'s failure path to accumulate each
        /// covered withdrawal's SHARE of the reverted batch's gas into its
        /// `WithdrawalIncurredFeeKey`, which the refund then deducts.
        actual_gas_cost_wei: UsdtAmount,
    },
    /// One guardian's vote on the current EVM fee market and USDT/ETH
    /// exchange rate (Phase 8, Task 1), mirroring [`Self::BlockCount`]'s
    /// per-peer-vote shape exactly: `process_consensus_item` stores this
    /// peer's vote (with a redundancy guard) and does not itself "apply"
    /// anything at threshold -- the current fee quote is read on demand as
    /// the per-field median over all stored votes (see
    /// `fedimint_usdt_server::Usdt::fee_vote_median`), not derived from any
    /// single peer's vote. Unlike `BlockCount`'s vote (which only ever
    /// increases, so the redundancy guard is `vote > current_vote`), the EVM
    /// fee market can move in either direction, so the guard here is
    /// equality-based (reject only an EXACT repeat of this peer's current
    /// vote). `vote` comes from this guardian's local, guardian-LOCAL
    /// `IServerEvmRpc::get_fee_estimate` read (never itself a consensus
    /// decision) -- the federation-wide fee decision is always the MEDIAN
    /// read from consensus DB, never a single guardian's raw RPC value.
    FeeVote(FeeVote),
    /// One guardian's periodic observation of whether the module's on-chain
    /// infrastructure is ready to honor the full deposit->claim->sweep->
    /// withdraw lifecycle (Part C), mirroring [`Self::Deposit`]'s per-peer
    /// observation-vote shape: `process_consensus_item` stores this peer's
    /// vote under `BootstrapVoteKey(ordered-item's peer)` (with a redundancy
    /// guard) and then deterministically latches "has ever been ready" the
    /// first time the aggregate tally reaches `Ready`. The federation's
    /// readiness state is never any single guardian's raw observation -- it
    /// is the per-field threshold count over all stored votes (see
    /// `fedimint_usdt_server::Usdt::bootstrap_state`). The five booleans come
    /// from this guardian's local, guardian-LOCAL read-only EVM RPC + config
    /// (never itself a consensus decision).
    BootstrapObservation(BootstrapObservation),
    /// Time out and replace a stuck/underpriced `SubmittedUserOp` (security
    /// finding 03). Proposed by `consensus_proposal` for any NON-superseded
    /// `SubmittedUserOp` whose `submitted_block` has fallen more than
    /// `submitted_op_timeout_blocks()` behind the consensus block count (a
    /// deterministic, consensus-DB-only judgement -- never wall-clock -- so
    /// every guardian agrees), mirroring [`Self::RotateSigning`]'s
    /// timed-out-session detection. Processing it
    /// (`fedimint_usdt_server::Usdt::process_replace_user_op`) is a pure
    /// function of the item, prior consensus DB state (the `SubmittedUserOp`,
    /// its covered `UnclaimedWithdrawal`s, and the fee-vote median), and
    /// config: it re-checks the timeout as a deterministic gate, then rebuilds
    /// the SAME logical op at the SAME `EntryPoint` `(sender, nonce)` with
    /// FRESH fees from the consensus median (bumped >= 10% over the old op
    /// so a bundler prefers the replacement), enqueues it as a fresh
    /// `PendingUserOp` + signing session, and marks the OLD op `superseded`
    /// (kept live so a late confirmation of it still settles -- the RBF-nonce
    /// safety point). Byte-identical on every guardian, signer or not.
    ReplaceUserOp { op_hash: [u8; 32] },
    /// One guardian's observation of the canonical hash of a confirmation-depth
    /// EVM block (deposit-by-proof anchor), mirroring [`Self::Deposit`]'s
    /// per-peer observation-vote shape. Proposed by `fedimint_usdt_server`'s
    /// guardian-local, READ-ONLY block-hash observer task (it only reads the
    /// hash via `IServerEvmRpc::get_block_hash` and queues it -- never itself a
    /// consensus write). `process_consensus_item` stores this peer's vote under
    /// `BlockHashVoteKey(ordered-item's peer)` (with a redundancy guard + a
    /// freshness gate mirroring the `Deposit` arm) and, once at least a
    /// threshold of guardians have proposed the IDENTICAL `(height,
    /// block_hash)` pair, writes it into the consensus block-hash ring
    /// (`write_block_hash_ring`) -- the anchor a later deposit-by-proof input
    /// verifies a client's `eth_getProof` state proof against. The ring write
    /// is therefore never any single guardian's raw observation; it is a pure
    /// function of the threshold-agreed pair + prior consensus DB.
    BlockHash(BlockHashObservation),
    /// One guardian's threshold-voted observation of a fully-swept, single-use
    /// deposit account's stranded on-chain `EntryPoint` gas deposit (finding
    /// A), mirroring [`Self::Deposit`]'s per-peer observation-vote shape.
    /// Proposed by `fedimint_usdt_server`'s guardian-local, READ-ONLY residual-
    /// recovery observer task (it only reads the account's `EntryPoint` balance
    /// via `IServerEvmRpc::get_entrypoint_deposit` and queues it -- never
    /// itself a consensus write). `process_consensus_item` stores this
    /// peer's vote (with a redundancy guard) and, once at least a threshold
    /// of guardians have proposed observations for the account, takes the
    /// threshold-MEDIAN `deposit_wei` (so a lone byzantine reporter cannot
    /// inflate the recovered amount) and — if it exceeds the op's own gas
    /// need with margin — builds a threshold-signed
    /// `EntryPoint.withdrawTo(recipient, amount)` op sending the residual
    /// to the deterministic `residual_recovery_recipient` consensus
    /// config address. The recovered ETH is broadcaster gas, not USDT pool
    /// balance, so it never touches `PoolState`. The op-build is a pure
    /// function of the threshold-agreed `deposit_wei`, the fee-vote median,
    /// prior consensus DB state, and config -- byte-identical on every
    /// guardian.
    RecoverResidual {
        account: EvmAddress,
        /// The observed on-chain `EntryPoint` gas deposit of the swept account,
        /// in wei. Carried as a `u64` (the codebase's wire representation for
        /// wei, matching `FeeVote::max_fee_per_gas_wei` and
        /// `broadcaster_min_balance_wei`) -- a single-op gas deposit is far
        /// below `u64::MAX` wei (~18.4 ETH). The guardian-local observer reads
        /// the raw balance as `u128` and clamps to this wire type; the
        /// `process_consensus_item` recovery arm widens back to `u128` for the
        /// `need`/margin arithmetic.
        deposit_wei: u64,
    },
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// Input for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum UsdtInput {
    /// Claim credited deposit funds. Core verifies the fedimint transaction is
    /// signed by `InputMeta.pub_key` = the deposit's claim key; there is no
    /// extra signature inside the input.
    V0(UsdtInputV0),
    /// Claim the reissued e-cash of a terminally-failed withdrawal (security
    /// finding 09), identified by the `OutPoint` of the `UsdtOutput::V0` that
    /// originally enqueued it. The server's `process_input` looks up the
    /// `RefundKey(out_point)` refund record (created when the withdrawal went
    /// terminal-`Failed`), returns `InputMeta { amounts: refund.amount, fees:
    /// ZERO, pub_key: refund.refund_pubkey }`, and REMOVES the refund record
    /// so it can be claimed EXACTLY ONCE (a second claim finds it absent ->
    /// [`UsdtInputError::UnknownRefund`]). Core verifies the fedimint
    /// transaction is signed by `pub_key` = the withdrawal's
    /// client-controlled `refund_pubkey`, so ONLY the original withdrawer can
    /// claim the refund -- never by `out_point` alone.
    RefundV0 { out_point: OutPoint },
    /// Credit (and, in the same transaction, mint) a deposit directly from a
    /// deterministically-verified on-chain USDT balance proof
    /// (deposit-by-proof). Replaces the guardian-polling observation path: the
    /// depositor funds the CREATE2 deposit account derived from `claim_pk`
    /// ([`derive_deposit_account`]), then submits this input carrying that
    /// `claim_pk` plus a [`DepositProof`] of the account's balance at a
    /// canonical block.
    ///
    /// The server derives `account = derive_deposit_account(claim_pk)` (the
    /// SAME binding [`DepositObservation`]-driven crediting enforces) and
    /// verifies `proof` proves THAT account's balance against the federation's
    /// consensus block-hash ring anchor for `proof.block_number`. Because the
    /// account is derived from `claim_pk`, a proof of some unrelated on-chain
    /// account (e.g. an exchange's) verifies against a different storage key
    /// and yields a zero delta -- an attacker cannot credit funds they cannot
    /// also derive a `claim_pk` for. Only the newly-proven delta over the
    /// account's existing high-water `credited` is minted, and core verifies
    /// the fedimint transaction is signed by `InputMeta.pub_key` = `claim_pk`,
    /// so only the depositor can spend it.
    DepositProofV0 {
        claim_pk: secp256k1::PublicKey,
        proof: DepositProof,
    },
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// Data for a `UsdtInput::V0`: claim `amount` of credited deposit from
/// `account`, offering `fee` (in the same [`UsdtAmount`] unit, mirroring
/// [`UsdtOutputV0::max_fee`]) to cover the federation's on-chain gas cost of
/// deploying and sweeping the deposit account. The server's `process_input`
/// rejects the input (`UsdtInputError::DepositFeeInsufficient`) if `fee` is
/// below the federation's current fee-vote-median-derived quote (see
/// [`deposit_fee_quote`]), and rejects it
/// (`UsdtInputError::FeeExceedsAmount`) if `fee >= amount`; the e-cash
/// actually issued to the claimant is `amount - fee`, while `fee`'s USDT
/// stays credited-but-unissued backing that the sweep still pulls into the
/// pool.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtInputV0 {
    pub account: EvmAddress,
    pub amount: UsdtAmount,
    pub fee: UsdtAmount,
}

/// Output for a fedimint transaction (Phase 8, Task 1): a user burning USDT
/// e-cash to enqueue an on-chain withdrawal.
///
/// Versioned like [`UsdtInput`] (a `V0` variant plus an
/// `#[encodable_default]` catch-all), so a future gas/fee model change can
/// add `UsdtOutput::V1` without breaking wire-compatibility with old
/// transactions still referencing `V0`.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum UsdtOutput {
    V0(UsdtOutputV0),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

/// Data for a `UsdtOutput::V0`: withdraw `amount` of USDT to `recipient`,
/// offering up to `max_fee` (in the same [`UsdtAmount`] unit) to cover the
/// federation's on-chain gas cost of paying it out. The server's
/// `process_output` rejects the output (`UsdtOutputError::FeeQuoteExceeded`)
/// if `max_fee` is below the federation's current fee-vote-median-derived
/// quote (see `fedimint_usdt_common::withdrawal_fee_quote`); `amount +
/// max_fee` of `USDT_UNIT`-denominated e-cash is burned from the submitting
/// transaction's funding.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtOutputV0 {
    pub recipient: EvmAddress,
    pub amount: UsdtAmount,
    pub max_fee: UsdtAmount,
    /// A client-controlled public key that will own the e-cash reissued if
    /// this withdrawal ever goes terminally `Failed` (security finding 09).
    /// The client derives the matching secret deterministically from its seed
    /// (see `fedimint_usdt_client`'s `refund_keypair_for_index`) and keeps it
    /// locally; the server stores this pubkey alongside the withdrawal
    /// (`UsdtWithdrawalV0::refund_pubkey`) and, on a terminal failure, writes a
    /// refund record claimable ONLY by a transaction signed by it (see
    /// [`UsdtInput::RefundV0`]). Making the refund key client-controlled (not
    /// the federation) is what guarantees the reissued e-cash can only be
    /// claimed by the original withdrawer.
    pub refund_pubkey: secp256k1::PublicKey,
}

/// Information needed by a client to update output funds.
///
/// Deliberately minimal (a unit struct, like the pre-Phase-8 placeholder):
/// `output_status` returns `Some(UsdtOutputOutcome)` once a withdrawal has
/// been enqueued (i.e. `process_output` succeeded for this `OutPoint`) and
/// `None` otherwise, just proving the output landed. The detailed
/// [lifecycle state](crate) (`Queued`/`Signing`/`Submitted`/`Confirmed`/
/// `Failed`) is server-only (`fedimint_usdt_server::db::WithdrawalState`)
/// and tracked via a dedicated status endpoint (Task 4), not via this
/// outcome type, so it can evolve (e.g. gain the signing `UserOp` hash)
/// without a wire-breaking change here.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtOutputOutcome;

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum UsdtInputError {
    #[error("No credited deposit record exists for this account")]
    UnknownDepositAccount,
    #[error("Claim of {requested} exceeds the {available} still claimable for this account")]
    InsufficientCredit {
        available: UsdtAmount,
        requested: UsdtAmount,
    },
    #[error("This input's fee {offered} is below the federation's deposit fee quote {quote}")]
    DepositFeeInsufficient {
        quote: UsdtAmount,
        offered: UsdtAmount,
    },
    #[error("This input's fee {fee} would consume all or more of its {amount} claimed amount")]
    FeeExceedsAmount { amount: UsdtAmount, fee: UsdtAmount },
    #[error("No federation fee-vote median is available yet; deposits cannot be claimed")]
    NoFeeQuoteAvailable,
    #[error("Computing the deposit fee quote overflowed")]
    FeeQuoteOverflow,
    #[error("No refund record exists for this out_point (never failed, or already claimed)")]
    UnknownRefund,
    #[error(
        "deposit proof's block {block} is not anchored in the federation's block-hash ring (not \
         yet confirmed, or aged out of the retained window)"
    )]
    DepositProofNotAnchored { block: u64 },
    #[error("deposit proof verification failed: {reason}")]
    DepositProofInvalid { reason: String },
    #[error(
        "deposit proof proves {proven} but {credited} is already credited for this account \
         (nothing new to credit)"
    )]
    DepositProofStale {
        proven: UsdtAmount,
        credited: UsdtAmount,
    },
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum UsdtOutputError {
    #[error("This module does not support this output variant")]
    UnsupportedOutputVariant,
    #[error("No federation fee-vote median is available yet; withdrawals cannot be queued")]
    NoFeeQuoteAvailable,
    #[error("Computing the withdrawal fee quote overflowed")]
    FeeQuoteOverflow,
    #[error("This output's max_fee {max_fee} is below the federation's fee quote {quote}")]
    FeeQuoteExceeded {
        quote: UsdtAmount,
        max_fee: UsdtAmount,
    },
}

/// Contains the types defined above
pub struct UsdtModuleTypes;

// Wire together the types for this module
plugin_types_trait_impl_common!(
    KIND,
    UsdtModuleTypes,
    UsdtClientConfig,
    UsdtInput,
    UsdtOutput,
    UsdtOutputOutcome,
    UsdtConsensusItem,
    UsdtInputError,
    UsdtOutputError
);

#[derive(Debug)]
pub struct UsdtCommonInit;

impl CommonModuleInit for UsdtCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = UsdtClientConfig;

    fn decoder() -> Decoder {
        UsdtModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for UsdtInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for UsdtOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for UsdtOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UsdtOutputOutcome")
    }
}

impl fmt::Display for UsdtConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::core::ModuleKind;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    use super::*;

    #[test]
    fn test_kind_is_usdt() {
        assert_eq!(KIND, ModuleKind::from_static_str("usdt"));
    }

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

    #[test]
    fn deposit_proof_round_trips_through_consensus_encoding() {
        let proof = DepositProof {
            block_number: 19_123_456,
            header_rlp: vec![0xf9, 0x02, 0x00, 0xa0, 0x01, 0x02, 0x03],
            account_proof: vec![
                vec![0x01, 0x02, 0x03],
                vec![0x04, 0x05, 0x06, 0x07],
                vec![0x08],
            ],
            storage_proof: vec![vec![0xaa, 0xbb, 0xcc], vec![0xdd, 0xee]],
        };

        let bytes = proof.consensus_encode_to_vec();
        let decoded =
            DepositProof::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("DepositProof should decode what it just encoded");

        assert_eq!(proof, decoded);
    }

    #[test]
    fn test_evm_address_round_trips_through_consensus_encoding() {
        let address = EvmAddress([0x11; 20]);
        let bytes = address.consensus_encode_to_vec();
        let decoded = EvmAddress::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("EvmAddress should decode what it just encoded");

        assert_eq!(address, decoded);
    }

    #[test]
    fn usdt_amount_roundtrips() {
        // (misc #3) `usdt_amount` is a pure relabeling of the smallest
        // on-chain USDT unit into core's `Amount` (custom `USDT_UNIT`); the
        // numeric value must survive untouched.
        for n in [0, 1, 10_000, 200_000_000, u64::MAX] {
            assert_eq!(usdt_amount(UsdtAmount(n)).msats, n);
        }
    }

    #[test]
    fn create_address_matches_known_ethereum_vectors() {
        // Canonical EIP-161 §1 CREATE-address example: sender
        // 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0 produces these contracts.
        let sender = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
            .parse::<EvmAddress>()
            .unwrap();
        assert_eq!(
            create_address(sender, 0),
            "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"
                .parse::<EvmAddress>()
                .unwrap(),
        );
        assert_eq!(
            create_address(sender, 1),
            "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8"
                .parse::<EvmAddress>()
                .unwrap(),
        );

        // Multi-byte nonce vector (nonce 0x100 == 256), exercising the
        // length-prefixed RLP integer branch.
        assert_eq!(
            create_address(sender, 256),
            "0x3837c1ae70354f670550c746580199ac6a73cb0a"
                .parse::<EvmAddress>()
                .unwrap(),
        );
    }

    #[test]
    fn test_usdt_amount_round_trips_through_consensus_encoding() {
        let amount = UsdtAmount(1_000_000);
        let bytes = amount.consensus_encode_to_vec();
        let decoded = UsdtAmount::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("UsdtAmount should decode what it just encoded");

        assert_eq!(amount, decoded);
    }

    #[test]
    fn test_fee_vote_round_trips_through_consensus_encoding() {
        let vote = FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let bytes = vote.consensus_encode_to_vec();
        let decoded = FeeVote::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("FeeVote should decode what it just encoded");

        assert_eq!(vote, decoded);
    }

    #[test]
    fn test_bootstrap_observation_round_trips_through_consensus_item_encoding() {
        let obs = BootstrapObservation {
            entry_point_ok: true,
            factory_ok: false,
            impl_ok: true,
            broadcaster_funded: false,
            rpc_healthy: true,
        };
        let item = UsdtConsensusItem::BootstrapObservation(obs);
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("BootstrapObservation item should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_status_response_round_trips_through_consensus_encoding() {
        let response = StatusResponse {
            state: BootstrapState::Degraded,
            entry_point_ok: true,
            factory_ok: true,
            impl_ok: true,
            funded_guardians: 2,
            healthy_guardians: 3,
            threshold: 3,
        };
        let bytes = response.consensus_encode_to_vec();
        let decoded =
            StatusResponse::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("StatusResponse should decode what it just encoded");

        assert_eq!(response, decoded);
    }

    #[test]
    fn test_evm_address_display_is_lowercase_hex_with_0x_prefix() {
        let address = EvmAddress([
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
        ]);
        let rendered = address.to_string();

        assert!(rendered.starts_with("0x"));
        assert_eq!(rendered.len(), 42);
        assert!(
            rendered
                .chars()
                .skip(2)
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn test_module_decoder_builds() {
        let _decoder = UsdtModuleTypes::decoder_builder().build();
    }

    fn hex_20(s: &str) -> [u8; 20] {
        let bytes = (0..20)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>();
        bytes.try_into().unwrap()
    }

    #[test]
    fn evm_address_matches_keccak_last_20_of_uncompressed() {
        // A fixed secp256k1 pubkey → its well-known Ethereum address.
        // Secret key = 0x0000...0001; address is the canonical test vector.
        let sk = secp256k1::SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        })
        .expect("valid scalar");
        let pk = sk.public_key(secp256k1::SECP256K1);
        // keccak256(uncompressed[1..])[12..] for sk=1:
        let expected = EvmAddress(hex_20("7e5f4552091a69125d5dfcb7b8c2659029395bdf"));
        assert_eq!(evm_address(&pk), expected);
    }

    #[test]
    fn derive_deposit_account_is_deterministic_and_claim_specific() {
        let group = secp256k1::SecretKey::from_slice(&[2u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let claim_a = secp256k1::SecretKey::from_slice(&[3u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let claim_b = secp256k1::SecretKey::from_slice(&[4u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        // Fixed non-zero test constants; the CREATE2 math is exercised
        // end-to-end (and pinned against a real on-chain factory) by
        // `fedimint-usdt-tests/tests/erc4337_harness.rs`, so any non-zero
        // addresses suffice here.
        let factory = EvmAddress([0xfa; 20]);
        let simple_account_impl = EvmAddress([0x1e; 20]);

        // Deterministic
        assert_eq!(
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a),
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a)
        );
        // Distinct per claim key
        assert_ne!(
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a),
            derive_deposit_account(&group, factory, simple_account_impl, &claim_b)
        );
        // Distinct from the bare (untweaked) group-key EOA address: the
        // deposit account is a CREATE2 *smart contract* address, never
        // literally `evm_address(group_public_key)`.
        assert_ne!(
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a),
            evm_address(&group)
        );
        // Distinct per factory (a different `SimpleAccountFactory` deployment
        // must never collide with another's counterfactual addresses).
        let other_factory = EvmAddress([0xfb; 20]);
        assert_ne!(
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a),
            derive_deposit_account(&group, other_factory, simple_account_impl, &claim_a)
        );
        // Distinct per `simple_account_impl` (changes `initCode`, hence the
        // CREATE2 address).
        let other_impl = EvmAddress([0x1f; 20]);
        assert_ne!(
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a),
            derive_deposit_account(&group, factory, other_impl, &claim_a)
        );
    }

    #[test]
    fn test_usdt_consensus_item_block_count_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::BlockCount(7);
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::BlockCount should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_deposit_round_trips_through_consensus_encoding() {
        let claim_pk = secp256k1::SecretKey::from_slice(&[5u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let item = UsdtConsensusItem::Deposit(DepositObservation {
            account: EvmAddress([9; 20]),
            balance: UsdtAmount(1_000_000),
            block: 42,
            block_hash: [0xAB; 32],
            claim_pk,
        });
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::Deposit should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_block_hash_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::BlockHash(BlockHashObservation {
            height: 123,
            block_hash: [0xEF; 32],
        });
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::BlockHash should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_mpc_round_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::MpcRound(MpcRoundItem {
            session_id: SigningSessionId([7; 32]),
            round: 3,
            chunk: 1,
            chunk_count: 2,
            payload: vec![1, 2, 3],
        });
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::MpcRound should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_mpc_signature_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::MpcSignature {
            session_id: SigningSessionId([8; 32]),
            signature: vec![1; 64],
        };
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::MpcSignature should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_user_op_confirmed_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::UserOpConfirmed {
            op_hash: [6; 32],
            success: true,
            block: 77,
            block_hash: [0xCD; 32],
            swept: UsdtAmount(1_234_000),
            actual_gas_cost_wei: UsdtAmount(5_000_000_000_000_000),
        };
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::UserOpConfirmed should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn derive_pool_account_is_deterministic_and_distinct_from_deposit_accounts() {
        let group = secp256k1::SecretKey::from_slice(&[7u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let other_group = secp256k1::SecretKey::from_slice(&[8u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let claim = secp256k1::SecretKey::from_slice(&[9u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let factory = EvmAddress([0xfa; 20]);
        let simple_account_impl = EvmAddress([0x1e; 20]);

        // Deterministic.
        assert_eq!(
            derive_pool_account(&group, factory, simple_account_impl),
            derive_pool_account(&group, factory, simple_account_impl)
        );
        // Distinct per group key (a different federation's pool never
        // collides).
        assert_ne!(
            derive_pool_account(&group, factory, simple_account_impl),
            derive_pool_account(&other_group, factory, simple_account_impl)
        );
        // Distinct from any deposit account derived under the same group key
        // (the pool is never mistaken for a claimant's deposit address).
        assert_ne!(
            derive_pool_account(&group, factory, simple_account_impl),
            derive_deposit_account(&group, factory, simple_account_impl, &claim)
        );
    }

    #[test]
    fn test_usdt_consensus_item_rotate_signing_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::RotateSigning {
            session_id: SigningSessionId([5; 32]),
        };
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::RotateSigning should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_replace_user_op_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::ReplaceUserOp {
            op_hash: [0x2b; 32],
        };
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::ReplaceUserOp should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn wei_gas_cost_to_usdt_matches_hand_computation_and_overflows_to_none() {
        // 360_000 gas * 66 gwei = 2.376e16 wei; at 3000 USDT/ETH
        // (usdt_per_eth_e6 = 3e9) that is 2.376e16 * 3e9 / 1e18 = 71_280_000
        // raw USDT units (1e-6 USDT each).
        let gas_cost_wei = 360_000u128 * 66_000_000_000u128;
        assert_eq!(
            wei_gas_cost_to_usdt(gas_cost_wei, 3_000_000_000),
            Some(UsdtAmount(71_280_000))
        );
        // A degenerate/byzantine rate that overflows u128 yields None (never a
        // wrapped value).
        assert_eq!(wei_gas_cost_to_usdt(u128::MAX, u64::MAX), None);
    }

    #[test]
    fn signing_session_id_is_deterministic_and_attempt_sensitive() {
        let digest = [9u8; 32];

        assert_eq!(
            signing_session_id(&digest, 0),
            signing_session_id(&digest, 0)
        );
        assert_ne!(
            signing_session_id(&digest, 0),
            signing_session_id(&digest, 1)
        );
    }

    #[test]
    fn test_usdt_input_v0_round_trips_through_consensus_encoding() {
        let input = UsdtInput::V0(UsdtInputV0 {
            account: EvmAddress([9; 20]),
            amount: UsdtAmount(1_000_000),
            fee: UsdtAmount(1_000),
        });
        let bytes = input.consensus_encode_to_vec();
        let decoded = UsdtInput::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("UsdtInput::V0 should decode what it just encoded");

        assert_eq!(input, decoded);
    }

    /// A fixed, valid secp256k1 public key for encoding round-trip tests.
    fn test_refund_pubkey() -> secp256k1::PublicKey {
        secp256k1::SecretKey::from_slice(&[0x24; 32])
            .expect("valid scalar")
            .public_key(secp256k1::SECP256K1)
    }

    #[test]
    fn test_usdt_output_v0_round_trips_through_consensus_encoding() {
        let output = UsdtOutput::V0(UsdtOutputV0 {
            recipient: EvmAddress([7; 20]),
            amount: UsdtAmount(2_000_000),
            max_fee: UsdtAmount(1_000),
            refund_pubkey: test_refund_pubkey(),
        });
        let bytes = output.consensus_encode_to_vec();
        let decoded = UsdtOutput::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("UsdtOutput::V0 should decode what it just encoded");

        assert_eq!(output, decoded);
    }

    #[test]
    fn test_usdt_input_refund_v0_round_trips_through_consensus_encoding() {
        use fedimint_core::{BitcoinHash as _, OutPoint, TransactionId};
        let input = UsdtInput::RefundV0 {
            out_point: OutPoint {
                txid: TransactionId::all_zeros(),
                out_idx: 3,
            },
        };
        let bytes = input.consensus_encode_to_vec();
        let decoded = UsdtInput::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("UsdtInput::RefundV0 should decode what it just encoded");

        assert_eq!(input, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_fee_vote_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::FeeVote(FeeVote {
            max_fee_per_gas_wei: 25_000_000_000,
            usdt_per_eth_e6: 3_200_000_000,
        });
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::FeeVote should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn fee_vote_in_sane_range_accepts_realistic_and_boundary_values() {
        // A realistic vote (30 gwei, $3000/ETH) is well within range.
        assert!(fee_vote_in_sane_range(&FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        }));

        // Both fields' exact ceilings are still sane (inclusive bound).
        assert!(fee_vote_in_sane_range(&FeeVote {
            max_fee_per_gas_wei: MAX_SANE_MAX_FEE_PER_GAS_WEI,
            usdt_per_eth_e6: MAX_SANE_USDT_PER_ETH_E6,
        }));

        // Both fields' minimum sane value (1) is still sane (inclusive
        // bound).
        assert!(fee_vote_in_sane_range(&FeeVote {
            max_fee_per_gas_wei: 1,
            usdt_per_eth_e6: 1,
        }));
    }

    #[test]
    fn fee_vote_in_sane_range_rejects_zero_and_above_ceiling() {
        let realistic = FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };

        // Zero in either field (the "0-median" DoS variant of the finding).
        assert!(!fee_vote_in_sane_range(&FeeVote {
            max_fee_per_gas_wei: 0,
            ..realistic
        }));
        assert!(!fee_vote_in_sane_range(&FeeVote {
            usdt_per_eth_e6: 0,
            ..realistic
        }));

        // One above the ceiling in either field (the extreme-vote DoS
        // variant of the finding).
        assert!(!fee_vote_in_sane_range(&FeeVote {
            max_fee_per_gas_wei: MAX_SANE_MAX_FEE_PER_GAS_WEI + 1,
            ..realistic
        }));
        assert!(!fee_vote_in_sane_range(&FeeVote {
            usdt_per_eth_e6: MAX_SANE_USDT_PER_ETH_E6 + 1,
            ..realistic
        }));
    }

    #[test]
    fn withdrawal_fee_quote_computes_expected_value() {
        // 30 gwei max_fee_per_gas, 3000.000000 USDT/ETH.
        let median = FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        // gas_cost_wei = 360_000 * 30e9 = 1.08e16
        // numerator = 1.08e16 * 3_000_000_000 * 120 = 3.888e27
        // denominator = 1e18 * 100 = 1e20
        // fee = 3.888e27 / 1e20 = 38_880_000 (raw USDT units == 38.88 USDT,
        // i.e. the unbuffered 32_400_000 scaled by the 20% buffer)
        let quote = withdrawal_fee_quote(&median).expect("must not overflow for realistic input");
        assert_eq!(quote, UsdtAmount(38_880_000));
    }

    #[test]
    fn withdrawal_fee_quote_is_deterministic() {
        let median = FeeVote {
            max_fee_per_gas_wei: 87_654_321,
            usdt_per_eth_e6: 3_456_789_012,
        };
        assert_eq!(withdrawal_fee_quote(&median), withdrawal_fee_quote(&median));
    }

    #[test]
    fn withdrawal_fee_quote_scales_with_gas_price() {
        let low = FeeVote {
            max_fee_per_gas_wei: 10_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let high = FeeVote {
            max_fee_per_gas_wei: 100_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let quote_low = withdrawal_fee_quote(&low).expect("must not overflow");
        let quote_high = withdrawal_fee_quote(&high).expect("must not overflow");
        assert!(quote_high.0 > quote_low.0);
    }

    #[test]
    fn withdrawal_fee_quote_overflow_is_none_not_a_panic() {
        // An extreme (e.g. byzantine-voted) FeeVote whose product overflows
        // u128 part-way through the computation must return `None`, never
        // panic (no unwrap/wrapping arithmetic).
        let median = FeeVote {
            max_fee_per_gas_wei: u64::MAX,
            usdt_per_eth_e6: u64::MAX,
        };
        assert_eq!(withdrawal_fee_quote(&median), None);
    }

    #[test]
    fn deposit_fee_quote_computes_expected_value() {
        // 30 gwei max_fee_per_gas, 3000.000000 USDT/ETH.
        let median = FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        // gas_cost_wei = 800_000 * 30e9 = 2.4e16
        // numerator = 2.4e16 * 3_000_000_000 * 120 = 8.64e27
        // denominator = 1e18 * 100 = 1e20
        // fee = 8.64e27 / 1e20 = 86_400_000 (raw USDT units == 86.4 USDT,
        // i.e. the unbuffered 72_000_000 scaled by the 20% buffer)
        let quote = deposit_fee_quote(&median).expect("must not overflow for realistic input");
        assert_eq!(quote, UsdtAmount(86_400_000));
    }

    #[test]
    fn deposit_fee_quote_is_deterministic() {
        let median = FeeVote {
            max_fee_per_gas_wei: 87_654_321,
            usdt_per_eth_e6: 3_456_789_012,
        };
        assert_eq!(deposit_fee_quote(&median), deposit_fee_quote(&median));
    }

    #[test]
    fn deposit_fee_quote_scales_with_gas_price() {
        let low = FeeVote {
            max_fee_per_gas_wei: 10_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let high = FeeVote {
            max_fee_per_gas_wei: 100_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let quote_low = deposit_fee_quote(&low).expect("must not overflow");
        let quote_high = deposit_fee_quote(&high).expect("must not overflow");
        assert!(quote_high.0 > quote_low.0);
    }

    #[test]
    fn deposit_fee_quote_zero_median_is_floored() {
        // A degenerate all-zero `FeeVote` median (e.g. an idle `anvil`
        // devnet reporting a zero base fee, or every guardian voting zeros)
        // must never yield a zero (free) deposit quote: the
        // `MIN_DEPOSIT_FEE` floor kicks in instead, mirroring
        // `withdrawal_fee_quote_zero_median_is_floored_not_free`.
        let median = FeeVote {
            max_fee_per_gas_wei: 0,
            usdt_per_eth_e6: 0,
        };
        let quote = deposit_fee_quote(&median).expect("zero median must not overflow");
        assert_eq!(quote, MIN_DEPOSIT_FEE);
        assert_ne!(
            quote.0, 0,
            "a degenerate zero median must never quote a free deposit"
        );
    }

    #[test]
    fn deposit_fee_quote_overflow_is_none_not_a_panic() {
        // An extreme (e.g. byzantine-voted) FeeVote whose product overflows
        // u128 part-way through the computation must return `None`, never
        // panic (no unwrap/wrapping arithmetic).
        let median = FeeVote {
            max_fee_per_gas_wei: u64::MAX,
            usdt_per_eth_e6: u64::MAX,
        };
        assert_eq!(deposit_fee_quote(&median), None);
    }

    #[test]
    fn chainlink_price_happy_path_8_decimals() {
        // $3000.00 at 8 decimals, fresh, complete round -> 3000_000000 (1e-6 USDT)
        let v =
            chainlink_eth_usd_to_usdt_per_eth_e6(300_000_000_000, 8, 42, 42, 1_000, 1_500, 14_400);
        assert_eq!(v, Some(3_000_000_000));
    }

    #[test]
    fn chainlink_price_rejects_non_positive_answer() {
        assert_eq!(
            chainlink_eth_usd_to_usdt_per_eth_e6(0, 8, 1, 1, 1_000, 1_000, 14_400),
            None
        );
        assert_eq!(
            chainlink_eth_usd_to_usdt_per_eth_e6(-1, 8, 1, 1, 1_000, 1_000, 14_400),
            None
        );
    }

    #[test]
    fn chainlink_price_rejects_incomplete_round() {
        // answered_in_round < round_id -> carried-over/incomplete
        assert_eq!(
            chainlink_eth_usd_to_usdt_per_eth_e6(300_000_000_000, 8, 42, 41, 1_000, 1_100, 14_400),
            None
        );
    }

    #[test]
    fn chainlink_price_rejects_stale() {
        // chain_now - updated_at (20_000) > max_staleness (14_400)
        assert_eq!(
            chainlink_eth_usd_to_usdt_per_eth_e6(300_000_000_000, 8, 1, 1, 1_000, 21_000, 14_400),
            None
        );
    }

    #[test]
    fn chainlink_price_rejects_future_timestamp() {
        // updated_at > chain_now (clock/feed anomaly) -> abstain
        assert_eq!(
            chainlink_eth_usd_to_usdt_per_eth_e6(300_000_000_000, 8, 1, 1, 2_000, 1_000, 14_400),
            None
        );
    }

    fn test_out_point(idx: u64) -> OutPoint {
        use fedimint_core::BitcoinHash as _;
        OutPoint {
            txid: fedimint_core::TransactionId::all_zeros(),
            out_idx: idx,
        }
    }

    #[test]
    fn test_withdrawal_status_request_round_trips_through_consensus_encoding() {
        let request = WithdrawalStatusRequest {
            out_point: test_out_point(3),
        };
        let bytes = request.consensus_encode_to_vec();
        let decoded = WithdrawalStatusRequest::consensus_decode_whole(
            &bytes,
            &ModuleDecoderRegistry::default(),
        )
        .expect("WithdrawalStatusRequest should decode what it just encoded");

        assert_eq!(request.out_point, decoded.out_point);
    }

    #[test]
    fn test_withdrawal_status_response_round_trips_every_variant_through_consensus_encoding() {
        let responses = [
            WithdrawalStatus::Unknown,
            WithdrawalStatus::Queued,
            WithdrawalStatus::Signing { op_hash: [1; 32] },
            WithdrawalStatus::Submitted { op_hash: [2; 32] },
            WithdrawalStatus::Confirmed { block: 99 },
            WithdrawalStatus::Failed {
                reason: "gas spike".to_string(),
            },
        ]
        .map(|status| WithdrawalStatusResponse { status });

        for response in responses {
            let bytes = response.consensus_encode_to_vec();
            let decoded = WithdrawalStatusResponse::consensus_decode_whole(
                &bytes,
                &ModuleDecoderRegistry::default(),
            )
            .expect("WithdrawalStatusResponse should decode what it just encoded");

            assert_eq!(response, decoded);
        }
    }

    #[test]
    fn test_withdrawal_status_response_round_trips_through_serde_json() {
        let response = WithdrawalStatusResponse {
            status: WithdrawalStatus::Signing { op_hash: [7; 32] },
        };
        let json = fedimint_core::module::serde_json::to_string(&response).expect("serializes");
        let decoded: WithdrawalStatusResponse = fedimint_core::module::serde_json::from_str(&json)
            .expect("WithdrawalStatusResponse should deserialize what it just serialized");

        assert_eq!(response, decoded);
    }

    #[test]
    fn withdrawal_fee_quote_zero_median_is_floored_not_free() {
        // A degenerate all-zero `FeeVote` median (e.g. an idle `anvil`
        // devnet reporting a zero base fee, or every guardian voting zeros)
        // must never yield a zero (free) withdrawal quote: the
        // `MIN_WITHDRAWAL_FEE` floor kicks in instead (Phase 9, Task 1
        // hardening).
        let median = FeeVote {
            max_fee_per_gas_wei: 0,
            usdt_per_eth_e6: 0,
        };
        let quote = withdrawal_fee_quote(&median).expect("zero median must not overflow");
        assert_eq!(quote, MIN_WITHDRAWAL_FEE);
        assert_ne!(
            quote.0, 0,
            "a degenerate zero median must never quote a free withdrawal"
        );
    }

    #[test]
    fn withdrawal_fee_quote_near_zero_median_is_also_floored() {
        // A tiny but nonzero median whose computed fee would round to below
        // the floor is still floored up to `MIN_WITHDRAWAL_FEE`, not left at
        // its (near-)free computed value.
        let median = FeeVote {
            max_fee_per_gas_wei: 1,
            usdt_per_eth_e6: 1,
        };
        let quote = withdrawal_fee_quote(&median).expect("tiny median must not overflow");
        assert_eq!(quote, MIN_WITHDRAWAL_FEE);
    }

    #[test]
    fn withdrawal_fee_quote_realistic_median_is_unaffected_by_the_floor() {
        // A realistic gas-market median (same as
        // `withdrawal_fee_quote_computes_expected_value`) computes well
        // above `MIN_WITHDRAWAL_FEE`, so the floor must not perturb it.
        let median = FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let quote = withdrawal_fee_quote(&median).expect("must not overflow for realistic input");
        assert_eq!(quote, UsdtAmount(38_880_000));
        assert!(quote.0 > MIN_WITHDRAWAL_FEE.0);
    }

    #[test]
    fn withdrawal_fee_quote_large_but_plausible_gas_price_does_not_overflow() {
        // A large but plausible fee spike: 5000 gwei max_fee_per_gas (far
        // above anything seen in practice, but nowhere near u64::MAX) and a
        // high ETH price, exercising the u128 intermediate without
        // overflowing.
        let median = FeeVote {
            max_fee_per_gas_wei: 5_000_000_000_000, // 5000 gwei
            usdt_per_eth_e6: 10_000_000_000,        // 10,000.000000 USDT/ETH
        };
        let quote = withdrawal_fee_quote(&median).expect("plausible fee spike must not overflow");
        assert!(quote.0 > 0);
    }

    /// Serializes tests that touch
    /// [`fedimint_core::envs::FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV`],
    /// a process-wide env var, so they cannot race against each other under
    /// `cargo test`'s default parallel-test execution (no other test in this
    /// crate reads or writes this specific var, so guarding just these
    /// suffices).
    static UNSAFE_LOW_DEPTH_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// RAII guard that sets
    /// [`fedimint_core::envs::FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV`] for
    /// the guard's lifetime and always clears it on drop (including on test
    /// panic), so a failing assertion never leaks the override into a later
    /// test.
    struct UnsafeLowDepthAckGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl UnsafeLowDepthAckGuard {
        fn set() -> Self {
            let lock = UNSAFE_LOW_DEPTH_ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // SAFETY: serialized by `UNSAFE_LOW_DEPTH_ENV_LOCK` above; no
            // other thread reads/writes this var concurrently.
            unsafe {
                std::env::set_var(
                    fedimint_core::envs::FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV,
                    "1",
                );
            }
            Self { _lock: lock }
        }
    }

    impl Drop for UnsafeLowDepthAckGuard {
        fn drop(&mut self) {
            // SAFETY: see `set` above.
            unsafe {
                std::env::remove_var(
                    fedimint_core::envs::FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV,
                );
            }
        }
    }

    fn valid_prod_params() -> UsdtGenParams {
        UsdtGenParams {
            usdt_contract: EvmAddress([0xab; 20]),
            chain_id: 1,
            confirmation_depth: MIN_PROD_CONFIRMATION_DEPTH,
            entry_point: EvmAddress([0xcd; 20]),
            account_factory: EvmAddress([0xce; 20]),
            simple_account_impl: EvmAddress([0xcf; 20]),
            check_ttl_blocks: 10_000,
            broadcaster_min_balance_wei: 50_000_000_000_000_000,
            eth_usd_price_feed: EvmAddress([0xd0; 20]),
            price_feed_max_staleness_secs: 14_400,
            residual_recovery_recipient: EvmAddress([0xd1; 20]),
        }
    }

    #[test]
    fn validate_usdt_params_accepts_dev_defaults() {
        // The compiled-in `UsdtGenParams::default()` targets anvil
        // (chain_id 31337, depth 1, placeholder zero addresses) -- this must
        // never be rejected, or every dev/test federation breaks.
        validate_usdt_params(&UsdtGenParams::default())
            .expect("compiled-in dev defaults must validate");
    }

    #[test]
    fn validate_usdt_params_rejects_zero_confirmation_depth() {
        // Unconditional -- even a dev chain must not accept depth 0.
        let dev = UsdtGenParams {
            confirmation_depth: 0,
            ..UsdtGenParams::default()
        };
        assert!(validate_usdt_params(&dev).is_err());

        let mut prod = valid_prod_params();
        prod.confirmation_depth = 0;
        assert!(validate_usdt_params(&prod).is_err());
    }

    #[test]
    fn validate_usdt_params_rejects_low_depth_on_prod_chain() {
        let _guard_absence = UNSAFE_LOW_DEPTH_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: serialized by the lock above.
        unsafe {
            std::env::remove_var(fedimint_core::envs::FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV);
        }

        let mut params = valid_prod_params();
        params.confirmation_depth = 1;
        let err = validate_usdt_params(&params)
            .expect_err("depth 1 on chain_id 1 must be rejected without the unsafe ack");
        assert!(err.to_string().contains("confirmation_depth"));
    }

    #[test]
    fn validate_usdt_params_accepts_low_depth_on_prod_chain_with_unsafe_ack() {
        let _guard = UnsafeLowDepthAckGuard::set();

        let mut params = valid_prod_params();
        params.confirmation_depth = 1;
        validate_usdt_params(&params)
            .expect("depth 1 must be accepted once the unsafe-low-depth env ack is set");
    }

    #[test]
    fn validate_usdt_params_rejects_zero_addresses_on_prod_chain() {
        let zero = EvmAddress([0u8; 20]);

        let mut usdt_contract_zero = valid_prod_params();
        usdt_contract_zero.usdt_contract = zero;
        assert!(validate_usdt_params(&usdt_contract_zero).is_err());

        let mut entry_point_zero = valid_prod_params();
        entry_point_zero.entry_point = zero;
        assert!(validate_usdt_params(&entry_point_zero).is_err());

        let mut account_factory_zero = valid_prod_params();
        account_factory_zero.account_factory = zero;
        assert!(validate_usdt_params(&account_factory_zero).is_err());

        let mut simple_account_impl_zero = valid_prod_params();
        simple_account_impl_zero.simple_account_impl = zero;
        assert!(validate_usdt_params(&simple_account_impl_zero).is_err());

        let mut residual_recipient_zero = valid_prod_params();
        residual_recipient_zero.residual_recovery_recipient = zero;
        assert!(validate_usdt_params(&residual_recipient_zero).is_err());

        // Same placeholders are fine on a dev chain.
        let dev_zero = UsdtGenParams::default();
        assert_eq!(dev_zero.usdt_contract, zero);
        validate_usdt_params(&dev_zero).expect("zero addresses are fine on a dev chain");
    }

    #[test]
    fn validate_usdt_params_bounds_staleness_and_min_balance() {
        let mut zero_staleness = valid_prod_params();
        zero_staleness.price_feed_max_staleness_secs = 0;
        assert!(validate_usdt_params(&zero_staleness).is_err());

        let mut huge_staleness = valid_prod_params();
        huge_staleness.price_feed_max_staleness_secs = 86_401;
        assert!(validate_usdt_params(&huge_staleness).is_err());

        let mut zero_balance = valid_prod_params();
        zero_balance.broadcaster_min_balance_wei = 0;
        assert!(validate_usdt_params(&zero_balance).is_err());

        let mut huge_balance = valid_prod_params();
        huge_balance.broadcaster_min_balance_wei = MAX_BROADCASTER_MIN_BALANCE_WEI + 1;
        assert!(validate_usdt_params(&huge_balance).is_err());

        let mut at_ceiling = valid_prod_params();
        at_ceiling.broadcaster_min_balance_wei = MAX_BROADCASTER_MIN_BALANCE_WEI;
        validate_usdt_params(&at_ceiling).expect("exactly at the ceiling must be accepted");
    }
}
