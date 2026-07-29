#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use async_trait::async_trait;
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCore,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::envs::{
    FM_ENABLE_MODULE_USDT_ENV, FM_USDT_ACCOUNT_FACTORY_ENV,
    FM_USDT_BROADCASTER_MIN_BALANCE_WEI_ENV, FM_USDT_BROADCASTER_PRIVATE_KEY_ENV,
    FM_USDT_BROADCASTER_PRIVATE_KEY_FILE_ENV, FM_USDT_CHAIN_ID_ENV, FM_USDT_CONFIRMATION_DEPTH_ENV,
    FM_USDT_CONTRACT_ENV, FM_USDT_ENTRY_POINT_ENV, FM_USDT_ETH_USD_PRICE_FEED_ENV,
    FM_USDT_EVM_RPC_API_KEY_ENV, FM_USDT_EVM_RPC_API_KEY_FILE_ENV, FM_USDT_EVM_RPC_URL_ENV,
    FM_USDT_POLL_INTERVAL_SECS_ENV, FM_USDT_SIMPLE_ACCOUNT_IMPL_ENV,
    FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV, env_secret_or_file, is_env_var_set_opt,
    is_running_in_test_env,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiVersion, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, SupportedModuleApiVersions, TransactionItemAmounts,
    api_endpoint,
};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_core::{InPoint, NumPeers, NumPeersExt, OutPoint, PeerId, push_db_pair_items};
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::{
    ServerModuleDbMigrationFn, ServerModuleDbMigrationFnContext,
};
use fedimint_server_core::{
    ConfigGenModuleArgs, EnvVarDoc, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use fedimint_threshold_ecdsa::{convert_signature, group_public_key};
pub use fedimint_usdt_common as common;
use fedimint_usdt_common::config::UsdtClientConfig;
use fedimint_usdt_common::endpoint_constants::{
    DEPOSIT_FEE_QUOTE_ENDPOINT, DEPOSIT_STATUS_ENDPOINT, GROUP_PUBLIC_KEY_ENDPOINT,
    POOL_STATE_ENDPOINT, REFUND_STATUS_ENDPOINT, USDT_STATUS_ENDPOINT, USEROP_STATUS_ENDPOINT,
    WITHDRAW_FEE_QUOTE_ENDPOINT, WITHDRAWAL_STATUS_ENDPOINT,
};
use fedimint_usdt_common::user_op::{SignedUserOp, eth_signed_message_hash, user_op_hash};
use fedimint_usdt_common::{
    BLOCK_HASH_RING_LEN, BlockHashObservation, BootstrapObservation, BootstrapState,
    DepositFeeQuoteRequest, DepositFeeQuoteResponse, DepositObservation, DepositStatusRequest,
    DepositStatusResponse, FeeVote, MAX_MPC_CHUNKS, MAX_MPC_ROUND_BYTES, MODULE_CONSENSUS_VERSION,
    MPC_ROUND_CHUNK_SIZE, MpcRoundItem, PoolStateResponse, RefundInfo, RefundStatusRequest,
    RefundStatusResponse, SigningSessionId, StatusResponse, USDT_UNIT, UsdtAmount, UsdtCommonInit,
    UsdtConsensusItem, UsdtGenParams, UsdtInput, UsdtInputError, UsdtModuleTypes, UsdtOutput,
    UsdtOutputError, UsdtOutputOutcome, UserOpStatus, UserOpStatusRequest, UserOpStatusResponse,
    WithdrawFeeQuoteRequest, WithdrawFeeQuoteResponse, WithdrawalStatus, WithdrawalStatusRequest,
    WithdrawalStatusResponse, deposit_fee_quote, deposit_salt, derive_deposit_account,
    derive_pool_account, evm_address, fee_vote_in_sane_range, pool_salt, signing_session_id,
    usdt_amount, validate_usdt_params, wei_gas_cost_to_usdt, withdrawal_fee_quote,
};
use futures::{FutureExt as _, StreamExt as _};
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use tracing::{debug, info, warn};

use crate::config::{UsdtConfig, UsdtConfigConsensus, UsdtConfigLocal, UsdtConfigPrivate};
use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, BlockHashRingKey, BlockHashRingPrefix,
    BlockHashVoteKey, BlockHashVotePrefix, BootstrapVoteKey, BootstrapVotePrefix, DbKeyPrefix,
    DepositObservationVoteAccountPrefix, DepositObservationVoteKey, DepositObservationVotePrefix,
    DepositRecord, DepositRecordKey, DepositRecordPrefix, FeeVoteKey, FeeVotePrefix,
    HasEverBeenReadyKey, HasEverBeenReadyPrefix, MpcRoundChunk, MpcRoundChunkKey,
    MpcRoundChunkPrefix, MpcRoundChunkSessionPrefix, MpcRoundChunkSessionRoundPeerPrefix,
    MpcRoundChunkSessionRoundPrefix, PendingUserOp, PendingUserOpKey, PendingUserOpPrefix,
    PoolState, PoolStateKey, PoolStatePrefix, Refund, RefundKey, RefundPrefix, SessionState,
    SigningPurpose, SigningSession, SigningSessionKey, SigningSessionPrefix, StoredFeeVote,
    SubmittedUserOp, SubmittedUserOpKey, SubmittedUserOpPrefix, UnclaimedWithdrawalKey,
    UnclaimedWithdrawalPrefix, UsdtWithdrawalV0, UserOpConfirmedObservation,
    UserOpConfirmedVoteKey, UserOpConfirmedVoteOpPrefix, UserOpConfirmedVotePrefix, UserOpPurpose,
    WithdrawalBatchCapKey, WithdrawalBatchCapPrefix, WithdrawalIncurredFeeKey,
    WithdrawalIncurredFeePrefix, WithdrawalState, WithdrawalStateKey, WithdrawalStatePrefix,
};
use crate::rpc::{AlloyEvmRpc, DynServerEvmRpc, IServerEvmRpc as _};
use crate::signing::{SessionSlot, SessionStore, pump_slot_outgoing, spawn_signing_session};
use crate::user_op::{
    DeployAndSweepParams, GasBounds, WithdrawalBatchParams, assemble_eth_signature,
};

mod dkg;
mod trusted_dealer_primes;

pub mod config;
pub mod db;
pub mod factory_bytecode;
pub mod proof;
pub mod rpc;
pub mod signing;
pub mod user_op;

/// Generates the module
#[derive(Debug, Clone, Default)]
pub struct UsdtInit {
    /// Test-only injected EVM RPC. `None` in production, in which case
    /// [`ServerModuleInit::init`] builds an [`AlloyEvmRpc`] from the
    /// guardian's configured `evm_rpc_url`. `Some` lets hermetic tests
    /// (`fedimint-usdt-tests`) share one `MockEvmRpc` across every
    /// guardian's module instance, so their reads agree (deposit consensus
    /// needs identical observations).
    evm_rpc_override: Option<crate::rpc::DynServerEvmRpc>,
    /// Test-only override for [`ServerModuleInit::default_config_gen_params`]
    /// (Phase 7, Task 6). `None` in production (and in every test that
    /// hasn't called [`Self::with_gen_params`]), in which case
    /// `default_config_gen_params` falls back to its usual compiled-in
    /// [`fedimint_usdt_common::UsdtGenParams::default`] (plus the
    /// `FM_USDT_CONTRACT_ENV` override). `Some` lets a hermetic test that has
    /// already deployed a real ERC-4337 stack (`entry_point`/
    /// `account_factory`/`simple_account_impl`/`usdt_contract`, e.g. via
    /// `deploy_4337_stack`) inject those REAL addresses into config-gen
    /// directly, rather than racing a process-global env var across
    /// (potentially parallel) test binaries — mirrors
    /// [`Self::evm_rpc_override`]'s injection pattern.
    gen_params_override: Option<fedimint_usdt_common::UsdtGenParams>,
}

impl UsdtInit {
    /// Builds a `UsdtInit` that hands every guardian the same injected
    /// `evm_rpc` instead of building an `AlloyEvmRpc`, for hermetic tests.
    #[must_use]
    pub fn with_evm_rpc(evm_rpc: crate::rpc::DynServerEvmRpc) -> Self {
        Self {
            evm_rpc_override: Some(evm_rpc),
            gen_params_override: None,
        }
    }

    /// Overrides [`ServerModuleInit::default_config_gen_params`] to return
    /// `gen_params` verbatim, for hermetic tests that need config-gen to
    /// carry real deployed contract addresses (Phase 7, Task 6). Chainable
    /// with [`Self::with_evm_rpc`] (e.g. `UsdtInit::with_evm_rpc(rpc).
    /// with_gen_params(params)`), since a real-`anvil` test needs both: the
    /// real addresses in config AND a real `AlloyEvmRpc` pointed at the same
    /// stack.
    #[must_use]
    pub fn with_gen_params(mut self, gen_params: fedimint_usdt_common::UsdtGenParams) -> Self {
        self.gen_params_override = Some(gen_params);
        self
    }
}

impl ModuleInit for UsdtInit {
    type Common = UsdtCommonInit;

    /// Dumps all database items for debugging
    #[allow(clippy::too_many_lines)]
    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::BlockCountVote => {
                    push_db_pair_items!(
                        dbtx,
                        BlockCountVotePrefix,
                        crate::db::BlockCountVoteKey,
                        u64,
                        items,
                        "Block Count Votes"
                    );
                }
                DbKeyPrefix::FeeVote => {
                    push_db_pair_items!(
                        dbtx,
                        FeeVotePrefix,
                        crate::db::FeeVoteKey,
                        StoredFeeVote,
                        items,
                        "Fee Votes"
                    );
                }
                DbKeyPrefix::DepositRecord => {
                    push_db_pair_items!(
                        dbtx,
                        DepositRecordPrefix,
                        crate::db::DepositRecordKey,
                        DepositRecord,
                        items,
                        "Deposit Records"
                    );
                }
                DbKeyPrefix::DepositObservationVote => {
                    push_db_pair_items!(
                        dbtx,
                        DepositObservationVotePrefix,
                        crate::db::DepositObservationVoteKey,
                        DepositObservation,
                        items,
                        "Deposit Observation Votes"
                    );
                }
                DbKeyPrefix::SigningSession => {
                    push_db_pair_items!(
                        dbtx,
                        SigningSessionPrefix,
                        crate::db::SigningSessionKey,
                        SigningSession,
                        items,
                        "Signing Sessions"
                    );
                }
                DbKeyPrefix::MpcRoundChunk => {
                    push_db_pair_items!(
                        dbtx,
                        MpcRoundChunkPrefix,
                        crate::db::MpcRoundChunkKey,
                        MpcRoundChunk,
                        items,
                        "MPC Round Chunks"
                    );
                }
                DbKeyPrefix::PendingUserOp => {
                    push_db_pair_items!(
                        dbtx,
                        PendingUserOpPrefix,
                        PendingUserOpKey,
                        PendingUserOp,
                        items,
                        "Pending UserOps"
                    );
                }
                DbKeyPrefix::SubmittedUserOp => {
                    push_db_pair_items!(
                        dbtx,
                        SubmittedUserOpPrefix,
                        SubmittedUserOpKey,
                        SubmittedUserOp,
                        items,
                        "Submitted UserOps"
                    );
                }
                DbKeyPrefix::PoolState => {
                    push_db_pair_items!(
                        dbtx,
                        PoolStatePrefix,
                        PoolStateKey,
                        PoolState,
                        items,
                        "Pool State"
                    );
                }
                DbKeyPrefix::UserOpConfirmedVote => {
                    push_db_pair_items!(
                        dbtx,
                        UserOpConfirmedVotePrefix,
                        UserOpConfirmedVoteKey,
                        UserOpConfirmedObservation,
                        items,
                        "UserOp Confirmed Votes"
                    );
                }
                DbKeyPrefix::UnclaimedWithdrawal => {
                    push_db_pair_items!(
                        dbtx,
                        UnclaimedWithdrawalPrefix,
                        UnclaimedWithdrawalKey,
                        UsdtWithdrawalV0,
                        items,
                        "Unclaimed Withdrawals"
                    );
                }
                DbKeyPrefix::WithdrawalState => {
                    push_db_pair_items!(
                        dbtx,
                        WithdrawalStatePrefix,
                        WithdrawalStateKey,
                        WithdrawalState,
                        items,
                        "Withdrawal States"
                    );
                }
                DbKeyPrefix::BootstrapVote => {
                    push_db_pair_items!(
                        dbtx,
                        BootstrapVotePrefix,
                        BootstrapVoteKey,
                        fedimint_usdt_common::BootstrapObservation,
                        items,
                        "Bootstrap Votes"
                    );
                }
                DbKeyPrefix::HasEverBeenReady => {
                    push_db_pair_items!(
                        dbtx,
                        HasEverBeenReadyPrefix,
                        HasEverBeenReadyKey,
                        (),
                        items,
                        "Has Ever Been Ready"
                    );
                }
                DbKeyPrefix::WithdrawalBatchCap => {
                    push_db_pair_items!(
                        dbtx,
                        WithdrawalBatchCapPrefix,
                        WithdrawalBatchCapKey,
                        u32,
                        items,
                        "Withdrawal Batch Caps"
                    );
                }
                DbKeyPrefix::Refund => {
                    push_db_pair_items!(
                        dbtx,
                        RefundPrefix,
                        RefundKey,
                        Refund,
                        items,
                        "Withdrawal Refunds"
                    );
                }
                DbKeyPrefix::WithdrawalIncurredFee => {
                    push_db_pair_items!(
                        dbtx,
                        WithdrawalIncurredFeePrefix,
                        WithdrawalIncurredFeeKey,
                        UsdtAmount,
                        items,
                        "Withdrawal Incurred Fees"
                    );
                }
                DbKeyPrefix::BlockHashRing => {
                    push_db_pair_items!(
                        dbtx,
                        BlockHashRingPrefix,
                        BlockHashRingKey,
                        [u8; 32],
                        items,
                        "Block Hash Ring"
                    );
                }
                DbKeyPrefix::BlockHashVote => {
                    push_db_pair_items!(
                        dbtx,
                        BlockHashVotePrefix,
                        crate::db::BlockHashVoteKey,
                        BlockHashObservation,
                        items,
                        "Block Hash Votes"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

/// Builds the config-gen leader's default [`UsdtGenParams`], applying every
/// documented `FM_USDT_*` env-var override (see
/// [`ServerModuleInit::get_documented_env_vars`] below). Fallible: a
/// malformed env var value (bad hex address, non-numeric `u64`) returns a
/// clear `anyhow::Error` describing which variable and why, instead of
/// corrupting state or panicking deep inside a `.parse()` call. The one
/// remaining panic boundary is [`UsdtInit::default_config_gen_params`]
/// itself, which the `ServerModuleInit`/`ModuleInit` trait requires to be
/// infallible.
///
/// Does not call [`fedimint_usdt_common::validate_usdt_params`] -- safety
/// validation runs uniformly at the config-gen call sites
/// (`UsdtInit::trusted_dealer_gen`, `dkg::distributed_gen`) and in
/// `validate_config`, so every path that produces or accepts a consensus
/// config is checked exactly once, regardless of whether the params came
/// from this env-driven default, [`UsdtInit::gen_params_override`], or a
/// setup-code-supplied override.
fn usdt_gen_params_from_env() -> anyhow::Result<UsdtGenParams> {
    let mut params = fedimint_usdt_common::UsdtGenParams::default();

    // Each override is a `0x`-prefixed 20-byte hex EvmAddress; an
    // unset/empty var is treated as absent.
    let env_override =
        |env_name: &str| -> anyhow::Result<Option<fedimint_usdt_common::EvmAddress>> {
            match std::env::var(env_name) {
                Ok(value) if !value.is_empty() => value
                    .parse()
                    .map(Some)
                    .with_context(|| format!("{env_name} must be a valid EvmAddress")),
                _ => Ok(None),
            }
        };

    if let Some(usdt_contract) = env_override(FM_USDT_CONTRACT_ENV)? {
        params.usdt_contract = usdt_contract;
    }
    if let Some(entry_point) = env_override(FM_USDT_ENTRY_POINT_ENV)? {
        params.entry_point = entry_point;
    }

    // Part A: the ERC-4337 `account_factory`/`simple_account_impl` are
    // DERIVED deterministically from the (now-resolved) `entry_point` plus
    // vendored constants, so the operator need not supply them and every
    // guardian computes the byte-identical addresses (a pure function of
    // the consensus `entry_point`). `account_factory =
    // CREATE2(ARACHNID_DEPLOYER, factory_create2_salt(),
    // FACTORY_CREATION_CODE ‖ abi.encode(entry_point))`;
    // `simple_account_impl = CREATE(account_factory, 1)` (the factory's
    // constructor's first internal deploy). The module then self-deploys
    // that exact factory on-chain (see `Usdt::spawn_bootstrap_observer`'s
    // deploy tick), and Part C's `getAddress`-equivalence readiness gate
    // verifies the on-chain factory matches before any deposit address is
    // handed out (fail-safe on a wrong constant).
    //
    // The `FM_USDT_ACCOUNT_FACTORY`/`FM_USDT_SIMPLE_ACCOUNT_IMPL` env
    // overrides remain an ESCAPE HATCH for a pre-deployed / nonstandard
    // stack: an explicit override always wins over the computed value.
    params.account_factory = match env_override(FM_USDT_ACCOUNT_FACTORY_ENV)? {
        Some(account_factory) => account_factory,
        None => factory_bytecode::derive_account_factory(params.entry_point),
    };
    params.simple_account_impl = match env_override(FM_USDT_SIMPLE_ACCOUNT_IMPL_ENV)? {
        Some(simple_account_impl) => simple_account_impl,
        None => factory_bytecode::derive_simple_account_impl(params.account_factory),
    };

    if let Some(feed) = env_override(FM_USDT_ETH_USD_PRICE_FEED_ENV)? {
        params.eth_usd_price_feed = feed;
    }

    // Numeric config-gen overrides. `chain_id` and `confirmation_depth`
    // default to anvil values (31337 / 1); a real chain (e.g. Sepolia)
    // MUST override `chain_id` -- it is bound into the ERC-4337
    // `userOpHash` the federation signs, so a wrong value makes every
    // signature invalid on-chain.
    let u64_env_override = |env_name: &str| -> anyhow::Result<Option<u64>> {
        match std::env::var(env_name) {
            Ok(value) if !value.is_empty() => value
                .parse()
                .map(Some)
                .with_context(|| format!("{env_name} must be a valid u64")),
            _ => Ok(None),
        }
    };
    if let Some(chain_id) = u64_env_override(FM_USDT_CHAIN_ID_ENV)? {
        params.chain_id = chain_id;
    }
    if let Some(confirmation_depth) = u64_env_override(FM_USDT_CONFIRMATION_DEPTH_ENV)? {
        params.confirmation_depth = confirmation_depth;
    }
    if let Some(min_balance) = u64_env_override(FM_USDT_BROADCASTER_MIN_BALANCE_WEI_ENV)? {
        params.broadcaster_min_balance_wei = min_balance;
    }

    Ok(params)
}

/// Deadline (in seconds) for every recurring, operational EVM RPC await this
/// module makes outside of consensus-decision paths (security finding 19):
/// the block-count/fee pollers, the bootstrap observer/self-deploy, the
/// per-account deposit balance read, and the `UserOp` submitter/receipt
/// poller. Shared with [`crate::rpc::AlloyEvmRpc`]'s bounded `reqwest`
/// client, so a stalled call is caught at the same bound regardless of
/// which layer (the HTTP client's own request timeout, or this module-level
/// deadline) happens to notice first. Mirrors the value the startup
/// transfer-fee/chain-id checks already hardcode as `Duration::from_secs(30)`
/// (kept as separate literals there since those are one-shot, not recurring,
/// checks).
const RPC_REQUEST_TIMEOUT_SECS: u64 = 30;

/// Default seconds between ticks of the latency-sensitive background observer
/// loops (block count, deposit scan, `UserOp` receipts) when
/// [`FM_USDT_POLL_INTERVAL_SECS_ENV`] is unset. See that env var's doc for the
/// full rationale; briefly, every guardian runs several independent RPC poll
/// loops, so lowering this multiplies total RPC quota consumption. The
/// slow-changing loops (fee estimate, post-bootstrap readiness) run at
/// [`SLOW_POLL_MULTIPLIER`]× this instead.
const DEFAULT_POLL_INTERVAL_SECS: u64 = 15;

/// Lower bound on the configured poll interval, guarding against a value so
/// small it degenerates into a busy loop hammering the RPC endpoint.
const MIN_POLL_INTERVAL_SECS: u64 = 5;

/// Multiplier applied to [`poll_interval_secs`] for loops whose data changes
/// far slower than the base tick and so need not poll as often: the fee/price
/// estimate (a Chainlink feed with a multi-minute heartbeat) and the
/// bootstrap-readiness loop once its immutable contract facts are cached (it
/// then only re-reads the slowly-changing broadcaster balance). Cuts those
/// loops' RPC volume by this factor with no material freshness cost -- the fee
/// refresh stays well within `FEE_VOTE_TTL_BLOCKS`.
const SLOW_POLL_MULTIPLIER: u64 = 4;

/// Seconds each background observer loop sleeps between ticks.
///
/// Under the test harness this is a fixed fast `1` (kept identical to the
/// former inline `is_running_in_test_env()` literals so test timing is
/// unchanged). In production it reads [`FM_USDT_POLL_INTERVAL_SECS_ENV`]
/// (default [`DEFAULT_POLL_INTERVAL_SECS`], floored at
/// [`MIN_POLL_INTERVAL_SECS`]); an unparseable value falls back to the
/// default. Guardian-local only -- it affects observation cadence, never a
/// consensus-agreed value, so guardians may run different intervals.
fn poll_interval_secs() -> u64 {
    if is_running_in_test_env() {
        return 1;
    }
    resolve_poll_interval(std::env::var(FM_USDT_POLL_INTERVAL_SECS_ENV).ok())
}

/// [`poll_interval_secs`] scaled by [`SLOW_POLL_MULTIPLIER`], for the
/// slow-changing loops (fee estimate; post-cache bootstrap readiness). Under
/// the test harness this collapses to the same fast `1` as the base interval
/// so test timing is unchanged.
fn slow_poll_interval_secs() -> u64 {
    if is_running_in_test_env() {
        return 1;
    }
    poll_interval_secs().saturating_mul(SLOW_POLL_MULTIPLIER)
}

/// Pure parse/clamp for [`poll_interval_secs`], split out so it is testable
/// without depending on `is_running_in_test_env()` (which is always true under
/// the test harness) or on mutating the process environment: `None` or an
/// unparseable value yields [`DEFAULT_POLL_INTERVAL_SECS`], and any parsed
/// value is floored at [`MIN_POLL_INTERVAL_SECS`].
fn resolve_poll_interval(raw: Option<String>) -> u64 {
    match raw {
        Some(secs) => match secs.trim().parse::<u64>() {
            Ok(secs) => secs.max(MIN_POLL_INTERVAL_SECS),
            Err(_) => DEFAULT_POLL_INTERVAL_SECS,
        },
        None => DEFAULT_POLL_INTERVAL_SECS,
    }
}

/// Maximum number of submitted `UserOp`s [`Usdt::spawn_user_op_submitter`]
/// processes concurrently (security finding 19), bounding this guardian's
/// simultaneous outbound RPC load while still ensuring a stall on one op
/// cannot block the others (unlike the old fully-serial `for` loop).
const USER_OP_SUBMIT_CONCURRENCY: usize = 8;

/// Wraps an EVM RPC await with [`RPC_REQUEST_TIMEOUT_SECS`] (security
/// finding 19), mapping a timed-out future into an `anyhow::Error` so it
/// lands in the exact same `Err` branch of the caller's existing
/// retry/sleep/cached-value logic as a normal RPC error -- never a panic or
/// an indefinitely wedged task. Mirrors the pattern the startup transfer-fee
/// check (a few lines below, in `UsdtInit::init`) already uses via
/// `fedimint_core::runtime::timeout` directly. A thin wrapper around
/// [`rpc_deadline_with`] fixing the deadline at the production value -- see
/// that function's doc comment for why the deadline itself is a parameter
/// rather than baked in here.
async fn rpc_deadline<T>(
    fut: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    rpc_deadline_with(Duration::from_secs(RPC_REQUEST_TIMEOUT_SECS), fut).await
}

/// [`rpc_deadline`]'s implementation, parameterized on the deadline itself
/// so `rpc_deadline_times_out` can exercise the timeout->`Err` mapping with a
/// short, deterministic duration instead of the real 30s production value
/// (`RPC_REQUEST_TIMEOUT_SECS`) or an `is_running_in_test_env`-scaled one --
/// the latter would depend on `NEXTEST`/`FM_IN_DEVIMINT` being set, which
/// plain `cargo test` (as `just test` runs it) does not set, making the
/// scaling unreliable for a unit test.
async fn rpc_deadline_with<T>(
    deadline: Duration,
    fut: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    match fedimint_core::runtime::timeout(deadline, fut).await {
        Ok(result) => result,
        Err(_elapsed) => Err(anyhow::anyhow!("RPC call timed out after {deadline:?}")),
    }
}

/// Startup chain-id sanity check (sec-15/17): confirms `evm_rpc` actually
/// points at the chain `consensus_chain_id` (i.e. `cfg.consensus.chain_id`)
/// expects, and refuses to start on a DEFINITIVE mismatch. `chain_id` is
/// bound into every signed ERC-4337 `userOpHash`
/// ([`fedimint_usdt_common::user_op::user_op_hash`]), so guardians running
/// against the wrong chain would sign `UserOps` that are valid nowhere,
/// silently wedging every sweep/withdrawal.
///
/// Distinguishes a definitive mismatch from an inability to determine the
/// chain id at all: an RPC error or timeout only warns and lets `init`
/// proceed, mirroring the existing transfer-fee startup check's fail-open
/// timeout handling a few lines below in `init` -- a transient RPC outage at
/// process start must not permanently brick a guardian that would otherwise
/// recover once the node is reachable again.
async fn check_chain_id_at_startup(
    evm_rpc: &crate::rpc::DynServerEvmRpc,
    consensus_chain_id: u64,
) -> anyhow::Result<()> {
    match fedimint_core::runtime::timeout(Duration::from_secs(30), evm_rpc.get_chain_id()).await {
        Ok(Ok(onchain_chain_id)) => {
            ensure!(
                onchain_chain_id == consensus_chain_id,
                "configured chain_id {consensus_chain_id} does not match the RPC-reported \
                 chain_id {onchain_chain_id}; refusing to start (every signed userOpHash is bound \
                 to chain_id, so running against the wrong chain would sign UserOps that are \
                 invalid everywhere)"
            );
            debug!(
                target: "usdt",
                consensus_chain_id,
                "startup chain-id check passed: RPC-reported chain_id matches consensus config"
            );
            Ok(())
        }
        Ok(Err(err)) => {
            warn!(
                target: "usdt",
                consensus_chain_id,
                err = %err.fmt_compact_anyhow(),
                "could not verify chain_id at startup (RPC error); proceeding without the check"
            );
            Ok(())
        }
        Err(_elapsed) => {
            warn!(
                target: "usdt",
                consensus_chain_id,
                "chain_id check timed out at startup; proceeding without the check"
            );
            Ok(())
        }
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for UsdtInit {
    type Module = Usdt;
    type Params = fedimint_usdt_common::UsdtGenParams;

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 0)],
        )
    }

    fn is_enabled_by_default(&self) -> bool {
        is_env_var_set_opt(FM_ENABLE_MODULE_USDT_ENV).unwrap_or(false)
    }

    /// The compiled-in [`fedimint_usdt_common::UsdtGenParams::default`]'s
    /// `usdt_contract` is a placeholder (`EvmAddress([0u8; 20])`): no real
    /// on-chain address is known at compile time. This override lets a
    /// config-gen leader (e.g. `devimint`, after deploying a test ERC-20 to
    /// its `anvil` instance) point the default instance at the real deployed
    /// contract via [`FM_USDT_CONTRACT_ENV`], without a code change.
    ///
    /// [`Self::gen_params_override`] (set via [`Self::with_gen_params`])
    /// takes priority over both the compiled-in default and the env var --
    /// see that field's doc comment.
    fn default_config_gen_params(&self) -> Self::Params {
        if let Some(gen_params) = &self.gen_params_override {
            return gen_params.clone();
        }

        // The fallible env-parsing work lives in `usdt_gen_params_from_env`
        // (unit-tested directly, see `env_override_parse_error_is_not_a_panic`
        // below) so a malformed env var produces a clean, testable
        // `anyhow::Error` rather than an ad hoc `panic!` at an arbitrary
        // parse call site. `default_config_gen_params` itself is infallible
        // per the `ServerModuleInit`/`ModuleInit` trait (it cannot return
        // `Result` without a workspace-wide trait signature change, out of
        // scope here), so this remains the one unavoidable panic boundary --
        // deterministic, before any consensus starts, exactly as documented
        // below.
        usdt_gen_params_from_env().unwrap_or_else(|err| {
            panic!("USDT module config-gen params misconfigured via environment variable: {err:#}")
        })
    }

    fn get_documented_env_vars(&self) -> Vec<EnvVarDoc> {
        vec![
            EnvVarDoc {
                name: FM_ENABLE_MODULE_USDT_ENV,
                description: "Set to 1/true to enable the USDT-on-EVM module (experimental). Disabled by default.",
            },
            EnvVarDoc {
                name: FM_USDT_EVM_RPC_URL_ENV,
                description: "Overrides the EVM RPC URL for this guardian at runtime, taking priority over the configured `evm_rpc_url`.",
            },
            EnvVarDoc {
                name: FM_USDT_EVM_RPC_API_KEY_ENV,
                description: "Optional per-guardian API key appended as the final path segment of the EVM RPC URL (Alchemy/Infura-style). Keeps the secret key out of the URL config. A bundler-capable provider (Alchemy/Infura/QuickNode) is required on a real chain: receipts are read via eth_getUserOperationReceipt.",
            },
            EnvVarDoc {
                name: FM_USDT_EVM_RPC_API_KEY_FILE_ENV,
                description: "File-based fallback for FM_USDT_EVM_RPC_API_KEY: path to a file whose (trimmed) contents are the API key. Used only when FM_USDT_EVM_RPC_API_KEY is unset/empty. Keeps the secret out of the process environment.",
            },
            EnvVarDoc {
                name: FM_USDT_CONTRACT_ENV,
                description: "Overrides the default instance's `usdt_contract` config-gen param (a 0x-prefixed 20-byte hex EVM address) for the config-gen leader.",
            },
            EnvVarDoc {
                name: FM_USDT_ENTRY_POINT_ENV,
                description: "Overrides the ERC-4337 `entry_point` config-gen param (a 0x-prefixed 20-byte hex EVM address) for the config-gen leader (e.g. devimint after deploying the 4337 stack).",
            },
            EnvVarDoc {
                name: FM_USDT_ACCOUNT_FACTORY_ENV,
                description: "Overrides the ERC-4337 `account_factory` config-gen param (a 0x-prefixed 20-byte hex EVM address) for the config-gen leader.",
            },
            EnvVarDoc {
                name: FM_USDT_SIMPLE_ACCOUNT_IMPL_ENV,
                description: "Overrides the ERC-4337 `simple_account_impl` config-gen param (a 0x-prefixed 20-byte hex EVM address) for the config-gen leader.",
            },
            EnvVarDoc {
                name: FM_USDT_BROADCASTER_PRIVATE_KEY_ENV,
                description: "Overrides this guardian's broadcaster EOA private key (hex) at runtime, taking priority over the configured `broadcaster_private_key`. Needed to front UserOp gas for sweeps/withdrawals.",
            },
            EnvVarDoc {
                name: FM_USDT_BROADCASTER_PRIVATE_KEY_FILE_ENV,
                description: "File-based fallback for FM_USDT_BROADCASTER_PRIVATE_KEY: path to a file whose (trimmed) contents are the private key. Used only when FM_USDT_BROADCASTER_PRIVATE_KEY is unset/empty. Keeps the secret out of the process environment.",
            },
            EnvVarDoc {
                name: FM_USDT_ETH_USD_PRICE_FEED_ENV,
                description: "Overrides the ERC-4337 USDT module's Chainlink ETH/USD price-feed config-gen param (a 0x-prefixed 20-byte hex EVM address) for the config-gen leader.",
            },
            EnvVarDoc {
                name: FM_USDT_CHAIN_ID_ENV,
                description: "Overrides the USDT module's `chain_id` config-gen param (decimal EVM chain id) for the config-gen leader. REQUIRED for non-anvil chains: chain_id is bound into the signed ERC-4337 userOpHash. Defaults to 31337.",
            },
            EnvVarDoc {
                name: FM_USDT_CONFIRMATION_DEPTH_ENV,
                description: "Overrides the USDT module's `confirmation_depth` config-gen param (decimal block count) for the config-gen leader. Raise for a real chain's reorg characteristics. Defaults to 1.",
            },
            EnvVarDoc {
                name: FM_USDT_BROADCASTER_MIN_BALANCE_WEI_ENV,
                description: "Overrides the USDT module's `broadcaster_min_balance_wei` config-gen param (decimal wei) for the config-gen leader — the min broadcaster ETH for the readiness `broadcaster_funded` condition. Defaults to 0.05 ETH; lower it for a cheap real-network test.",
            },
            EnvVarDoc {
                name: FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV,
                description: "Set to 1 to acknowledge and allow a non-dev chain_id's confirmation_depth to be below the module's minimum safe production depth (6 blocks). Unset by default, so config-gen/validate_config reject an unsafely low depth on any chain other than the known anvil/hardhat dev ids.",
            },
        ]
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        let cfg: UsdtConfig = args.cfg().to_typed()?;

        // NOTE: the old all-zero-placeholder startup `warn!` guard was removed
        // as obsolete. `account_factory`/`simple_account_impl` are now DERIVED
        // deterministically from `entry_point` at config-gen (Part A, see
        // `default_config_gen_params`), so they are never the all-zero
        // placeholder in practice; the module self-deploys that exact factory
        // on-chain; and the real "does the on-chain factory match this build's
        // vendored proxy code so derived deposit addresses are spendable?"
        // hazard is now caught on-chain by the readiness gate's
        // `factory_get_address == derive_pool_account` check (Part C), which
        // fail-safes (the federation never reports `Ready`, so no deposit
        // address is ever handed out) instead of merely warning.

        let evm_rpc = if let Some(evm_rpc) = &self.evm_rpc_override {
            evm_rpc.clone()
        } else {
            let evm_rpc_url = std::env::var(FM_USDT_EVM_RPC_URL_ENV)
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| cfg.private.local.evm_rpc_url.clone());
            // Optional API key appended as the RPC URL's final path segment
            // (Alchemy/Infura/... style), so the secret key can live in its own
            // env var rather than baked into the URL. No-op when unset.
            // `env_secret_or_file` also accepts the key via
            // `FM_USDT_EVM_RPC_API_KEY_FILE` (a path to a file containing the
            // key), keeping it out of the process environment (sec-misc#8).
            let evm_rpc_url = match env_secret_or_file(
                FM_USDT_EVM_RPC_API_KEY_ENV,
                FM_USDT_EVM_RPC_API_KEY_FILE_ENV,
            )? {
                Some(key) => format!("{}/{key}", evm_rpc_url.trim_end_matches('/')),
                None => evm_rpc_url,
            };
            let mut rpc = AlloyEvmRpc::new(&evm_rpc_url)?
                .with_entry_point(cfg.consensus.entry_point)
                .with_price_feed(
                    cfg.consensus.eth_usd_price_feed,
                    cfg.consensus.price_feed_max_staleness_secs,
                );
            // Same file-based fallback as above, via
            // `FM_USDT_BROADCASTER_PRIVATE_KEY_FILE` (sec-misc#8).
            let broadcaster_private_key = env_secret_or_file(
                FM_USDT_BROADCASTER_PRIVATE_KEY_ENV,
                FM_USDT_BROADCASTER_PRIVATE_KEY_FILE_ENV,
            )?
            .or_else(|| cfg.private.local.broadcaster_private_key.clone());
            if let Some(broadcaster_private_key) = &broadcaster_private_key {
                rpc = rpc.with_broadcaster(broadcaster_private_key)?;
            }
            rpc.into_dyn()
        };

        // Startup chain-id sanity check (sec-15/17): confirm the RPC endpoint
        // just built above actually points at the chain this federation's
        // consensus config expects. A DEFINITIVE mismatch (the RPC answered
        // with a different chain id) hard-fails startup; an RPC error or
        // timeout only warns and lets startup proceed (see
        // `check_chain_id_at_startup`'s doc comment for the rationale).
        check_chain_id_at_startup(&evm_rpc, cfg.consensus.chain_id).await?;

        // Startup transfer-fee solvency check (guardian-local; REFUSES to start
        // on a confirmed fee). This module credits the pool by the full
        // REQUESTED transfer amount, not the on-chain balance delta, so a token
        // that deducts a transfer fee (Tether-style `basisPointsRate != 0`)
        // would make `PoolState.balance` drift ABOVE real holdings (cumulative
        // insolvency) and short-pay withdrawal recipients (see the audit
        // register's fee-insolvency risk). We therefore refuse to start against
        // such a token.
        //
        // FAIL-OPEN on any read error or timeout: a standard fee-less ERC-20
        // REVERTS `basisPointsRate()` (indistinguishable here from an
        // unreachable node), so refusing on every error would block startup
        // against every standard token and on transient RPC blips -- we
        // hard-fail ONLY on a CONFIRMED nonzero rate, and otherwise proceed with
        // a warning. Bounded by a timeout so a hung node cannot wedge startup.
        // Not a consensus path -- a guardian-local observation like the deposit
        // checker; it gates only THIS guardian's startup, never a consensus
        // write.
        let usdt_contract = cfg.consensus.usdt_contract;
        match fedimint_core::runtime::timeout(
            Duration::from_secs(30),
            evm_rpc.get_erc20_basis_points_rate(usdt_contract),
        )
        .await
        {
            Ok(Ok(0)) => debug!(
                target: "usdt",
                %usdt_contract,
                "startup fee check passed: token charges no transfer fee (basisPointsRate == 0)"
            ),
            Ok(Ok(basis_points)) => anyhow::bail!(
                "refusing to start the USDT module: the configured token {usdt_contract} reports a \
                 nonzero transfer-fee rate (basisPointsRate = {basis_points}). This module credits \
                 the pool by the full requested transfer amount, so a fee-charging token would \
                 drift PoolState.balance above real holdings (cumulative insolvency) and short-pay \
                 withdrawal recipients. Configure a fee-less token, or address the fee-insolvency \
                 accounting (see the audit register) before running."
            ),
            Ok(Err(err)) => warn!(
                target: "usdt",
                %usdt_contract,
                err = %err.fmt_compact_anyhow(),
                "could not verify the token's transfer-fee rate at startup (the token likely \
                 implements no transfer fee, or the node was unreachable); proceeding without the \
                 fee-solvency guard"
            ),
            Err(_elapsed) => warn!(
                target: "usdt",
                %usdt_contract,
                "the token transfer-fee-rate check timed out at startup; proceeding without the \
                 fee-solvency guard"
            ),
        }

        Ok(Usdt::new(
            cfg,
            evm_rpc,
            args.db().clone(),
            args.task_group().clone(),
            args.our_peer_id(),
            args.num_peers(),
        ))
    }

    /// Generates configs for all peers in a trusted manner for testing.
    ///
    /// This reconstructs the full threshold-ECDSA secret in one place (the
    /// `cggmp21` "trusted dealer"), which is only appropriate for
    /// development/test federations. Production federations must run
    /// [`ServerModuleInit::distributed_gen`] instead.
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
        params: &Self::Params,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        // `trusted_dealer_gen` is infallible per the `ServerModuleInit` trait
        // (returns a plain `BTreeMap`, not `Result`), so an unsafe param set
        // is a deterministic panic here -- consistent with this function's
        // existing style (see the `.expect(...)` calls a few lines below) and
        // with this being a test/dev-only path (see this fn's doc comment).
        // Production key generation runs `distributed_gen`, which validates
        // fallibly (see `dkg::distributed_gen`).
        validate_usdt_params(params).expect("USDT config-gen params failed safety validation");

        let num_peers = peers.to_num_peers();
        let n = u16::try_from(num_peers.total())
            .expect("federation sizes fit in u16 in every supported deployment");
        let threshold = u16::try_from(num_peers.threshold())
            .expect("federation sizes fit in u16 in every supported deployment");

        // Inject a fixed pool of pregenerated Paillier safe primes instead of
        // searching for fresh ones at runtime, which turns config generation
        // from minutes into milliseconds. This is sound ONLY because the
        // trusted dealer is test/dev-only and already reconstructs the full
        // secret centrally (see `trusted_dealer_primes` for the security
        // scope). Production key generation runs `distributed_gen`, which keeps
        // generating fresh primes and is untouched. If `n` exceeds the embedded
        // pool we fall back to live generation.
        let mut builder = cggmp21::trusted_dealer::builder::<fedimint_threshold_ecdsa::Curve, _>(n)
            .set_threshold(Some(threshold))
            .hd_wallet(true);
        if let Some(primes) = trusted_dealer_primes::pregenerated_primes(n as usize) {
            builder = builder.set_pregenerated_primes(primes);
        }
        let shares = builder
            .generate_shares(&mut OsRng)
            .expect("trusted dealer share generation failed");

        let group_public_key =
            group_public_key(&shares[0]).expect("dealer-generated share has a valid group key");

        let secp = secp256k1::Secp256k1::new();
        let mpc_encryption_keys: BTreeMap<PeerId, (secp256k1::SecretKey, secp256k1::PublicKey)> =
            peers
                .iter()
                .map(|&peer| (peer, secp.generate_keypair(&mut OsRng)))
                .collect();
        let mpc_encryption_pks: BTreeMap<PeerId, secp256k1::PublicKey> = mpc_encryption_keys
            .iter()
            .map(|(&peer, (_, pk))| (peer, *pk))
            .collect();

        peers
            .iter()
            .enumerate()
            .map(|(index, &peer)| {
                let cfg = UsdtConfig {
                    private: UsdtConfigPrivate {
                        key_share: shares[index].clone(),
                        mpc_encryption_sk: mpc_encryption_keys[&peer].0,
                        local: UsdtConfigLocal {
                            evm_rpc_url: crate::config::default_evm_rpc_url(),
                            broadcaster_private_key: None,
                        },
                    },
                    consensus: UsdtConfigConsensus {
                        group_public_key,
                        mpc_encryption_pks: mpc_encryption_pks.clone(),
                        threshold,
                        network: args.network,
                        usdt_contract: params.usdt_contract,
                        chain_id: params.chain_id,
                        confirmation_depth: params.confirmation_depth,
                        entry_point: params.entry_point,
                        account_factory: params.account_factory,
                        simple_account_impl: params.simple_account_impl,
                        check_ttl_blocks: params.check_ttl_blocks,
                        broadcaster_min_balance_wei: params.broadcaster_min_balance_wei,
                        eth_usd_price_feed: params.eth_usd_price_feed,
                        price_feed_max_staleness_secs: params.price_feed_max_staleness_secs,
                    },
                };

                (peer, cfg.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
        params: &Self::Params,
    ) -> anyhow::Result<ServerModuleConfig> {
        let config = dkg::distributed_gen(peers, args, params).await?;
        Ok(config.to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<UsdtClientConfig> {
        let config = UsdtConfigConsensus::from_erased(config)?;
        Ok(UsdtClientConfig {
            group_public_key: config.group_public_key,
            network: config.network,
            usdt_contract: config.usdt_contract,
            chain_id: config.chain_id,
            confirmation_depth: config.confirmation_depth,
            entry_point: config.entry_point,
            account_factory: config.account_factory,
            simple_account_impl: config.simple_account_impl,
        })
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<UsdtConfig>()?;

        ensure!(
            group_public_key(&config.private.key_share)? == config.consensus.group_public_key,
            "This guardian's key share does not aggregate to the consensus group public key"
        );

        let secp = secp256k1::Secp256k1::new();
        let our_mpc_pk = config.private.mpc_encryption_sk.public_key(&secp);
        ensure!(
            config.consensus.mpc_encryption_pks.get(identity) == Some(&our_mpc_pk),
            "This guardian's MPC encryption public key does not match the consensus configuration"
        );

        // Defense-in-depth (sec-17): re-run the same safety validation the
        // config-gen paths already ran, over the params as they landed in
        // THIS guardian's consensus config. Catches a bad config that
        // somehow reached a guardian without going through
        // `trusted_dealer_gen`/`dkg::distributed_gen` (e.g. a hand-edited
        // config file, or a future config-gen path that forgets the check).
        validate_usdt_params(&UsdtGenParams {
            usdt_contract: config.consensus.usdt_contract,
            chain_id: config.consensus.chain_id,
            confirmation_depth: config.consensus.confirmation_depth,
            entry_point: config.consensus.entry_point,
            account_factory: config.consensus.account_factory,
            simple_account_impl: config.consensus.simple_account_impl,
            check_ttl_blocks: config.consensus.check_ttl_blocks,
            broadcaster_min_balance_wei: config.consensus.broadcaster_min_balance_wei,
            eth_usd_price_feed: config.consensus.eth_usd_price_feed,
            price_feed_max_staleness_secs: config.consensus.price_feed_max_staleness_secs,
        })
        .context("consensus config failed USDT safety validation")?;

        Ok(())
    }

    /// DB migrations to move from old to newer versions.
    ///
    /// `DatabaseVersion(0)` is the module's first real migration (security
    /// finding 06): [`FeeVoteKey`](crate::db::FeeVoteKey)'s value changed
    /// from a bare [`FeeVote`] to [`StoredFeeVote`] (adds `recorded_block`,
    /// the freshness stamp `fee_vote_median`'s TTL/quorum gate needs). See
    /// [`migrate_db_v0`] for why this migration drops rather than rewrites
    /// the old-format rows.
    ///
    /// `DatabaseVersion(1)` (security findings 04/12/15): both
    /// [`DepositObservation`](fedimint_usdt_common::DepositObservation) and
    /// [`UserOpConfirmedObservation`](crate::db::UserOpConfirmedObservation)
    /// gained a `block_hash` field. See [`migrate_db_v1`] for why this
    /// migration drops (rather than rewrites) the old-format vote rows.
    ///
    /// `DatabaseVersion(2)` (security finding 03):
    /// [`SubmittedUserOp`](crate::db::SubmittedUserOp) gained a trailing
    /// `superseded: bool` field (the reprice/replacement RBF-nonce-safety
    /// flag). See [`migrate_db_v2`] for why this REWRITES (rather than drops)
    /// the existing rows.
    ///
    /// `DatabaseVersion(3)` (security finding 09, terminal-withdrawal refund):
    /// [`UserOpConfirmedObservation`](crate::db::UserOpConfirmedObservation)
    /// gained `actual_gas_cost_wei` (its transient `UserOpConfirmedVote` table
    /// is DROPPED like [`migrate_db_v1`]), and the persistent
    /// [`UsdtWithdrawalV0`](crate::db::UsdtWithdrawalV0) gained a trailing
    /// `refund_pubkey` (its `UnclaimedWithdrawal` rows are REWRITTEN in place,
    /// like [`migrate_db_v2`], appending a placeholder key). See
    /// [`migrate_db_v3`].
    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Usdt>> {
        let mut migrations: BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Usdt>> =
            BTreeMap::new();
        migrations.insert(
            DatabaseVersion(0),
            Box::new(|ctx| migrate_db_v0(ctx).boxed()),
        );
        migrations.insert(
            DatabaseVersion(1),
            Box::new(|ctx| migrate_db_v1(ctx).boxed()),
        );
        migrations.insert(
            DatabaseVersion(2),
            Box::new(|ctx| migrate_db_v2(ctx).boxed()),
        );
        migrations.insert(
            DatabaseVersion(3),
            Box::new(|ctx| migrate_db_v3(ctx).boxed()),
        );
        migrations
    }
}

/// Migrates [`FeeVoteKey`](crate::db::FeeVoteKey)'s value shape from the
/// pre-hardening bare [`FeeVote`] to [`StoredFeeVote`] (security finding 06).
///
/// Rather than reinterpreting each old-format row's bytes into the new shape,
/// this simply drops every existing `FeeVote` entry: they are guardian-local,
/// ephemeral per-peer observations (never economically load-bearing on their
/// own, only their current median is), and every guardian's
/// `usdt-fee-estimate-poller` re-proposes its current reading -- stamped with
/// a real `recorded_block` -- within one poll interval of upgrading, so the
/// federation's fee-vote quorum re-establishes itself almost immediately.
/// Fabricating a `recorded_block` for the old rows instead (e.g. `0`) would
/// just make them read as maximally stale under the new TTL check anyway, so
/// dropping them outright (mirroring `fedimint-mint-server`'s
/// `migrate_db_v1`, which also `raw_remove_by_prefix`s a stale-format table)
/// is simpler and has no observable difference in outcome.
async fn migrate_db_v0(mut ctx: ServerModuleDbMigrationFnContext<'_, Usdt>) -> anyhow::Result<()> {
    ctx.dbtx()
        .raw_remove_by_prefix(&[DbKeyPrefix::FeeVote as u8])
        .await
        .expect("DB error");
    Ok(())
}

/// Migrates the deposit- and userop-observation vote tables' value shapes for
/// the `block_hash` binding (security findings 04/12/15):
/// [`DepositObservationVoteKey`](crate::db::DepositObservationVoteKey)'s value
/// ([`DepositObservation`](fedimint_usdt_common::DepositObservation)) and
/// [`UserOpConfirmedVoteKey`](crate::db::UserOpConfirmedVoteKey)'s value
/// ([`UserOpConfirmedObservation`](crate::db::UserOpConfirmedObservation)) each
/// gained a `block_hash` field.
///
/// Like [`migrate_db_v0`], this DROPS every existing row of both tables rather
/// than reinterpreting the old-format bytes. These are transient, guardian-
/// local observation votes: the deposit scanner re-proposes each pending
/// account's observation every scan tick, and the user-op submitter re-polls
/// and re-proposes every `SubmittedUserOp`'s receipt every submit tick -- both
/// now stamped with a real `block_hash` -- so both vote quorums re-establish
/// themselves within one tick of upgrading. Fabricating a `block_hash` for the
/// old rows (e.g. all-zero) would be worse than dropping them: a zero hash is
/// not any real fork's hash, so those rows could never full-field-equal a
/// freshly-observed vote and would just linger as dead weight until expired.
/// Dropping them outright (mirroring `fedimint-mint-server`'s `migrate_db_v1`,
/// which also `raw_remove_by_prefix`es a stale-format table) is simpler and
/// loses nothing meaningful.
async fn migrate_db_v1(mut ctx: ServerModuleDbMigrationFnContext<'_, Usdt>) -> anyhow::Result<()> {
    ctx.dbtx()
        .raw_remove_by_prefix(&[DbKeyPrefix::DepositObservationVote as u8])
        .await
        .expect("DB error");
    ctx.dbtx()
        .raw_remove_by_prefix(&[DbKeyPrefix::UserOpConfirmedVote as u8])
        .await
        .expect("DB error");
    Ok(())
}

/// Migrates [`SubmittedUserOp`](crate::db::SubmittedUserOp)'s value shape for
/// the `superseded: bool` field added in `MODULE_CONSENSUS_VERSION` 0.6
/// (security finding 03's reprice/replacement RBF-nonce-safety flag).
///
/// Unlike [`migrate_db_v0`]/[`migrate_db_v1`] (which DROP transient,
/// re-proposed vote tables), `SubmittedUserOp` is NOT transient: it is the
/// sole record of a federation-agreed-signed op awaiting on-chain
/// confirmation -- a withdrawal whose e-cash was already burned, or a sweep
/// pulling deposits into the pool. Dropping it would strand those funds. So
/// this REWRITES each existing row in place instead.
///
/// The rewrite is a byte-append: `superseded` is the LAST field of the
/// struct, and a struct's `Encodable` is just its fields concatenated in
/// declaration order, so a pre-0.6 row's bytes are exactly the new encoding
/// MINUS the trailing `superseded`. Appending `Encodable`-for-`bool`'s
/// single-byte encoding of `false` (`0x00`) therefore yields a valid 0.6 row
/// that decodes with `superseded == false` -- the correct default (a row that
/// pre-dates the replacement machinery has never been superseded). Reads the
/// raw rows first (releasing the read borrow) before re-inserting, so the
/// mutation does not alias the scan.
async fn migrate_db_v2(mut ctx: ServerModuleDbMigrationFnContext<'_, Usdt>) -> anyhow::Result<()> {
    let entries: Vec<(Vec<u8>, Vec<u8>)> = ctx
        .dbtx()
        .raw_find_by_prefix(&[DbKeyPrefix::SubmittedUserOp as u8])
        .await
        .expect("DB error")
        .collect()
        .await;
    for (key, mut value) in entries {
        // Append `superseded: false` (bool `false` encodes to the single byte
        // `0x00`).
        value.push(0u8);
        ctx.dbtx()
            .raw_insert_bytes(&key, &value)
            .await
            .expect("DB error");
    }
    Ok(())
}

/// The placeholder `refund_pubkey` [`migrate_db_v3`] appends to pre-0.8
/// in-flight [`UsdtWithdrawalV0`](crate::db::UsdtWithdrawalV0) rows (security
/// finding 09): the BIP-341 nothing-up-my-sleeve secp256k1 point `H =
/// lift_x(sha256(G))`, a valid compressed public key with NO known discrete
/// logarithm. Pre-0.8 withdrawals were enqueued by clients that never derived
/// a refund key, so there is no real key to migrate to. Defaulting to an
/// unspendable point (rather than, say, the generator `G`, whose private key
/// `1` is public) keeps the withdrawal record valid and audit-correct -- if
/// it settles it is paid normally and this is never read; if it ever fails,
/// the resulting refund is a still-tracked federation liability that no
/// attacker can steal (nobody can sign for `H`). This is strictly no worse
/// than pre-0.8 behavior, where a failed withdrawal had no refund path at all.
pub const LEGACY_REFUND_PLACEHOLDER_PUBKEY: [u8; 33] =
    alloy::primitives::hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");

/// Migrates for security finding 09 (terminal-withdrawal refund).
///
/// Two consensus-serialized shapes changed:
///
/// - [`UserOpConfirmedObservation`](crate::db::UserOpConfirmedObservation) (the
///   `UserOpConfirmedVote` table's value) gained `actual_gas_cost_wei`. Like
///   [`migrate_db_v1`], this DROPS every row of that transient, re-proposed
///   vote table rather than reinterpreting old bytes: the user-op submitter
///   re-polls every `SubmittedUserOp`'s receipt and re-proposes it -- now
///   carrying `actual_gas_cost_wei` -- within one tick of upgrading, so the
///   quorum re-establishes itself immediately. Fabricating a gas cost for the
///   old rows would be worse than dropping (an all-zero gas figure would never
///   full-field-equal a freshly-observed vote and would linger as dead weight
///   until expired).
///
/// - The persistent [`UsdtWithdrawalV0`](crate::db::UsdtWithdrawalV0) (the
///   `UnclaimedWithdrawal` table's value) gained a trailing `refund_pubkey`.
///   These rows CANNOT be dropped -- each is a still-funded obligation whose
///   e-cash was already burned, and `audit` must keep subtracting it -- so this
///   REWRITES each in place (like [`migrate_db_v2`]) by byte-appending
///   [`LEGACY_REFUND_PLACEHOLDER_PUBKEY`]. A struct's `Encodable` is its fields
///   concatenated in declaration order and a `PublicKey` encodes as a fixed 33
///   compressed bytes with no length prefix, so a pre-0.8 row's bytes are
///   exactly the new encoding minus the trailing key; appending the
///   placeholder's 33 bytes yields a valid 0.8 row. See
///   [`LEGACY_REFUND_PLACEHOLDER_PUBKEY`] for why the placeholder is an
///   unspendable point rather than a real key.
async fn migrate_db_v3(mut ctx: ServerModuleDbMigrationFnContext<'_, Usdt>) -> anyhow::Result<()> {
    ctx.dbtx()
        .raw_remove_by_prefix(&[DbKeyPrefix::UserOpConfirmedVote as u8])
        .await
        .expect("DB error");

    let entries: Vec<(Vec<u8>, Vec<u8>)> = ctx
        .dbtx()
        .raw_find_by_prefix(&[DbKeyPrefix::UnclaimedWithdrawal as u8])
        .await
        .expect("DB error")
        .collect()
        .await;
    for (key, mut value) in entries {
        value.extend_from_slice(&LEGACY_REFUND_PLACEHOLDER_PUBKEY);
        ctx.dbtx()
            .raw_insert_bytes(&key, &value)
            .await
            .expect("DB error");
    }
    Ok(())
}

/// USDT-on-EVM module
#[derive(Debug)]
pub struct Usdt {
    pub cfg: UsdtConfig,
    /// Read (and, later, broadcast) access to this guardian's configured EVM
    /// node.
    pub evm_rpc: DynServerEvmRpc,
    /// Kept for test scaffolding (`db_for_test`, `#[cfg(test)]`); the
    /// deposit-checker task spawned in [`Usdt::new`] is handed its own clone
    /// before this field is set, so no production consensus method reads it
    /// directly.
    #[allow(dead_code)]
    db: Database,
    our_peer_id: PeerId,
    num_peers: NumPeers,
    /// This guardian's most recently polled view of the EVM chain head,
    /// refreshed in the background by the poller task spawned in
    /// [`Usdt::new`] (wallet-style block-count cache, but push-updated by a
    /// dedicated poller instead of pulled synchronously on every
    /// `consensus_proposal`, since EVM RPC calls are not guaranteed to be as
    /// cheap/local as the wallet's bitcoind status cache).
    block_count: Arc<AtomicU64>,
    /// Kept for test scaffolding; the deposit-checker task spawned in
    /// [`Usdt::new`] is handed its own reference before this field is set,
    /// so no production method reads it directly.
    #[allow(dead_code)]
    task_group: TaskGroup,
    /// This guardian's in-memory table of currently-running off-thread
    /// threshold-ECDSA signing sessions (see [`crate::signing`]), spawned by
    /// [`Usdt::start_session`] and pumped round-by-round from
    /// `consensus_proposal`/`process_consensus_item` over `MpcRound`
    /// consensus items.
    signing_sessions: SessionStore,
    /// This guardian-LOCAL table of assembled signatures, keyed by session:
    /// the compact 64-byte secp256k1 signature a signer produced once its
    /// off-thread state machine finished. Deliberately NOT consensus DB
    /// state — a non-signer guardian cannot compute the signature, so writing
    /// it to the consensus DB (signers would, non-signers would not) would
    /// diverge the federation. In Phase 6a the consensus `SigningSession`
    /// tracks only `round`; federation-wide agreement on the final signature
    /// (so non-signers hold it too) is a Phase 6b concern. Read by Task 4's
    /// status endpoint.
    completed_signatures: Arc<Mutex<BTreeMap<SigningSessionId, Vec<u8>>>>,
    /// Signatures this guardian's off-thread signers have assembled and are
    /// awaiting federation-wide agreement (Phase 6b): pushed by
    /// [`Usdt::advance_local_signer`] alongside (not instead of) its
    /// `completed_signatures` write, drained into
    /// `UsdtConsensusItem::MpcSignature` proposals in `consensus_proposal`.
    /// Mirrors `user_op_confirmed_proposals`'s drain pattern.
    #[allow(clippy::type_complexity)]
    pending_signature_proposals: Arc<Mutex<Vec<(SigningSessionId, Vec<u8>)>>>,
    /// `UserOp` on-chain outcomes gathered by the background
    /// `usdt-user-op-submitter` task (spawned in [`Usdt::new`]; see
    /// [`Usdt::spawn_user_op_submitter`]), drained into
    /// `UsdtConsensusItem::UserOpConfirmed` proposals in
    /// `consensus_proposal` (Phase 7, Task 5).
    user_op_confirmed_proposals: Arc<Mutex<Vec<UserOpConfirmedProposal>>>,
    /// This guardian's most recently polled [`FeeVote`] (current EVM fee
    /// market / USDT-per-ETH exchange rate), refreshed in the background by
    /// [`Usdt::spawn_fee_estimate_poller`] (Phase 8, Task 1) -- mirrors
    /// `block_count`'s push-updated cache pattern exactly, except `Option`
    /// (rather than an `AtomicU64` defaulting to `0`) since a `FeeVote` of
    /// all-zero fields would be a meaningfully wrong value to ever propose,
    /// unlike block count `0`, which is a legitimate (if unlikely)
    /// "chain not observed yet" state already handled elsewhere. `None`
    /// until the poller's first successful read, AND whenever the most
    /// recent poll failed (security finding 06's freshness facet -- the
    /// poller clears this on error rather than keeping a stale reading, so
    /// this guardian stops proposing/refreshing its `FeeVote` while its fee
    /// source is unreachable; see [`Usdt::spawn_fee_estimate_poller`]).
    fee_estimate: Arc<Mutex<Option<FeeVote>>>,
    /// Readiness observations gathered by the background bootstrap-observer
    /// task (Part C; spawned in [`Usdt::new`], see
    /// [`Usdt::spawn_bootstrap_observer`]), drained into
    /// `UsdtConsensusItem::BootstrapObservation` proposals in
    /// `consensus_proposal`. Mirrors `user_op_confirmed_proposals`'s drain
    /// pattern; each observation is this guardian's own guardian-LOCAL read of
    /// the on-chain readiness conditions, never itself a consensus
    /// decision.
    bootstrap_proposals: Arc<Mutex<Vec<BootstrapObservation>>>,
    /// This guardian's most recent confirmation-depth block-hash observation
    /// (deposit-by-proof anchor), refreshed in the background by the READ-ONLY
    /// [`Usdt::spawn_block_hash_observer`] task and drained into a
    /// `UsdtConsensusItem::BlockHash` proposal in `consensus_proposal`. `None`
    /// until the observer's first successful read; a single-slot `Option`
    /// (latest wins) since only the most recent anchor is worth proposing --
    /// mirrors `fee_estimate`'s cache shape. Never itself a consensus write; it
    /// becomes a ring entry only once threshold-aggregated in the ordered
    /// `process` path.
    block_hash_proposals: Arc<Mutex<Option<BlockHashObservation>>>,
}

/// One guardian-local observation of a submitted `UserOp`'s on-chain outcome
/// (Phase 7, Task 5), gathered by [`Usdt::spawn_user_op_submitter`] and
/// drained into `UsdtConsensusItem::UserOpConfirmed` proposals by
/// `consensus_proposal`. Plain data -- mirrors
/// [`fedimint_usdt_common::DepositObservation`]'s role for the deposit-side
/// quorum.
#[derive(Debug, Clone)]
struct UserOpConfirmedProposal {
    op_hash: [u8; 32],
    success: bool,
    block: u64,
    /// Canonical hash of `block`, from the authoritative `EntryPoint` log (see
    /// [`crate::rpc::IServerEvmRpc::get_user_op_receipt`]).
    block_hash: [u8; 32],
    swept: UsdtAmount,
    /// The op's on-chain gas cost in WEI (security finding 09), read verbatim
    /// from the `EntryPoint` `UserOperationEvent` log's `actualGasCost` (see
    /// [`crate::rpc::IServerEvmRpc::get_user_op_receipt`]). Wei, not USDT.
    actual_gas_cost_wei: UsdtAmount,
}

/// Per-field tally of the [`BootstrapObservation`] votes currently in the
/// consensus `BootstrapVote` table (Part C), produced by
/// [`Usdt::bootstrap_counts`]. Each field counts the guardians whose latest
/// vote has that condition `true`; the readiness derivation compares each
/// against `threshold`.
#[derive(Debug, Default, Clone, Copy)]
struct BootstrapCounts {
    entry_point_ok: usize,
    factory_ok: usize,
    impl_ok: usize,
    funded: usize,
    rpc_healthy: usize,
}

/// Grouped handles for [`Usdt::spawn_user_op_submitter`], bundling its many
/// related parameters into one utility struct (per this workspace's
/// convention for functions that would otherwise take too many individual
/// parameters) instead of listing them all out.
struct UserOpSubmitterHandles {
    db: Database,
    evm_rpc: DynServerEvmRpc,
    user_op_confirmed_proposals: Arc<Mutex<Vec<UserOpConfirmedProposal>>>,
    /// EVM reorg confirmation depth (security finding 04): a receipt is not
    /// proposed for threshold confirmation until its block is this many
    /// consensus blocks deep, mirroring the deposit scanner's own depth gate.
    confirmation_depth: u64,
    /// Needed to compute `consensus_block_count(dbtx, num_peers)` for the
    /// depth gate from the guardian-local DB.
    num_peers: NumPeers,
}

/// Grouped handles/config for [`Usdt::spawn_bootstrap_observer`] (Part C),
/// mirroring [`DepositCheckerHandles`]'s convention. All fields are read-only
/// inputs to the guardian-local readiness poll (config values + the EVM RPC
/// handle + the proposal sink); the poll never touches the consensus DB.
struct BootstrapObserverHandles {
    evm_rpc: DynServerEvmRpc,
    bootstrap_proposals: Arc<Mutex<Vec<BootstrapObservation>>>,
    group_public_key: secp256k1::PublicKey,
    entry_point: fedimint_usdt_common::EvmAddress,
    account_factory: fedimint_usdt_common::EvmAddress,
    simple_account_impl: fedimint_usdt_common::EvmAddress,
    broadcaster_min_balance_wei: u64,
}

/// Grouped handles/config for [`Usdt::spawn_block_hash_observer`]
/// (deposit-by-proof anchor), mirroring [`DepositCheckerHandles`]'s
/// convention. All uses are read-only: the observer reads
/// `consensus_block_count` from the guardian-local DB, reads the canonical
/// hash of the confirmation-depth block via `evm_rpc.get_block_hash`, and
/// queues it into `block_hash_proposals` -- it NEVER writes the consensus DB
/// (commit-safety constraint).
struct BlockHashObserverHandles {
    db: Database,
    evm_rpc: DynServerEvmRpc,
    /// This guardian's most recently polled chain head (see
    /// [`Usdt::spawn_block_count_poller`]); used only to skip observing a
    /// confirmation-depth height this guardian's own node has not yet imported.
    block_count: Arc<AtomicU64>,
    confirmation_depth: u64,
    /// Needed to compute `consensus_block_count(dbtx, num_peers)` (the shared
    /// height reference all honest guardians target) from the local DB.
    num_peers: NumPeers,
    block_hash_proposals: Arc<Mutex<Option<BlockHashObservation>>>,
}

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Usdt {
    /// Define the consensus types
    type Common = UsdtModuleTypes;
    type Init = UsdtInit;

    #[allow(clippy::too_many_lines)]
    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<UsdtConsensusItem> {
        let mut items = Vec::new();

        let head = self.block_count.load(Ordering::Relaxed);
        let current_consensus = self.consensus_block_count(dbtx).await;
        let mut vote = head;
        if current_consensus != 0 {
            // This prevents catching up more than a handful of blocks in a
            // single consensus round if the federation (or this guardian's
            // EVM node) was offline for a prolonged period of time.
            vote = vote.min(current_consensus + if is_running_in_test_env() { 100 } else { 5 });
        }

        let current_vote = dbtx
            .get_value(&BlockCountVoteKey(self.our_peer_id))
            .await
            .unwrap_or(0);

        if vote > current_vote {
            items.push(UsdtConsensusItem::BlockCount(vote));
        }

        // Propose this guardian's most recently polled `FeeVote` (see
        // `spawn_fee_estimate_poller`), mirroring the `BlockCount` proposal
        // above but with equality-based (not `>`) dedup: the EVM fee market
        // moves in both directions, so "changed" (not "increased") is the
        // right redundancy test (Phase 8, Task 1).
        //
        // Security finding 06's freshness facet: also re-propose an
        // UNCHANGED value once this peer's stored vote's `recorded_block`
        // has fallen `FEE_VOTE_REFRESH_BLOCKS` behind the current consensus
        // block count, so a healthy guardian whose polled value is stable
        // keeps its vote fresh under `fee_vote_median`'s TTL instead of
        // silently aging out. `None` here (no cached local reading -- either
        // never polled, or the poller is currently failing, see
        // `spawn_fee_estimate_poller`) proposes nothing, letting this
        // guardian's last stored vote age past the TTL and drop out of the
        // quorum, rather than pin a stale/wrong value forever.
        let fee_vote = *self.fee_estimate.lock().expect("not poisoned");
        if let Some(vote) = fee_vote {
            let current_vote = dbtx.get_value(&FeeVoteKey(self.our_peer_id)).await;
            let should_propose = match &current_vote {
                Some(stored) => {
                    stored.vote != vote
                        || current_consensus.saturating_sub(stored.recorded_block)
                            >= FEE_VOTE_REFRESH_BLOCKS
                }
                None => true,
            };
            if should_propose {
                items.push(UsdtConsensusItem::FeeVote(vote));
            }
        }

        // Propose this guardian's most recent readiness observation (Part C;
        // gathered by `spawn_bootstrap_observer`), mirroring the `FeeVote`
        // proposal above: equality-based dedup (the readiness conditions move
        // in both directions), and only the LATEST drained observation
        // matters (the poller queues its full current view each tick, so
        // earlier queued views are stale). Skip proposing when it is
        // unchanged from this peer's already-recorded vote, so an unchanged
        // readiness state does not spam consensus every round.
        let latest_bootstrap =
            std::mem::take(&mut *self.bootstrap_proposals.lock().expect("not poisoned")).pop();
        if let Some(obs) = latest_bootstrap {
            let current_vote = dbtx.get_value(&BootstrapVoteKey(self.our_peer_id)).await;
            if current_vote != Some(obs) {
                items.push(UsdtConsensusItem::BootstrapObservation(obs));
            }
        }

        // Propose this guardian's most recent confirmation-depth block-hash
        // observation (deposit-by-proof anchor; gathered by the READ-ONLY
        // `spawn_block_hash_observer`), mirroring the `FeeVote`/`Bootstrap`
        // drains: only the LATEST observation matters (the observer overwrites
        // its single slot each tick), and it is proposed only when it differs
        // from this peer's already-recorded vote, so an unchanged anchor does
        // not spam consensus every round (`process_consensus_item`'s redundancy
        // guard is what actually enforces this). The observation is a
        // guardian-LOCAL RPC read, never itself a consensus write; it becomes a
        // ring entry only once threshold-aggregated in the ordered `process`
        // path.
        let latest_block_hash = self
            .block_hash_proposals
            .lock()
            .expect("not poisoned")
            .take();
        if let Some(obs) = latest_block_hash {
            let current_vote = dbtx.get_value(&BlockHashVoteKey(self.our_peer_id)).await;
            if current_vote != Some(obs) {
                items.push(UsdtConsensusItem::BlockHash(obs));
            }
        }

        // Propose this guardian's payload for the current round of every
        // signing session it is a signer of, unless it has already been
        // recorded for that round (the redundancy guard `process_consensus_item`
        // enforces). The payload is pulled from the session's off-thread state
        // machine; a signer whose payload is not yet ready simply proposes
        // nothing this round and tries again next `consensus_proposal`.
        let sessions: Vec<(SigningSessionId, SigningSession)> = dbtx
            .find_by_prefix(&SigningSessionPrefix)
            .await
            .map(|(SigningSessionKey(id), session)| (id, session))
            .collect()
            .await;

        // Propose a rotation for any signing session that has stalled past the
        // timeout (see `propose_timed_out_rotations`). Read-only; no
        // consensus-DB write.
        items.extend(self.propose_timed_out_rotations(dbtx, &sessions).await);

        // Propose a reprice/replacement for any `SubmittedUserOp` that has
        // gone unconfirmed past `submitted_op_timeout_blocks()` (security
        // finding 03). Read-only; no consensus-DB write.
        items.extend(self.propose_replace_user_ops(dbtx).await);

        for (session_id, session) in sessions {
            if !session.signers.contains(&self.our_peer_id) {
                continue;
            }

            // Only READ the current round's pending payload — never remove or
            // pump the slot here. Fedimint runs `consensus_proposal` in a
            // separate task (`submit_module_ci_proposals`, a ~100ms timer)
            // CONCURRENTLY with `process_consensus_item`; if this drain took
            // the slot out to pump it, it could win the race against
            // `advance_local_signer`'s `remove`, which would then find no slot
            // and skip `submit_round` — permanently stalling the signing
            // session. The pump is therefore driven exclusively by the slot's
            // owner: `start_session` (round 0) and `advance_local_signer`
            // (subsequent rounds), both of which pre-fill `pending_outgoing`
            // before the next round needs proposing. A brief `None` here (the
            // window while `advance_local_signer` owns the slot mid-`.await`)
            // just skips this tick; the next 100ms tick proposes it.
            let payload = {
                let store = self.signing_sessions.lock().expect("not poisoned");
                store
                    .get(&session_id)
                    .and_then(|s| s.pending_outgoing.clone())
            };
            let Some(payload) = payload else {
                continue;
            };

            // Split the round's payload into `MPC_ROUND_CHUNK_SIZE`-byte
            // chunks (a single oversized `MpcRound` item would exceed the
            // `AlephBFT` unit byte limit and never be ordered). Propose every
            // chunk not already recorded for this (session, round, peer); the
            // redundancy guard in `process_consensus_item` drops any repeats
            // that race in before they land in the DB.
            let chunks = chunk_payload(&payload);
            let chunk_count = u16::try_from(chunks.len())
                .expect("a signing round payload never splits into more than u16::MAX chunks");
            for (chunk_index, chunk_bytes) in chunks.into_iter().enumerate() {
                let chunk = u16::try_from(chunk_index).expect("chunk index fits in u16");
                if dbtx
                    .get_value(&MpcRoundChunkKey(
                        session_id,
                        session.round,
                        self.our_peer_id,
                        chunk,
                    ))
                    .await
                    .is_some()
                {
                    continue;
                }
                items.push(UsdtConsensusItem::MpcRound(MpcRoundItem {
                    session_id,
                    round: session.round,
                    chunk,
                    chunk_count,
                    payload: chunk_bytes,
                }));
            }
        }

        // Drain signatures this guardian's off-thread signers have
        // assembled (see `advance_local_signer`), proposing an
        // `MpcSignature` for each whose session is not already `Completed`
        // in this dbtx snapshot -- a cheap dedup; `process_consensus_item`'s
        // redundancy guard is what actually enforces exactly-once agreement.
        let pending_signatures = std::mem::take(
            &mut *self
                .pending_signature_proposals
                .lock()
                .expect("not poisoned"),
        );
        for (session_id, signature) in pending_signatures {
            let already_completed = matches!(
                dbtx.get_value(&SigningSessionKey(session_id)).await,
                Some(SigningSession {
                    state: SessionState::Completed(_),
                    ..
                })
            );
            if !already_completed {
                items.push(UsdtConsensusItem::MpcSignature {
                    session_id,
                    signature,
                });
            }
        }

        // Drain `UserOp` on-chain outcomes gathered by the background
        // `usdt-user-op-submitter` task (see `spawn_user_op_submitter`),
        // proposing only those that differ from what this peer has already
        // voted for the op (avoiding redundant proposals that
        // `process_consensus_item` would reject) -- mirrors the `Deposit`
        // drain above exactly.
        let pending_confirmations = std::mem::take(
            &mut *self
                .user_op_confirmed_proposals
                .lock()
                .expect("not poisoned"),
        );
        for proposal in pending_confirmations {
            let obs = UserOpConfirmedObservation {
                success: proposal.success,
                block: proposal.block,
                block_hash: proposal.block_hash,
                swept: proposal.swept,
                actual_gas_cost_wei: proposal.actual_gas_cost_wei,
            };
            let current_vote = dbtx
                .get_value(&UserOpConfirmedVoteKey(proposal.op_hash, self.our_peer_id))
                .await;
            if current_vote != Some(obs) {
                items.push(UsdtConsensusItem::UserOpConfirmed {
                    op_hash: proposal.op_hash,
                    success: proposal.success,
                    block: proposal.block,
                    block_hash: proposal.block_hash,
                    swept: proposal.swept,
                    actual_gas_cost_wei: proposal.actual_gas_cost_wei,
                });
            }
        }

        items
    }

    #[allow(clippy::too_many_lines)]
    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: UsdtConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        // WARNING: `process_consensus_item` should return an `Err` for items that do
        // not change any internal consensus state. Failure to do so, will result in an
        // (potentially significantly) increased consensus history size.
        match consensus_item {
            UsdtConsensusItem::BlockCount(vote) => {
                let current_vote = dbtx
                    .get_value(&BlockCountVoteKey(peer_id))
                    .await
                    .unwrap_or(0);

                ensure!(vote > current_vote, "Block count vote is redundant");

                dbtx.insert_entry(&BlockCountVoteKey(peer_id), &vote).await;

                // Deterministic trigger (Phase 8, Task 2): every guardian,
                // right here, checks whether the withdrawal-batch policy
                // fires now that this vote may have moved the consensus
                // block-count median forward -- mirrors
                // `Usdt::maybe_trigger_sweep`'s placement in the `Deposit`
                // arm (a pure function of the item, prior consensus-DB
                // state, and config; see `Usdt::maybe_trigger_withdrawal_batch`'s
                // own doc comment for the full determinism argument).
                self.maybe_trigger_withdrawal_batch(dbtx).await;

                Ok(())
            }
            UsdtConsensusItem::Deposit(obs) => {
                // Security finding 14: self-authenticate BEFORE storing the
                // vote, not only later inside `credit_deposit` (which runs
                // only once threshold-many IDENTICAL votes accumulate). A
                // pure function of `obs` and this module's consensus config
                // (`group_public_key`/`account_factory`/
                // `simple_account_impl`), so every honest guardian computes
                // the same result. Returning `Err` here makes a malformed
                // observation non-state-changing, so it is never persisted
                // as a `DepositObservationVoteKey` and never retained in
                // consensus history -- otherwise a Byzantine guardian could
                // bloat the vote table forever with fresh random accounts
                // that never reach threshold (see
                // `security-review/14-low-junk-consensus-votes-db-bloat.md`).
                ensure!(
                    fedimint_usdt_common::derive_deposit_account(
                        &self.cfg.consensus.group_public_key,
                        self.cfg.consensus.account_factory,
                        self.cfg.consensus.simple_account_impl,
                        &obs.claim_pk,
                    ) == obs.account,
                    "deposit observation claim_pk does not derive its account"
                );

                // Security finding 12: FRESHNESS gate. Reject (non-state-
                // changing `Err`, BEFORE any DB mutation) an observation that
                // is outside the acceptable window relative to consensus:
                //   * too NEW: `obs.block` must be at least `confirmation_depth` behind the
                //     consensus block count (mirrors the deposit scanner's own read height), so
                //     an observation cannot be credited before it is confirmation-deep; and
                //   * too OLD: `obs.block` must be within `confirmation_depth +
                //     DEPOSIT_VOTE_MAX_AGE_BLOCKS` of the consensus block count, so a very old
                //     pre-reorg vote can never complete a threshold long after the fact (the
                //     deep- reorg stale-vote scenario). Purely a function of `obs` +
                //     `consensus_block_count(dbtx)` + config, so every honest guardian decides
                //     identically.
                let confirmation_depth = self.cfg.consensus.confirmation_depth;
                let ccount = self.consensus_block_count(dbtx).await;
                ensure!(
                    obs.block <= ccount.saturating_sub(confirmation_depth),
                    "deposit observation block is not yet confirmation-deep"
                );
                ensure!(
                    ccount.saturating_sub(obs.block)
                        <= confirmation_depth + DEPOSIT_VOTE_MAX_AGE_BLOCKS,
                    "deposit observation is too old (outside the freshness window)"
                );

                // Store this peer's vote; redundancy guard (unbounded-history rule).
                let key = DepositObservationVoteKey(obs.account, peer_id);
                if dbtx.insert_entry(&key, &obs).await.as_ref() == Some(&obs) {
                    bail!("Deposit observation vote is redundant");
                }

                // Security finding 12: EXPIRY + SUPERSESSION of stale/older
                // stored votes for this account (deterministic hygiene, reads
                // only `ccount` + the stored votes + `obs`). Remove any stored
                // vote that is now either outside the freshness window (so a
                // sub-threshold set of stale votes cannot linger and later
                // complete a threshold after a deep reorg) OR at a strictly
                // LOWER block than this fresh observation (a higher-block
                // observation supersedes older, now-divergent ones). This never
                // removes `obs` itself (equal block, in-window) and only ever
                // removes votes that could NOT have counted toward `obs`'s tally
                // anyway (a different `block`/`block_hash` cannot full-field-
                // equal `obs`), so it cannot change THIS credit decision -- it
                // only prevents stale accumulation. `credited` stays monotonic.
                let stored: Vec<(DepositObservationVoteKey, DepositObservation)> = dbtx
                    .find_by_prefix(&DepositObservationVoteAccountPrefix(obs.account))
                    .await
                    .collect()
                    .await;
                for (vote_key, vote) in &stored {
                    let too_old = ccount.saturating_sub(vote.block)
                        > confirmation_depth + DEPOSIT_VOTE_MAX_AGE_BLOCKS;
                    let superseded = vote.block < obs.block && *vote != obs;
                    if too_old || superseded {
                        dbtx.remove_entry(vote_key).await;
                    }
                }

                // Count identical observations for this account (over what
                // survives the expiry/supersession sweep above).
                let votes: Vec<DepositObservation> = dbtx
                    .find_by_prefix(&DepositObservationVoteAccountPrefix(obs.account))
                    .await
                    .map(|(_, v)| v)
                    .collect()
                    .await;
                let agreeing = votes.iter().filter(|v| **v == obs).count();

                if agreeing >= self.num_peers.threshold() {
                    self.credit_deposit(dbtx, &obs).await?;
                }
                Ok(())
            }
            UsdtConsensusItem::MpcRound(item) => self.process_mpc_round(dbtx, item, peer_id).await,
            UsdtConsensusItem::RotateSigning { session_id } => {
                self.process_rotate_signing(dbtx, session_id).await
            }
            UsdtConsensusItem::ReplaceUserOp { op_hash } => {
                self.process_replace_user_op(dbtx, op_hash).await
            }
            UsdtConsensusItem::MpcSignature {
                session_id,
                signature,
            } => {
                self.process_mpc_signature(dbtx, session_id, signature)
                    .await
            }
            UsdtConsensusItem::UserOpConfirmed {
                op_hash,
                success,
                block,
                block_hash,
                swept,
                actual_gas_cost_wei,
            } => {
                // DETERMINISTIC, mirrors the `Deposit` arm's exact
                // observation-quorum shape: store this peer's vote
                // (redundancy guard, unbounded-history rule), tally only
                // EXACTLY-matching votes (full-field `PartialEq` on
                // `UserOpConfirmedObservation`), and apply at threshold.
                //
                // Security finding 14: before storing, require `op_hash` to
                // correspond to a real `SubmittedUserOp` -- a pure
                // consensus-DB read, so every honest guardian computes the
                // same result. A confirmation vote for an op nobody
                // submitted is meaningless, and without this check a
                // Byzantine guardian could bloat `UserOpConfirmedVote`
                // forever with fresh random op hashes that never reach
                // threshold (mirrors the `Deposit` arm's `claim_pk`
                // self-authentication fix; see
                // `security-review/14-low-junk-consensus-votes-db-bloat.md`).
                ensure!(
                    dbtx.get_value(&SubmittedUserOpKey(op_hash)).await.is_some(),
                    "UserOpConfirmed vote for an op that was never submitted"
                );

                let obs = UserOpConfirmedObservation {
                    success,
                    block,
                    block_hash,
                    swept,
                    actual_gas_cost_wei,
                };
                let key = UserOpConfirmedVoteKey(op_hash, peer_id);
                if dbtx.insert_entry(&key, &obs).await.as_ref() == Some(&obs) {
                    bail!("UserOp confirmation vote is redundant");
                }

                let votes: Vec<UserOpConfirmedObservation> = dbtx
                    .find_by_prefix(&UserOpConfirmedVoteOpPrefix(op_hash))
                    .await
                    .map(|(_, v)| v)
                    .collect()
                    .await;
                let agreeing = votes.iter().filter(|v| **v == obs).count();

                if agreeing >= self.num_peers.threshold() {
                    self.apply_user_op_confirmed(dbtx, op_hash, &obs).await;
                }
                Ok(())
            }
            UsdtConsensusItem::FeeVote(vote) => {
                // Security finding 06's bounds facet: reject an
                // out-of-range vote outright (non-state-changing `Err`, so
                // it is never stored/retained in consensus history). A pure
                // function of `vote` alone -- every guardian rejects
                // identically. Without this, a single Byzantine extreme
                // vote could push `withdrawal_fee_quote`/`deposit_fee_quote`
                // into `FeeQuoteOverflow`, turning consensus quoting into a
                // deposit/withdrawal DoS.
                ensure!(
                    fee_vote_in_sane_range(&vote),
                    "FeeVote is outside the sane range"
                );

                // DETERMINISTIC, mirrors the `BlockCount` arm's discipline:
                // store this peer's vote (now with a `recorded_block`
                // freshness stamp, security finding 06) with a redundancy
                // guard. Unlike `BlockCount` (monotonic, so the guard is
                // `vote > current_vote`), the EVM fee market moves in both
                // directions, so the value-equality guard is used here --
                // relaxed (security finding 06's freshness facet) to also
                // ACCEPT an unchanged value once the peer's previously
                // stored vote has gone `FEE_VOTE_REFRESH_BLOCKS` blocks
                // without a refresh, so a healthy guardian's stable-valued
                // vote can keep itself fresh under `fee_vote_median`'s TTL
                // instead of being rejected as "redundant" forever. No
                // threshold-triggered "apply" step: the federation's fee
                // quote is always read on demand as the median over
                // whatever FRESH votes are currently stored (see
                // `Usdt::fee_vote_median`), never derived from any single
                // peer's vote or written to a separate consensus-agreed
                // record here.
                let current_block = self.consensus_block_count(dbtx).await;
                let current_vote = dbtx.get_value(&FeeVoteKey(peer_id)).await;
                let is_redundant = match &current_vote {
                    Some(stored) => {
                        stored.vote == vote
                            && current_block.saturating_sub(stored.recorded_block)
                                < FEE_VOTE_REFRESH_BLOCKS
                    }
                    None => false,
                };
                ensure!(!is_redundant, "FeeVote is redundant");

                dbtx.insert_entry(
                    &FeeVoteKey(peer_id),
                    &StoredFeeVote {
                        vote,
                        recorded_block: current_block,
                    },
                )
                .await;

                Ok(())
            }
            UsdtConsensusItem::BootstrapObservation(obs) => {
                // DETERMINISTIC (Part C), mirrors the `Deposit`/`FeeVote`
                // arms' discipline: store the ORDERED item's origin peer's
                // vote (keyed by `peer_id`, the framework-supplied origin --
                // NEVER `self.our_peer_id`), with an equality-based
                // redundancy guard (reject an EXACT repeat of this peer's
                // current vote; the readiness conditions move in both
                // directions).
                let key = BootstrapVoteKey(peer_id);
                if dbtx.insert_entry(&key, &obs).await.as_ref() == Some(&obs) {
                    bail!("Bootstrap observation vote is redundant");
                }

                // Deterministic readiness latch: the moment the aggregate
                // tally first reaches `Ready`, persist `HasEverBeenReadyKey`
                // so `bootstrap_state` can later report `Degraded` (was
                // `Ready`, regressed) distinctly from `AwaitingInfra`. This
                // is a pure function of (ordered item + prior consensus DB +
                // config): it reads only the just-updated `BootstrapVote`
                // table and the threshold, and writes the latch identically
                // on every guardian.
                if self.bootstrap_ready(dbtx).await
                    && dbtx.get_value(&HasEverBeenReadyKey).await.is_none()
                {
                    dbtx.insert_new_entry(&HasEverBeenReadyKey, &()).await;
                }

                Ok(())
            }
            UsdtConsensusItem::BlockHash(obs) => {
                // Deposit-by-proof anchor: persist a threshold-agreed
                // confirmation-depth `(height, block_hash)` into the block-hash
                // ring. DETERMINISTIC, mirroring the `Deposit` arm's discipline
                // exactly -- a pure function of the ordered item, prior
                // consensus DB state, and `cfg.consensus` (no RPC/wall-clock/
                // `our_peer_id`, so every honest guardian decides identically).
                //
                // FRESHNESS gate (mirrors the `Deposit` arm, security finding
                // 12), reject BEFORE any DB mutation so a rejected observation
                // is non-state-changing:
                //   * too NEW: `obs.height` must be at least `confirmation_depth` behind the
                //     consensus block count, so the ring never anchors a block that is not yet
                //     confirmation-deep; and
                //   * too OLD: `obs.height` must be within `confirmation_depth +
                //     DEPOSIT_VOTE_MAX_AGE_BLOCKS` of the consensus block count, so a stale
                //     pre-reorg vote can never complete a threshold long after the fact and
                //     re-anchor an old height.
                let confirmation_depth = self.cfg.consensus.confirmation_depth;
                let ccount = self.consensus_block_count(dbtx).await;
                ensure!(
                    obs.height <= ccount.saturating_sub(confirmation_depth),
                    "block-hash observation is not yet confirmation-deep"
                );
                ensure!(
                    ccount.saturating_sub(obs.height)
                        <= confirmation_depth + DEPOSIT_VOTE_MAX_AGE_BLOCKS,
                    "block-hash observation is too old (outside the freshness window)"
                );

                // Store the ORDERED item's origin peer's vote (keyed by the
                // framework-supplied `peer_id`, NEVER `self.our_peer_id`), with
                // an equality-based redundancy guard: reject (non-state-changing
                // `Err`) an EXACT repeat of this peer's current vote so a
                // re-proposed unchanged observation cannot bloat consensus
                // history.
                let key = BlockHashVoteKey(peer_id);
                if dbtx.insert_entry(&key, &obs).await.as_ref() == Some(&obs) {
                    bail!("block-hash observation vote is redundant");
                }

                // Tally FULLY-equal `(height, block_hash)` votes across every
                // peer (one slot per peer). Two guardians observing the same
                // height on DIFFERENT forks vote non-equal hashes, so they never
                // aggregate toward the ring write.
                let votes: Vec<BlockHashObservation> = dbtx
                    .find_by_prefix(&BlockHashVotePrefix)
                    .await
                    .map(|(_, v)| v)
                    .collect()
                    .await;
                let agreeing = votes.iter().filter(|v| **v == obs).count();

                if agreeing >= self.num_peers.threshold() {
                    write_block_hash_ring(dbtx, obs.height, obs.block_hash).await;
                }

                Ok(())
            }
            UsdtConsensusItem::Default { .. } => {
                bail!("The usdt module does not support this consensus item yet")
            }
        }
    }

    /// Claims (a portion of) a `credited` deposit, funding
    /// `input.amount - input.fee` (in [`USDT_UNIT`]) into the submitting
    /// transaction. `input.fee` must clear the federation's current
    /// fee-vote-median-derived deposit quote
    /// ([`fedimint_usdt_common::deposit_fee_quote`]), mirroring
    /// `process_output`'s `max_fee`/[`withdrawal_fee_quote`] check; the fee
    /// stays credited-but-unissued and is later swept into the pool as
    /// federation fee revenue (Task 3).
    ///
    /// # Determinism (consensus-critical)
    ///
    /// A pure function of `(input, prior consensus DB state, config)`: reads
    /// only the fee-vote median (`Usdt::fee_vote_median`) -- no RPC, no
    /// wall-clock, no `our_peer_id`. Every guardian processing the same
    /// ordered input against the same prior DB state computes the identical
    /// `Ok`/`Err` and the identical `DepositRecordKey` write.
    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b UsdtInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, UsdtInputError> {
        let input = match input {
            UsdtInput::V0(input) => input,
            UsdtInput::RefundV0 { out_point } => {
                // Security finding 09: claim a terminally-failed withdrawal's
                // reissued e-cash. Look up (and REMOVE) the refund record so it
                // can be claimed EXACTLY ONCE -- a second `RefundV0` for the
                // same `out_point` finds it absent and errors below. Returning
                // `refund.refund_pubkey` as `InputMeta.pub_key` makes the
                // fedimint transaction framework verify the claim is signed by
                // the original withdrawer's client-controlled refund key, so
                // NO ONE else can claim it (never by `out_point` alone). The
                // reissued amount balances against the mint primary module,
                // which mints `refund.amount` of `USDT_UNIT` e-cash; `fees` is
                // `ZERO` (the incurred gas was already netted out when the
                // refund was created). A pure consensus-DB read+remove: every
                // guardian computes the identical `InputMeta` and clears the
                // same record.
                let Some(refund) = dbtx.get_value(&RefundKey(*out_point)).await else {
                    return Err(UsdtInputError::UnknownRefund);
                };
                dbtx.remove_entry(&RefundKey(*out_point)).await;
                info!(
                    target: "usdt",
                    %out_point,
                    amount = refund.amount.0,
                    "withdrawal refund CLAIMED; reissued e-cash minted to the original withdrawer"
                );
                return Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_custom(USDT_UNIT, usdt_amount(refund.amount)),
                        fees: Amounts::ZERO,
                    },
                    pub_key: refund.refund_pubkey,
                });
            }
            UsdtInput::DepositProofV0 { claim_pk, proof } => {
                return self.process_deposit_proof(dbtx, claim_pk, proof).await;
            }
            UsdtInput::Default { .. } => {
                return Err(UsdtInputError::UnknownDepositAccount); // unknown/default variant
            }
        };
        let mut record = dbtx
            .get_value(&DepositRecordKey(input.account))
            .await
            .ok_or(UsdtInputError::UnknownDepositAccount)?;
        let available = record.credited.0.saturating_sub(record.claimed.0);
        if input.amount.0 > available {
            return Err(UsdtInputError::InsufficientCredit {
                available: UsdtAmount(available),
                requested: input.amount,
            });
        }

        // Mirrors `process_output`'s `median`/`quote` handling exactly: an
        // absent median (no fee vote has landed yet) or an overflowing quote
        // computation are distinct, explicit rejections rather than being
        // folded into `DepositFeeInsufficient` via an effectively-infinite
        // sentinel quote.
        let median = self
            .fee_vote_median(dbtx)
            .await
            .ok_or(UsdtInputError::NoFeeQuoteAvailable)?;
        let quote = deposit_fee_quote(&median).ok_or(UsdtInputError::FeeQuoteOverflow)?;
        if input.fee.0 < quote.0 {
            return Err(UsdtInputError::DepositFeeInsufficient {
                quote,
                offered: input.fee,
            });
        }
        if input.amount.0 <= input.fee.0 {
            return Err(UsdtInputError::FeeExceedsAmount {
                amount: input.amount,
                fee: input.fee,
            });
        }

        // `saturating_add` (Phase 9, Task 1 hardening, N1): `claimed` is
        // already bounded above by `credited` (a real, finite on-chain
        // balance) via the `available` check just above, so this can never
        // actually saturate -- but a deterministic saturate is strictly
        // safer than a deterministic panic on the (unreachable in practice)
        // chance of a `u64` overflow, and saturation is exactly as
        // reproducible across guardians as a raw `+` would be (still a pure
        // function of the two operands). Note `claimed` advances by the
        // FULL `input.amount` (not `amount - fee`): the fee's USDT remains
        // part of this deposit's credited-but-unissued balance until the
        // sweep pulls the whole thing into the pool, at which point it
        // becomes federation fee revenue (see `audit`'s doc comment).
        record.claimed = UsdtAmount(record.claimed.0.saturating_add(input.amount.0));
        dbtx.insert_entry(&DepositRecordKey(input.account), &record)
            .await;

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_custom(USDT_UNIT, usdt_amount(input.amount)),
                fees: Amounts::new_custom(USDT_UNIT, usdt_amount(input.fee)),
            },
            pub_key: record.claim_pk,
        })
    }

    /// Debits `output.amount + output.max_fee` (in [`USDT_UNIT`]) from the
    /// submitting transaction's funding and enqueues an on-chain withdrawal
    /// (Phase 8, Task 1). `output.max_fee` must clear the federation's
    /// current fee-vote-median-derived quote
    /// ([`fedimint_usdt_common::withdrawal_fee_quote`]); the excess over the
    /// actual on-chain gas cost accrues to the federation (Task 3).
    ///
    /// # Determinism (consensus-critical)
    ///
    /// A pure function of `(output, prior consensus DB state, config)`:
    /// reads only the fee-vote median (`Usdt::fee_vote_median`, itself a
    /// pure read over the consensus `FeeVote` table) and
    /// `Usdt::consensus_block_count` (also consensus-DB-derived,
    /// diagnostic-only bookkeeping for `requested_block`, mirroring
    /// `PendingUserOp::created_block`) -- no RPC, no wall-clock, no
    /// `our_peer_id`. Every guardian processing the same ordered output
    /// against the same prior DB state computes the identical
    /// `Ok`/`Err` and the identical `UnclaimedWithdrawalKey`/
    /// `WithdrawalStateKey` writes.
    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a UsdtOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, UsdtOutputError> {
        let UsdtOutput::V0(withdrawal) = output else {
            return Err(UsdtOutputError::UnsupportedOutputVariant); // unknown/default variant
        };

        let median = self
            .fee_vote_median(dbtx)
            .await
            .ok_or(UsdtOutputError::NoFeeQuoteAvailable)?;
        let quote = withdrawal_fee_quote(&median).ok_or(UsdtOutputError::FeeQuoteOverflow)?;

        if withdrawal.max_fee.0 < quote.0 {
            return Err(UsdtOutputError::FeeQuoteExceeded {
                quote,
                max_fee: withdrawal.max_fee,
            });
        }

        let requested_block = self.consensus_block_count(dbtx).await;
        dbtx.insert_new_entry(
            &UnclaimedWithdrawalKey(out_point),
            &UsdtWithdrawalV0 {
                recipient: withdrawal.recipient,
                amount: withdrawal.amount,
                max_fee: withdrawal.max_fee,
                requested_block,
                // Carried onto the queued withdrawal so a later terminal
                // failure can write a refund claimable only by the original
                // withdrawer (security finding 09), without re-reading the
                // consumed output.
                refund_pubkey: withdrawal.refund_pubkey,
            },
        )
        .await;
        dbtx.insert_new_entry(&WithdrawalStateKey(out_point), &WithdrawalState::Queued)
            .await;
        info!(
            target: "usdt",
            %out_point,
            recipient = %withdrawal.recipient,
            amount = withdrawal.amount.0,
            max_fee = withdrawal.max_fee.0,
            requested_block,
            "withdrawal queued (awaiting batch trigger)"
        );

        Ok(TransactionItemAmounts {
            amounts: Amounts::new_custom(USDT_UNIT, usdt_amount(withdrawal.amount)),
            fees: Amounts::new_custom(USDT_UNIT, usdt_amount(withdrawal.max_fee)),
        })
    }

    /// `Some(UsdtOutputOutcome)` once `out_point`'s withdrawal has been
    /// enqueued (a `WithdrawalStateKey` record exists for it -- i.e.
    /// `process_output` succeeded), `None` otherwise. Read directly from
    /// consensus DB, so any guardian answers identically; see
    /// [`UsdtOutputOutcome`]'s doc comment for why the detailed lifecycle
    /// state itself is not carried here.
    async fn output_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> Option<UsdtOutputOutcome> {
        dbtx.get_value(&WithdrawalStateKey(out_point))
            .await
            .map(|_state| UsdtOutputOutcome)
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        // Every `credited` (guardian-observed, confirmed on-chain) deposit is
        // an asset backing the USDT-`mintv2` instance's issued e-cash
        // liability. `claimed <= credited` always (`process_input` only ever
        // moves `claimed` up to `credited`), so reporting the full
        // `credited - swept` amount here -- not `credited - claimed` -- can
        // only create a surplus (deposits credited but not yet claimed into
        // e-cash), never a deficit, keeping the federation's global balance
        // sheet (`fedimint_core::module::audit::Audit::net_assets`) solvent.
        //
        // NO-DOUBLE-COUNTING (Phase 7, Task 5, SOLVENCY-CRITICAL): once a
        // deposit account's USDT has been swept to the pool
        // (`Usdt::apply_user_op_confirmed`), it is represented by
        // `PoolState.balance`, not by that deposit's `credited` amount
        // anymore -- reporting BOTH would double-count the same on-chain
        // USDT as two separate assets. `DepositRecord::swept` tracks exactly
        // how much of `credited` has already moved into the pool (monotonic,
        // capped at `credited`, bumped only in `apply_user_op_confirmed`),
        // so this module's total asset is `sum(credited - swept)` (the
        // not-yet-swept remainder of every deposit, counted once) PLUS
        // `PoolState.balance` (the pooled remainder, counted once) below --
        // together, every on-chain USDT the federation vouches for is
        // counted EXACTLY once, whichever side of a sweep it currently sits
        // on.
        //
        // PROVISIONAL (Phase 5, mirrors `deposit_address`'s doc comment):
        // the on-chain deposit account is derived from the group public key
        // (`derive_deposit_account`), so once the federation has reached
        // consensus that it holds `credited` USDT there, it is already
        // vouching for that balance the same way the wallet module vouches
        // for UTXOs it controls.
        //
        // WITHDRAWAL OBLIGATION (Phase 8, Task 2, SOLVENCY-CRITICAL): a
        // withdrawal output's `amount + max_fee` is burned from the user's
        // e-cash the moment `process_output` accepts it -- i.e. the
        // mintv2-USDT-instance liability drops by that much IMMEDIATELY,
        // long before the pool actually pays it out. `PoolState.balance`
        // above, however, is only debited once the withdrawal's batch
        // `UserOp` confirms (`Usdt::apply_withdraw_confirmed`). Without a
        // correction, `audit` would therefore transiently OVER-report net
        // assets by exactly `amount` for every `Queued`/`Signing`/
        // `Submitted` withdrawal (a temporary surplus, so still solvent --
        // never a deficit -- but not the TIGHT/accurate figure). Subtracting
        // every `UnclaimedWithdrawal.amount` below closes that gap exactly:
        // `UnclaimedWithdrawalKey` records exist for precisely the
        // `Queued`/`Signing`/`Submitted` set (removed the instant a
        // withdrawal reaches `Confirmed`, see `apply_withdraw_confirmed`),
        // so this subtraction is in effect for exactly as long as the
        // corresponding `amount` remains counted in `PoolState.balance`
        // above but no longer in the liability side -- keeping `audit`'s
        // net figure CONSTANT (not just non-negative) across the entire
        // queue -> batch -> confirm lifecycle. `max_fee` is deliberately
        // NOT subtracted here: it was never earmarked to leave the pool (the
        // recipient is only ever paid `amount`), so it correctly remains
        // counted as the federation's own accrued fee revenue. This mirrors
        // the wallet module's own peg-out accounting (`UnsignedTransaction`/
        // `PendingTransaction`'s `change`-only reporting): the outgoing
        // portion of a not-yet-broadcast/confirmed spend is excluded from
        // assets as soon as it is committed to, not only once it lands
        // on-chain.
        audit
            .add_items(dbtx, module_instance_id, &DepositRecordPrefix, |_k, v| {
                i64::try_from(v.credited.0.saturating_sub(v.swept.0)).unwrap_or(i64::MAX)
            })
            .await;
        audit
            .add_items(dbtx, module_instance_id, &PoolStatePrefix, |_k, v| {
                i64::try_from(v.balance.0).unwrap_or(i64::MAX)
            })
            .await;
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &UnclaimedWithdrawalPrefix,
                |_k, v| -i64::try_from(v.amount.0).unwrap_or(i64::MAX),
            )
            .await;
        // WITHDRAWAL REFUND OBLIGATION (security finding 09, SOLVENCY-CRITICAL):
        // a terminally-failed withdrawal's `UnclaimedWithdrawal` is replaced by
        // a `Refund` (see `create_withdrawal_refund`), an unclaimed liability
        // for the reissued e-cash the original withdrawer can still claim. It
        // must be subtracted for the same reason the `UnclaimedWithdrawal`
        // above is: the pool still backs the amount, but the federation now
        // owes it back as e-cash rather than an on-chain payout. The two are
        // mutually exclusive per `out_point` (the swap is atomic), so at most
        // one is ever subtracted for a given withdrawal at a time -- and the
        // instant the `RefundV0` claim removes the `RefundKey` (minting the
        // e-cash via the mint module), this subtraction stops, keeping net
        // assets consistent across the full withdraw -> fail -> refund -> claim
        // lifecycle.
        audit
            .add_items(dbtx, module_instance_id, &RefundPrefix, |_k, v| {
                -i64::try_from(v.amount.0).unwrap_or(i64::MAX)
            })
            .await;
    }

    #[allow(clippy::too_many_lines)]
    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            api_endpoint! {
                GROUP_PUBLIC_KEY_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, _context, _params: ()| -> secp256k1::PublicKey {
                    Ok(module.cfg.consensus.group_public_key)
                }
            },
            api_endpoint! {
                DEPOSIT_STATUS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, context, req: DepositStatusRequest| -> DepositStatusResponse {
                    // Read-only: mirrors lnv2's
                    // `DECRYPTION_KEY_SHARE_ENDPOINT`.
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    Ok(module
                        .handle_deposit_status(&mut dbtx.to_ref_nc(), req.claim_pk)
                        .await)
                }
            },
            api_endpoint! {
                POOL_STATE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, context, _params: ()| -> PoolStateResponse {
                    // Read-only diagnostic (Phase 7, Task 5): reads
                    // consensus DB, so any guardian answers identically.
                    // `PoolState` may not exist yet (no sweep has confirmed
                    // yet), in which case report the deterministically
                    // derived pool address with a zero balance, mirroring
                    // `deposit_status`'s pre-credit-zeros shape.
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    let pool = dbtx.get_value(&PoolStateKey).await.unwrap_or(PoolState {
                        account: module.pool_account(),
                        balance: UsdtAmount(0),
                        nonce: 0,
                    });

                    Ok(PoolStateResponse {
                        account: pool.account,
                        balance: pool.balance,
                    })
                }
            },
            api_endpoint! {
                USEROP_STATUS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Usdt, context, req: UserOpStatusRequest| -> UserOpStatusResponse {
                    // Read-only diagnostic (Phase 7, Task 5): reads
                    // consensus DB, so any guardian answers identically.
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    let status = if dbtx
                        .get_value(&PendingUserOpKey(req.op_hash))
                        .await
                        .is_some()
                    {
                        UserOpStatus::Pending
                    } else if dbtx
                        .get_value(&SubmittedUserOpKey(req.op_hash))
                        .await
                        .is_some()
                    {
                        UserOpStatus::Submitted
                    } else {
                        UserOpStatus::Unknown
                    };

                    Ok(UserOpStatusResponse { status })
                }
            },
            api_endpoint! {
                WITHDRAW_FEE_QUOTE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, context, _req: WithdrawFeeQuoteRequest| -> WithdrawFeeQuoteResponse {
                    // Read-only (Phase 8, Task 1): the quote is derived
                    // entirely from the consensus-agreed `FeeVote` median,
                    // so any guardian answers identically
                    // (threshold-agreement via `request_current_consensus`,
                    // mirroring `deposit_status`). See
                    // `Usdt::handle_withdraw_fee_quote` for the
                    // `available` semantics (misc #4).
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    Ok(module
                        .handle_withdraw_fee_quote(&mut dbtx.to_ref_nc())
                        .await)
                }
            },
            api_endpoint! {
                DEPOSIT_FEE_QUOTE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, context, _req: DepositFeeQuoteRequest| -> DepositFeeQuoteResponse {
                    // Read-only, mirrors `WITHDRAW_FEE_QUOTE_ENDPOINT`
                    // exactly: the quote is derived entirely from the
                    // consensus-agreed `FeeVote` median, so any guardian
                    // answers identically. See `Usdt::handle_deposit_fee_quote`
                    // for the `available` semantics (misc #4).
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    Ok(module
                        .handle_deposit_fee_quote(&mut dbtx.to_ref_nc())
                        .await)
                }
            },
            api_endpoint! {
                WITHDRAWAL_STATUS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, context, req: WithdrawalStatusRequest| -> WithdrawalStatusResponse {
                    // Read-only (Phase 8, Task 3): mirrors `deposit_status`/
                    // `withdraw_fee_quote` -- reads consensus DB, so any
                    // guardian answers identically (threshold-agreement via
                    // `request_current_consensus`).
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    Ok(module
                        .handle_withdrawal_status(&mut dbtx.to_ref_nc(), req.out_point)
                        .await)
                }
            },
            api_endpoint! {
                REFUND_STATUS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, context, req: RefundStatusRequest| -> RefundStatusResponse {
                    // Read-only (security finding 09): mirrors
                    // `withdrawal_status` -- reads consensus DB, so any
                    // guardian answers identically (threshold-agreement via
                    // `request_current_consensus`).
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    Ok(module
                        .handle_refund_status(&mut dbtx.to_ref_nc(), req.out_point)
                        .await)
                }
            },
            api_endpoint! {
                USDT_STATUS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, context, _params: ()| -> StatusResponse {
                    // Read-only (Part C): the readiness state + per-condition
                    // tally are derived entirely from the threshold-aggregated
                    // `BootstrapObservation` votes (and the readiness latch) in
                    // consensus DB, so any guardian answers identically
                    // (threshold-agreement via `request_current_consensus`,
                    // mirroring `pool_state`/`withdraw_fee_quote`).
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    Ok(module.handle_status(&mut dbtx.to_ref_nc()).await)
                }
            },
        ]
    }
}

/// Advisory (non-enforced) number of further guardian-observed EVM blocks a
/// `withdraw_fee_quote`/`deposit_fee_quote` response should be treated as
/// valid for before re-querying, since the fee-vote-median-derived quote can
/// move as guardians' individual `FeeVote`s change. Not read by any
/// consensus decision -- `process_output`/`process_input` always re-derive
/// the quote fresh from the median at the point they process the item,
/// regardless of how stale a client's cached quote is.
const FEE_QUOTE_VALID_BLOCKS: u64 = 50;

/// Maximum age (in consensus blocks) a stored [`StoredFeeVote`] may have and
/// still count toward [`fee_vote_median`]'s quorum (security finding 06's
/// freshness facet). A vote older than this is excluded from the median as
/// if its guardian had never voted -- closing the "stale honest vote from a
/// now-broken fee source stays authoritative forever" gap, and (combined with
/// [`FEE_VOTE_REFRESH_BLOCKS`]) making a permanently-down guardian's poller
/// age its vote out of the quorum entirely rather than pin a wrong value.
const FEE_VOTE_TTL_BLOCKS: u64 = 50;

/// Re-proposal cadence for a guardian's own [`StoredFeeVote`] (security
/// finding 06's freshness facet), strictly less than [`FEE_VOTE_TTL_BLOCKS`]
/// so a healthy guardian whose polled value hasn't changed still refreshes
/// its `recorded_block` comfortably before the TTL would otherwise age it
/// out. `consensus_proposal` re-proposes this guardian's current fee
/// estimate once its stored vote's `recorded_block` falls this far behind
/// `consensus_block_count`, even when the polled value itself is unchanged --
/// mirroring `BlockCountVote`'s "propose again every round while behind"
/// cadence, but gated on age (the fee market, unlike block count, does not
/// move monotonically) rather than on inequality.
const FEE_VOTE_REFRESH_BLOCKS: u64 = 20;

/// Extra age (in consensus blocks, ON TOP of `confirmation_depth`) a stored
/// [`DepositObservation`] vote may have and still be accepted / counted
/// toward a threshold credit (security finding 12). A vote is FRESH only while
/// `consensus_block_count - obs.block <= confirmation_depth +
/// DEPOSIT_VOTE_MAX_AGE_BLOCKS`; older votes are rejected at store time and
/// opportunistically expired from the vote table when a later `Deposit` item
/// for the same account is processed. This closes the "a very old pre-reorg
/// vote completes a threshold much later, after a deep reorg removed the
/// deposit" gap: even a Byzantine or delayed-honest duplicate of a stale
/// observation can no longer credit funds once the observation has aged out of
/// this window. Computed purely from `consensus_block_count(dbtx)` (never
/// wall-clock), so every guardian agrees.
const DEPOSIT_VOTE_MAX_AGE_BLOCKS: u64 = 100;

/// A fixed, compiled-in `secp256k1` public key -- the point for secret scalar
/// `1` (the curve generator `G`) -- used by [`Usdt::observe_bootstrap`] as a
/// deterministic sample claim key (sec-16 readiness deepening, finding 16).
///
/// `observe_bootstrap`'s factory readiness check previously sampled only
/// [`pool_salt`], a single fixed, claim-key-independent salt; a malicious or
/// mistaken factory could special-case that one salt in `getAddress` while
/// mis-deploying every real (claim-key-derived) deposit account. Checking
/// `factory.getAddress(owner, deposit_salt(sample_claim_pk()))` against the
/// off-chain [`derive_deposit_account`] closes that bypass by exercising the
/// exact same claim-key-derived salt path a real deposit address uses.
///
/// A pure function of a compiled-in constant -- every guardian computes the
/// byte-identical key, so their `BootstrapObservation`s can agree. This is
/// NOT a real claim key: no deposit is ever expected at its derived address,
/// it exists purely as a readiness probe. Cached in a [`std::sync::LazyLock`]
/// since [`Usdt::spawn_bootstrap_observer`] recomputes it every poll tick.
#[must_use]
pub fn sample_claim_pk() -> secp256k1::PublicKey {
    static SAMPLE_CLAIM_PK: std::sync::LazyLock<secp256k1::PublicKey> =
        std::sync::LazyLock::new(|| {
            secp256k1::SecretKey::from_slice(&{
                let mut scalar = [0u8; 32];
                scalar[31] = 1;
                scalar
            })
            .expect("scalar 1 is a valid secp256k1 secret key")
            .public_key(secp256k1::SECP256K1)
        });
    *SAMPLE_CLAIM_PK
}

impl Usdt {
    /// Create new module instance, spawning the background block-count
    /// poller task (see [`Usdt::spawn_block_count_poller`]) and the other
    /// guardian-local observer/submitter tasks (see e.g.
    /// [`Usdt::spawn_user_op_submitter`]).
    pub fn new(
        cfg: UsdtConfig,
        evm_rpc: DynServerEvmRpc,
        db: Database,
        task_group: TaskGroup,
        our_peer_id: PeerId,
        num_peers: NumPeers,
    ) -> Usdt {
        let block_count = Arc::new(AtomicU64::new(0));
        Self::spawn_block_count_poller(&task_group, evm_rpc.clone(), block_count.clone());

        let user_op_confirmed_proposals = Arc::new(Mutex::new(Vec::new()));
        Self::spawn_user_op_submitter(
            &task_group,
            UserOpSubmitterHandles {
                db: db.clone(),
                evm_rpc: evm_rpc.clone(),
                user_op_confirmed_proposals: user_op_confirmed_proposals.clone(),
                confirmation_depth: cfg.consensus.confirmation_depth,
                num_peers,
            },
        );

        let fee_estimate = Arc::new(Mutex::new(None));
        Self::spawn_fee_estimate_poller(&task_group, evm_rpc.clone(), fee_estimate.clone());

        let bootstrap_proposals = Arc::new(Mutex::new(Vec::new()));
        Self::spawn_bootstrap_observer(
            &task_group,
            BootstrapObserverHandles {
                evm_rpc: evm_rpc.clone(),
                bootstrap_proposals: bootstrap_proposals.clone(),
                group_public_key: cfg.consensus.group_public_key,
                entry_point: cfg.consensus.entry_point,
                account_factory: cfg.consensus.account_factory,
                simple_account_impl: cfg.consensus.simple_account_impl,
                broadcaster_min_balance_wei: cfg.consensus.broadcaster_min_balance_wei,
            },
        );

        let block_hash_proposals = Arc::new(Mutex::new(None));
        Self::spawn_block_hash_observer(
            &task_group,
            BlockHashObserverHandles {
                db: db.clone(),
                evm_rpc: evm_rpc.clone(),
                block_count: block_count.clone(),
                confirmation_depth: cfg.consensus.confirmation_depth,
                num_peers,
                block_hash_proposals: block_hash_proposals.clone(),
            },
        );

        Usdt {
            cfg,
            evm_rpc,
            db,
            our_peer_id,
            num_peers,
            block_count,
            task_group,
            signing_sessions: Arc::new(Mutex::new(BTreeMap::new())),
            completed_signatures: Arc::new(Mutex::new(BTreeMap::new())),
            pending_signature_proposals: Arc::new(Mutex::new(Vec::new())),
            user_op_confirmed_proposals,
            fee_estimate,
            bootstrap_proposals,
            block_hash_proposals,
        }
    }

    /// Test-only constructor: builds the module without spawning the
    /// background poller task, using a fresh, unstarted [`TaskGroup`]. Tests
    /// set `block_count` directly instead of relying on the poller.
    #[cfg(test)]
    pub fn new_for_test(
        cfg: UsdtConfig,
        evm_rpc: DynServerEvmRpc,
        db: Database,
        our_peer_id: PeerId,
        num_peers: NumPeers,
    ) -> Usdt {
        Usdt {
            cfg,
            evm_rpc,
            db,
            our_peer_id,
            num_peers,
            block_count: Arc::new(AtomicU64::new(0)),
            task_group: TaskGroup::new(),
            signing_sessions: Arc::new(Mutex::new(BTreeMap::new())),
            completed_signatures: Arc::new(Mutex::new(BTreeMap::new())),
            pending_signature_proposals: Arc::new(Mutex::new(Vec::new())),
            user_op_confirmed_proposals: Arc::new(Mutex::new(Vec::new())),
            fee_estimate: Arc::new(Mutex::new(None)),
            // The bootstrap-observer poller is NOT spawned in tests (mirroring
            // the other pollers, skipped by `new_for_test`); tests drive
            // readiness by feeding `BootstrapObservation` items through
            // `process_consensus_item` directly.
            bootstrap_proposals: Arc::new(Mutex::new(Vec::new())),
            // The block-hash observer poller is NOT spawned in tests (mirroring
            // the other pollers); tests drive the ring by feeding
            // `BlockHash` items through `process_consensus_item` directly.
            block_hash_proposals: Arc::new(Mutex::new(None)),
        }
    }

    /// Returns this guardian's stored [`Database`], for test scaffolding
    /// that needs to open transactions against the same database the module
    /// was constructed with. Returns a reference (rather than a clone) so
    /// the resulting `DatabaseTransaction` can borrow through it.
    #[cfg(test)]
    pub fn db_for_test(&self) -> &Database {
        &self.db
    }

    /// Spawns a background task that polls `evm_rpc.get_block_number()` into
    /// `block_count` on a fixed interval, so `consensus_proposal` can read a
    /// cheap, cached view of the EVM chain head instead of making a
    /// synchronous RPC call on every consensus round.
    fn spawn_block_count_poller(
        task_group: &TaskGroup,
        evm_rpc: DynServerEvmRpc,
        block_count: Arc<AtomicU64>,
    ) {
        task_group.spawn_cancellable("usdt-block-count-poller", async move {
            loop {
                match rpc_deadline(evm_rpc.get_block_number()).await {
                    Ok(n) => {
                        block_count.store(n, Ordering::Relaxed);
                    }
                    Err(err) => {
                        warn!(
                            target: "usdt",
                            err = %err.fmt_compact_anyhow(),
                            "block count poll failed"
                        );
                    }
                }

                fedimint_core::runtime::sleep(Duration::from_secs(poll_interval_secs())).await;
            }
        });
    }

    /// Spawns a background task that polls `evm_rpc.get_fee_estimate()` into
    /// `fee_estimate` on a fixed interval (Phase 8, Task 1), mirroring
    /// [`Usdt::spawn_block_count_poller`] exactly: `consensus_proposal`
    /// reads a cheap, cached view of this guardian's current fee-market
    /// observation instead of making a synchronous RPC call on every
    /// consensus round. The cached value is this guardian's own
    /// guardian-LOCAL observation, never itself a consensus decision -- it
    /// only becomes one once proposed as a `UsdtConsensusItem::FeeVote` and
    /// aggregated (by median, over every peer's vote) into the federation's
    /// actual fee quote (see [`Usdt::fee_vote_median`]).
    fn spawn_fee_estimate_poller(
        task_group: &TaskGroup,
        evm_rpc: DynServerEvmRpc,
        fee_estimate: Arc<Mutex<Option<FeeVote>>>,
    ) {
        task_group.spawn_cancellable("usdt-fee-estimate-poller", async move {
            loop {
                match rpc_deadline(evm_rpc.get_fee_estimate()).await {
                    Ok(vote) => {
                        *fee_estimate.lock().expect("not poisoned") = Some(vote);
                    }
                    Err(err) => {
                        // Security finding 06's freshness facet: clear the
                        // cached reading (rather than keeping the last
                        // successful one) so `consensus_proposal` stops
                        // re-proposing/refreshing this guardian's `FeeVote`
                        // while its fee source is unreachable. Its
                        // last-stored vote then ages past
                        // `FEE_VOTE_TTL_BLOCKS` on its own and drops out of
                        // `fee_vote_median`'s quorum, instead of pinning a
                        // possibly-wrong value forever.
                        warn!(
                            target: "usdt",
                            err = %err.fmt_compact_anyhow(),
                            "fee estimate poll failed; abstaining until the next successful poll"
                        );
                        *fee_estimate.lock().expect("not poisoned") = None;
                    }
                }

                // Slow cadence: the Chainlink ETH/USD feed has a multi-minute
                // heartbeat and the refresh stays well within
                // `FEE_VOTE_TTL_BLOCKS`, so polling it every base tick is pure
                // waste. See `SLOW_POLL_MULTIPLIER`.
                fedimint_core::runtime::sleep(Duration::from_secs(slow_poll_interval_secs())).await;
            }
        });
    }

    /// Spawns the Part C bootstrap-observer: a background task that
    /// periodically computes this guardian's [`BootstrapObservation`] (the
    /// five readiness booleans) from read-only EVM RPC + config and pushes it
    /// into `bootstrap_proposals`, for `consensus_proposal` to drain into
    /// `UsdtConsensusItem::BootstrapObservation` proposals. Mirrors
    /// [`Usdt::spawn_fee_estimate_poller`]'s cadence/style exactly.
    ///
    /// A PURE READER: it makes only read-only RPC calls and reads no
    /// consensus DB. Its output influences consensus solely via the proposals
    /// it queues, which are threshold-aggregated by
    /// [`Usdt::bootstrap_state`] -- exactly the deposit-checker /
    /// fee-estimate pattern.
    ///
    /// Every RPC error fails the whole observation to the all-`false`
    /// (unhealthy) value, so a guardian whose node is unreachable votes
    /// itself out of the readiness quorum rather than silently reporting
    /// stale readiness.
    fn spawn_bootstrap_observer(task_group: &TaskGroup, handles: BootstrapObserverHandles) {
        let BootstrapObserverHandles {
            evm_rpc,
            bootstrap_proposals,
            group_public_key,
            entry_point,
            account_factory,
            simple_account_impl,
            broadcaster_min_balance_wei,
        } = handles;

        task_group.spawn_cancellable("usdt-bootstrap-observer", async move {
            // Latched once an observation reports all three immutable contract
            // booleans true. Immutable facts (contract code + CREATE2
            // derivations) never revert, so once verified this guardian stops
            // re-reading them (see `observe_bootstrap`) and stops running the
            // now-pointless self-deploy tick, and drops to the slow cadence.
            let mut contracts_verified = false;
            loop {
                // Part A deploy tick (guardian-local side effect, writes NO
                // consensus): self-deploy the SimpleAccountFactory if it is not
                // yet on-chain and this guardian's broadcaster is funded. Runs
                // before observing so a just-deployed factory can be voted ready
                // on the same tick. Best-effort: any error is logged and the
                // observation still proceeds (a wrong/absent factory simply
                // keeps the federation not-`Ready` via Part C's gate). Skipped
                // entirely once the factory is verified present -- it can only
                // be deployed once.
                if !contracts_verified
                    && let Err(err) = Self::ensure_factory_deployed(
                        evm_rpc.as_ref(),
                        entry_point,
                        account_factory,
                        broadcaster_min_balance_wei,
                    )
                    .await
                {
                    warn!(
                        target: "usdt",
                        err = %err.fmt_compact_anyhow(),
                        "factory self-deploy tick failed; will retry next tick"
                    );
                }

                let observation = Self::observe_bootstrap(
                    evm_rpc.as_ref(),
                    &group_public_key,
                    entry_point,
                    account_factory,
                    simple_account_impl,
                    broadcaster_min_balance_wei,
                    contracts_verified,
                )
                .await;

                // Latch once all immutable contract facts are confirmed. This
                // read is before the move-into-`push` below.
                let all_contracts_ok =
                    observation.entry_point_ok && observation.factory_ok && observation.impl_ok;

                bootstrap_proposals
                    .lock()
                    .expect("not poisoned")
                    .push(observation);

                if all_contracts_ok {
                    contracts_verified = true;
                }

                // Once verified, only the slowly-changing broadcaster balance
                // is re-read, so drop to the slow cadence; until then poll at
                // the base interval for fast startup convergence.
                let interval = if contracts_verified {
                    slow_poll_interval_secs()
                } else {
                    poll_interval_secs()
                };
                fedimint_core::runtime::sleep(Duration::from_secs(interval)).await;
            }
        });
    }

    /// Computes this guardian's [`BootstrapObservation`] from read-only EVM
    /// RPC + config (the body of [`Usdt::spawn_bootstrap_observer`]'s loop,
    /// extracted so it is independently testable). Guardian-local: no
    /// consensus DB, no `our_peer_id`, no wall-clock.
    ///
    /// If ANY RPC read errors, returns the all-`false` observation
    /// (`rpc_healthy = false`, and every other field best-effort `false`):
    /// an unhealthy node must not report readiness.
    async fn observe_bootstrap(
        evm_rpc: &dyn crate::rpc::IServerEvmRpc,
        group_public_key: &secp256k1::PublicKey,
        entry_point: fedimint_usdt_common::EvmAddress,
        account_factory: fedimint_usdt_common::EvmAddress,
        simple_account_impl: fedimint_usdt_common::EvmAddress,
        broadcaster_min_balance_wei: u64,
        contracts_verified: bool,
    ) -> BootstrapObservation {
        let observe = || async {
            // Broadcaster funding is re-read every tick (the operator tops the
            // gas wallet up out-of-band, so it genuinely changes) and doubles
            // as this loop's liveness probe: if the RPC endpoint is
            // unreachable this errors and the whole observation fails to the
            // all-`false` unhealthy value below.
            let broadcaster_funded = rpc_deadline(evm_rpc.broadcaster_eth_balance())
                .await?
                .is_some_and(|balance| balance >= u128::from(broadcaster_min_balance_wei));

            // Once the immutable contract facts below have all been verified
            // (`contracts_verified`), they can never change --
            // entry_point/factory/impl are immutable contracts and the CREATE2
            // derivations are deterministic -- so skip re-reading them every
            // tick. This eliminates ~6 RPC calls per tick per guardian (3x
            // `get_code`, 2x `factory_get_address`, 1x `accountImplementation`),
            // the dominant idle RPC load. The caller latches this flag once an
            // observation reports all three contract booleans true.
            if contracts_verified {
                return Ok(BootstrapObservation {
                    entry_point_ok: true,
                    factory_ok: true,
                    impl_ok: true,
                    broadcaster_funded,
                    rpc_healthy: true,
                });
            }

            let entry_point_ok = rpc_deadline(evm_rpc.get_code_len(entry_point)).await? > 0;

            // Factory readiness (the footgun-killer): the factory must have
            // code AND its on-chain `getAddress(owner, pool_salt)` must equal
            // this build's off-chain `derive_pool_account` -- proving the
            // deployed factory's immutable `accountImplementation` + baked
            // `ERC1967Proxy` initCode match this build's vendored proxy code,
            // so every derived deposit/pool address is spendable. The pool
            // account (a fixed, claim-key-independent address) is used as the
            // representative counterfactual since it shares the exact CREATE2
            // construction with every deposit account.
            let factory_has_code = rpc_deadline(evm_rpc.get_code_len(account_factory)).await? > 0;
            let owner = evm_address(group_public_key);
            let expected_pool =
                derive_pool_account(group_public_key, account_factory, simple_account_impl);
            let onchain_pool =
                rpc_deadline(evm_rpc.factory_get_address(account_factory, owner, pool_salt()))
                    .await?;
            let pool_salt_ok = onchain_pool == expected_pool;

            // sec-16 readiness deepening (finding 16): `pool_salt` alone is a
            // single fixed, claim-key-independent salt, so a special-cased
            // factory could pass the check above while mis-deploying every
            // real (claim-key-derived) deposit account. Additionally sample
            // one deterministic claim-key-derived salt
            // (`sample_claim_pk`/`deposit_salt`) and require the SAME
            // equivalence against the off-chain `derive_deposit_account`
            // this build's clients actually use to compute deposit
            // addresses.
            let sample_claim_pk = sample_claim_pk();
            let expected_sample_deposit = derive_deposit_account(
                group_public_key,
                account_factory,
                simple_account_impl,
                &sample_claim_pk,
            );
            let onchain_sample_deposit = rpc_deadline(evm_rpc.factory_get_address(
                account_factory,
                owner,
                deposit_salt(&sample_claim_pk),
            ))
            .await?;
            let deposit_salt_ok = onchain_sample_deposit == expected_sample_deposit;

            // sec-16 readiness deepening: independently confirm the factory's
            // own immutable `accountImplementation()` matches the module's
            // configured `simple_account_impl`, rather than relying solely on
            // the CREATE2-address equivalences above to imply it -- a factory
            // could conceivably special-case `getAddress` for exactly the
            // salts readiness samples while proxying real `createAccount`
            // calls to a different implementation.
            let onchain_impl =
                rpc_deadline(evm_rpc.factory_account_implementation(account_factory)).await?;
            let impl_matches_factory = onchain_impl == simple_account_impl;

            let factory_ok =
                factory_has_code && pool_salt_ok && deposit_salt_ok && impl_matches_factory;

            let impl_ok = rpc_deadline(evm_rpc.get_code_len(simple_account_impl)).await? > 0;

            Ok::<BootstrapObservation, anyhow::Error>(BootstrapObservation {
                entry_point_ok,
                factory_ok,
                impl_ok,
                broadcaster_funded,
                rpc_healthy: true,
            })
        };

        match observe().await {
            Ok(observation) => observation,
            Err(err) => {
                warn!(
                    target: "usdt",
                    err = %err.fmt_compact_anyhow(),
                    "bootstrap readiness poll failed; reporting unhealthy"
                );
                BootstrapObservation {
                    entry_point_ok: false,
                    factory_ok: false,
                    impl_ok: false,
                    broadcaster_funded: false,
                    rpc_healthy: false,
                }
            }
        }
    }

    /// Part A: self-deploys this module's `SimpleAccountFactory` on-chain if it
    /// is not already present and this guardian's broadcaster is funded. A
    /// guardian-local side effect that writes NO consensus item (exactly like
    /// the deposit-checker / `UserOp` submitter); the deployed factory becomes
    /// a federation fact only once guardians *observe* it and vote it ready
    /// (Part C). Idempotent and race-safe:
    ///
    /// 1. If `account_factory` already has code, do nothing (the common steady
    ///    state; kept off the hot path).
    /// 2. Else, only if this guardian's broadcaster holds at least the
    ///    configured minimum ETH: ensure the canonical Arachnid CREATE2
    ///    deployer exists (bootstrapping it on a bare devnet), then
    ///    CREATE2-deploy the factory from the vendored creation code. Two
    ///    guardians racing is harmless — the deterministic CREATE2 address
    ///    means the redundant deploy reverts (and its explicit-nonce
    ///    broadcaster tx cannot wedge later submissions).
    ///
    /// The factory address the deploy produces equals
    /// [`factory_bytecode::derive_account_factory`]`(entry_point)` ==
    /// `account_factory` (the config-gen'd value), so Part C's on-chain
    /// `getAddress`-equivalence check then verifies it and lets the federation
    /// reach `Ready`.
    async fn ensure_factory_deployed(
        evm_rpc: &dyn crate::rpc::IServerEvmRpc,
        entry_point: fedimint_usdt_common::EvmAddress,
        account_factory: fedimint_usdt_common::EvmAddress,
        broadcaster_min_balance_wei: u64,
    ) -> anyhow::Result<()> {
        // 1. Already deployed -> nothing to do.
        if rpc_deadline(evm_rpc.get_code_len(account_factory)).await? > 0 {
            return Ok(());
        }

        // 2. Only the guardians whose broadcaster is funded attempt the deploy
        //    (fronting its gas). `None` (no broadcaster) counts as not funded.
        let funded = rpc_deadline(evm_rpc.broadcaster_eth_balance())
            .await?
            .is_some_and(|balance| balance >= u128::from(broadcaster_min_balance_wei));
        if !funded {
            return Ok(());
        }

        rpc_deadline(evm_rpc.ensure_create2_deployer()).await?;
        rpc_deadline(evm_rpc.deploy_factory(entry_point)).await?;
        info!(
            target: "usdt",
            %account_factory,
            %entry_point,
            "self-deployed the module's SimpleAccountFactory on-chain"
        );

        Ok(())
    }

    /// Spawns the deposit-by-proof block-hash observer: a background task that
    /// periodically reads the canonical hash of the confirmation-depth block
    /// (`consensus_block_count - confirmation_depth`) via
    /// `evm_rpc.get_block_hash` and queues it into `block_hash_proposals`, for
    /// `consensus_proposal` to drain into a `UsdtConsensusItem::BlockHash`
    /// proposal.
    ///
    /// A PURE READER, mirroring [`Usdt::spawn_block_count_poller`]'s
    /// read-only discipline (COMMIT-SAFETY constraint -- the sec-13 lesson,
    /// see this module's removed `spawn_deposit_checker` for the background
    /// on why guardian-local tasks must never commit consensus DB state): it
    /// opens only a NON-committable `db.begin_transaction_nc()` to read
    /// `consensus_block_count`, makes one read-only RPC call, and writes
    /// NOTHING to the consensus DB. The observed hash becomes a ring entry
    /// solely in the ordered `process_consensus_item` path, and only once
    /// threshold-many guardians propose the identical `(height,
    /// block_hash)` pair (see the `UsdtConsensusItem::BlockHash` arm) --
    /// never on this task's own say-so.
    ///
    /// The height is derived from the CONSENSUS block count (not this
    /// guardian's raw chain tip), so every honest guardian targets the SAME
    /// height and their votes can aggregate; `block_count` (this guardian's
    /// polled tip) is consulted only to SKIP a height its own node has not yet
    /// imported (`at > cached_head`), retried next tick. An RPC error likewise
    /// just abstains this tick.
    fn spawn_block_hash_observer(task_group: &TaskGroup, handles: BlockHashObserverHandles) {
        let BlockHashObserverHandles {
            db,
            evm_rpc,
            block_count,
            confirmation_depth,
            num_peers,
            block_hash_proposals,
        } = handles;

        task_group.spawn_cancellable("usdt-block-hash-observer", async move {
            loop {
                let mut dbtx = db.begin_transaction_nc().await;
                let ccount = consensus_block_count(&mut dbtx.to_ref_nc(), num_peers).await;
                drop(dbtx);

                let at = ccount.saturating_sub(confirmation_depth);
                let cached_head = block_count.load(Ordering::Relaxed);

                // Abstain until consensus has observed the chain (`ccount != 0`)
                // and this guardian's own node has imported the
                // confirmation-depth block (`at <= cached_head`).
                if ccount != 0 && at <= cached_head {
                    match rpc_deadline(evm_rpc.get_block_hash(at)).await {
                        Ok(block_hash) => {
                            *block_hash_proposals.lock().expect("not poisoned") =
                                Some(BlockHashObservation {
                                    height: at,
                                    block_hash,
                                });
                        }
                        Err(err) => {
                            debug!(
                                target: "usdt",
                                err = %err.fmt_compact_anyhow(),
                                at_block = at,
                                "block-hash observation read failed, retrying next tick"
                            );
                        }
                    }
                }

                fedimint_core::runtime::sleep(Duration::from_secs(poll_interval_secs())).await;
            }
        });
    }

    /// Spawns a background task that submits every consensus-agreed
    /// [`SubmittedUserOp`] via `evm_rpc.submit_user_ops` and polls
    /// `evm_rpc.get_user_op_receipt` for its confirmation, gathering
    /// confirmed outcomes into `user_op_confirmed_proposals` for
    /// `consensus_proposal` to drain into `UsdtConsensusItem::UserOpConfirmed`
    /// proposals (Phase 7, Task 5).
    ///
    /// Mirrors [`Usdt::spawn_block_count_poller`]'s read-only discipline: reads
    /// the module DB via `db.begin_transaction_nc()` (non-committable) and
    /// NEVER commits a write to it -- submission is idempotent (the
    /// `EntryPoint` dedups by `(sender, nonce)`, so a redundant or
    /// multi-guardian submission of the same op is harmless) and purely
    /// guardian-local; the only consensus-DB write this task's output can
    /// ever cause is via the ordinary `UserOpConfirmed` consensus-item path
    /// (`Usdt::apply_user_op_confirmed`), gated on federation-wide
    /// threshold agreement, never on this task's own say-so. `swept` is
    /// derived from the already-consensus-agreed `op`'s own calldata --
    /// [`crate::user_op::decode_transfer_amount`] for a `DeployAndSweep` op,
    /// [`crate::user_op::decode_batch_transfer_total`] for a `Withdraw` op
    /// (Phase 8, Task 2) -- not from the RPC response; only `success`/
    /// `block` are guardian-local RPC reads. `swept` is otherwise a pure
    /// function of consensus data, so every guardian proposing for the same
    /// `op_hash` proposes an identical `swept` value once they agree on
    /// `success`.
    ///
    /// Security finding 19: processed with bounded concurrency (see the
    /// function body) rather than a serial loop, so one hung/slow op's RPC
    /// calls cannot starve the others; this constant caps how many ops are
    /// in flight against `evm_rpc` at once.
    #[allow(clippy::too_many_lines)]
    fn spawn_user_op_submitter(task_group: &TaskGroup, handles: UserOpSubmitterHandles) {
        let UserOpSubmitterHandles {
            db,
            evm_rpc,
            user_op_confirmed_proposals,
            confirmation_depth,
            num_peers,
        } = handles;

        task_group.spawn_cancellable("usdt-user-op-submitter", async move {
            loop {
                let mut dbtx = db.begin_transaction_nc().await;
                let submitted: Vec<(SubmittedUserOpKey, SubmittedUserOp)> = dbtx
                    .find_by_prefix(&SubmittedUserOpPrefix)
                    .await
                    .collect()
                    .await;
                // Security finding 04: the consensus block count as this
                // guardian sees it, for the confirmation-depth gate below. Read
                // once per tick (it is identical for every op in the batch).
                let ccount = consensus_block_count(&mut dbtx, num_peers).await;
                drop(dbtx);

                // Security finding 19: bounded concurrency (not a serial
                // `for` loop) so a stalled/slow `submit_user_ops` or
                // `get_user_op_receipt` for ONE op cannot starve
                // submission/receipt-polling of every other submitted op --
                // each op's own two RPC awaits are additionally bounded by
                // `rpc_deadline`, so a truly hung provider surfaces as an
                // `Err` (the existing "retry next tick" branch) instead of
                // wedging that op's task forever. `USER_OP_SUBMIT_CONCURRENCY`
                // caps how many ops are in flight at once, bounding this
                // guardian's simultaneous outbound RPC load.
                let evm_rpc = &evm_rpc;
                let user_op_confirmed_proposals = &user_op_confirmed_proposals;
                futures::stream::iter(submitted)
                    .for_each_concurrent(
                        USER_OP_SUBMIT_CONCURRENCY,
                        move |(SubmittedUserOpKey(op_hash), record)| async move {
                            // Idempotent, guardian-local: errors (including
                            // "already included") are swallowed and simply
                            // retried next tick.
                            if let Err(err) =
                                rpc_deadline(evm_rpc.submit_user_ops(vec![record.signed.clone()]))
                                    .await
                            {
                                debug!(
                                    target: "usdt",
                                    err = %err.fmt_compact_anyhow(),
                                    ?op_hash,
                                    "UserOp submission failed, retrying next tick"
                                );
                            }

                            match rpc_deadline(evm_rpc.get_user_op_receipt(op_hash)).await {
                                Ok(Some(receipt)) => {
                                    // Security finding 04: CONFIRMATION-DEPTH
                                    // gate. Do not propose a threshold
                                    // confirmation until the receipt's block is
                                    // `confirmation_depth` consensus blocks deep
                                    // (mirrors the deposit scanner's own depth
                                    // gate), so a reorg shallower than the depth
                                    // cannot make the federation apply an
                                    // irreversible sweep/withdrawal settlement
                                    // against a block that later disappears. The
                                    // op stays `SubmittedUserOp`, so this is
                                    // simply re-polled next tick until it is
                                    // deep enough.
                                    if receipt.block.saturating_add(confirmation_depth) > ccount {
                                        debug!(
                                            target: "usdt",
                                            ?op_hash,
                                            receipt_block = receipt.block,
                                            ccount,
                                            confirmation_depth,
                                            "UserOp receipt not yet confirmation-deep, deferring \
                                             confirmation proposal"
                                        );
                                        return;
                                    }
                                    // `swept` doubles as "amount moved by
                                    // this op": swept-TO-the-pool for
                                    // `DeployAndSweep`, paid-OUT-of-the-pool
                                    // for `Withdraw` (Phase 8, Task 2) --
                                    // both decoded from the already
                                    // federation-agreed `op`'s own calldata,
                                    // never from the RPC response, per this
                                    // fn's own doc comment.
                                    //
                                    // Security finding 21 (Phase 9
                                    // hardening): fail CLOSED on a decode
                                    // error instead of the old
                                    // `.unwrap_or(UsdtAmount(0))` --
                                    // decoding the ALREADY-committed
                                    // calldata of a successful op can only
                                    // fail on an invariant violation (e.g. a
                                    // future/malformed op format this
                                    // guardian's decoder doesn't understand
                                    // yet), and proposing `swept = 0` for it
                                    // would let a real on-chain transfer
                                    // settle without ever moving the
                                    // corresponding pool accounting. Skip
                                    // proposing ANY confirmation for this op
                                    // this tick instead -- `return` simply
                                    // leaves `SubmittedUserOp` in place, so
                                    // this is retried (and re-logged) every
                                    // tick for as long as it stays live,
                                    // never silently dropped.
                                    let swept = if receipt.success {
                                        let decoded = match &record.purpose {
                                            UserOpPurpose::DeployAndSweep { .. } => {
                                                crate::user_op::decode_transfer_amount(
                                                    &record.signed.unsigned,
                                                )
                                            }
                                            UserOpPurpose::Withdraw { .. } => {
                                                crate::user_op::decode_batch_transfer_total(
                                                    &record.signed.unsigned,
                                                )
                                            }
                                        };
                                        match decoded {
                                            Ok(swept) => swept,
                                            Err(err) => {
                                                warn!(
                                                    target: "usdt",
                                                    ?op_hash,
                                                    err = %err.fmt_compact_anyhow(),
                                                    purpose = ?record.purpose,
                                                    "failed to decode swept amount from \
                                                     committed op calldata; not proposing a \
                                                     confirmation for this op"
                                                );
                                                return;
                                            }
                                        }
                                    } else {
                                        UsdtAmount(0)
                                    };
                                    debug!(
                                        target: "usdt",
                                        ?op_hash,
                                        success = receipt.success,
                                        block = receipt.block,
                                        swept = swept.0,
                                        purpose = ?record.purpose,
                                        "UserOp receipt observed on-chain, proposing threshold \
                                         confirmation"
                                    );
                                    user_op_confirmed_proposals
                                        .lock()
                                        .expect("not poisoned")
                                        .push(UserOpConfirmedProposal {
                                            op_hash,
                                            success: receipt.success,
                                            block: receipt.block,
                                            block_hash: receipt.block_hash,
                                            swept,
                                            // Security finding 09: carry the
                                            // authoritative `actualGasCost`
                                            // (wei) so a failed withdrawal
                                            // batch can deduct its on-chain
                                            // gas from the refund.
                                            actual_gas_cost_wei: receipt.actual_gas_cost_wei,
                                        });
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    debug!(
                                        target: "usdt",
                                        err = %err.fmt_compact_anyhow(),
                                        ?op_hash,
                                        "UserOp receipt poll failed, retrying next tick"
                                    );
                                }
                            }
                        },
                    )
                    .await;

                fedimint_core::runtime::sleep(Duration::from_secs(poll_interval_secs())).await;
            }
        });
    }

    /// Median (over all peers, unresponsive peers counted as `0`) of the
    /// most recent `BlockCount` votes, mirroring
    /// `Wallet::consensus_block_count` (but `u64`-valued since EVM block
    /// numbers do not fit the wallet's `u32` bitcoin block heights).
    ///
    /// Delegates to the free [`consensus_block_count`] function so any
    /// `'static`-spawned background task (which has no `Usdt` to call this
    /// method on) can compute the same value without duplicating the median
    /// logic.
    pub async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        consensus_block_count(dbtx, self.num_peers).await
    }

    /// The federation's current withdrawal fee quote: the per-field MEDIAN
    /// (over every peer's stored, FRESH [`StoredFeeVote`]) of
    /// `max_fee_per_gas_wei` and `usdt_per_eth_e6` independently, `None`
    /// unless at least `num_peers.threshold()` fresh votes are present
    /// (Phase 8, Task 1; security finding 06's quorum + freshness facets).
    ///
    /// Delegates to the free [`fee_vote_median`] function, mirroring
    /// [`Self::consensus_block_count`]'s delegation to the free
    /// [`consensus_block_count`] -- kept as a free function so any future
    /// `'static`-spawned background task could compute the same value
    /// without a `&Usdt` (today, nothing needs to; `process_output` and the
    /// `withdraw_fee_quote` endpoint both hold `&self`).
    ///
    /// # Quorum + freshness (security finding 06)
    ///
    /// Before this hardening, ANY non-empty vote set (even a single vote)
    /// was accepted as authoritative, and votes never expired -- letting one
    /// early Byzantine vote control the quote during bootstrap/partial-vote
    /// windows, and a stale honest vote from a broken fee source stay
    /// authoritative forever. Now, a vote only counts toward the median if
    /// it is FRESH (`consensus_block_count - recorded_block <=
    /// FEE_VOTE_TTL_BLOCKS`), and the median is `None` unless at least
    /// `num_peers.threshold()` such fresh votes exist -- both computed
    /// purely from consensus DB state (`consensus_block_count`), never
    /// wall-clock, so every guardian agrees.
    ///
    /// Deliberately does NOT zero-pad missing/stale votes out to `num_peers`
    /// the way [`consensus_block_count`] does: block count is monotonic (a
    /// missing/lagging peer's vote is always "behind", so padding with `0`
    /// is a safe, conservative default), but the EVM fee market moves in
    /// both directions, so padding an absent guardian's vote with `0` would
    /// let a Byzantine guardian bias the fee quote DOWN merely by
    /// withholding a vote (undercharging users, at the federation's
    /// expense) — the opposite of what padding protects against for block
    /// count. The median is instead taken over whatever FRESH votes are
    /// actually present, which — combined with `process_consensus_item`'s
    /// per-vote redundancy guard and the quorum requirement above — bounds
    /// any single Byzantine guardian's influence on the result to one vote
    /// out of at least `threshold()` votes.
    pub async fn fee_vote_median(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<FeeVote> {
        let current_block = self.consensus_block_count(dbtx).await;
        fee_vote_median(dbtx, self.num_peers, current_block).await
    }

    /// Tallies the per-field [`BootstrapObservation`] vote counts across every
    /// peer (Part C). A pure read over the consensus `BootstrapVote` table
    /// (order-independent counting, so the range-scan order is irrelevant),
    /// used by both [`Usdt::bootstrap_ready`] and the `usdt_status` endpoint.
    async fn bootstrap_counts(&self, dbtx: &mut DatabaseTransaction<'_>) -> BootstrapCounts {
        let votes: Vec<BootstrapObservation> = dbtx
            .find_by_prefix(&BootstrapVotePrefix)
            .await
            .map(|(_, v)| v)
            .collect()
            .await;

        let mut counts = BootstrapCounts::default();
        for vote in votes {
            counts.entry_point_ok += usize::from(vote.entry_point_ok);
            counts.factory_ok += usize::from(vote.factory_ok);
            counts.impl_ok += usize::from(vote.impl_ok);
            counts.funded += usize::from(vote.broadcaster_funded);
            counts.rpc_healthy += usize::from(vote.rpc_healthy);
        }
        counts
    }

    /// Whether the aggregate readiness tally currently meets every condition
    /// at threshold (Part C): each of the three federation facts
    /// (EntryPoint/factory/impl) and both self-fact quorums
    /// (broadcaster-funded / RPC-healthy) must be voted by at least
    /// `threshold` guardians. A pure function of the consensus `BootstrapVote`
    /// table and config -- byte-identical on every guardian. NB this is the
    /// raw "ready now" predicate (it does NOT consult the `HasEverBeenReady`
    /// latch), so it is exactly what `process_consensus_item` checks before
    /// setting that latch.
    async fn bootstrap_ready(&self, dbtx: &mut DatabaseTransaction<'_>) -> bool {
        let counts = self.bootstrap_counts(dbtx).await;
        let t = self.num_peers.threshold();
        counts.entry_point_ok >= t
            && counts.factory_ok >= t
            && counts.impl_ok >= t
            && counts.funded >= t
            && counts.rpc_healthy >= t
    }

    /// Derives the module's consensus-agreed [`BootstrapState`] (Part C):
    /// `Ready` if the tally meets every condition at threshold now; otherwise
    /// `Degraded` if the `HasEverBeenReady` latch is set (it was `Ready`
    /// before and has regressed); otherwise `AwaitingInfra`. A pure function
    /// of the consensus `BootstrapVote` table, the latch, and config -- so
    /// every guardian answers identically.
    async fn bootstrap_state(&self, dbtx: &mut DatabaseTransaction<'_>) -> BootstrapState {
        if self.bootstrap_ready(dbtx).await {
            return BootstrapState::Ready;
        }
        if dbtx.get_value(&HasEverBeenReadyKey).await.is_some() {
            BootstrapState::Degraded
        } else {
            BootstrapState::AwaitingInfra
        }
    }

    /// Assembles the `usdt_status` endpoint's [`StatusResponse`] from the
    /// consensus-agreed readiness tally + state + threshold (Part C). Read
    /// entirely from consensus DB, so any guardian answers identically.
    async fn handle_status(&self, dbtx: &mut DatabaseTransaction<'_>) -> StatusResponse {
        let counts = self.bootstrap_counts(dbtx).await;
        let state = self.bootstrap_state(dbtx).await;
        let t = self.num_peers.threshold();

        StatusResponse {
            state,
            entry_point_ok: counts.entry_point_ok >= t,
            factory_ok: counts.factory_ok >= t,
            impl_ok: counts.impl_ok >= t,
            funded_guardians: u16::try_from(counts.funded).unwrap_or(u16::MAX),
            healthy_guardians: u16::try_from(counts.rpc_healthy).unwrap_or(u16::MAX),
            threshold: u16::try_from(t).unwrap_or(u16::MAX),
        }
    }

    /// Whether `session` has gone `timeout_blocks()` consensus blocks
    /// without progress (session creation or its last `round` advance —
    /// see `last_progress_block`'s doc comment). Used by Task 3 to decide
    /// when a stalled session should be retried under a rotated signer
    /// subset instead of waited on forever. Only an `InProgress` session
    /// can time out: `Completed`/`Failed` are already terminal.
    ///
    /// # Determinism (consensus-critical)
    ///
    /// A pure function of `session` (consensus DB) and
    /// `consensus_block_count` (the Phase-5 median of `BlockCountVoteKey`
    /// votes, identical on every guardian) — byte-identical everywhere it is
    /// called from consensus code. Deliberately NOT wall-clock: per-guardian
    /// clock skew would let honest guardians disagree about whether a
    /// session had timed out, which would diverge any decision built on top
    /// of it.
    ///
    /// Drives the retry-on-timeout flow: `consensus_proposal` proposes a
    /// `RotateSigning` for every session this reports timed out, and the
    /// `RotateSigning` arm of `process_consensus_item` re-checks it as a
    /// deterministic gate before failing the attempt and starting the next.
    async fn timed_out(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        session: &SigningSession,
    ) -> bool {
        matches!(session.state, SessionState::InProgress)
            && self.consensus_block_count(dbtx).await
                > session.last_progress_block.saturating_add(timeout_blocks())
    }

    /// Credits (and mints, atomically with the transaction's paired mint
    /// output) a deposit from a verified [`DepositProof`], for the
    /// [`UsdtInput::DepositProofV0`] arm of [`Self::process_input`].
    ///
    /// The `account` whose balance is verified is DERIVED from `claim_pk`
    /// ([`derive_deposit_account`]) -- the exact same binding
    /// [`Self::credit_deposit`] enforces for the observation path -- so a
    /// proof of any account a submitter cannot also derive a `claim_pk` for
    /// (e.g. an exchange's hot wallet) verifies against a different storage
    /// key and yields a zero delta. Only the newly-proven delta over the
    /// account's existing high-water `credited` becomes spendable e-cash, and
    /// `claimed` is advanced by that same delta so the freshly-minted value
    /// can never be re-claimed a second time through the [`UsdtInput::V0`]
    /// path (whose over-claim guard reads `credited - claimed`). The high-water
    /// `credited` is advanced to the proven balance and the SAME
    /// [`Self::maybe_trigger_sweep`] bookkeeping the observation path fires is
    /// fired here, so the on-chain USDT is deploy-and-swept into the pool
    /// exactly as before.
    ///
    /// Unlike [`UsdtInput::V0`], no deposit fee is charged here: the input
    /// carries no `fee` field and its `delta` is minted in full (paired 1:1
    /// with the transaction's mint output). The deploy+sweep gas is fronted by
    /// the broadcaster EOA out of band, as it already is for the
    /// observation-driven path (see [`derive_deposit_account`]'s note on
    /// broadcaster funding never being reimbursed on-chain).
    ///
    /// # Determinism (consensus-critical)
    ///
    /// A pure function of `(claim_pk, proof, prior consensus DB state,
    /// config)`: `derive_deposit_account` and `verify_deposit_proof` are pure
    /// (keccak/RLP/trie-walk only -- no RPC, no wall-clock, no `our_peer_id`,
    /// no floats), and the only consensus reads are the block-hash ring anchor
    /// and this account's [`DepositRecord`]. Every guardian computes the
    /// identical `Ok`/`Err` and the identical `DepositRecordKey` write.
    async fn process_deposit_proof(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        claim_pk: &secp256k1::PublicKey,
        proof: &fedimint_usdt_common::DepositProof,
    ) -> Result<InputMeta, UsdtInputError> {
        // The account this proof must be for is derived from `claim_pk`; this
        // IS the claim binding (no separate check needed -- an unrelated
        // account's proof simply verifies against the wrong storage key).
        let account = derive_deposit_account(
            &self.cfg.consensus.group_public_key,
            self.cfg.consensus.account_factory,
            self.cfg.consensus.simple_account_impl,
            claim_pk,
        );

        // Anchor: `proof.block_number` must have an agreed canonical hash in
        // the federation's block-hash ring. `None` => not yet confirmed to
        // consensus, or aged out of the retained window => reject.
        let expected = ring_hash_at(dbtx, proof.block_number).await.ok_or(
            UsdtInputError::DepositProofNotAnchored {
                block: proof.block_number,
            },
        )?;

        // Deterministic MPT verification against the anchored hash. Returns
        // the PROVEN balance (proof-of-absence => 0); the size cap is enforced
        // inside. The reason string is a pure function of the (deterministic)
        // proof, so it is identical across guardians.
        let proven = crate::proof::verify_deposit_proof(
            proof,
            expected,
            &self.cfg.consensus.usdt_contract,
            &account,
        )
        .map_err(|e| UsdtInputError::DepositProofInvalid {
            reason: e.to_string(),
        })?;

        let mut record =
            dbtx.get_value(&DepositRecordKey(account))
                .await
                .unwrap_or(DepositRecord {
                    claim_pk: *claim_pk,
                    credited: UsdtAmount(0),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                });

        // High-water mark: only the delta over what is already credited is
        // new, spendable value. A resubmitted/stale proof (proven <= credited)
        // gives delta 0 and is rejected as a duplicate.
        let credited = record.credited;
        let delta = proven.0.saturating_sub(credited.0);
        if delta == 0 {
            return Err(UsdtInputError::DepositProofStale { proven, credited });
        }

        // Advance the monotonic high-water `credited` to the proven balance
        // AND advance `claimed` by the minted delta (`claimed <= credited`
        // stays invariant, keeping `audit` conservative and the `V0` over-claim
        // guard tight against re-minting this same value).
        record.credited = proven;
        record.claimed = UsdtAmount(record.claimed.0.saturating_add(delta));
        record.last_observed_block = proof.block_number;
        dbtx.insert_entry(&DepositRecordKey(account), &record).await;

        // Same deterministic sweep trigger the observation path fires on
        // credit: enqueue the deploy-and-sweep `UserOp` for this account.
        self.maybe_trigger_sweep(dbtx, account).await;

        info!(
            target: "usdt",
            account = %account,
            proven = proven.0,
            delta,
            block = proof.block_number,
            "deposit credited from verified proof; delta minted to depositor"
        );

        // The delta funds `USDT_UNIT` value into the transaction, which the
        // client pairs 1:1 with a mint output (deposit + claim atomic). No
        // fee: `fees` is `ZERO`.
        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_custom(USDT_UNIT, usdt_amount(UsdtAmount(delta))),
                fees: Amounts::ZERO,
            },
            pub_key: *claim_pk,
        })
    }

    /// Credits a deposit observation that has reached threshold agreement:
    /// creates the account's [`DepositRecord`] (using `obs.claim_pk`) if it
    /// does not exist yet, advances `credited` monotonically forward to
    /// `obs.balance` (balance is monotonic between sweeps since only the
    /// federation moves funds out), updates `last_observed_block`, and
    /// clears the round's votes.
    ///
    /// # No longer reachable via honest `consensus_proposal` (proof-driven
    /// crediting, sec-13)
    ///
    /// The guardian-local polling task that used to scan per-account
    /// guardian-poll records and propose `UsdtConsensusItem::Deposit` items
    /// for this to process has been removed entirely: it committed consensus DB
    /// state from an uncoordinated background task racing the ordered
    /// `process_consensus_item` path (and, separately, the other guardian
    /// pollers), which is exactly the `WriteConflict` crash security finding 13
    /// fixed. Deposits are now credited by the client submitting a verified
    /// [`fedimint_usdt_common::DepositProof`] as a
    /// [`fedimint_usdt_common::UsdtInput::DepositProofV0`] (see
    /// `Self::process_deposit_proof`), which performs the equivalent
    /// high-water/sweep bookkeeping inline inside the ordered transaction-
    /// processing path -- never from a spawned task.
    ///
    /// `UsdtConsensusItem::Deposit`/[`DepositObservation`] and this method are
    /// kept (rather than deleted) purely for consensus wire-format stability:
    /// this crate's `#[derive(Encodable, Decodable)]` assigns enum variant
    /// tags positionally (0-indexed among non-`#[encodable_default]`
    /// variants) when no variant carries an explicit
    /// `#[encodable(index = N)]`, as none do here -- deleting a variant from
    /// the middle of [`fedimint_usdt_common::UsdtConsensusItem`] would
    /// silently shift every later-declared variant's wire tag, corrupting
    /// decode of existing consensus history for `MpcRound`, `MpcSignature`,
    /// `RotateSigning`, `UserOpConfirmed`, `FeeVote`,
    /// `BootstrapObservation`, `ReplaceUserOp`, and `BlockHash` unless every
    /// one of them were re-pinned with an explicit index (a
    /// `MODULE_CONSENSUS_VERSION`-bump-scale change, out of scope here). No
    /// honest guardian proposes a `Deposit` item any more; this arm now only
    /// matters if a byzantine guardian replays one, in which case it must
    /// still behave exactly as before (self-authenticating, threshold-gated,
    /// deterministic) rather than silently misbehave.
    ///
    /// # Determinism (consensus-critical)
    ///
    /// `process_consensus_item` must be a pure function of `(ordered
    /// consensus items, prior consensus DB state)` — byte-identical on every
    /// honest guardian. The claim key therefore MUST come from `obs` itself,
    /// never from an existing [`DepositRecord`].
    ///
    /// `ensure!` below is a self-authentication check, not a local-state
    /// read: it is a pure function of `obs` and this module's consensus
    /// config (`group_public_key`), so every honest guardian computes the
    /// same result. It also prevents a byzantine guardian from proposing an
    /// observation whose `claim_pk` does not actually derive `account`
    /// (which would let it credit an attacker-chosen claim key for someone
    /// else's deposit account).
    async fn credit_deposit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        obs: &DepositObservation,
    ) -> anyhow::Result<()> {
        let claim_pk = obs.claim_pk;
        ensure!(
            fedimint_usdt_common::derive_deposit_account(
                &self.cfg.consensus.group_public_key,
                self.cfg.consensus.account_factory,
                self.cfg.consensus.simple_account_impl,
                &claim_pk
            ) == obs.account,
            "observation claim_pk does not derive its account"
        );

        let mut record = dbtx
            .get_value(&DepositRecordKey(obs.account))
            .await
            .unwrap_or(DepositRecord {
                claim_pk,
                credited: UsdtAmount(0),
                claimed: UsdtAmount(0),
                last_observed_block: 0,
                swept: UsdtAmount(0),
                nonce: 0,
            });
        // Only credit forward; balance is monotonic between sweeps.
        if obs.balance.0 > record.credited.0 {
            record.credited = obs.balance;
        }
        record.last_observed_block = obs.block;
        dbtx.insert_entry(&DepositRecordKey(obs.account), &record)
            .await;
        // Clear the round's votes.
        dbtx.remove_by_prefix(&DepositObservationVoteAccountPrefix(obs.account))
            .await;

        // Deterministic trigger (Phase 7, Task 5): every guardian, right
        // here, enqueues the deploy-and-sweep `UserOp` for this account and
        // starts its MPC signing session -- a pure function of the just-
        // written `DepositRecord` (consensus DB) and this module's config.
        // See `maybe_trigger_sweep`'s own doc comment for the full
        // determinism argument and the first-sweep-only scope of this phase.
        self.maybe_trigger_sweep(dbtx, obs.account).await;

        Ok(())
    }

    /// Deterministically enqueues the deploy-and-sweep [`PendingUserOp`] for
    /// `account` and starts its `SigningPurpose::UserOp` signing session, if
    /// `account`'s [`DepositRecord`] has an un-swept remainder
    /// (`credited - swept > 0`) that is not already being swept by an
    /// in-flight op. Called from [`Usdt::credit_deposit`] right after the
    /// credit write, and re-called from [`Usdt::apply_user_op_confirmed`]
    /// right after a successful sweep confirms, so it always observes the
    /// freshest `DepositRecord`.
    ///
    /// # Re-sweeping a reused deposit address (issue #6)
    ///
    /// A deposit address can receive more than one on-chain transfer, so
    /// `credited` may grow after an earlier, fixed-`amount` sweep already
    /// moved less than the current `credited`. Each call sweeps exactly the
    /// current `credited - swept` remainder at `record.nonce` -- the deposit
    /// account's live `SimpleAccount` nonce -- so the leftover is pooled
    /// rather than stranded on-chain. `needs_deploy` is `record.nonce == 0`
    /// (only the first, account-creating sweep carries `initCode`).
    ///
    /// # Determinism (consensus-critical)
    ///
    /// A pure function of `account`'s [`DepositRecord`] (consensus DB) and
    /// this module's config (`account_factory`/`usdt_contract`/
    /// `entry_point`/`chain_id`/`group_public_key`) --
    /// [`build_deploy_and_sweep_userop`] and [`user_op_hash`] take no
    /// RPC/wall-clock input, so every guardian builds the byte-identical
    /// `op`/`op_hash`. The only conditional consensus-DB writes are the
    /// `PendingUserOpKey`/`SigningSession` inserts, gated on a check of the
    /// SAME consensus DB (`PendingUserOpKey`/`SubmittedUserOpKey` presence
    /// for this exact `op_hash`) -- identical on every guardian.
    /// `start_session`'s only `our_peer_id`-conditional part is the
    /// in-memory off-thread signer spawn, a guardian-local side effect (see
    /// its own doc comment).
    ///
    /// # Per-account serialization (nonce-collision avoidance)
    ///
    /// At most one `DeployAndSweep` op for a given `account` may be in flight
    /// at a time: if a `Pending` or `Submitted` `DeployAndSweep` op already
    /// targets this `account`, this call returns without enqueuing a second.
    /// Two concurrent sweeps of the same account would both be built at the
    /// same on-chain `record.nonce` (which only advances on confirm) and the
    /// second would revert with an `EntryPoint` invalid-nonce error (AA25).
    /// Serializing them -- and re-triggering from
    /// [`Usdt::apply_user_op_confirmed`] once the in-flight one confirms and
    /// `record.nonce` has advanced -- lets `credited` grow safely mid-flight
    /// while every remainder is eventually swept at its own correct nonce.
    ///
    /// # Scope / known limitation
    ///
    /// The credit rule (`Usdt::credit_deposit`) is intentionally raw-balance
    /// (`balance > credited`), not `swept + balance`, to stay race-free
    /// against an observation straddling a sweep. A brand-new deposit paid to
    /// an address whose balance has already been fully swept back to `0`
    /// therefore stays a documented limitation (it would not raise `credited`
    /// above the already-swept total); this method only re-sweeps the
    /// `credited - swept` remainder that the credit rule does record.
    async fn maybe_trigger_sweep(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        account: fedimint_usdt_common::EvmAddress,
    ) {
        let Some(record) = dbtx.get_value(&DepositRecordKey(account)).await else {
            return;
        };
        // Sweep only the not-yet-pooled remainder. `saturating_sub` is belt-
        // and-suspenders: `swept` is always clamped to `credited` on write.
        let remainder = record.credited.0.saturating_sub(record.swept.0);
        if remainder == 0 {
            return;
        }

        // Per-account in-flight guard: never build a second `DeployAndSweep`
        // op for `account` while one is still `Pending` or `Submitted`. Both
        // would carry the same on-chain `record.nonce` (it only advances when
        // a sweep confirms), so the later one would revert with an
        // `EntryPoint` invalid-nonce error (AA25). The confirm path re-calls
        // this method once the in-flight op finalizes and `record.nonce` has
        // advanced, so a `credited` that grew mid-flight is still swept.
        if self.deploy_and_sweep_in_flight(dbtx, account).await {
            return;
        }

        // Price the op from the consensus live-gas median (not the 30 gwei
        // devnet default) so the broadcaster-fronted EntryPoint prefund stays
        // affordable on a real chain. Deterministic: the median is a consensus
        // value, so every guardian builds the identical op (its
        // `max_fee_per_gas` is part of the signed `userOpHash`).
        //
        // Security finding 02 (Task 4.3): without a fresh median (Task 4.2's
        // quorum/freshness gate) the deploy+sweep cost cannot be priced at
        // all, so the dust-economics gate below cannot be evaluated either --
        // defer the sweep entirely rather than falling back to some
        // unpriced/floor default. A later credit or the confirm-path
        // retrigger re-calls this method once a median exists.
        let Some(median) = self.fee_vote_median(dbtx).await else {
            debug!(
                target: "usdt",
                account = ?account,
                "no fee median; deferring sweep until it can be priced"
            );
            return;
        };

        // Maintainer decision (finding 02): never sweep a deposit account
        // unless the amount credited to the user, net of the deploy+sweep
        // gas fee it would cost the federation, is strictly positive. This
        // does NOT touch `credited` -- the solvency/audit invariant is
        // unchanged, sub-threshold dust simply sits on-chain unswept (and,
        // via `process_input`'s identical `amount <= deposit_fee` check,
        // unclaimable), costing the federation nothing. This is what stops
        // an attacker from forcing a deploy+sweep the federation pays gas
        // for by sending never-claimed dust to unlimited fresh deposit
        // accounts.
        let Some(sweep_fee) = fedimint_usdt_common::deposit_fee_quote(&median) else {
            debug!(
                target: "usdt",
                account = ?account,
                "deposit fee quote unavailable (overflow); deferring sweep"
            );
            return;
        };
        if remainder <= sweep_fee.0 {
            debug!(
                target: "usdt",
                account = ?account,
                remainder,
                sweep_fee = sweep_fee.0,
                "deposit remainder does not cover its deploy+sweep gas fee; not sweeping (dust)"
            );
            return;
        }

        let owner = evm_address(&self.cfg.consensus.group_public_key);
        let params = DeployAndSweepParams {
            account_factory: self.cfg.consensus.account_factory,
            usdt_contract: self.cfg.consensus.usdt_contract,
            deposit_account: account,
            owner,
            claim_pk: record.claim_pk,
            amount: UsdtAmount(remainder),
            pool: self.pool_account(),
            nonce: alloy::primitives::U256::from(record.nonce),
            needs_deploy: record.nonce == 0,
            paymaster_and_data: Vec::new(),
            gas_bounds: GasBounds::DEPLOY_AND_SWEEP_DEVNET
                .with_median_fees(Some(median.max_fee_per_gas_wei)),
        };
        let op = crate::user_op::build_deploy_and_sweep_userop(params);
        let op_hash = user_op_hash(
            &op,
            self.cfg.consensus.entry_point,
            self.cfg.consensus.chain_id,
        );

        // Idempotent: if this exact op is already pending or already
        // submitted, don't re-enqueue (also protects against re-deriving an
        // unchanged op on a repeat/late-arriving threshold-reaching vote for
        // the same already-credited balance).
        if dbtx.get_value(&PendingUserOpKey(op_hash)).await.is_some()
            || dbtx.get_value(&SubmittedUserOpKey(op_hash)).await.is_some()
        {
            return;
        }

        let created_block = self.consensus_block_count(dbtx).await;
        dbtx.insert_entry(
            &PendingUserOpKey(op_hash),
            &PendingUserOp {
                op: op.clone(),
                purpose: UserOpPurpose::DeployAndSweep { source: account },
                created_block,
            },
        )
        .await;
        info!(
            target: "usdt",
            ?op_hash,
            %account,
            remainder,
            nonce = record.nonce,
            needs_deploy = record.nonce == 0,
            "sweep enqueued (PendingUserOp), starting MPC signing session"
        );

        // `start_session` is called identically by every guardian here:
        // every guardian processes this same `Deposit` consensus item, so
        // every guardian starts the identical session deterministically --
        // no separate consensus item is needed to fan this out, since this
        // trigger is ALREADY inside `process_consensus_item` and therefore
        // already runs on every guardian directly.
        let digest = eth_signed_message_hash(op_hash);
        self.start_session(dbtx, SigningPurpose::UserOp(op_hash), digest, 0)
            .await;
    }

    /// Actively (re)triggers a deploy-and-sweep for every deposit account with
    /// an un-swept remainder (`credited > swept`), pulling their USDT into the
    /// pool to fund queued withdrawals sooner than passively waiting for each
    /// deposit's own credit-triggered sweep. Called by
    /// [`Usdt::maybe_trigger_withdrawal_batch`] when the pool-balance gate
    /// finds the pool cannot yet cover the queued batch.
    ///
    /// DETERMINISTIC + IDEMPOTENT: it iterates the consensus `DepositRecord`
    /// set (fixed key order) and defers to [`Usdt::maybe_trigger_sweep`], whose
    /// in-flight guard skips any account already mid-sweep and whose op is a
    /// pure function of the account's record -- so every guardian enqueues the
    /// identical set of sweep ops, and re-running it (every waiting trigger)
    /// enqueues nothing new.
    async fn accelerate_sweeps_for_withdrawals(&self, dbtx: &mut DatabaseTransaction<'_>) {
        let records: Vec<(fedimint_usdt_common::EvmAddress, DepositRecord)> = dbtx
            .find_by_prefix(&DepositRecordPrefix)
            .await
            .map(|(DepositRecordKey(account), record)| (account, record))
            .collect()
            .await;
        for (account, record) in records {
            if record.credited.0 > record.swept.0 {
                self.maybe_trigger_sweep(dbtx, account).await;
            }
        }
    }

    /// `true` if a `Withdraw`-purpose `UserOp` is currently `Pending`
    /// (awaiting/undergoing MPC signing) or `Submitted` (signed, awaiting
    /// on-chain confirmation) -- i.e. a withdrawal batch is already "in
    /// flight" and [`Usdt::maybe_trigger_withdrawal_batch`] must not start a
    /// second one. Both tables are scanned fully and filtered by
    /// `UserOpPurpose::Withdraw`, since -- unlike `DeployAndSweep` ops,
    /// which are keyed per deposit account and may legitimately have many
    /// concurrently pending -- this module never intentionally has more than
    /// one `Withdraw`-purpose op outstanding at a time (see
    /// `maybe_trigger_withdrawal_batch`'s doc comment for why: two
    /// concurrent batches would both be built against the SAME
    /// `PoolState.nonce`, since it only advances on confirm, and would
    /// collide on-chain).
    async fn withdraw_batch_in_flight(&self, dbtx: &mut DatabaseTransaction<'_>) -> bool {
        let pending: Vec<(PendingUserOpKey, PendingUserOp)> = dbtx
            .find_by_prefix(&PendingUserOpPrefix)
            .await
            .collect()
            .await;
        if let Some((PendingUserOpKey(op_hash), _)) = pending
            .iter()
            .find(|(_, p)| matches!(p.purpose, UserOpPurpose::Withdraw { .. }))
        {
            debug!(
                target: "usdt",
                ?op_hash,
                state = "Pending",
                "withdrawal batch trigger blocked: a Withdraw op is already in-flight (awaiting/undergoing MPC signing)"
            );
            return true;
        }

        let submitted: Vec<(SubmittedUserOpKey, SubmittedUserOp)> = dbtx
            .find_by_prefix(&SubmittedUserOpPrefix)
            .await
            .collect()
            .await;
        if let Some((SubmittedUserOpKey(op_hash), _)) = submitted
            .iter()
            .find(|(_, s)| matches!(s.purpose, UserOpPurpose::Withdraw { .. }))
        {
            debug!(
                target: "usdt",
                ?op_hash,
                state = "Submitted",
                "withdrawal batch trigger blocked: a Withdraw op is already in-flight (signed, awaiting on-chain confirmation)"
            );
            return true;
        }
        false
    }

    /// `true` if a `DeployAndSweep`-purpose `UserOp` for exactly this
    /// `account` is currently `Pending` (awaiting/undergoing MPC signing) or
    /// `Submitted` (signed, awaiting on-chain confirmation) -- i.e. a sweep
    /// of this deposit account is already "in flight" and
    /// [`Usdt::maybe_trigger_sweep`] must not start a second one at the same
    /// on-chain nonce (which would collide, AA25). Unlike
    /// [`Usdt::withdraw_batch_in_flight`], the scan is filtered to a SINGLE
    /// `account` (`DeployAndSweep { source }` with `source == account`):
    /// different accounts have independent nonces and may legitimately sweep
    /// concurrently.
    ///
    /// A pure function of consensus-DB state (`PendingUserOp`/
    /// `SubmittedUserOp` tables) and `account`, so identical on every
    /// guardian.
    async fn deploy_and_sweep_in_flight(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        account: fedimint_usdt_common::EvmAddress,
    ) -> bool {
        let pending: Vec<(PendingUserOpKey, PendingUserOp)> = dbtx
            .find_by_prefix(&PendingUserOpPrefix)
            .await
            .collect()
            .await;
        if pending.iter().any(|(_, p)| {
            matches!(p.purpose, UserOpPurpose::DeployAndSweep { source } if source == account)
        }) {
            return true;
        }

        let submitted: Vec<(SubmittedUserOpKey, SubmittedUserOp)> = dbtx
            .find_by_prefix(&SubmittedUserOpPrefix)
            .await
            .collect()
            .await;
        submitted.iter().any(|(_, s)| {
            matches!(s.purpose, UserOpPurpose::DeployAndSweep { source } if source == account)
        })
    }

    /// Deterministically batches every currently-`Queued` withdrawal into
    /// ONE `Withdraw`-purpose `UserOp` from the pool `SimpleAccount`, and
    /// starts its MPC signing session, if the batching policy fires (Phase
    /// 8, Task 2). Called from the `BlockCount` consensus-item arm, mirroring
    /// where [`Usdt::maybe_trigger_sweep`] sits in the `Deposit` arm -- a
    /// deterministic consensus-DB-driven trigger, not a background task.
    ///
    /// # Trigger policy
    ///
    /// Fires when at least one `Queued` withdrawal exists AND EITHER the
    /// oldest of them (by `UsdtWithdrawalV0::requested_block`) has waited at
    /// least [`batch_interval_blocks`] consensus blocks, OR there are at
    /// least [`BATCH_MAX_ITEMS`] queued withdrawals. Using the oldest
    /// queued withdrawal's own `requested_block` (already written by
    /// `Usdt::process_output`) as the interval anchor -- rather than a
    /// separate "last batch" singleton -- bounds every individual
    /// withdrawal's own maximum queuing delay directly, and needs no extra
    /// consensus-DB state.
    ///
    /// # Guards
    ///
    /// - [`Usdt::withdraw_batch_in_flight`]: never starts a second
    ///   `Withdraw`-purpose op while one is `Pending`/`Submitted` (both would
    ///   collide on the same `PoolState.nonce`).
    /// - Only withdrawals whose [`WithdrawalState`] is EXACTLY `Queued` are
    ///   ever candidates: one already `Signing`/`Submitted` (part of an
    ///   in-flight batch) or terminal (`Confirmed`) is excluded, so a
    ///   withdrawal is never double-batched.
    ///
    /// # Determinism (consensus-critical)
    ///
    /// A pure function of the full `UnclaimedWithdrawal`/`WithdrawalState`/
    /// `PoolState` consensus-DB tables and this module's config
    /// (`account_factory`/`usdt_contract`/`entry_point`/`chain_id`/
    /// `group_public_key`) -- no RPC, no wall-clock, no `our_peer_id`.
    /// `queued` is sorted by `OutPoint` (a total order) before being fed to
    /// [`crate::user_op::build_withdrawal_batch_userop`], so every guardian
    /// builds the byte-identical op/`op_hash` from the byte-identical
    /// input. The only conditional consensus-DB writes
    /// (`PendingUserOpKey`/`WithdrawalStateKey`/`SigningSession` inserts)
    /// are gated on checks of that SAME consensus DB -- identical on every
    /// guardian. `start_session`'s only `our_peer_id`-conditional part is
    /// the in-memory off-thread signer spawn, a guardian-local side effect
    /// (see its own doc comment).
    /// Reads `out_point`'s [`WithdrawalBatchCapKey`] -- the maximum batch
    /// size this withdrawal may next be included in (security finding 05,
    /// poisoned-batch isolation) -- defaulting to [`BATCH_MAX_ITEMS`] when
    /// absent (every withdrawal starts uncapped). Pure function of the
    /// committed consensus DB; no RPC/wall-clock.
    async fn withdrawal_batch_cap(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> usize {
        dbtx.get_value(&WithdrawalBatchCapKey(out_point))
            .await
            .map_or(BATCH_MAX_ITEMS, |cap| cap as usize)
    }

    async fn maybe_trigger_withdrawal_batch(&self, dbtx: &mut DatabaseTransaction<'_>) {
        if self.withdraw_batch_in_flight(dbtx).await {
            return;
        }

        let all: Vec<(UnclaimedWithdrawalKey, UsdtWithdrawalV0)> = dbtx
            .find_by_prefix(&UnclaimedWithdrawalPrefix)
            .await
            .collect()
            .await;

        let mut queued: Vec<(OutPoint, UsdtWithdrawalV0)> = Vec::new();
        for (UnclaimedWithdrawalKey(out_point), withdrawal) in all {
            if dbtx.get_value(&WithdrawalStateKey(out_point)).await == Some(WithdrawalState::Queued)
            {
                queued.push((out_point, withdrawal));
            }
        }
        if queued.is_empty() {
            return;
        }

        let consensus_block_count = self.consensus_block_count(dbtx).await;
        let oldest_requested_block = queued
            .iter()
            .map(|(_, w)| w.requested_block)
            .min()
            .expect("queued is non-empty, checked above");
        let waited_long_enough =
            consensus_block_count >= oldest_requested_block + batch_interval_blocks();
        let enough_items = queued.len() >= BATCH_MAX_ITEMS;
        if !waited_long_enough && !enough_items {
            debug!(
                target: "usdt",
                queued = queued.len(),
                consensus_block_count,
                oldest_requested_block,
                interval_blocks = batch_interval_blocks(),
                fires_at_block = oldest_requested_block + batch_interval_blocks(),
                batch_max_items = BATCH_MAX_ITEMS,
                "withdrawal batch waiting for interval (or item threshold)"
            );
            return;
        }

        // Deterministic ordering (`OutPoint`'s total `Ord`): every guardian
        // sorts identically, so the batch's `dest`/`value`/`func` arrays
        // (and hence `call_data`/`op_hash`) are byte-identical everywhere.
        queued.sort_by_key(|(out_point, _)| *out_point);

        // Cap the batch SIZE (not just the trigger threshold) so a burst of
        // queued withdrawals can never build a single `executeBatch` too large
        // to be bundled/included on-chain (which would never confirm and, on
        // the next trigger, rebuild the identical oversized batch -- a
        // permanent liveness wedge of ALL withdrawals). The `OutPoint` sort
        // above makes "which `BATCH_MAX_ITEMS`" deterministic; the remainder
        // stays `Queued` and is picked up by the next batch (the in-flight
        // guard serializes batches, so nonces never collide).
        queued.truncate(BATCH_MAX_ITEMS);

        // POISON-ISOLATION CAP (security finding 05): shrink the batch
        // further to the smallest per-withdrawal `WithdrawalBatchCapKey`
        // among the (already sorted, `BATCH_MAX_ITEMS`-windowed) candidates
        // above. A withdrawal that shared a recently-failed batch of size
        // `n` was left with a cap of `max(1, n / 2)` (see
        // `Usdt::apply_withdraw_confirmed`'s doc comment); truncating the
        // window to the window's minimum cap means a poisoned group can
        // never be rebuilt at its old (failing) size -- it is forced to
        // binary-split on every subsequent failure until it isolates down to
        // a singleton. Reads only the sorted `queued` window + their
        // committed `WithdrawalBatchCapKey` records (or the
        // `BATCH_MAX_ITEMS` default when absent) -- deterministic, no
        // RPC/wall-clock.
        let mut effective_cap = BATCH_MAX_ITEMS;
        for &(out_point, _) in &queued {
            effective_cap = effective_cap.min(self.withdrawal_batch_cap(dbtx, out_point).await);
        }
        queued.truncate(effective_cap);

        let pool = dbtx.get_value(&PoolStateKey).await.unwrap_or(PoolState {
            account: self.pool_account(),
            balance: UsdtAmount(0),
            nonce: 0,
        });

        // POOL-BALANCE GATE: only build a batch the pool can actually pay.
        // Every withdrawal's `amount` (NOT `max_fee` -- the fee stays pooled as
        // the federation's fee revenue and never leaves) must be covered by
        // `PoolState.balance`. Without this gate a withdrawal requested before
        // its backing deposits have swept into the pool would build an
        // `executeBatch` the pool cannot fund; the on-chain call reverts,
        // `apply_withdraw_confirmed` returns the withdrawals to `Queued`, and
        // -- since their `requested_block` is unchanged -- an identical doomed
        // batch is re-triggered every confirmation cycle, burning broadcaster
        // gas until the sweeps happen to catch up. Gating here is
        // determinism-safe: `pool.balance` and every `amount` are consensus-DB
        // values, so every guardian reaches the identical decision. The batch
        // simply waits (withdrawals stay `Queued`) until sweeps fund the pool.
        //
        // Wedge-freedom is CONDITIONAL, not absolute: it holds only WHILE the
        // backing deposits' sweeps eventually succeed. Each outstanding
        // withdrawal is backed by credited deposits, and the in-flight guard
        // means only sweeps (which add to the pool) can run while this batch
        // waits, so `pool.balance` rises to coverage AS LONG AS those sweeps
        // confirm. The exception: `apply_user_op_confirmed` deliberately does
        // NOT auto-retrigger a FAILED sweep (see `retrigger_source` there), so
        // a deposit whose sweep persistently reverts (e.g. a blacklisted /
        // paused / fee-reverting token) never funds the pool -- and a
        // withdrawal whose e-cash was already burned then wedges in `Queued`
        // indefinitely with its backing e-cash destroyed. That failure mode is
        // a documented maintainer design item (no withdrawal escape-hatch /
        // Failed-refund path yet), out of scope for this gate.
        let batch_total = queued
            .iter()
            .fold(0u64, |acc, (_, w)| acc.saturating_add(w.amount.0));
        if pool.balance.0 < batch_total {
            info!(
                target: "usdt",
                queued = queued.len(),
                batch_total,
                pool_balance = pool.balance.0,
                shortfall = batch_total.saturating_sub(pool.balance.0),
                pool_account = %pool.account,
                "withdrawal batch waiting for pool funding (batch total exceeds pool balance); accelerating sweeps"
            );
            // ACCELERATE SWEEP: the pool cannot yet cover the queued
            // withdrawals. Rather than passively wait for each backing
            // deposit's own credit-triggered sweep, actively (re)trigger a
            // sweep for every deposit that still has an un-swept remainder so
            // their USDT flows into the pool and covers the batch sooner. The
            // withdrawal batch fires on a later trigger once those sweeps
            // confirm and `pool.balance` rises. Deterministic + idempotent (see
            // the helper).
            self.accelerate_sweeps_for_withdrawals(dbtx).await;
            return;
        }

        self.build_and_enqueue_withdrawal_batch(
            dbtx,
            &queued,
            &pool,
            batch_total,
            consensus_block_count,
            enough_items,
        )
        .await;
    }

    /// Builds the single `Withdraw`-purpose `executeBatch` `UserOp` from the
    /// (already sorted, truncated, and pool-covered) `queued` withdrawals,
    /// enqueues it as a `PendingUserOp`, flips each withdrawal to
    /// `WithdrawalState::Signing`, and starts its MPC signing session. Split
    /// out of [`Usdt::maybe_trigger_withdrawal_batch`] purely to keep that
    /// method's decision logic readable; every input is a consensus-DB value
    /// or config, so this remains a pure, byte-identical function of consensus
    /// state on every guardian (see the caller's determinism note). `trigger`
    /// (`enough_items`) is diagnostic-only, feeding the log line's cause.
    async fn build_and_enqueue_withdrawal_batch(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        queued: &[(OutPoint, UsdtWithdrawalV0)],
        pool: &PoolState,
        batch_total: u64,
        consensus_block_count: u64,
        enough_items: bool,
    ) {
        let outpoints: Vec<OutPoint> = queued.iter().map(|(o, _)| *o).collect();
        let withdrawals: Vec<(fedimint_usdt_common::EvmAddress, UsdtAmount)> = queued
            .iter()
            .map(|(_, w)| (w.recipient, w.amount))
            .collect();

        // Consensus live-gas median prices the op (see the sweep site's note).
        let median = self.fee_vote_median(dbtx).await;
        let owner = evm_address(&self.cfg.consensus.group_public_key);
        let needs_deploy = pool.nonce == 0;
        let params = WithdrawalBatchParams {
            account_factory: self.cfg.consensus.account_factory,
            usdt_contract: self.cfg.consensus.usdt_contract,
            pool: pool.account,
            owner,
            withdrawals: withdrawals.clone(),
            nonce: alloy::primitives::U256::from(pool.nonce),
            needs_deploy,
            paymaster_and_data: Vec::new(),
            gas_bounds: GasBounds::withdrawal_batch(withdrawals.len(), needs_deploy)
                .with_median_fees(median.map(|m| m.max_fee_per_gas_wei)),
        };
        let op = crate::user_op::build_withdrawal_batch_userop(params);
        let op_hash = user_op_hash(
            &op,
            self.cfg.consensus.entry_point,
            self.cfg.consensus.chain_id,
        );

        dbtx.insert_entry(
            &PendingUserOpKey(op_hash),
            &PendingUserOp {
                op: op.clone(),
                purpose: UserOpPurpose::Withdraw {
                    outpoints: outpoints.clone(),
                },
                created_block: consensus_block_count,
            },
        )
        .await;

        for &out_point in &outpoints {
            dbtx.insert_entry(
                &WithdrawalStateKey(out_point),
                &WithdrawalState::Signing(op_hash),
            )
            .await;
        }

        info!(
            target: "usdt",
            ?op_hash,
            count = outpoints.len(),
            batch_total,
            nonce = pool.nonce,
            needs_deploy,
            trigger = if enough_items { "item-threshold" } else { "interval" },
            "withdrawal batch built (PendingUserOp), starting MPC signing session"
        );

        let digest = eth_signed_message_hash(op_hash);
        self.start_session(dbtx, SigningPurpose::UserOp(op_hash), digest, 0)
            .await;
    }

    /// This federation's fixed pool `SimpleAccount` address (see
    /// [`derive_pool_account`]) -- a pure function of config, computed fresh
    /// on every call rather than cached, so it is trivially identical on
    /// every guardian and never goes stale if config were ever inspected
    /// before [`PoolState`] exists in the DB yet.
    fn pool_account(&self) -> fedimint_usdt_common::EvmAddress {
        derive_pool_account(
            &self.cfg.consensus.group_public_key,
            self.cfg.consensus.account_factory,
            self.cfg.consensus.simple_account_impl,
        )
    }

    /// Applies a threshold-agreed [`UserOpConfirmedObservation`] for
    /// `op_hash`, branching on the finalized [`SubmittedUserOp::purpose`]
    /// (Phase 8, Task 2): a `DeployAndSweep` op, if `success`, credits
    /// `PoolState.balance` by the RE-DERIVED swept amount (see "Security
    /// finding 21" below) and marks the corresponding [`DepositRecord`]
    /// (recovered from the op's own `sender`, i.e. the swept deposit
    /// account) as swept forward (Phase 7 behavior, unchanged); a
    /// `Withdraw` op settles the covered withdrawals -- see
    /// [`Usdt::apply_withdraw_confirmed`]'s own doc comment. Either way,
    /// clears the now-finalized [`SubmittedUserOp`] and the op's vote
    /// prefix. Replay-safe: if `SubmittedUserOpKey(op_hash)` is already
    /// absent (a prior threshold-reaching duplicate vote already applied
    /// this `op_hash`), this is a no-op.
    ///
    /// # Determinism (consensus-critical)
    ///
    /// A pure function of `op_hash`, `obs` (both from the ordered consensus
    /// item), and prior consensus-DB state (`SubmittedUserOp`/`PoolState`/
    /// `DepositRecord`/`UnclaimedWithdrawal`/`WithdrawalState`) --
    /// byte-identical on every guardian, signer or not. `obs` itself is
    /// federation-agreed (only reached after >= threshold IDENTICAL votes,
    /// verified by the caller's full-field `PartialEq` tally), so using its
    /// `success`/`swept`/`block` fields here is not reading any single
    /// guardian's local RPC result. `submitted.purpose` is likewise
    /// consensus-DB state (copied verbatim from the `PendingUserOp` that
    /// started the signing session -- see `Usdt::process_mpc_signature`),
    /// never `our_peer_id`-conditional.
    ///
    /// # Security finding 21 (Phase 9 hardening): re-derive, don't trust
    ///
    /// A `success: true` observation's amount is never applied as-voted.
    /// `submitted.signed.unsigned.call_data` (already consensus-committed,
    /// deterministic, no RPC) is re-decoded per `submitted.purpose` --
    /// [`crate::user_op::decode_transfer_amount`] for `DeployAndSweep`,
    /// [`crate::user_op::decode_batch_transfer_total`] for `Withdraw` --
    /// and `obs.swept` is required to equal it exactly before that
    /// RE-DERIVED amount (not the raw vote) is used for the actual
    /// settlement math below. This shrinks the trusted surface of a
    /// `UserOpConfirmed` vote from "threshold must agree on every field,
    /// including a deterministic amount" down to "threshold agrees on
    /// success/block; the amount is derived from already-committed
    /// consensus state". On a decode error OR a mismatch -- an invariant
    /// violation, unreachable on the honest path since
    /// `spawn_user_op_submitter` fails closed on the same decode (see its
    /// own doc comment) -- this function leaves EVERY bit of state
    /// untouched (does not even advance the nonce) and warns loudly,
    /// keeping `SubmittedUserOp` live for a later retry/timeout mechanism
    /// to act on. Leaving state fully untouched (rather than, say,
    /// advancing the nonce but skipping only the balance mutation) is
    /// deliberate: since `SubmittedUserOp` is NOT removed on this path, it
    /// does not gain the removal-based idempotency guard the happy path
    /// below relies on -- a late, independently-threshold-crossing
    /// duplicate vote for the same mismatch must replay as a complete
    /// no-op, never double-mutate any counter.
    #[allow(clippy::too_many_lines)]
    async fn apply_user_op_confirmed(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        op_hash: [u8; 32],
        obs: &UserOpConfirmedObservation,
    ) {
        let Some(submitted) = dbtx.get_value(&SubmittedUserOpKey(op_hash)).await else {
            // Already applied by an earlier threshold-reaching vote for this
            // op_hash (e.g. a late peer's vote pushes `agreeing` past
            // threshold again after a prior vote already applied it).
            dbtx.remove_by_prefix(&UserOpConfirmedVoteOpPrefix(op_hash))
                .await;
            return;
        };

        let effective_swept = if obs.success {
            let expected = match &submitted.purpose {
                UserOpPurpose::DeployAndSweep { .. } => {
                    crate::user_op::decode_transfer_amount(&submitted.signed.unsigned)
                }
                UserOpPurpose::Withdraw { .. } => {
                    crate::user_op::decode_batch_transfer_total(&submitted.signed.unsigned)
                }
            };
            match expected {
                Ok(expected) if expected == obs.swept => expected,
                Ok(expected) => {
                    warn!(
                        target: "usdt",
                        ?op_hash,
                        obs_swept = obs.swept.0,
                        expected_swept = expected.0,
                        purpose = ?submitted.purpose,
                        "UserOpConfirmed swept amount does not match the amount decoded from \
                         the op's own committed calldata -- NOT applying settlement, leaving \
                         SubmittedUserOp live for retry (invariant violation, security finding \
                         21)"
                    );
                    return;
                }
                Err(err) => {
                    warn!(
                        target: "usdt",
                        ?op_hash,
                        err = %err.fmt_compact_anyhow(),
                        purpose = ?submitted.purpose,
                        "failed to re-derive swept amount from committed op calldata at apply \
                         time -- NOT applying settlement, leaving SubmittedUserOp live for retry \
                         (invariant violation, security finding 21)"
                    );
                    return;
                }
            }
        } else {
            UsdtAmount(0)
        };

        info!(
            target: "usdt",
            ?op_hash,
            success = obs.success,
            swept = effective_swept.0,
            block = obs.block,
            purpose = ?submitted.purpose,
            "UserOp confirmed on-chain (applying threshold-agreed outcome)"
        );

        // Set to the swept deposit account only for a SUCCESSFUL
        // `DeployAndSweep`, so that -- after this op is cleared from the
        // in-flight tables below -- we can promptly re-sweep any remainder
        // that `credited` grew into while this sweep was in flight. Deliberately
        // left `None` on failure: a persistently-reverting sweep (e.g. a
        // non-standard token whose `transfer` reverts) would otherwise
        // tight-loop, re-enqueuing and burning gas every confirmation cycle.
        // On failure the remainder simply stays `credited - swept` (solvent,
        // still on-chain) and is retried only by a LATER deposit observation on
        // this account (`credit_deposit` -> `maybe_trigger_sweep`). NOTE: if no
        // such future deposit ever arrives, the remainder stays un-swept
        // indefinitely -- there is no standalone sweep-retry -- which can wedge
        // any already-burned withdrawal that was relying on it (documented
        // maintainer design item; see `maybe_trigger_withdrawal_batch`'s
        // pool-balance gate).
        let mut retrigger_source: Option<fedimint_usdt_common::EvmAddress> = None;

        match &submitted.purpose {
            UserOpPurpose::DeployAndSweep { .. } => {
                let source = submitted.signed.unsigned.sender;

                if obs.success {
                    let mut pool = dbtx.get_value(&PoolStateKey).await.unwrap_or(PoolState {
                        account: self.pool_account(),
                        balance: UsdtAmount(0),
                        nonce: 0,
                    });
                    // `saturating_add` (Phase 9, Task 1 hardening, N1): both
                    // adds below are bounded in practice (a pool balance /
                    // deposit's `swept` amount tracking real, finite
                    // on-chain USDT transfers), but a deterministic saturate
                    // is strictly safer than a deterministic panic on the
                    // (unreachable) chance of a `u64` overflow, and stays
                    // just as reproducible across guardians as a raw `+`.
                    // Uses `effective_swept` (re-derived and cross-checked
                    // against `obs.swept` above, security finding 21), not
                    // the raw vote field.
                    pool.balance = UsdtAmount(pool.balance.0.saturating_add(effective_swept.0));
                    dbtx.insert_entry(&PoolStateKey, &pool).await;

                    retrigger_source = Some(source);
                }

                // Advance this deposit account's tracked `SimpleAccount` nonce
                // UNCONDITIONALLY (success OR failure), mirroring the
                // `Withdraw` path's unconditional `PoolState.nonce` bump (see
                // `apply_withdraw_confirmed`'s doc comment): the `EntryPoint`
                // validates and increments the on-chain nonce (and runs
                // `initCode`) BEFORE the sweep `callData` executes, so the
                // nonce is consumed whether or not the transfer reverted. If
                // the guardian's tracked `record.nonce` did not mirror that,
                // every later sweep of this account would be built at a stale
                // (already-consumed) nonce and revert forever (AA25). On
                // success we additionally advance `swept` (clamped to
                // `credited`), which is what the pool credit above accounts
                // for; on failure `swept` is left untouched. Written once.
                if let Some(mut record) = dbtx.get_value(&DepositRecordKey(source)).await {
                    record.nonce = record.nonce.saturating_add(1);
                    if obs.success {
                        record.swept = UsdtAmount(
                            record
                                .swept
                                .0
                                .saturating_add(effective_swept.0)
                                .min(record.credited.0),
                        );
                    }
                    dbtx.insert_entry(&DepositRecordKey(source), &record).await;
                }
            }
            UserOpPurpose::Withdraw { outpoints } => {
                self.apply_withdraw_confirmed(dbtx, outpoints, obs, effective_swept)
                    .await;
            }
        }

        dbtx.remove_entry(&SubmittedUserOpKey(op_hash)).await;
        dbtx.remove_by_prefix(&UserOpConfirmedVoteOpPrefix(op_hash))
            .await;

        // RBF-nonce cleanup (security finding 03): this op landed on-chain, so
        // the `EntryPoint` consumed its `(sender, nonce)` -- no sibling in its
        // replacement chain (a superseded predecessor, or a still-signing
        // higher-fee successor) can ever land at the same nonce. Remove the
        // whole chain now, so (a) settlement is exactly-once (a late confirm of
        // a sibling finds no `SubmittedUserOp` and is rejected), and (b) the
        // in-flight guards stop blocking new batches/sweeps at the now-advanced
        // nonce. Runs for BOTH success and revert: a `UserOpConfirmed`
        // observation only ever exists for an op the `EntryPoint` actually
        // included, so the nonce is spent either way (see
        // `apply_withdraw_confirmed`'s doc comment). Must run BEFORE the
        // success-only re-sweep retrigger below, so the freed nonce is clear
        // when the next sweep is built.
        self.purge_user_op_nonce_chain(
            dbtx,
            submitted.signed.unsigned.sender,
            submitted.signed.unsigned.nonce,
            op_hash,
        )
        .await;

        // Re-trigger AFTER the op is cleared from the in-flight tables, so
        // `maybe_trigger_sweep`'s per-account in-flight guard no longer sees
        // THIS (now-finalized) op and can enqueue the next sweep at the
        // freshly-advanced `record.nonce`. Only on success (see
        // `retrigger_source`'s comment for why failure does not auto-retry).
        if let Some(source) = retrigger_source {
            self.maybe_trigger_sweep(dbtx, source).await;
        }
    }

    /// Settles a confirmed `Withdraw`-purpose `UserOp`'s `outpoints` (Phase
    /// 8, Task 2), called only from [`Usdt::apply_user_op_confirmed`].
    ///
    /// `PoolState.nonce` is incremented UNCONDITIONALLY (before branching on
    /// `obs.success`): a `UserOpConfirmed` observation only ever exists for
    /// an op the `EntryPoint` actually validated and included (produced a
    /// `UserOperationEvent`) -- `success` there reflects only whether the
    /// `callData` (`executeBatch`) execution itself reverted, which happens
    /// strictly AFTER nonce validation/increment and (if `needs_deploy`) the
    /// `initCode` deploy. So the on-chain nonce (and, if this was the pool's
    /// first-ever op, its deployment) is consumed either way; failing to
    /// mirror that here would make this guardian's `PoolState.nonce` fall
    /// out of sync with the real on-chain value and every subsequent batch
    /// would be built with a stale (already-consumed) nonce, permanently
    /// wedging withdrawals.
    ///
    /// On `success`: debits `PoolState.balance` by `swept` (the total
    /// actually paid out -- see the `swept` parameter's own doc, security
    /// finding 21), marks every `outpoints` withdrawal
    /// `WithdrawalState::Confirmed { block: obs.block }`, and removes its
    /// now-settled `UnclaimedWithdrawal` (so `Usdt::audit` stops
    /// subtracting it -- see that method's doc comment for the solvency
    /// argument).
    ///
    /// On `!success` (security finding 05, poisoned-batch isolation task):
    /// `PoolState.balance` is left untouched either way (nothing left the
    /// pool on-chain), but the per-outpoint state transition now depends on
    /// how many withdrawals this failed batch covered (`n =
    /// outpoints.len()`, read from the confirmed op's own committed
    /// `purpose` -- deterministic, no RPC/wall-clock):
    ///
    /// - `n <= 1` (a singleton batch failed -- this withdrawal alone, isolated
    ///   from every other queued withdrawal, still reverts): this IS the
    ///   poisoned withdrawal. Move it to terminal `WithdrawalState::Failed {
    ///   reason }` and REFUND it: [`Usdt::create_withdrawal_refund`] replaces
    ///   its `UnclaimedWithdrawal` with a [`Refund`] (security finding 09)
    ///   reissuing `(amount + max_fee)` minus the gas already incurred, then
    ///   removes its [`WithdrawalBatchCapKey`]/`WithdrawalIncurredFeeKey`
    ///   (housekeeping). It is NOT re-queued: re-queueing a batch that already
    ///   failed alone would rebuild the byte-identical singleton forever (the
    ///   original `DoS` this finding reports, just shrunk to size 1).
    /// - `n > 1`: NOT the poison alone -- one or more of these `n` withdrawals
    ///   fail together, but which one is unknown. Revert every covered outpoint
    ///   to `WithdrawalState::Queued` (as before) AND set its
    ///   [`WithdrawalBatchCapKey`] to `max(1, n / 2)` (integer halving).
    ///   `Usdt::maybe_trigger_withdrawal_batch`'s `effective_cap` then caps the
    ///   NEXT batch containing any of these withdrawals to that smaller size,
    ///   deterministically binary-splitting the failing group on every
    ///   subsequent failure until the poison lands alone in a singleton batch
    ///   (the `n <= 1` case above) and honest members clear in a split that no
    ///   longer contains it. The halving strictly decreases for any `n > 1` and
    ///   floors at 1, so the isolation always terminates within `ceil(log2(n))`
    ///   failed rounds.
    ///
    /// On the `n > 1` branch `UnclaimedWithdrawal` is left in place (still a
    /// real, still-funded obligation being re-queued); on the `n <= 1` branch
    /// it becomes a [`Refund`] (security finding 09). Both failure branches
    /// first accumulate each covered withdrawal's SHARE of this batch's
    /// `obs.actual_gas_cost_wei` into its `WithdrawalIncurredFeeKey`, so the
    /// eventual refund is net of every failed batch's gas.
    ///
    /// `swept` (Phase 9 hardening, security finding 21): the AUTHORITATIVE
    /// amount to debit, computed by the caller
    /// ([`Usdt::apply_user_op_confirmed`]) by re-deriving it from
    /// `submitted.signed.unsigned.call_data` via
    /// [`crate::user_op::decode_batch_transfer_total`] and cross-checking
    /// it against the voted `obs.swept` -- NOT read from `obs.swept`
    /// directly here, so this function can never be called with an
    /// unverified amount. `UsdtAmount(0)` (irrelevant, unused) when
    /// `!obs.success`.
    async fn apply_withdraw_confirmed(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        outpoints: &[OutPoint],
        obs: &UserOpConfirmedObservation,
        swept: UsdtAmount,
    ) {
        let mut pool = dbtx.get_value(&PoolStateKey).await.unwrap_or(PoolState {
            account: self.pool_account(),
            balance: UsdtAmount(0),
            nonce: 0,
        });
        pool.nonce += 1;

        if obs.success {
            pool.balance = UsdtAmount(pool.balance.0.saturating_sub(swept.0));
        }
        dbtx.insert_entry(&PoolStateKey, &pool).await;

        let n = outpoints.len();
        // Security finding 05 (poisoned-batch isolation): halved (floor 1)
        // cap for a >1-member failed batch, so the NEXT batch containing any
        // of these withdrawals is capped smaller by
        // `Usdt::maybe_trigger_withdrawal_batch`'s `effective_cap`. `n` is
        // bounded by `BATCH_MAX_ITEMS` (a `usize` constant that trivially
        // fits `u32`), so this conversion cannot fail.
        let split_cap: u32 =
            u32::try_from((n / 2).max(1)).expect("n <= BATCH_MAX_ITEMS, which fits in u32");

        if obs.success {
            for &out_point in outpoints {
                dbtx.insert_entry(
                    &WithdrawalStateKey(out_point),
                    &WithdrawalState::Confirmed { block: obs.block },
                )
                .await;
                dbtx.remove_entry(&UnclaimedWithdrawalKey(out_point)).await;
                dbtx.remove_entry(&WithdrawalBatchCapKey(out_point)).await;
                // Only refunded (terminally-failed) withdrawals ever read the
                // incurred-fee accumulator; a settled one drops it (security
                // finding 09 housekeeping).
                dbtx.remove_entry(&WithdrawalIncurredFeeKey(out_point))
                    .await;
            }
        } else {
            // Security finding 09: this batch reverted on-chain but STILL
            // consumed gas (the `EntryPoint` validated/included it before the
            // transfer reverted). Charge each covered withdrawal its equal
            // SHARE of that gas into its `WithdrawalIncurredFeeKey`
            // accumulator, so that when the withdrawal eventually goes
            // terminal-`Failed` its refund is reduced by the gas the
            // federation actually burned on its behalf. Deterministic: the
            // wei figure is the threshold-agreed `obs.actual_gas_cost_wei`,
            // the rate is the consensus `FeeVote` median, and `n` is the
            // committed batch size -- no RPC/wall-clock. An absent/overflowing
            // median yields a `0` share (the user is refunded slightly more,
            // never less -- the solvency-safe direction).
            let share = if n == 0 {
                UsdtAmount(0)
            } else {
                self.fee_vote_median(dbtx)
                    .await
                    .and_then(|median| {
                        wei_gas_cost_to_usdt(
                            u128::from(obs.actual_gas_cost_wei.0),
                            median.usdt_per_eth_e6,
                        )
                    })
                    .map_or(UsdtAmount(0), |total| UsdtAmount(total.0 / (n as u64)))
            };
            for &out_point in outpoints {
                let accrued = dbtx
                    .get_value(&WithdrawalIncurredFeeKey(out_point))
                    .await
                    .map_or(0, |f| f.0)
                    .saturating_add(share.0);
                dbtx.insert_entry(&WithdrawalIncurredFeeKey(out_point), &UsdtAmount(accrued))
                    .await;
            }

            if n <= 1 {
                // Isolated (singleton) failure: this withdrawal alone reverts
                // even with no other withdrawal sharing its batch -- it IS the
                // poison. Terminal, and now REFUNDED: reissue its e-cash minus
                // the incurred gas accumulated above (security finding 09).
                // Not re-queued (see the doc comment above for why re-queueing
                // here would rebuild the identical failing singleton forever).
                for &out_point in outpoints {
                    self.create_withdrawal_refund(
                        dbtx,
                        out_point,
                        "transfer reverts when isolated (recipient likely blacklisted/paused)"
                            .to_string(),
                    )
                    .await;
                }
            } else {
                // Not yet isolated: re-queue every covered withdrawal, but cap
                // the next batch that may include any of them to half this
                // batch's size, deterministically splitting the failing group
                // down towards singletons. The incurred-fee accumulator above
                // persists across these re-queues.
                for &out_point in outpoints {
                    dbtx.insert_entry(&WithdrawalStateKey(out_point), &WithdrawalState::Queued)
                        .await;
                    dbtx.insert_entry(&WithdrawalBatchCapKey(out_point), &split_cap)
                        .await;
                }
            }
        }

        if obs.success {
            info!(
                target: "usdt",
                count = n,
                paid_out = swept.0,
                block = obs.block,
                pool_balance_after = pool.balance.0,
                new_pool_nonce = pool.nonce,
                "withdrawal batch CONFIRMED on-chain; withdrawals settled"
            );
        } else if n <= 1 {
            warn!(
                target: "usdt",
                count = n,
                block = obs.block,
                new_pool_nonce = pool.nonce,
                "singleton withdrawal batch REVERTED on-chain in isolation; withdrawal marked \
                 terminal Failed and its e-cash reissued as a refund minus incurred gas (sec-09)"
            );
        } else {
            warn!(
                target: "usdt",
                count = n,
                split_cap,
                block = obs.block,
                new_pool_nonce = pool.nonce,
                "withdrawal batch REVERTED on-chain; withdrawals returned to Queued with a \
                 halved batch cap for isolation retry (pool balance untouched)"
            );
        }
    }

    /// Turns a terminally-failed withdrawal into a reissued-e-cash refund
    /// (security finding 09), the shared body of BOTH terminal-`Failed` sites
    /// ([`Usdt::apply_withdraw_confirmed`]'s isolated-singleton revert and
    /// [`Usdt::process_replace_user_op`]'s over-ceiling reprice-abort).
    ///
    /// The withdrawal's `(amount + max_fee)` e-cash was burned the instant
    /// `process_output` accepted it; here it is reissued MINUS the gas already
    /// incurred on-chain (`WithdrawalIncurredFeeKey`, clamped so the refund is
    /// never negative) as a [`Refund`] record claimable ONLY by the original
    /// withdrawer's `refund_pubkey` (see [`UsdtInput::RefundV0`]). Concretely:
    ///
    /// 1. Load the queued [`UsdtWithdrawalV0`] (its `amount`/`max_fee`/
    ///    `refund_pubkey`) and the incurred-fee accumulator (absent == 0).
    /// 2. `refund = (amount + max_fee) - min(incurred, amount + max_fee)`.
    /// 3. Write `RefundKey(out_point) -> Refund { refund, refund_pubkey, reason
    ///    }` (the liability now tracked as the refund).
    /// 4. Remove `UnclaimedWithdrawalKey`, `WithdrawalIncurredFeeKey`, and
    ///    `WithdrawalBatchCapKey` for `out_point` (the withdrawal is terminal).
    /// 5. Set `WithdrawalStateKey(out_point) = Failed { reason }` for status.
    ///
    /// The `UnclaimedWithdrawal` -> `Refund` swap is atomic within `dbtx`, so
    /// `audit` (which subtracts each live `UnclaimedWithdrawal.amount` AND each
    /// live `Refund.amount`) never double-counts: exactly one of the two
    /// exists for a given `out_point` at any time, and the refund is settled
    /// the instant its `RefundV0` claim removes the `RefundKey`.
    ///
    /// # Determinism (consensus-critical)
    ///
    /// A pure function of committed DB state + the passed `reason`: reads only
    /// the withdrawal and incurred-fee records, writes deterministically. No
    /// RPC, no wall-clock, no `our_peer_id` -- every guardian processing the
    /// same terminal transition writes the identical `Refund`.
    async fn create_withdrawal_refund(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
        reason: String,
    ) {
        let Some(withdrawal) = dbtx.get_value(&UnclaimedWithdrawalKey(out_point)).await else {
            // Defensive: nothing left to refund for this out_point (already
            // settled or refunded). Still record the terminal state so
            // `withdrawal_status` reports it, but never fabricate a second
            // refund -- that would risk reissuing e-cash twice.
            dbtx.insert_entry(
                &WithdrawalStateKey(out_point),
                &WithdrawalState::Failed { reason },
            )
            .await;
            return;
        };

        let gross = withdrawal.amount.0.saturating_add(withdrawal.max_fee.0);
        let incurred = dbtx
            .get_value(&WithdrawalIncurredFeeKey(out_point))
            .await
            .map_or(0, |f| f.0)
            .min(gross);
        let refund_amount = UsdtAmount(gross.saturating_sub(incurred));

        dbtx.insert_entry(
            &RefundKey(out_point),
            &Refund {
                amount: refund_amount,
                refund_pubkey: withdrawal.refund_pubkey,
                reason: reason.clone(),
            },
        )
        .await;
        dbtx.remove_entry(&UnclaimedWithdrawalKey(out_point)).await;
        dbtx.remove_entry(&WithdrawalIncurredFeeKey(out_point))
            .await;
        dbtx.remove_entry(&WithdrawalBatchCapKey(out_point)).await;
        dbtx.insert_entry(
            &WithdrawalStateKey(out_point),
            &WithdrawalState::Failed { reason },
        )
        .await;

        info!(
            target: "usdt",
            %out_point,
            refund_amount = refund_amount.0,
            incurred_gas = incurred,
            "withdrawal terminally FAILED; reissued e-cash refund created (claimable once by the \
             original withdrawer)"
        );
    }

    /// Reports `claim_pk`'s deposit account state: `claimable` is
    /// `credited - claimed` (saturating). Returns all-zero amounts (with the
    /// derived `account` still populated) if no [`DepositRecord`] exists yet,
    /// so a client can poll this before any credit has landed.
    async fn handle_deposit_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        claim_pk: secp256k1::PublicKey,
    ) -> DepositStatusResponse {
        let account = derive_deposit_account(
            &self.cfg.consensus.group_public_key,
            self.cfg.consensus.account_factory,
            self.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        let (credited, claimed) = dbtx
            .get_value(&DepositRecordKey(account))
            .await
            .map_or((UsdtAmount(0), UsdtAmount(0)), |record| {
                (record.credited, record.claimed)
            });

        DepositStatusResponse {
            account,
            credited,
            claimed,
            claimable: UsdtAmount(credited.0.saturating_sub(claimed.0)),
        }
    }

    /// Reports `out_point`'s consensus-agreed [`WithdrawalStatus`] (Phase 8,
    /// Task 3): the server-only [`WithdrawalState`] (`Queued`/`Signing`/
    /// `Submitted`/`Confirmed`/`Failed`) mapped 1:1 onto its wasm-safe
    /// `-common` mirror, or [`WithdrawalStatus::Unknown`] if no
    /// [`WithdrawalStateKey`] record exists at all (e.g. a typo'd or
    /// not-yet-processed `OutPoint`). Read-only, mirrors
    /// [`Self::handle_deposit_status`].
    async fn handle_withdrawal_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> WithdrawalStatusResponse {
        let status = match dbtx.get_value(&WithdrawalStateKey(out_point)).await {
            None => WithdrawalStatus::Unknown,
            Some(WithdrawalState::Queued) => WithdrawalStatus::Queued,
            Some(WithdrawalState::Signing(op_hash)) => WithdrawalStatus::Signing { op_hash },
            Some(WithdrawalState::Submitted(op_hash)) => WithdrawalStatus::Submitted { op_hash },
            Some(WithdrawalState::Confirmed { block }) => WithdrawalStatus::Confirmed { block },
            Some(WithdrawalState::Failed { reason }) => WithdrawalStatus::Failed { reason },
        };

        WithdrawalStatusResponse { status }
    }

    /// Reports the live refund record for `out_point` (security finding 09):
    /// the reissued-e-cash `(amount, reason)` a `UsdtInput::RefundV0` can
    /// claim, or `None` if no [`RefundKey`] exists (the withdrawal never
    /// failed, or its refund was already claimed and the record removed). A
    /// client uses `amount` to set its `ClientInput.amounts` so the reissued
    /// e-cash mints and the claim transaction balances. Read-only, mirrors
    /// [`Self::handle_withdrawal_status`] -- reads consensus DB, so any
    /// guardian answers identically.
    async fn handle_refund_status(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        out_point: OutPoint,
    ) -> RefundStatusResponse {
        let refund = dbtx
            .get_value(&RefundKey(out_point))
            .await
            .map(|r| RefundInfo {
                amount: r.amount,
                reason: r.reason,
            });

        RefundStatusResponse { refund }
    }

    /// Reports the federation's current withdrawal fee quote (Phase 8, Task
    /// 1): `max_fee` is the minimum fee a `UsdtOutput::V0` must offer right
    /// now, derived entirely from the consensus-agreed `FeeVote` median, so
    /// any guardian answers identically. Read-only.
    ///
    /// `available` (misc #4, finding 06's client-confusion facet) is `false`
    /// when there is no `FeeVote` median yet, or the quote overflows -- in
    /// that case `max_fee` is a non-authoritative `UsdtAmount(0)`
    /// placeholder, distinct from a real free quote. `process_output` is
    /// what actually enforces `NoFeeQuoteAvailable`/`FeeQuoteOverflow` at
    /// submission time regardless of what this endpoint reports, so
    /// `available: false` here can never itself be used to withdraw for
    /// free -- it exists purely so callers can avoid submitting against a
    /// placeholder quote. When `available` is `true`, `max_fee` is
    /// byte-identical to what this endpoint computed before `available`
    /// existed.
    async fn handle_withdraw_fee_quote(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> WithdrawFeeQuoteResponse {
        let median = self.fee_vote_median(dbtx).await;
        let quote = median.and_then(|median| withdrawal_fee_quote(&median));

        WithdrawFeeQuoteResponse {
            max_fee: quote.unwrap_or(UsdtAmount(0)),
            valid_blocks: FEE_QUOTE_VALID_BLOCKS,
            available: quote.is_some(),
        }
    }

    /// Reports the federation's current deposit fee quote, mirroring
    /// [`Self::handle_withdraw_fee_quote`] exactly (including the
    /// `available` semantics): `fee` is the minimum fee a `UsdtInput::V0`
    /// must offer right now, derived entirely from the consensus-agreed
    /// `FeeVote` median.
    async fn handle_deposit_fee_quote(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> DepositFeeQuoteResponse {
        let median = self.fee_vote_median(dbtx).await;
        let quote = median.and_then(|median| deposit_fee_quote(&median));

        DepositFeeQuoteResponse {
            fee: quote.unwrap_or(UsdtAmount(0)),
            valid_blocks: FEE_QUOTE_VALID_BLOCKS,
            available: quote.is_some(),
        }
    }

    /// Processes one `MpcRound` chunk consensus item (the body of
    /// `process_consensus_item`'s `MpcRound` arm, extracted so that method
    /// stays under the line limit).
    ///
    /// # Determinism (consensus-critical)
    ///
    /// Everything here that writes the consensus DB or decides `Ok`/`Err` is a
    /// pure function of the ordered `item`, prior consensus-DB state
    /// (`SigningSession`/`MpcRoundChunkKey`), and config (`signers`) —
    /// byte-identical on every guardian, signer or not. The ONLY consensus-DB
    /// writes are the `MpcRoundChunkKey` insert and the `session.round += 1`
    /// bump. The off-thread state-machine interactions
    /// (`submit_round`/`into_output`) and the `completed_signatures` write are
    /// guardian-LOCAL and MUST NOT feed either. Reassembly (concatenating a
    /// peer's chunks `0..C` in ascending index) is likewise a pure function of
    /// the consensus DB, so every signer reassembles identical payloads.
    #[allow(clippy::too_many_lines)]
    async fn process_mpc_round(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        item: MpcRoundItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        let MpcRoundItem {
            session_id,
            round,
            chunk,
            chunk_count,
            payload,
        } = item;

        let session = dbtx
            .get_value(&SigningSessionKey(session_id))
            .await
            .ok_or_else(|| anyhow::anyhow!("MpcRound for unknown signing session"))?;

        ensure!(
            session.signers.contains(&peer_id),
            "MpcRound from a peer outside the session's signer subset"
        );
        ensure!(
            round == session.round,
            "MpcRound for a stale or future round"
        );
        ensure!(
            chunk_count >= 1 && chunk < chunk_count,
            "MpcRound with an out-of-range chunk index or a zero chunk count"
        );

        // Sec-11 hardening: bound a single chunk's size and a round's chunk
        // count BEFORE touching the DB, so a Byzantine selected signer cannot
        // use an oversized payload or an inflated `chunk_count` (up to
        // `u16::MAX`) to bloat the consensus DB.
        ensure!(
            payload.len() <= MPC_ROUND_CHUNK_SIZE,
            "MpcRound chunk payload exceeds MPC_ROUND_CHUNK_SIZE"
        );
        ensure!(
            chunk_count <= MAX_MPC_CHUNKS,
            "MpcRound chunk_count exceeds MAX_MPC_CHUNKS"
        );

        // Sec-11 hardening: this peer's OWN prior chunks for this
        // (session, round) must agree on `chunk_count` (a peer cannot
        // silently change how many chunks it claims to be sending partway
        // through), and their cumulative bytes plus this chunk must stay
        // under MAX_MPC_ROUND_BYTES. Read only THIS peer's chunks (not the
        // whole round) -- cheaper, and all that either check needs.
        let existing_peer_chunks: Vec<(MpcRoundChunkKey, MpcRoundChunk)> = dbtx
            .find_by_prefix(&MpcRoundChunkSessionRoundPeerPrefix(
                session_id, round, peer_id,
            ))
            .await
            .collect()
            .await;
        let mut stored_bytes: usize = 0;
        for (_, existing) in &existing_peer_chunks {
            ensure!(
                existing.count == chunk_count,
                "MpcRound chunk_count inconsistent with prior chunks from this peer"
            );
            stored_bytes = stored_bytes.saturating_add(existing.bytes.len());
        }
        ensure!(
            stored_bytes.saturating_add(payload.len()) <= MAX_MPC_ROUND_BYTES,
            "MpcRound cumulative bytes exceed MAX_MPC_ROUND_BYTES"
        );

        // Redundancy guard (unbounded-history rule): a repeat chunk for the
        // same (session, round, peer, chunk) changes no consensus state, so it
        // must be rejected.
        if dbtx
            .insert_entry(
                &MpcRoundChunkKey(session_id, round, peer_id, chunk),
                &MpcRoundChunk {
                    count: chunk_count,
                    bytes: payload,
                },
            )
            .await
            .is_some()
        {
            bail!("redundant MpcRound chunk");
        }

        // Ordered by ascending subset position (the sorted signer list), so
        // every signer reassembles and submits the round's payloads to its
        // state machine in the identical party order.
        let mut signers = session.signers.clone();
        signers.sort_unstable();

        // Every peer's chunks for this round, grouped by peer. Reading the
        // whole (session, round) prefix once and grouping is a pure function
        // of the consensus DB.
        let mut chunks_by_peer: BTreeMap<PeerId, BTreeMap<u16, MpcRoundChunk>> = BTreeMap::new();
        let round_chunks: Vec<(MpcRoundChunkKey, MpcRoundChunk)> = dbtx
            .find_by_prefix(&MpcRoundChunkSessionRoundPrefix(session_id, round))
            .await
            .collect()
            .await;
        for (MpcRoundChunkKey(_, _, peer, idx), value) in round_chunks {
            chunks_by_peer.entry(peer).or_default().insert(idx, value);
        }

        // A peer is complete when, among its chunks, it has some `count = C`
        // and exactly chunks `0..C` all present. Derive each peer's `C` from
        // its own chunks (do not assume a shared count).
        let peer_complete = |peer: &PeerId| -> bool {
            let Some(peer_chunks) = chunks_by_peer.get(peer) else {
                return false;
            };
            let Some((_, first)) = peer_chunks.iter().next() else {
                return false;
            };
            let count = first.count;
            usize::from(count) == peer_chunks.len()
                && (0..count).all(|i| peer_chunks.contains_key(&i))
        };

        if signers.iter().all(peer_complete) {
            // Every signer's full payload for this round is in — advance the
            // consensus round counter. DETERMINISTIC: every guardian (signer or
            // not) performs exactly this write.
            let mut advanced = session.clone();
            advanced.round += 1;
            // A round advancing is progress: reset the `timed_out` baseline
            // so a healthy, slowly-progressing session is never mistaken for
            // a stalled one. Deterministic — `consensus_block_count` is a
            // pure function of the consensus DB.
            advanced.last_progress_block = self.consensus_block_count(dbtx).await;
            dbtx.insert_entry(&SigningSessionKey(session_id), &advanced)
                .await;

            // Guardian-LOCAL, signer-only: reassemble each signer's full
            // payload and feed it to this guardian's off-thread state machine;
            // if it then finishes, stash the assembled signature. Never touches
            // the consensus DB or the `Ok`/`Err` decision -- so a problem here
            // must be handled by skipping the local submission, NOT by
            // returning `Err` (that would roll back this transaction's
            // already-committed, deterministic round-advance write above and
            // desync this guardian's DB from a non-signer's).
            if session.signers.contains(&self.our_peer_id) {
                // Sec-11 defense in depth: insert-time per-peer byte caps
                // already make this unreachable, but pre-compute each
                // signer's total reassembled length and refuse to allocate
                // if one ever exceeds MAX_MPC_ROUND_BYTES anyway, rather than
                // trusting stored chunk metadata blindly.
                let peer_totals: BTreeMap<PeerId, usize> = signers
                    .iter()
                    .map(|peer| {
                        let peer_chunks = chunks_by_peer
                            .get(peer)
                            .expect("every signer was just confirmed complete");
                        (
                            *peer,
                            peer_chunks.values().map(|c| c.bytes.len()).sum::<usize>(),
                        )
                    })
                    .collect();

                if let Some((oversized_peer, total_len)) = peer_totals
                    .iter()
                    .map(|(&peer, &total_len)| (peer, total_len))
                    .find(|&(_, total_len)| total_len > MAX_MPC_ROUND_BYTES)
                {
                    warn!(
                        target: "usdt",
                        ?session_id,
                        round = advanced.round,
                        peer = ?oversized_peer,
                        total_len,
                        "reassembled MpcRound payload exceeds MAX_MPC_ROUND_BYTES; skipping \
                         local signer submission for this round (insert-time caps should make \
                         this unreachable)"
                    );
                } else {
                    let mut payloads = Vec::with_capacity(signers.len());
                    for peer in &signers {
                        let peer_chunks = chunks_by_peer
                            .get(peer)
                            .expect("every signer was just confirmed complete");
                        let mut reassembled = Vec::with_capacity(peer_totals[peer]);
                        for idx in
                            0..u16::try_from(peer_chunks.len()).expect("chunk count fits in u16")
                        {
                            reassembled.extend_from_slice(
                                &peer_chunks
                                    .get(&idx)
                                    .expect("chunks 0..len were just confirmed present")
                                    .bytes,
                            );
                        }
                        payloads.push(reassembled);
                    }
                    self.advance_local_signer(session_id, advanced.round, payloads)
                        .await;
                }
            }
        }

        Ok(())
    }

    /// Processes one `RotateSigning` consensus item (the body of
    /// `process_consensus_item`'s `RotateSigning` arm): fails a stalled,
    /// timed-out signing attempt and deterministically starts the next one
    /// under a rotated signer subset.
    ///
    /// # Determinism (consensus-critical)
    ///
    /// A pure function of the item, prior consensus-DB state
    /// (`SigningSession`/`BlockCountVoteKey`), and config — byte-identical on
    /// every guardian, signer or not, and independent of `our_peer_id`. Both
    /// `ensure!` gates read only consensus state: `timed_out` folds in
    /// `consensus_block_count` (the median of `BlockCountVoteKey` votes,
    /// identical everywhere), so a premature or stale rotate is rejected
    /// identically on every guardian. The consensus-DB writes (old attempt ->
    /// `Failed`, new `SigningSession`) are identical everywhere; the only
    /// `our_peer_id`-conditional part is the in-memory signer spawn INSIDE
    /// `start_session`, a guardian-local side effect. Rejecting a
    /// non-`InProgress` session upholds the unbounded-history rule and dedups a
    /// repeat rotate of the same attempt.
    async fn process_rotate_signing(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        session_id: SigningSessionId,
    ) -> anyhow::Result<()> {
        let session = dbtx
            .get_value(&SigningSessionKey(session_id))
            .await
            .ok_or_else(|| anyhow::anyhow!("RotateSigning for unknown signing session"))?;

        ensure!(
            matches!(session.state, SessionState::InProgress),
            "RotateSigning for a non-in-progress session"
        );
        ensure!(
            self.timed_out(dbtx, &session).await,
            "RotateSigning for a session that has not timed out"
        );

        // Fail the timed-out attempt, then deterministically start the next
        // one (fresh id, rotated subset, `attempt + 1`).
        let mut failed = session.clone();
        failed.state = SessionState::Failed;
        dbtx.insert_entry(&SigningSessionKey(session_id), &failed)
            .await;

        // Sec-11 hardening: a failed attempt's `MpcRoundChunk` records serve
        // no further purpose -- GC them all (every round, every peer) in one
        // sweep so they don't linger in the consensus DB across attempts.
        // Deterministic: every guardian sweeps the identical prefix.
        dbtx.remove_by_prefix(&MpcRoundChunkSessionPrefix(session_id))
            .await;

        self.start_session(dbtx, session.purpose, session.digest, session.attempt + 1)
            .await;

        Ok(())
    }

    /// Processes one `MpcSignature` consensus item (the body of
    /// `process_consensus_item`'s `MpcSignature` arm): verifies a signer's
    /// proposed signature against the DKG group key and, if valid, writes it
    /// to the consensus `SigningSession` as the federation-agreed record.
    ///
    /// # Determinism (consensus-critical)
    ///
    /// A pure function of the item, prior consensus-DB state
    /// (`SigningSession`, and -- for a `SigningPurpose::UserOp` session --
    /// its `PendingUserOp`), and config (`group_public_key`) --
    /// byte-identical on every guardian, signer or not, and independent of
    /// `our_peer_id`. The consensus-DB writes are `SigningSessionKey`'s
    /// `state -> Completed(signature)` and, for a `UserOp`-purpose session
    /// only, the deterministic `SubmittedUserOp` insert / `PendingUserOp`
    /// removal (Phase 7, Task 5) described below. Verifying the signature
    /// against the group key BEFORE writing it (rather than trusting the
    /// proposer) is a Byzantine guard: a malformed or forged proposal must
    /// never enter the agreed record, no matter which peer proposed it.
    ///
    /// **`UserOp` finalization (Phase 7, Task 5; sec-01 hardening).**
    /// `SigningPurpose::UserOp(op_hash)` is the ONLY purpose a signing
    /// session can have, and a session is only ever authorized to finalize
    /// if a live `PendingUserOp` still backs its `op_hash` -- this is what
    /// makes "verified against the group key" and "authorized to act" two
    /// separate checks instead of one. If no `PendingUserOp` is found (it
    /// was never created, or a racing attempt already consumed it), this
    /// method returns `Err` and -- critically -- does NOT write
    /// `SessionState::Completed`, so a signature with no backing
    /// consensus-approved record can never be finalized or persisted as an
    /// agreed outcome (see `mpc_signature_without_pending_user_op_is_rejected`
    /// in this module's tests). Otherwise, this assembles the 65-byte
    /// Ethereum `SignedUserOp` from the now-verified compact `(r, s)` (via
    /// [`assemble_eth_signature`], brute-forcing the recovery id against the
    /// group-key owner -- deterministic, and, since `signature` already
    /// verified against `group_public_key` over `session.digest` above,
    /// mathematically guaranteed to succeed) and writes it as a
    /// `SubmittedUserOp`, clearing the `PendingUserOp`. This is done in the
    /// SAME arm (not a separate consensus item) because the agreed signature
    /// is already fully determined by this item alone -- every guardian,
    /// including non-signers, computes the identical `SignedUserOp` from it.
    /// All fallible steps (signature parse/verify, signature assembly, the
    /// `PendingUserOp` lookup) happen BEFORE any write in this function, so
    /// either everything here commits or nothing does.
    async fn process_mpc_signature(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        session_id: SigningSessionId,
        signature: Vec<u8>,
    ) -> anyhow::Result<()> {
        let session = dbtx
            .get_value(&SigningSessionKey(session_id))
            .await
            .ok_or_else(|| anyhow::anyhow!("MpcSignature for unknown signing session"))?;

        ensure!(
            !matches!(session.state, SessionState::Completed(_)),
            "redundant MpcSignature"
        );

        let sig = secp256k1::ecdsa::Signature::from_compact(&signature)
            .map_err(|_| anyhow::anyhow!("malformed signature"))?;
        secp256k1::Secp256k1::verification_only()
            .verify_ecdsa(
                &secp256k1::Message::from_digest(session.digest),
                &sig,
                &self.cfg.consensus.group_public_key,
            )
            .map_err(|_| anyhow::anyhow!("MpcSignature does not verify against the group key"))?;

        // Prepare the UserOp-finalization write BEFORE any write happens
        // below -- see this method's doc comment. `SigningPurpose` has only
        // one production variant, so this match is exhaustive: there is no
        // purpose that can reach `Completed` without an authorizing
        // `PendingUserOp` record.
        let SigningPurpose::UserOp(op_hash) = session.purpose;
        let pending = dbtx
            .get_value(&PendingUserOpKey(op_hash))
            .await
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "MpcSignature for session {session_id:?} (op_hash {op_hash:?}) has no live \
                 PendingUserOp backing it -- refusing to finalize an unauthorized signature"
                )
            })?;
        let compact: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("MPC signature is not the expected 64-byte compact length")
        })?;
        let owner = evm_address(&self.cfg.consensus.group_public_key);
        let eth_sig = assemble_eth_signature(compact, session.digest, owner).map_err(|err| {
            anyhow::anyhow!(
                "failed to assemble the Ethereum signature for completed UserOp session \
                 {session_id:?} (op_hash {op_hash:?}): {err}"
            )
        })?;

        let mut completed = session;
        completed.state = SessionState::Completed(signature);
        dbtx.insert_entry(&SigningSessionKey(session_id), &completed)
            .await;

        let submitted_block = self.consensus_block_count(dbtx).await;
        let signed = SignedUserOp {
            unsigned: pending.op,
            signature: eth_sig.to_vec(),
        };
        dbtx.insert_entry(
            &SubmittedUserOpKey(op_hash),
            &SubmittedUserOp {
                signed,
                // Carried forward verbatim (Phase 8, Task 2) so
                // `apply_user_op_confirmed` knows purely from consensus
                // DB state whether this op is a `DeployAndSweep` or a
                // `Withdraw` once it confirms -- see
                // `SubmittedUserOp::purpose`'s doc comment.
                purpose: pending.purpose,
                submitted_block,
                // A freshly-finalized op is never superseded (security finding
                // 03); only `process_replace_user_op` ever sets this.
                superseded: false,
            },
        )
        .await;
        dbtx.remove_entry(&PendingUserOpKey(op_hash)).await;

        // Sec-11 hardening: this session is now Completed and its chunks
        // will never be read again -- GC them all (every round, every peer)
        // in one sweep, mirroring `process_rotate_signing`'s GC of a
        // failed attempt's chunks. Deterministic: every guardian sweeps the
        // identical prefix.
        dbtx.remove_by_prefix(&MpcRoundChunkSessionPrefix(session_id))
            .await;

        info!(
            target: "usdt",
            ?op_hash,
            "MPC signature verified; UserOp finalized to SubmittedUserOp (submitter will broadcast handleOps)"
        );

        Ok(())
    }

    /// The deterministic signer subset for a session's `(digest, attempt)`:
    /// a combination schedule that, over one full period of `C(n, t)`
    /// attempts, enumerates EVERY size-`t` subset of the `n` peers exactly
    /// once (security finding 10). This guarantees liveness under any
    /// `f = NumPeers::max_evil()`-sized Byzantine/offline set: since
    /// `t = n - f`, the all-honest complement of any tolerated faulty set is
    /// itself one size-`t` subset, so it is guaranteed to be reached within
    /// `C(n, t)` attempts. The previous contiguous-rotating-window schedule
    /// only ever tried `n` of the `C(n, t)` subsets, which for `f >= 2` can
    /// permanently miss the all-honest subset (see
    /// `security-review/10-medium-signer-rotation-byzantine-liveness.md`).
    ///
    /// Returned in the same canonical sorted order
    /// [`spawn_signing_session`]/[`process_mpc_round`] use everywhere else,
    /// so every guardian independently agrees on both the membership and the
    /// party ordering of each attempt's subset.
    ///
    /// A pure function of `num_peers`, `digest`, and `attempt` — no
    /// RPC/wall-clock/`our_peer_id` — so every guardian computes the
    /// identical subset for the same `(digest, attempt)`:
    /// 1. Enumerate all `C(n, t)` size-`t` combinations of `0..n` in a fixed
    ///    lexicographic order (see [`t_combinations`]).
    /// 2. Derive a per-session seed from the first 8 bytes of `digest`, so
    ///    different sessions start their walk at different offsets (spreads
    ///    load across guardians) without affecting coverage.
    /// 3. `idx = (seed + attempt) % C(n, t)`. Because the stride over `attempt`
    ///    is 1 and `gcd(1, C(n, t)) = 1`, a single session's attempts `0, 1,
    ///    .., C(n, t) - 1` visit every combination exactly once before
    ///    repeating (a full-period walk) — see
    ///    `rotation_covers_every_combination_within_period`.
    fn signer_subset(&self, digest: &[u8; 32], attempt: u32) -> Vec<PeerId> {
        let ids: Vec<PeerId> = self.num_peers.peer_ids().collect();
        let t = self.num_peers.threshold();
        let combos = t_combinations(&ids, t);
        let period = combos.len();
        let seed = u64::from_be_bytes(
            digest[0..8]
                .try_into()
                .expect("digest is a fixed-size [u8; 32]; the first 8 bytes always fit"),
        );
        // Reduce `(seed + attempt) mod period` in u128 so the sum can never
        // overflow (which would shift residues by `2^64 mod period != 0` and
        // skip combinations) and no 32-bit-target truncation of `seed` occurs.
        // The result is < period (a usize), so `usize::try_from` always succeeds.
        let idx =
            usize::try_from((u128::from(seed) + u128::from(attempt)) % u128::from(period as u64))
                .expect("value is < period, which is a usize");
        // Already sorted: `t_combinations` builds each combination from
        // ascending indices into the already-sorted `ids`.
        combos[idx].clone()
    }

    /// Proposes a [`UsdtConsensusItem::RotateSigning`] for every `session` in
    /// `sessions` that has stalled past the timeout, so
    /// `process_consensus_item` fails that attempt and starts the next under a
    /// rotated signer subset. Detection is deterministic (via
    /// `consensus_block_count`, never wall-clock). Already-`Failed` sessions
    /// are skipped as a cheap dedup; `timed_out` also rejects them (only
    /// `InProgress` can time out), and the `RotateSigning` arm's guards are
    /// what actually enforce exactly-once rotation. Proposed by every guardian,
    /// signer or not, so rotation does not depend on the previous subset
    /// staying live. Read-only: makes no consensus-DB write.
    async fn propose_timed_out_rotations(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        sessions: &[(SigningSessionId, SigningSession)],
    ) -> Vec<UsdtConsensusItem> {
        let mut items = Vec::new();
        for (session_id, session) in sessions {
            if matches!(session.state, SessionState::Failed) {
                continue;
            }
            if self.timed_out(dbtx, session).await {
                items.push(UsdtConsensusItem::RotateSigning {
                    session_id: *session_id,
                });
            }
        }
        items
    }

    /// Proposes a [`UsdtConsensusItem::ReplaceUserOp`] for every
    /// `SubmittedUserOp` that has gone unconfirmed past
    /// [`submitted_op_timeout_blocks`] (security finding 03), so
    /// `process_consensus_item` times it out and rebuilds it at a higher fee
    /// under the SAME `EntryPoint` `(sender, nonce)`. Mirrors
    /// [`Usdt::propose_timed_out_rotations`] exactly: a deterministic,
    /// consensus-DB-only judgement (via `consensus_block_count`, never
    /// wall-clock), proposed by every guardian, signer or not. Read-only:
    /// makes no consensus-DB write.
    ///
    /// Already-`superseded` ops are skipped -- they have already been replaced
    /// and are kept only so a late confirmation of them still settles (the
    /// RBF-nonce safety invariant); re-timing them out would rebuild a THIRD
    /// op at the same nonce needlessly. The `process_replace_user_op` arm's
    /// own guards (existence, not-superseded, re-checked timeout) are what
    /// actually enforce exactly-once replacement.
    async fn propose_replace_user_ops(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<UsdtConsensusItem> {
        let ccount = self.consensus_block_count(dbtx).await;
        let submitted: Vec<(SubmittedUserOpKey, SubmittedUserOp)> = dbtx
            .find_by_prefix(&SubmittedUserOpPrefix)
            .await
            .collect()
            .await;
        let mut items = Vec::new();
        for (SubmittedUserOpKey(op_hash), s) in submitted {
            if s.superseded {
                continue;
            }
            if ccount
                > s.submitted_block
                    .saturating_add(submitted_op_timeout_blocks())
            {
                items.push(UsdtConsensusItem::ReplaceUserOp { op_hash });
            }
        }
        items
    }

    /// Processes one [`UsdtConsensusItem::ReplaceUserOp`] (security finding
    /// 03): times out a stuck/underpriced `SubmittedUserOp` and REPLACES it
    /// with a higher-fee op at the SAME `EntryPoint` `(sender, nonce)`, so the
    /// old and replacement ops are mutually exclusive on-chain (the
    /// `EntryPoint` includes at most one op per `(sender, nonce)`).
    ///
    /// # RBF-nonce safety (the double-execution guard)
    ///
    /// The OLD op is marked `superseded` and KEPT, not removed: if it actually
    /// landed on-chain, a late `UserOpConfirmed` vote for its hash still passes
    /// the existence check in `process_consensus_item` and settles. Because the
    /// replacement is the old op with ONLY its two fee fields bumped, the two
    /// share byte-identical `call_data`/`sender`/`nonce`/`init_code`, and
    /// settlement is a pure function of `purpose` + the confirmed op's own
    /// calldata -- so whichever of the chain confirms settles identically. The
    /// moment any member confirms, [`Usdt::purge_user_op_nonce_chain`] removes
    /// the whole `(sender, nonce)` chain, so settlement is exactly-once.
    ///
    /// # Determinism (consensus-critical)
    ///
    /// A pure function of the item, prior consensus-DB state (the
    /// `SubmittedUserOp`, its covered `UnclaimedWithdrawal`s, and the fee-vote
    /// median), and config -- byte-identical on every guardian, signer or not,
    /// independent of `our_peer_id`. The reprice fee comes from the consensus
    /// `fee_vote_median` (a consensus value), NEVER a guardian-local RPC read:
    /// the fee is part of the signed `userOpHash`, so every guardian MUST build
    /// the identical replacement op. Both no-op gates (`ensure!`/`bail!`) read
    /// only consensus state, so a premature/duplicate/already-superseded
    /// replace is rejected identically everywhere, upholding the
    /// unbounded-history rule (a non-state-changing item returns `Err`, exactly
    /// like [`Usdt::process_rotate_signing`]).
    #[allow(clippy::too_many_lines)]
    async fn process_replace_user_op(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        op_hash: [u8; 32],
    ) -> anyhow::Result<()> {
        let submitted = dbtx
            .get_value(&SubmittedUserOpKey(op_hash))
            .await
            .ok_or_else(|| {
                anyhow::anyhow!("ReplaceUserOp for an unknown/already-cleared SubmittedUserOp")
            })?;

        // Non-state-changing gates (mirror `process_rotate_signing`): a
        // superseded op is already replaced; a not-yet-timed-out op must not be
        // repriced prematurely. Re-checking the timeout here (not just at
        // proposal time) is the deterministic gate every guardian re-evaluates.
        ensure!(
            !submitted.superseded,
            "ReplaceUserOp for an already-superseded op"
        );
        let ccount = self.consensus_block_count(dbtx).await;
        ensure!(
            ccount
                > submitted
                    .submitted_block
                    .saturating_add(submitted_op_timeout_blocks()),
            "ReplaceUserOp for an op that has not timed out"
        );

        // Reprice from the consensus fee median (deterministic). Without one we
        // cannot build a fresh, correctly-priced replacement -- leave the op
        // as-is (non-state-changing) and let a later round retry once a median
        // exists (mirrors `maybe_trigger_sweep`'s defer-on-no-median).
        let median = self.fee_vote_median(dbtx).await.ok_or_else(|| {
            anyhow::anyhow!("ReplaceUserOp deferred: no fee median to reprice from")
        })?;

        let old = submitted.signed.unsigned.clone();

        // Fresh median-derived fee (2x headroom, clamped) -- the SAME formula
        // the builders use -- then bumped >= 10% over the OLD op's fees so a
        // bundler prefers the replacement (ERC-4337 mempool replacement rule).
        // The `GasBounds` receiver is a throwaway: `with_median_fees` only
        // touches the two fee fields.
        let priced =
            GasBounds::DEPLOY_AND_SWEEP_DEVNET.with_median_fees(Some(median.max_fee_per_gas_wei));
        let new_max_fee_per_gas = priced
            .max_fee_per_gas
            .max(bump_10_percent(old.max_fee_per_gas));
        let new_max_priority_fee_per_gas = priced
            .max_priority_fee_per_gas
            .max(bump_10_percent(old.max_priority_fee_per_gas))
            .min(new_max_fee_per_gas);

        // The replacement is the OLD op with ONLY the two fee fields bumped:
        // its calldata/nonce/sender/init_code/gas-limits stay byte-identical,
        // which is what makes settling on whichever confirms produce identical
        // accounting (RBF-nonce safety).
        let mut new_op = old.clone();
        new_op.max_fee_per_gas = new_max_fee_per_gas;
        new_op.max_priority_fee_per_gas = new_max_priority_fee_per_gas;

        // The broadcaster-fronted prefund the replacement will cost, in wei,
        // priced from the op's ACTUAL (already-2x-headroom) fee fields.
        let total_gas_units = old
            .verification_gas_limit
            .saturating_add(old.call_gas_limit)
            .saturating_add(u128::try_from(old.pre_verification_gas).unwrap_or(u128::MAX));
        let gas_cost_wei = total_gas_units.saturating_mul(new_max_fee_per_gas);

        match &submitted.purpose {
            UserOpPurpose::Withdraw { outpoints } => {
                // Ceiling = the sum of the covered withdrawals' committed
                // `max_fee` (what the users agreed to pay). If the repriced op
                // would cost more USDT than that, DON'T replace: terminal-fail
                // every covered withdrawal, reissuing its e-cash as a refund
                // (security finding 09, via `create_withdrawal_refund`), and
                // remove the stuck op (+ its votes).
                let mut ceiling: u64 = 0;
                for &out_point in outpoints {
                    if let Some(w) = dbtx.get_value(&UnclaimedWithdrawalKey(out_point)).await {
                        ceiling = ceiling.saturating_add(w.max_fee.0);
                    }
                }
                let over_ceiling = match fedimint_usdt_common::wei_gas_cost_to_usdt(
                    gas_cost_wei,
                    median.usdt_per_eth_e6,
                ) {
                    Some(cost) => cost.0 > ceiling,
                    // An overflowing (byzantine/degenerate) rate is treated
                    // as unaffordable rather than silently letting an
                    // unbounded prefund through.
                    None => true,
                };
                if over_ceiling {
                    for &out_point in outpoints {
                        // Security finding 09: terminal failure -> reissue the
                        // withdrawal's e-cash as a refund. This repriced op
                        // TIMED OUT and never confirmed on-chain, so it
                        // incurred no gas of its own; the refund deducts only
                        // whatever gas prior confirmed-failed batches already
                        // accumulated into `WithdrawalIncurredFeeKey` (0 for a
                        // withdrawal that only ever timed out).
                        self.create_withdrawal_refund(
                            dbtx,
                            out_point,
                            "gas exceeds committed max_fee".to_string(),
                        )
                        .await;
                    }
                    dbtx.remove_entry(&SubmittedUserOpKey(op_hash)).await;
                    dbtx.remove_by_prefix(&UserOpConfirmedVoteOpPrefix(op_hash))
                        .await;
                    // RBF-nonce cleanup (security finding 03): every withdrawal
                    // covered by this (sender, nonce) is now terminal-`Failed`,
                    // so the WHOLE replacement chain at that nonce is dead. If
                    // this op was itself a replacement, earlier `superseded`
                    // predecessors (and any still-signing sibling) linger in the
                    // DB; `withdraw_batch_in_flight` counts any Submitted
                    // `Withdraw` op IGNORING `superseded`, so an orphaned
                    // predecessor would make it return `true` forever and wedge
                    // ALL future withdrawal batches. Tear down the entire chain
                    // (Submitted/Pending ops + votes + signing sessions) with the
                    // same helper the confirmation path uses -- `op_hash` was
                    // already removed above, so pass it as the `except`. The
                    // covered withdrawals are already terminal-`Failed` with a
                    // refund created above. Deterministic: reads only the
                    // committed DB.
                    self.purge_user_op_nonce_chain(
                        dbtx,
                        submitted.signed.unsigned.sender,
                        submitted.signed.unsigned.nonce,
                        op_hash,
                    )
                    .await;
                    warn!(
                        target: "usdt",
                        ?op_hash,
                        count = outpoints.len(),
                        gas_cost_wei,
                        ceiling,
                        "withdrawal batch reprice exceeds the covered withdrawals' committed \
                         max_fee; marking them Failed (refundable in Phase 6.1) and clearing the \
                         stuck op + its whole replacement chain"
                    );
                    return Ok(());
                }
            }
            UserOpPurpose::DeployAndSweep { .. } => {
                // A sweep's deposit funds are safe on-chain (still
                // `credited - swept`); there is no refund concept. If the
                // repriced fee would exceed the config gas ceiling, DON'T
                // replace -- leave the op as-is (non-state-changing) and warn.
                if new_max_fee_per_gas > SWEEP_MAX_FEE_PER_GAS_WEI {
                    warn!(
                        target: "usdt",
                        ?op_hash,
                        new_max_fee_per_gas,
                        ceiling_wei = SWEEP_MAX_FEE_PER_GAS_WEI,
                        "sweep reprice exceeds the gas ceiling; leaving the op stuck (deposit \
                         funds are safe on-chain, no refund needed)"
                    );
                    bail!("sweep reprice exceeds the gas ceiling; leaving op stuck");
                }
            }
        }

        // Within ceiling: enqueue the replacement + start its signing session,
        // then mark the OLD op superseded (kept live so a late confirm of it
        // still settles -- RBF-nonce safety).
        let new_hash = user_op_hash(
            &new_op,
            self.cfg.consensus.entry_point,
            self.cfg.consensus.chain_id,
        );
        // Defensive idempotency: never clobber an already-enqueued replacement
        // (a fresh `new_hash` makes this unreachable on the honest path).
        ensure!(
            dbtx.get_value(&PendingUserOpKey(new_hash)).await.is_none()
                && dbtx
                    .get_value(&SubmittedUserOpKey(new_hash))
                    .await
                    .is_none(),
            "ReplaceUserOp replacement op is already enqueued"
        );

        dbtx.insert_entry(
            &PendingUserOpKey(new_hash),
            &PendingUserOp {
                op: new_op,
                purpose: submitted.purpose.clone(),
                created_block: ccount,
            },
        )
        .await;

        // Re-tag the covered withdrawals to the replacement's hash (they were
        // `Submitted(old_hash)`); mirrors the build path's `Signing(op_hash)`
        // tag. Purely informational -- `apply_withdraw_confirmed` settles by
        // `outpoints` (from the op's purpose), not by this hash.
        if let UserOpPurpose::Withdraw { outpoints } = &submitted.purpose {
            for &out_point in outpoints {
                dbtx.insert_entry(
                    &WithdrawalStateKey(out_point),
                    &WithdrawalState::Signing(new_hash),
                )
                .await;
            }
        }

        let mut superseded_old = submitted.clone();
        superseded_old.superseded = true;
        dbtx.insert_entry(&SubmittedUserOpKey(op_hash), &superseded_old)
            .await;

        info!(
            target: "usdt",
            ?op_hash,
            ?new_hash,
            new_max_fee_per_gas,
            old_max_fee_per_gas = old.max_fee_per_gas,
            purpose = ?submitted.purpose,
            "SubmittedUserOp timed out; enqueued higher-fee replacement at the same \
             (sender, nonce), old op kept superseded for RBF-nonce safety"
        );

        let digest = eth_signed_message_hash(new_hash);
        self.start_session(dbtx, SigningPurpose::UserOp(new_hash), digest, 0)
            .await;

        Ok(())
    }

    /// Removes the entire in-flight `(sender, nonce)` replacement chain EXCEPT
    /// `except_hash` (the just-confirmed op, whose own removal the caller
    /// handles), the RBF-nonce cleanup for security finding 03. The
    /// `EntryPoint` includes at most one op per `(sender, nonce)`, so once one
    /// member has confirmed (success OR revert -- either consumed the on-chain
    /// nonce), no sibling can ever land; leaving them would keep the in-flight
    /// guards blocking new batches/sweeps and risk a later spurious
    /// timeout/replace acting on a dead nonce. Removes matching
    /// `SubmittedUserOp`s (+ their confirmation votes) AND `PendingUserOp`s
    /// still mid-signing (+ their signing sessions and round chunks). Read
    /// `sender`/`nonce` from each record's own op. Deterministic: scans
    /// committed consensus tables only.
    async fn purge_user_op_nonce_chain(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        sender: fedimint_usdt_common::EvmAddress,
        nonce: alloy::primitives::U256,
        except_hash: [u8; 32],
    ) {
        let submitted: Vec<(SubmittedUserOpKey, SubmittedUserOp)> = dbtx
            .find_by_prefix(&SubmittedUserOpPrefix)
            .await
            .collect()
            .await;
        for (SubmittedUserOpKey(hash), s) in submitted {
            if hash == except_hash {
                continue;
            }
            if s.signed.unsigned.sender == sender && s.signed.unsigned.nonce == nonce {
                dbtx.remove_entry(&SubmittedUserOpKey(hash)).await;
                dbtx.remove_by_prefix(&UserOpConfirmedVoteOpPrefix(hash))
                    .await;
            }
        }

        let pending: Vec<(PendingUserOpKey, PendingUserOp)> = dbtx
            .find_by_prefix(&PendingUserOpPrefix)
            .await
            .collect()
            .await;
        for (PendingUserOpKey(hash), p) in pending {
            if hash == except_hash {
                continue;
            }
            if p.op.sender == sender && p.op.nonce == nonce {
                dbtx.remove_entry(&PendingUserOpKey(hash)).await;
                self.remove_signing_sessions_for_op(dbtx, hash).await;
            }
        }
    }

    /// Removes every `SigningSession` (all attempts) whose purpose is
    /// `SigningPurpose::UserOp(op_hash)`, plus its round chunks -- used by
    /// [`Usdt::purge_user_op_nonce_chain`] to tear down a replacement chain
    /// member that was still mid-signing when a sibling confirmed, so its
    /// orphaned session does not rotate/retry forever (an unbounded
    /// consensus-DB churn) trying to finalize an op whose nonce is already
    /// spent. Deterministic: scans the committed `SigningSession` table.
    async fn remove_signing_sessions_for_op(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        op_hash: [u8; 32],
    ) {
        let sessions: Vec<(SigningSessionKey, SigningSession)> = dbtx
            .find_by_prefix(&SigningSessionPrefix)
            .await
            .collect()
            .await;
        for (SigningSessionKey(id), session) in sessions {
            if session.purpose == SigningPurpose::UserOp(op_hash) {
                dbtx.remove_entry(&SigningSessionKey(id)).await;
                dbtx.remove_by_prefix(&MpcRoundChunkSessionPrefix(id)).await;
            }
        }
    }

    /// Starts (idempotently) a threshold-ECDSA signing session over `digest`
    /// on its `attempt`'th try.
    ///
    /// Writes the consensus [`SigningSession`] — id
    /// [`signing_session_id(&digest, attempt)`][signing_session_id], signer
    /// subset [`signer_subset(&digest, attempt)`][Self::signer_subset], `round:
    /// 0`, [`SessionState::InProgress`] — and no-ops if a session for this
    /// `(digest, attempt)` already exists. If this guardian is in the subset
    /// it also spawns the off-thread signing state machine into
    /// `signing_sessions` and pre-pumps round 0's payload, so the next
    /// `consensus_proposal` can propose it immediately.
    ///
    /// # Determinism
    ///
    /// The consensus-DB write is a pure function of `(purpose, digest,
    /// attempt)`, prior consensus DB state, and `num_peers` — byte-identical
    /// on every guardian. The ONLY `our_peer_id`-conditional part is the
    /// in-memory off-thread signer spawn, a guardian-local side effect that
    /// never touches the consensus DB.
    ///
    /// # Panics
    ///
    /// Panics if this guardian's config is malformed for the signer subset
    /// (see [`spawn_signing_session`]'s panics), or if the in-memory
    /// `signing_sessions` mutex is poisoned (a prior panic while holding it).
    pub async fn start_session(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        purpose: SigningPurpose,
        digest: [u8; 32],
        attempt: u32,
    ) {
        let session_id = signing_session_id(&digest, attempt);
        if dbtx
            .get_value(&SigningSessionKey(session_id))
            .await
            .is_some()
        {
            return;
        }

        let signers = self.signer_subset(&digest, attempt);
        // The block count at creation is this session's initial "progress"
        // baseline for `timed_out` — a session that never sees a round
        // advance still gets `timeout_blocks()` consensus blocks before it
        // is considered stalled, rather than starting out already timed out.
        let last_progress_block = self.consensus_block_count(dbtx).await;

        dbtx.insert_new_entry(
            &SigningSessionKey(session_id),
            &SigningSession {
                purpose,
                digest,
                signers: signers.clone(),
                round: 0,
                state: SessionState::InProgress,
                attempt,
                last_progress_block,
            },
        )
        .await;

        if signers.contains(&self.our_peer_id)
            && let Some(handle) =
                spawn_signing_session(session_id, digest, &signers, self.our_peer_id, &self.cfg)
        {
            let mut slot = SessionSlot {
                handle,
                pending_outgoing: None,
                round: 0,
                done: false,
            };
            pump_slot_outgoing(&mut slot).await;
            self.signing_sessions
                .lock()
                .expect("not poisoned")
                .insert(session_id, slot);
        }
    }

    /// Guardian-LOCAL signer step for a round that just reached consensus:
    /// submits the round's `payloads` (party-ordered by ascending subset
    /// position) to this guardian's off-thread signing state machine, pumps
    /// it, and — once the machine finishes — stores the assembled compact
    /// 64-byte signature in `completed_signatures` and drops the slot.
    ///
    /// # Determinism
    ///
    /// This is IN-MEMORY, signer-only state that must never influence
    /// `process_consensus_item`'s consensus-DB writes or its `Ok`/`Err`
    /// result — those are identical on signers and non-signers. Errors here
    /// (a dead state-machine thread, an unconvertible signature) are
    /// therefore logged and swallowed, never propagated: a signer's local
    /// failure changing control flow would diverge the federation. A guardian
    /// with no slot for `session_id` (not a signer, or restarted mid-session)
    /// simply no-ops.
    async fn advance_local_signer(
        &self,
        session_id: SigningSessionId,
        round: u16,
        payloads: Vec<Vec<u8>>,
    ) {
        let slot = self
            .signing_sessions
            .lock()
            .expect("not poisoned")
            .remove(&session_id);
        let Some(mut slot) = slot else {
            return;
        };

        if let Err(err) = slot.handle.submit_round(payloads).await {
            warn!(
                target: "usdt",
                err = %err.fmt_compact_anyhow(),
                "submitting round payloads to the off-thread signer failed; dropping session"
            );
            return;
        }
        slot.pending_outgoing = None;
        slot.round = round;
        pump_slot_outgoing(&mut slot).await;

        if !slot.done {
            // More rounds to go; park the slot back in the store for the next
            // `consensus_proposal` to pull round `round`'s payload from.
            self.signing_sessions
                .lock()
                .expect("not poisoned")
                .insert(session_id, slot);
            return;
        }

        // Finished: reap the output and stash the compact signature
        // (guardian-local — never the consensus DB).
        match slot.handle.into_output().await {
            Ok(sig) => match convert_signature(sig) {
                Ok(sig) => {
                    let sig_bytes = sig.serialize_compact().to_vec();
                    self.completed_signatures
                        .lock()
                        .expect("not poisoned")
                        .insert(session_id, sig_bytes.clone());
                    // Still guardian-local/in-memory here: proposing this as
                    // the federation-agreed record is the deterministic
                    // consensus step in `consensus_proposal` below.
                    self.pending_signature_proposals
                        .lock()
                        .expect("not poisoned")
                        .push((session_id, sig_bytes));
                }
                Err(err) => warn!(
                    target: "usdt",
                    err = %err.fmt_compact_anyhow(),
                    "off-thread signer produced an unconvertible signature"
                ),
            },
            Err(err) => warn!(
                target: "usdt",
                err = %err.fmt_compact_anyhow(),
                "off-thread signer failed to produce its final output"
            ),
        }
    }
}

/// Splits a signing round's full per-peer payload into
/// [`MPC_ROUND_CHUNK_SIZE`]-byte chunks, so each chunk fits under Fedimint's
/// `AlephBFT` unit byte limit when carried as its own `MpcRound` consensus
/// item.
///
/// A zero-length payload yields a single empty chunk, so the returned length
/// (the `chunk_count` carried on every chunk) is always `>= 1`. Pure and
/// deterministic: every guardian splits an identical payload into identical
/// chunks, and concatenating the result back reproduces `payload` exactly.
fn chunk_payload(payload: &[u8]) -> Vec<Vec<u8>> {
    if payload.is_empty() {
        return vec![Vec::new()];
    }
    payload
        .chunks(MPC_ROUND_CHUNK_SIZE)
        .map(<[u8]>::to_vec)
        .collect()
}

/// Enumerates every size-`t` combination of `items` in a fixed lexicographic
/// order (ordered by ascending index into `items`), used by
/// [`Usdt::signer_subset`] (security finding 10) to build a deterministic
/// combination schedule that is guaranteed to eventually try every `t`-of-`n`
/// signer subset.
///
/// Pure and deterministic: identical `items`/`t` always yield an identical,
/// identically-ordered result on every guardian. `items` is expected to
/// already be sorted (as `NumPeers::peer_ids()` yields), so each returned
/// combination is itself sorted.
///
/// Returns an empty `Vec` if `t > items.len()`; returns a single empty
/// combination if `t == 0`. `n` is always small in practice (a federation's
/// guardian count, realistically <= ~20), so `C(n, t)` is cheap to fully
/// materialize.
fn t_combinations<T: Copy>(items: &[T], t: usize) -> Vec<Vec<T>> {
    let n = items.len();
    if t > n {
        return Vec::new();
    }
    if t == 0 {
        return vec![Vec::new()];
    }

    let mut result = Vec::new();
    // `idx[i]` is the index into `items` for position `i` of the current
    // combination; starts at the lexicographically-first combination
    // `[0, 1, .., t-1]`.
    let mut idx: Vec<usize> = (0..t).collect();
    loop {
        result.push(idx.iter().map(|&i| items[i]).collect());

        // Find the rightmost position that can still be advanced: position
        // `i` can hold at most `i + n - t` (so the remaining `t - 1 - i`
        // positions after it still have room for strictly-increasing
        // indices up to `n - 1`).
        let mut advance_at = None;
        for i in (0..t).rev() {
            if idx[i] < i + n - t {
                advance_at = Some(i);
                break;
            }
        }
        let Some(i) = advance_at else {
            // Every position is already at its maximum: the last
            // combination `[n-t, .., n-1]` was just pushed.
            break;
        };
        idx[i] += 1;
        for j in (i + 1)..t {
            idx[j] = idx[j - 1] + 1;
        }
    }
    result
}

/// The number of consensus blocks a signing session may go without progress
/// (see [`SigningSession::last_progress_block`]'s doc comment) before
/// [`Usdt::timed_out`] considers it stalled. Small under
/// `is_running_in_test_env()` so tests don't have to wait for 50 real
/// consensus blocks to exercise the timeout path; both values are otherwise
/// arbitrary safety margins with no consensus-correctness requirement beyond
/// "every guardian computes the same one" (which `is_running_in_test_env()`
/// does, being a pure function of the process environment, identical across
/// a test federation's guardians).
fn timeout_blocks() -> u64 {
    if is_running_in_test_env() { 2 } else { 50 }
}

/// The number of consensus blocks a `SubmittedUserOp` may remain unconfirmed
/// (past its `submitted_block`) before [`Usdt::propose_replace_user_ops`]
/// proposes timing it out and replacing it at a higher fee (security finding
/// 03). Mirrors [`timeout_blocks`]'s test-scaling exactly: small under
/// `is_running_in_test_env()` so tests don't have to wait for 25 real
/// consensus blocks, and (like `timeout_blocks`) an otherwise-arbitrary
/// safety margin with no consensus-correctness requirement beyond "every
/// guardian computes the same one" (which `is_running_in_test_env()` does,
/// being a pure function of the process environment, identical across a test
/// federation's guardians). Chosen larger than [`timeout_blocks`] in
/// production (25 vs. a signing session's own 50) is deliberate: a submitted
/// op should be given a generous window for on-chain inclusion before being
/// repriced.
fn submitted_op_timeout_blocks() -> u64 {
    if is_running_in_test_env() { 2 } else { 25 }
}

/// Ceiling on a REPRICED sweep (`DeployAndSweep`) op's `max_fee_per_gas`
/// (security finding 03): matches `GasBounds::OP_FEE_CEILING_WEI` (200 gwei),
/// the same cap [`GasBounds::with_median_fees`] clamps a median-derived fee
/// to. A sweep whose 10%-bumped replacement fee would exceed this is NOT
/// replaced -- its deposit funds are safe on-chain (still `credited - swept`),
/// so there is no refund concept and nothing to fail; the op is simply left
/// as-is (see [`Usdt::process_replace_user_op`]'s `DeployAndSweep` arm). This
/// bounds how far repeated repricings can ratchet a stuck sweep's
/// broadcaster-fronted prefund.
const SWEEP_MAX_FEE_PER_GAS_WEI: u128 = 200_000_000_000;

/// Bumps a fee field by >= 10% (ceiling-rounded), the ERC-4337 mempool
/// replacement rule a repriced op must clear so a bundler prefers it over the
/// op it supersedes (security finding 03). Ceiling-rounding guarantees the
/// result is STRICTLY greater than `fee` for any `fee >= 1` (a real op's fee
/// is always floored at 1 gwei), so the replacement is never merely equal to
/// the original. `saturating_add` keeps it panic-free at the `u128` ceiling
/// (unreachable in practice, and the sweep/withdraw ceilings bite first).
fn bump_10_percent(fee: u128) -> u128 {
    fee.saturating_add(fee.div_ceil(10))
}

/// The number of consensus blocks the OLDEST currently-`Queued` withdrawal
/// (by `UsdtWithdrawalV0::requested_block`) may wait before
/// [`Usdt::maybe_trigger_withdrawal_batch`] forces a batch regardless of how
/// few withdrawals are queued (Phase 8, Task 2).
///
/// At ~12s per EVM block, 2 blocks bounds a lone withdrawal's queuing delay
/// to ~24s -- near-immediate, while still coalescing any withdrawals that
/// pile up within that window into one `executeBatch` op (one pool nonce,
/// one MPC signing session). Small under `is_running_in_test_env()`,
/// mirroring [`timeout_blocks`] -- both values are otherwise arbitrary policy
/// knobs (bounding worst-case withdrawal latency vs. batching efficiency)
/// with no consensus-correctness requirement beyond "every guardian computes
/// the same one" (which `is_running_in_test_env()` does, being a pure
/// function of the process environment, identical across a test federation's
/// guardians).
fn batch_interval_blocks() -> u64 {
    if is_running_in_test_env() { 3 } else { 2 }
}

/// The number of `Queued` withdrawals that forces
/// [`Usdt::maybe_trigger_withdrawal_batch`] to batch immediately, regardless
/// of [`batch_interval_blocks`] (Phase 8, Task 2). A plain, non-test-scaled
/// constant (unlike `batch_interval_blocks`): 20 ERC-20 transfers per
/// `executeBatch` is a conservative bound that keeps a single batch's
/// calldata/gas comfortably within typical limits, and a unit test can seed
/// this many queued withdrawals directly without needing to wait on
/// wall-clock/block-count timing.
const BATCH_MAX_ITEMS: usize = 20;

/// Free-function core of [`Usdt::consensus_block_count`], taking `num_peers`
/// by value instead of borrowing it from `&self`, so it can be called both
/// from that method and from any `'static`-spawned background task (which
/// cannot hold a `&Usdt` reference).
async fn consensus_block_count(dbtx: &mut DatabaseTransaction<'_>, num_peers: NumPeers) -> u64 {
    let peer_count = num_peers.total();

    let mut counts = dbtx
        .find_by_prefix(&BlockCountVotePrefix)
        .await
        .map(|entry| entry.1)
        .collect::<Vec<u64>>()
        .await;

    while counts.len() < peer_count {
        counts.push(0);
    }

    counts.sort_unstable();

    counts[peer_count / 2]
}

/// Free-function core of [`Usdt::fee_vote_median`]; see that method's doc
/// comment for the full rationale (in particular why, unlike
/// [`consensus_block_count`], this does NOT zero-pad missing/stale votes out
/// to a peer count).
///
/// `current_block` is the caller's already-computed `consensus_block_count`
/// (threaded in rather than recomputed here so callers that already have it
/// -- e.g. [`Usdt::fee_vote_median`] -- do not pay for a second read of the
/// `BlockCountVote` table).
async fn fee_vote_median(
    dbtx: &mut DatabaseTransaction<'_>,
    num_peers: NumPeers,
    current_block: u64,
) -> Option<FeeVote> {
    let votes: Vec<FeeVote> = dbtx
        .find_by_prefix(&FeeVotePrefix)
        .await
        .map(|entry| entry.1)
        .filter(|stored: &StoredFeeVote| {
            let age = current_block.saturating_sub(stored.recorded_block);
            std::future::ready(age <= FEE_VOTE_TTL_BLOCKS)
        })
        .map(|stored| stored.vote)
        .collect()
        .await;

    if votes.len() < num_peers.threshold() {
        return None;
    }

    let mut max_fee_per_gas_wei: Vec<u64> = votes.iter().map(|v| v.max_fee_per_gas_wei).collect();
    let mut usdt_per_eth_e6: Vec<u64> = votes.iter().map(|v| v.usdt_per_eth_e6).collect();
    max_fee_per_gas_wei.sort_unstable();
    usdt_per_eth_e6.sort_unstable();

    Some(FeeVote {
        max_fee_per_gas_wei: max_fee_per_gas_wei[max_fee_per_gas_wei.len() / 2],
        usdt_per_eth_e6: usdt_per_eth_e6[usdt_per_eth_e6.len() / 2],
    })
}

/// Inserts `(height, hash)` into the [`BlockHashRingKey`] ring -- the
/// canonical-block-hash anchor a later deposit-by-proof verification task
/// checks a claimed inclusion proof's block hash against -- then prunes
/// every entry that has fallen out of the trailing
/// [`BLOCK_HASH_RING_LEN`]-height window ending at `height`, i.e. every
/// entry at height `h` with `h + BLOCK_HASH_RING_LEN <= height`.
///
/// Uses `insert_entry` (not `insert_new_entry`): a caller re-writing the
/// same height (e.g. after a local reorg) overwrites the stored hash rather
/// than panicking. Saturating arithmetic throughout so a `height` near
/// `u64::MAX` cannot overflow the prune comparison.
///
/// Callers are expected to call this with monotonically non-decreasing
/// `height`s; pruning is always relative to the height just written (not the
/// ring's current max), so writing an out-of-order LOWER height does not
/// widen the retained window back out.
///
/// Called from the ordered `process_consensus_item` path
/// (`UsdtConsensusItem::BlockHash`) once a threshold of guardians agree on a
/// confirmation-depth `(height, block_hash)` pair -- never from a
/// guardian-local task (commit-safety constraint).
async fn write_block_hash_ring(dbtx: &mut DatabaseTransaction<'_>, height: u64, hash: [u8; 32]) {
    dbtx.insert_entry(&BlockHashRingKey(height), &hash).await;

    let keys: Vec<BlockHashRingKey> = dbtx
        .find_by_prefix(&BlockHashRingPrefix)
        .await
        .map(|(key, _)| key)
        .collect()
        .await;

    for key in keys {
        if key.0.saturating_add(BLOCK_HASH_RING_LEN) <= height {
            dbtx.remove_entry(&key).await;
        }
    }
}

/// Reads the ring's canonical block hash at `height`, or `None` if `height`
/// was never written or has since fallen out of the retained window (see
/// [`write_block_hash_ring`]).
///
/// The deposit-by-proof anchor read by [`Usdt::process_deposit_proof`]: a
/// proof for a block with no entry here is rejected as not-yet-anchored.
async fn ring_hash_at(dbtx: &mut DatabaseTransaction<'_>, height: u64) -> Option<[u8; 32]> {
    dbtx.get_value(&BlockHashRingKey(height)).await
}

/// The highest height currently present in the ring, or `None` before the
/// first [`write_block_hash_ring`] call.
///
/// Not yet called from production code -- see [`write_block_hash_ring`]'s
/// doc comment.
#[allow(dead_code)]
async fn ring_latest_height(dbtx: &mut DatabaseTransaction<'_>) -> Option<u64> {
    dbtx.find_by_prefix(&BlockHashRingPrefix)
        .await
        .map(|(key, _)| key.0)
        .collect::<Vec<u64>>()
        .await
        .into_iter()
        .max()
}

#[cfg(test)]
mod tests {
    use fedimint_core::bitcoin::Network;
    use fedimint_core::{Amount, BitcoinHash, PeerId, TransactionId};
    use fedimint_usdt_common::{EvmAddress, UsdtInputV0};

    use super::*;

    /// An arbitrary [`InPoint`] for `process_input` tests, which never read
    /// `_in_point` today (the txid/index are irrelevant to claim processing).
    fn test_in_point() -> InPoint {
        InPoint {
            txid: TransactionId::all_zeros(),
            in_idx: 0,
        }
    }

    const NUM_PEERS: u16 = 4;

    #[test]
    fn trusted_dealer_gen_produces_consistent_valid_configs() {
        let peers = (0..NUM_PEERS).map(PeerId::from).collect::<Vec<_>>();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };

        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );
        assert_eq!(server_cfgs.len(), usize::from(NUM_PEERS));

        let typed_cfgs = server_cfgs
            .iter()
            .map(|(peer, cfg)| {
                (
                    *peer,
                    cfg.clone()
                        .to_typed::<UsdtConfig>()
                        .expect("config was just generated by the same configgen"),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let group_public_key = typed_cfgs[&peers[0]].consensus.group_public_key;
        for cfg in typed_cfgs.values() {
            assert_eq!(cfg.consensus.group_public_key, group_public_key);
            assert_eq!(cfg.consensus.threshold, 3);
            assert_eq!(
                fedimint_threshold_ecdsa::group_public_key(&cfg.private.key_share)
                    .expect("valid key share"),
                group_public_key
            );
        }

        for peer in &peers {
            UsdtInit::default()
                .validate_config(peer, server_cfgs[peer].clone())
                .expect("dealer-generated config must validate for every peer");
        }
    }

    #[test]
    fn config_gen_params_flow_into_consensus_and_client_config() {
        let peers = (0..NUM_PEERS).map(PeerId::from).collect::<Vec<_>>();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let params = fedimint_usdt_common::UsdtGenParams {
            usdt_contract: fedimint_usdt_common::EvmAddress([0xab; 20]),
            chain_id: 1,
            confirmation_depth: 6,
            entry_point: fedimint_usdt_common::EvmAddress([0xcd; 20]),
            account_factory: fedimint_usdt_common::EvmAddress([0xce; 20]),
            simple_account_impl: fedimint_usdt_common::EvmAddress([0xcf; 20]),
            check_ttl_blocks: 500,
            broadcaster_min_balance_wei: 1_000,
            eth_usd_price_feed: fedimint_usdt_common::EvmAddress([0xd0; 20]),
            price_feed_max_staleness_secs: 3_600,
        };

        let server_cfgs = UsdtInit::default().trusted_dealer_gen(&peers, &args, &params);
        let cfg0 = server_cfgs[&peers[0]]
            .clone()
            .to_typed::<UsdtConfig>()
            .unwrap();
        assert_eq!(cfg0.consensus.usdt_contract, params.usdt_contract);
        assert_eq!(cfg0.consensus.confirmation_depth, 6);
        assert_eq!(cfg0.consensus.entry_point, params.entry_point);
        assert_eq!(cfg0.consensus.account_factory, params.account_factory);
        assert_eq!(
            cfg0.consensus.simple_account_impl,
            params.simple_account_impl
        );
        assert_eq!(cfg0.consensus.check_ttl_blocks, 500);

        let client_cfg = UsdtInit::default()
            .get_client_config(&cfg0.clone().to_erased().consensus)
            .unwrap();
        assert_eq!(client_cfg.usdt_contract, params.usdt_contract);
        assert_eq!(client_cfg.confirmation_depth, 6);
        assert_eq!(client_cfg.chain_id, 1);
        assert_eq!(client_cfg.entry_point, params.entry_point);
        assert_eq!(client_cfg.account_factory, params.account_factory);
        assert_eq!(client_cfg.simple_account_impl, params.simple_account_impl);
    }

    /// A mostly-no-op [`IServerEvmRpc`] sufficient for constructing a
    /// [`Usdt`] module in tests that exercise consensus logic (block-count
    /// median/redundancy, user-op submission/confirmation) rather than
    /// EVM-RPC-driven balance polling. This is deliberately separate from
    /// `fedimint-usdt-tests`' fuller scriptable `MockEvmRpc`:
    /// `fedimint-usdt-server` cannot depend on `fedimint-usdt-tests` (which
    /// itself depends on this crate) without a dependency cycle.
    #[derive(Debug, Default)]
    struct MockEvmRpc {
        /// Every `SignedUserOp` batch passed to `submit_user_ops`, in call
        /// order (Phase 7 Task 4), so tests can assert on what consensus
        /// logic attempted to submit.
        submitted_user_ops: Mutex<Vec<Vec<fedimint_usdt_common::user_op::SignedUserOp>>>,
        /// Scripted `get_user_op_receipt` responses, keyed by `user_op_hash`.
        /// Unset hashes read as `None` (op not yet included on-chain).
        user_op_receipts: Mutex<
            std::collections::HashMap<[u8; 32], fedimint_usdt_common::user_op::UserOpReceipt>,
        >,
        /// Scripted `get_chain_id()` response (Task 3.1, sec-17). Defaults to
        /// `Ok(0)`, set via `set_chain_id`/`set_chain_id_error`.
        chain_id: Mutex<u64>,
        /// When `true`, `get_chain_id()` returns `Err` instead of the
        /// scripted `chain_id` value, for exercising the startup RPC-error
        /// (warn-and-continue) path.
        chain_id_err: Mutex<bool>,
        /// Scripted `get_code_len` responses, keyed by address (sec-16
        /// readiness deepening; see `set_code_len`). Unset addresses read as
        /// `0` (no code).
        code_len: Mutex<std::collections::HashMap<fedimint_usdt_common::EvmAddress, usize>>,
        /// Scripted `factory_get_address` responses, keyed by `(factory,
        /// owner, salt)` (sec-16 readiness deepening; see
        /// `set_factory_get_address`). Unset entries read as the all-zero
        /// address.
        #[allow(clippy::type_complexity)]
        factory_addresses: Mutex<
            std::collections::HashMap<
                (
                    fedimint_usdt_common::EvmAddress,
                    fedimint_usdt_common::EvmAddress,
                    [u8; 32],
                ),
                fedimint_usdt_common::EvmAddress,
            >,
        >,
        /// Scripted `factory_account_implementation` responses, keyed by
        /// `factory` (sec-16 readiness deepening; see
        /// `set_factory_account_implementation`). Unset entries read as the
        /// all-zero address.
        factory_account_implementations: Mutex<
            std::collections::HashMap<
                fedimint_usdt_common::EvmAddress,
                fedimint_usdt_common::EvmAddress,
            >,
        >,
        /// `user_op_hash`es for which `get_user_op_receipt` never resolves
        /// (security finding 19; see `set_receipt_hangs`), used to prove a
        /// stalled RPC call for one op cannot block progress on others.
        hung_receipts: Mutex<std::collections::HashSet<[u8; 32]>>,
        /// `user_op_hash`es the BUNDLER claims success for but for which the
        /// authoritative `EntryPoint` `UserOperationEvent` log is ABSENT
        /// (security finding 15 op facet; see
        /// `set_bundler_success_without_entrypoint_log`). Models the
        /// cross-check contract of `AlloyEvmRpc::get_user_op_receipt`: a
        /// bundler hint with no confirming `EntryPoint` log resolves to `None`
        /// (do NOT confirm), NOT to a fabricated receipt.
        bundler_only_receipts: Mutex<std::collections::HashSet<[u8; 32]>>,
        /// Scripted `get_block_hash` overrides, keyed by block number. An
        /// unscripted block falls back to a deterministic block-number-derived
        /// hash (see `mock_block_hash`).
        block_hashes: Mutex<std::collections::HashMap<u64, [u8; 32]>>,
    }

    /// Deterministic, block-number-derived stand-in for a canonical block hash
    /// (NOT a real keccak256): stable and distinct per height, all the
    /// deposit-observation/user-op `block_hash` binding needs in hermetic unit
    /// tests. Mirrors `fedimint-usdt-tests`' `mock_block_hash`.
    fn mock_block_hash(block: u64) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&block.to_be_bytes());
        hash[31] = 0xB1;
        hash
    }

    impl MockEvmRpc {
        /// Scripts the [`fedimint_usdt_common::user_op::UserOpReceipt`]
        /// `get_user_op_receipt(user_op_hash)` returns.
        fn set_user_op_receipt(
            &self,
            user_op_hash: [u8; 32],
            receipt: fedimint_usdt_common::user_op::UserOpReceipt,
        ) {
            self.user_op_receipts
                .lock()
                .expect("not poisoned")
                .insert(user_op_hash, receipt);
        }

        /// Scripts `get_user_op_receipt(user_op_hash)` to never resolve
        /// (security finding 19), simulating a provider that accepts the
        /// request but never answers -- used to prove `rpc_deadline` bounds
        /// the await and that the bounded-concurrency submitter still makes
        /// progress on other ops despite this one hanging.
        fn set_receipt_hangs(&self, user_op_hash: [u8; 32]) {
            self.hung_receipts
                .lock()
                .expect("not poisoned")
                .insert(user_op_hash);
        }

        /// Scripts `get_user_op_receipt(user_op_hash)` to model the security
        /// finding 15 mismatch: the bundler claims the op succeeded, but the
        /// authoritative `EntryPoint` `UserOperationEvent` log is absent -- so
        /// the cross-checked result is `None` (do NOT confirm), exactly as
        /// `AlloyEvmRpc::get_user_op_receipt` returns when its single-block
        /// `eth_getLogs` finds no matching event.
        fn set_bundler_success_without_entrypoint_log(&self, user_op_hash: [u8; 32]) {
            self.bundler_only_receipts
                .lock()
                .expect("not poisoned")
                .insert(user_op_hash);
        }

        /// Scripts the canonical hash `get_block_hash(block)` returns,
        /// overriding the default `mock_block_hash`-derived value.
        #[allow(dead_code)]
        fn set_block_hash(&self, block: u64, hash: [u8; 32]) {
            self.block_hashes
                .lock()
                .expect("not poisoned")
                .insert(block, hash);
        }

        /// Every `SignedUserOp` batch previously passed to
        /// `submit_user_ops`, in call order.
        #[allow(dead_code)]
        fn submitted_user_ops(&self) -> Vec<Vec<fedimint_usdt_common::user_op::SignedUserOp>> {
            self.submitted_user_ops
                .lock()
                .expect("not poisoned")
                .clone()
        }

        /// Scripts `get_chain_id()` to return `Ok(chain_id)`.
        fn set_chain_id(&self, chain_id: u64) {
            *self.chain_id.lock().expect("not poisoned") = chain_id;
        }

        /// Scripts `get_chain_id()` to return `Err`.
        fn set_chain_id_error(&self) {
            *self.chain_id_err.lock().expect("not poisoned") = true;
        }

        /// Scripts the length returned by `get_code_len(addr)` (sec-16
        /// readiness deepening).
        fn set_code_len(&self, addr: fedimint_usdt_common::EvmAddress, len: usize) {
            self.code_len
                .lock()
                .expect("not poisoned")
                .insert(addr, len);
        }

        /// Scripts the address returned by `factory_get_address(factory,
        /// owner, salt)` for that exact `(factory, owner, salt)` triple
        /// (sec-16 readiness deepening: lets a test give a mock factory a
        /// correct `pool_salt` address but a wrong sample-deposit-salt
        /// address, or vice versa).
        fn set_factory_get_address(
            &self,
            factory: fedimint_usdt_common::EvmAddress,
            owner: fedimint_usdt_common::EvmAddress,
            salt: [u8; 32],
            address: fedimint_usdt_common::EvmAddress,
        ) {
            self.factory_addresses
                .lock()
                .expect("not poisoned")
                .insert((factory, owner, salt), address);
        }

        /// Scripts the address returned by
        /// `factory_account_implementation(factory)` (sec-16 readiness
        /// deepening).
        fn set_factory_account_implementation(
            &self,
            factory: fedimint_usdt_common::EvmAddress,
            implementation: fedimint_usdt_common::EvmAddress,
        ) {
            self.factory_account_implementations
                .lock()
                .expect("not poisoned")
                .insert(factory, implementation);
        }
    }

    #[async_trait::async_trait]
    impl crate::rpc::IServerEvmRpc for MockEvmRpc {
        async fn get_chain_id(&self) -> anyhow::Result<u64> {
            if *self.chain_id_err.lock().expect("not poisoned") {
                anyhow::bail!("mock RPC: chain-id read failed");
            }
            Ok(*self.chain_id.lock().expect("not poisoned"))
        }

        async fn get_block_number(&self) -> anyhow::Result<u64> {
            Ok(0)
        }

        async fn get_block_hash(&self, block: u64) -> anyhow::Result<[u8; 32]> {
            Ok(self
                .block_hashes
                .lock()
                .expect("not poisoned")
                .get(&block)
                .copied()
                .unwrap_or_else(|| mock_block_hash(block)))
        }

        async fn get_erc20_balance(
            &self,
            _token: fedimint_usdt_common::EvmAddress,
            _holder: fedimint_usdt_common::EvmAddress,
            _at_block: u64,
        ) -> anyhow::Result<fedimint_usdt_common::UsdtAmount> {
            // No balance polling in these consensus-logic tests (the deposit
            // scanner that read this was removed with the guardian-poll path);
            // deposit crediting is now proof-driven via `process_deposit_proof`.
            Ok(fedimint_usdt_common::UsdtAmount(0))
        }

        async fn get_erc20_basis_points_rate(
            &self,
            _token: fedimint_usdt_common::EvmAddress,
        ) -> anyhow::Result<u64> {
            // Mock: a standard (fee-less) token.
            Ok(0)
        }

        async fn get_fee_estimate(&self) -> anyhow::Result<fedimint_usdt_common::FeeVote> {
            Ok(fedimint_usdt_common::FeeVote {
                max_fee_per_gas_wei: 0,
                usdt_per_eth_e6: 0,
            })
        }

        async fn get_code_len(
            &self,
            addr: fedimint_usdt_common::EvmAddress,
        ) -> anyhow::Result<usize> {
            Ok(self
                .code_len
                .lock()
                .expect("not poisoned")
                .get(&addr)
                .copied()
                .unwrap_or(0))
        }

        async fn factory_get_address(
            &self,
            factory: fedimint_usdt_common::EvmAddress,
            owner: fedimint_usdt_common::EvmAddress,
            salt: [u8; 32],
        ) -> anyhow::Result<fedimint_usdt_common::EvmAddress> {
            Ok(self
                .factory_addresses
                .lock()
                .expect("not poisoned")
                .get(&(factory, owner, salt))
                .copied()
                .unwrap_or(fedimint_usdt_common::EvmAddress([0u8; 20])))
        }

        async fn factory_account_implementation(
            &self,
            factory: fedimint_usdt_common::EvmAddress,
        ) -> anyhow::Result<fedimint_usdt_common::EvmAddress> {
            Ok(self
                .factory_account_implementations
                .lock()
                .expect("not poisoned")
                .get(&factory)
                .copied()
                .unwrap_or(fedimint_usdt_common::EvmAddress([0u8; 20])))
        }

        async fn broadcaster_eth_balance(&self) -> anyhow::Result<Option<u128>> {
            Ok(None)
        }

        async fn send_raw_transaction(&self, _signed_tx: Vec<u8>) -> anyhow::Result<[u8; 32]> {
            Ok([0u8; 32])
        }

        async fn ensure_create2_deployer(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn deploy_factory(
            &self,
            _entry_point: fedimint_usdt_common::EvmAddress,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn submit_user_ops(
            &self,
            ops: Vec<fedimint_usdt_common::user_op::SignedUserOp>,
        ) -> anyhow::Result<()> {
            self.submitted_user_ops
                .lock()
                .expect("not poisoned")
                .push(ops);
            Ok(())
        }

        async fn get_user_op_receipt(
            &self,
            user_op_hash: [u8; 32],
        ) -> anyhow::Result<Option<fedimint_usdt_common::user_op::UserOpReceipt>> {
            if self
                .hung_receipts
                .lock()
                .expect("not poisoned")
                .contains(&user_op_hash)
            {
                // Security finding 19: simulates a provider that never
                // answers. Never resolves; the caller's `rpc_deadline` (or
                // the test's own bounded wait) is what must make progress
                // possible despite this.
                std::future::pending::<()>().await;
            }
            // Security finding 15 op facet: a bundler hint with no confirming
            // EntryPoint log cross-checks to `None` (do not confirm), even
            // though the bundler claimed success -- mirrors
            // `AlloyEvmRpc::get_user_op_receipt`'s single-block `eth_getLogs`
            // finding no matching event. Only the authoritative log (a
            // scripted `UserOpReceipt`, carrying its `block_hash`) yields
            // `Some`.
            if self
                .bundler_only_receipts
                .lock()
                .expect("not poisoned")
                .contains(&user_op_hash)
                && !self
                    .user_op_receipts
                    .lock()
                    .expect("not poisoned")
                    .contains_key(&user_op_hash)
            {
                return Ok(None);
            }
            Ok(self
                .user_op_receipts
                .lock()
                .expect("not poisoned")
                .get(&user_op_hash)
                .copied())
        }
    }

    #[tokio::test]
    async fn init_fails_on_chain_id_mismatch() {
        let mock = Arc::new(MockEvmRpc::default());
        mock.set_chain_id(999);
        let evm_rpc: crate::rpc::DynServerEvmRpc = mock;

        let err = check_chain_id_at_startup(&evm_rpc, 1)
            .await
            .expect_err("a definitive RPC-reported chain_id mismatch must hard-fail init");
        assert!(err.to_string().contains("chain_id"));
    }

    #[tokio::test]
    async fn init_passes_on_chain_id_match() {
        let mock = Arc::new(MockEvmRpc::default());
        mock.set_chain_id(1);
        let evm_rpc: crate::rpc::DynServerEvmRpc = mock;

        check_chain_id_at_startup(&evm_rpc, 1)
            .await
            .expect("a matching RPC-reported chain_id must pass");
    }

    #[tokio::test]
    async fn init_warns_but_continues_on_chain_id_rpc_error() {
        let mock = Arc::new(MockEvmRpc::default());
        mock.set_chain_id_error();
        let evm_rpc: crate::rpc::DynServerEvmRpc = mock;

        check_chain_id_at_startup(&evm_rpc, 1)
            .await
            .expect("an RPC error reading chain_id must warn and let startup continue, not fail");
    }

    /// Serializes tests that touch process-wide `FM_USDT_*` env vars so they
    /// cannot race under `cargo test`'s default parallel-test execution.
    static ENV_VAR_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn env_override_parse_error_is_not_a_panic() {
        let _lock = ENV_VAR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::set_var(FM_USDT_CHAIN_ID_ENV, "not-a-number");
        }
        let result = std::panic::catch_unwind(usdt_gen_params_from_env);
        // SAFETY: see above.
        unsafe {
            std::env::remove_var(FM_USDT_CHAIN_ID_ENV);
        }

        match result {
            Ok(inner) => {
                let err = inner.expect_err("a malformed FM_USDT_CHAIN_ID must be a clean Err");
                assert!(err.to_string().contains(FM_USDT_CHAIN_ID_ENV));
            }
            // A panic here means `usdt_gen_params_from_env` panicked instead
            // of returning `Result::Err` on a malformed env var -- surface
            // the original panic payload/message rather than discarding it.
            Err(panic_payload) => std::panic::resume_unwind(panic_payload),
        }
    }

    #[test]
    fn poll_interval_resolves_default_override_and_clamp() {
        // Unset -> default.
        assert_eq!(resolve_poll_interval(None), DEFAULT_POLL_INTERVAL_SECS);
        // A valid override is applied verbatim (with surrounding whitespace
        // trimmed, mirroring how operators paste env values).
        assert_eq!(resolve_poll_interval(Some("60".to_string())), 60);
        assert_eq!(resolve_poll_interval(Some("  45 ".to_string())), 45);
        // Below the floor is clamped up, never a busy loop.
        assert_eq!(
            resolve_poll_interval(Some("1".to_string())),
            MIN_POLL_INTERVAL_SECS
        );
        assert_eq!(
            resolve_poll_interval(Some("0".to_string())),
            MIN_POLL_INTERVAL_SECS
        );
        // An exactly-at-floor value is preserved.
        assert_eq!(
            resolve_poll_interval(Some(MIN_POLL_INTERVAL_SECS.to_string())),
            MIN_POLL_INTERVAL_SECS
        );
        // Unparseable -> default (never a panic, mirroring the gen-param envs).
        assert_eq!(
            resolve_poll_interval(Some("not-a-number".to_string())),
            DEFAULT_POLL_INTERVAL_SECS
        );
        assert_eq!(
            resolve_poll_interval(Some(String::new())),
            DEFAULT_POLL_INTERVAL_SECS
        );
    }

    #[test]
    fn env_override_valid_values_are_applied() {
        let _lock = ENV_VAR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::set_var(FM_USDT_CHAIN_ID_ENV, "1");
            std::env::set_var(FM_USDT_CONFIRMATION_DEPTH_ENV, "6");
        }
        let result = usdt_gen_params_from_env();
        // SAFETY: see above.
        unsafe {
            std::env::remove_var(FM_USDT_CHAIN_ID_ENV);
            std::env::remove_var(FM_USDT_CONFIRMATION_DEPTH_ENV);
        }

        let params = result.expect("valid env overrides must parse cleanly");
        assert_eq!(params.chain_id, 1);
        assert_eq!(params.confirmation_depth, 6);
    }

    /// Returns a path in the OS temp dir unique to this call, so parallel
    /// test binaries never collide on the same secret file.
    fn unique_secret_file_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "fedimint-usdt-server-test-{tag}-{}-{n}",
            std::process::id()
        ))
    }

    /// The `init()` consuming site for the RPC API key
    /// (`FM_USDT_EVM_RPC_API_KEY_ENV`) delegates to `env_secret_or_file` with
    /// `FM_USDT_EVM_RPC_API_KEY_FILE_ENV` as the file fallback (sec-misc#8).
    /// This pins that exact const pairing so a future refactor cannot
    /// silently swap in the wrong `_FILE` env var.
    #[test]
    fn rpc_api_key_can_come_from_file() {
        let _lock = ENV_VAR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::remove_var(FM_USDT_EVM_RPC_API_KEY_ENV);
            std::env::remove_var(FM_USDT_EVM_RPC_API_KEY_FILE_ENV);
        }

        let path = unique_secret_file_path("rpc-api-key");
        // nosemgrep: ban-fs-write -- test-only: create a throwaway temp secret file
        std::fs::write(&path, "my-rpc-api-key\n").expect("can write temp secret file");
        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::set_var(FM_USDT_EVM_RPC_API_KEY_FILE_ENV, &path);
        }

        let result = env_secret_or_file(
            FM_USDT_EVM_RPC_API_KEY_ENV,
            FM_USDT_EVM_RPC_API_KEY_FILE_ENV,
        );

        // SAFETY: see above.
        unsafe {
            std::env::remove_var(FM_USDT_EVM_RPC_API_KEY_FILE_ENV);
        }
        std::fs::remove_file(&path).expect("can remove temp secret file");

        assert_eq!(
            result.expect("file-backed RPC API key must read cleanly"),
            Some("my-rpc-api-key".to_owned())
        );
    }

    /// Same as `rpc_api_key_can_come_from_file`, for the broadcaster private
    /// key's `init()` consuming site.
    #[test]
    fn broadcaster_key_can_come_from_file() {
        let _lock = ENV_VAR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::remove_var(FM_USDT_BROADCASTER_PRIVATE_KEY_ENV);
            std::env::remove_var(FM_USDT_BROADCASTER_PRIVATE_KEY_FILE_ENV);
        }

        let path = unique_secret_file_path("broadcaster-key");
        // nosemgrep: ban-fs-write -- test-only: create a throwaway temp secret file
        std::fs::write(&path, "  0xdeadbeef\n").expect("can write temp secret file");
        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::set_var(FM_USDT_BROADCASTER_PRIVATE_KEY_FILE_ENV, &path);
        }

        let result = env_secret_or_file(
            FM_USDT_BROADCASTER_PRIVATE_KEY_ENV,
            FM_USDT_BROADCASTER_PRIVATE_KEY_FILE_ENV,
        );

        // SAFETY: see above.
        unsafe {
            std::env::remove_var(FM_USDT_BROADCASTER_PRIVATE_KEY_FILE_ENV);
        }
        std::fs::remove_file(&path).expect("can remove temp secret file");

        assert_eq!(
            result.expect("file-backed broadcaster key must read cleanly"),
            Some("0xdeadbeef".to_owned())
        );
    }

    /// Builds a [`Usdt`] module (via [`Usdt::new_for_test`], so no poller
    /// task is spawned) over a fresh in-memory database, backed by a
    /// trusted-dealer-generated config for `num_peers` guardians, acting as
    /// peer 0, with its block-count cache pre-seeded to `cached_head`.
    ///
    /// `async` for parity with the module's other async test helpers/callers
    /// (`test_module_with_block_count(..).await`), even though this
    /// particular helper has no `.await` point of its own today.
    #[allow(clippy::unused_async)]
    async fn test_module_with_block_count(num_peers: u16, cached_head: u64) -> Usdt {
        let peers = (0..num_peers).map(PeerId::from).collect::<Vec<_>>();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );
        let cfg = server_cfgs[&peers[0]]
            .clone()
            .to_typed::<UsdtConfig>()
            .expect("config was just generated by the same configgen");

        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );

        let module = Usdt::new_for_test(
            cfg,
            MockEvmRpc::default().into_dyn(),
            db,
            PeerId::from(0),
            peers.to_num_peers(),
        );
        module.block_count.store(cached_head, Ordering::Relaxed);
        module
    }

    #[tokio::test]
    async fn block_count_median_and_redundancy_guard() {
        let module = test_module_with_block_count(4, 0).await; // 4 peers, cached head 0
        let mut dbtx = module.db_for_test().begin_transaction().await;

        // No votes → median 0.
        assert_eq!(module.consensus_block_count(&mut dbtx.to_ref_nc()).await, 0);

        // Three of four peers vote 100 → median (index 2 of sorted [0,100,100,100]) =
        // 100.
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::BlockCount(100),
                    PeerId::from(p),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            module.consensus_block_count(&mut dbtx.to_ref_nc()).await,
            100
        );

        // Re-submitting the same or lower vote is rejected (unbounded-history rule).
        let err = module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::BlockCount(100),
                PeerId::from(0),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("redundant"));
    }

    /// Feeds `(height, block_hash)` as peer `peer`'s `BlockHash` observation
    /// through `process_consensus_item` (the ordered ring-population path),
    /// returning the result so callers can assert accept vs. reject.
    async fn vote_block_hash(
        module: &Usdt,
        dbtx: &mut DatabaseTransaction<'_>,
        peer: u16,
        height: u64,
        block_hash: [u8; 32],
    ) -> anyhow::Result<()> {
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::BlockHash(BlockHashObservation { height, block_hash }),
                PeerId::from(peer),
            )
            .await
    }

    /// A threshold-agreed confirmation-depth `(height, block_hash)` observation
    /// is persisted into the ring in the ordered `process` path, and only once
    /// the threshold is reached; older heights prune out of the window.
    #[tokio::test]
    async fn block_hash_observation_populates_ring_at_threshold_and_prunes() {
        let num_peers = 4u16; // threshold = 3
        let module = test_module_with_block_count(num_peers, 0).await;
        // confirmation_depth defaults to 1 for the test config.
        let confirmation_depth = module.cfg.consensus.confirmation_depth;

        // Consensus block count = 100, so the confirmation-depth height is 99.
        seed_block_count_votes(module.db_for_test(), num_peers, 100).await;
        let height = 100u64.saturating_sub(confirmation_depth); // 99
        let hash = [0xA1; 32];

        let mut dbtx = module.db_for_test().begin_transaction().await;

        // Two of four peers agree: below the threshold of 3 -> ring still empty.
        vote_block_hash(&module, &mut dbtx.to_ref_nc(), 0, height, hash)
            .await
            .expect("first fresh vote is accepted");
        vote_block_hash(&module, &mut dbtx.to_ref_nc(), 1, height, hash)
            .await
            .expect("second fresh vote is accepted");
        assert_eq!(ring_hash_at(&mut dbtx.to_ref_nc(), height).await, None);

        // The third identical vote reaches threshold -> the ring is written in
        // this ordered `process` path.
        vote_block_hash(&module, &mut dbtx.to_ref_nc(), 2, height, hash)
            .await
            .expect("threshold vote is accepted");
        assert_eq!(
            ring_hash_at(&mut dbtx.to_ref_nc(), height).await,
            Some(hash)
        );
        assert_eq!(
            ring_latest_height(&mut dbtx.to_ref_nc()).await,
            Some(height)
        );
        dbtx.commit_tx().await;

        // Advance consensus far enough that a new confirmation-depth anchor
        // falls `BLOCK_HASH_RING_LEN` beyond the old one, which prunes it.
        let new_ccount = 400u64;
        seed_block_count_votes(module.db_for_test(), num_peers, new_ccount).await;
        let new_height = new_ccount.saturating_sub(confirmation_depth); // 399
        assert!(new_height >= height + BLOCK_HASH_RING_LEN);
        let new_hash = [0xB2; 32];

        let mut dbtx = module.db_for_test().begin_transaction().await;
        for p in [0u16, 1, 2] {
            vote_block_hash(&module, &mut dbtx.to_ref_nc(), p, new_height, new_hash)
                .await
                .expect("fresh higher-height vote is accepted");
        }
        assert_eq!(
            ring_hash_at(&mut dbtx.to_ref_nc(), new_height).await,
            Some(new_hash)
        );
        // The old height has fallen out of the retained window.
        assert_eq!(ring_hash_at(&mut dbtx.to_ref_nc(), height).await, None);
    }

    /// The freshness gate (mirroring the `Deposit` arm) rejects observations
    /// that are not yet confirmation-deep or that have aged out, and the
    /// redundancy guard rejects an exact repeat -- all BEFORE any ring write.
    #[tokio::test]
    async fn block_hash_observation_freshness_and_redundancy_guards() {
        let num_peers = 4u16;
        let module = test_module_with_block_count(num_peers, 0).await;
        let confirmation_depth = module.cfg.consensus.confirmation_depth;
        // `ccount` must exceed `confirmation_depth + DEPOSIT_VOTE_MAX_AGE_BLOCKS`
        // for any height to be able to fall outside the too-old bound.
        let ccount = 1_000u64;
        seed_block_count_votes(module.db_for_test(), num_peers, ccount).await;
        let mut dbtx = module.db_for_test().begin_transaction().await;

        // Too NEW: a height that is not yet confirmation-deep is rejected.
        let too_new = ccount.saturating_sub(confirmation_depth) + 1;
        let err = vote_block_hash(&module, &mut dbtx.to_ref_nc(), 0, too_new, [0x01; 32])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not yet confirmation-deep"));

        // Too OLD: outside `confirmation_depth + DEPOSIT_VOTE_MAX_AGE_BLOCKS`.
        let too_old = ccount.saturating_sub(confirmation_depth + DEPOSIT_VOTE_MAX_AGE_BLOCKS + 1);
        let err = vote_block_hash(&module, &mut dbtx.to_ref_nc(), 0, too_old, [0x02; 32])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too old"));

        // A fresh vote is accepted; an EXACT repeat is redundant (rejected).
        let height = ccount.saturating_sub(confirmation_depth);
        vote_block_hash(&module, &mut dbtx.to_ref_nc(), 0, height, [0x03; 32])
            .await
            .expect("fresh vote accepted");
        let err = vote_block_hash(&module, &mut dbtx.to_ref_nc(), 0, height, [0x03; 32])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("redundant"));
    }

    /// Two guardians observing the SAME confirmation-depth height on DIFFERENT
    /// forks (distinct hashes) never aggregate toward the ring write: the
    /// full-field tally counts only identical `(height, block_hash)` pairs.
    #[tokio::test]
    async fn block_hash_cross_fork_votes_do_not_aggregate() {
        let num_peers = 4u16; // threshold = 3
        let module = test_module_with_block_count(num_peers, 0).await;
        let confirmation_depth = module.cfg.consensus.confirmation_depth;
        seed_block_count_votes(module.db_for_test(), num_peers, 100).await;
        let height = 100u64.saturating_sub(confirmation_depth);
        let mut dbtx = module.db_for_test().begin_transaction().await;

        // Three peers vote the same height but pairwise-distinct hashes: no
        // single hash reaches the threshold of 3.
        vote_block_hash(&module, &mut dbtx.to_ref_nc(), 0, height, [0xAA; 32])
            .await
            .unwrap();
        vote_block_hash(&module, &mut dbtx.to_ref_nc(), 1, height, [0xBB; 32])
            .await
            .unwrap();
        vote_block_hash(&module, &mut dbtx.to_ref_nc(), 2, height, [0xCC; 32])
            .await
            .unwrap();
        assert_eq!(ring_hash_at(&mut dbtx.to_ref_nc(), height).await, None);
    }

    /// The guardian-local observer path (its `consensus_proposal` drain) only
    /// PROPOSES a `BlockHash` item; it never writes the ring. Only the ordered
    /// `process_consensus_item` path does (verified by the tests above).
    #[tokio::test]
    async fn block_hash_proposal_path_does_not_write_ring() {
        let num_peers = 4u16;
        let module = test_module_with_block_count(num_peers, 0).await;
        let confirmation_depth = module.cfg.consensus.confirmation_depth;
        seed_block_count_votes(module.db_for_test(), num_peers, 100).await;
        let height = 100u64.saturating_sub(confirmation_depth);
        let obs = BlockHashObservation {
            height,
            block_hash: [0xD4; 32],
        };

        // Simulate what the READ-ONLY observer task does: queue its observation
        // into the single-slot proposal cache (never touching the DB).
        *module.block_hash_proposals.lock().expect("not poisoned") = Some(obs);

        let mut dbtx = module.db_for_test().begin_transaction().await;
        let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;

        // The observation surfaces as a proposal...
        assert!(
            items.contains(&UsdtConsensusItem::BlockHash(obs)),
            "consensus_proposal should surface the queued block-hash observation"
        );
        // ...but the ring was NOT written by the proposal path.
        assert_eq!(ring_latest_height(&mut dbtx.to_ref_nc()).await, None);
    }

    /// An all-conditions-met [`BootstrapObservation`] (Part C).
    fn ready_observation() -> BootstrapObservation {
        BootstrapObservation {
            entry_point_ok: true,
            factory_ok: true,
            impl_ok: true,
            broadcaster_funded: true,
            rpc_healthy: true,
        }
    }

    /// Feeds `obs` as peer `peer`'s `BootstrapObservation` through
    /// `process_consensus_item` (the deterministic vote-recording path).
    async fn vote_bootstrap(
        module: &Usdt,
        dbtx: &mut DatabaseTransaction<'_>,
        peer: u16,
        obs: BootstrapObservation,
    ) {
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::BootstrapObservation(obs),
                PeerId::from(peer),
            )
            .await
            .expect("recording a fresh bootstrap vote succeeds");
    }

    #[tokio::test]
    async fn bootstrap_state_is_awaiting_infra_with_no_votes() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let mut dbtx = module.db_for_test().begin_transaction().await;

        assert_eq!(
            module.bootstrap_state(&mut dbtx.to_ref_nc()).await,
            BootstrapState::AwaitingInfra
        );
    }

    #[tokio::test]
    async fn bootstrap_state_is_awaiting_infra_below_threshold() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let mut dbtx = module.db_for_test().begin_transaction().await;

        // Only 2 of 4 peers report all-ready: below the threshold of 3.
        for p in [0u16, 1] {
            vote_bootstrap(&module, &mut dbtx.to_ref_nc(), p, ready_observation()).await;
        }

        assert_eq!(
            module.bootstrap_state(&mut dbtx.to_ref_nc()).await,
            BootstrapState::AwaitingInfra
        );
        // The latch was never set (never reached Ready).
        assert!(
            dbtx.to_ref_nc()
                .get_value(&HasEverBeenReadyKey)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn bootstrap_state_becomes_ready_at_threshold_and_sets_latch() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let mut dbtx = module.db_for_test().begin_transaction().await;

        for p in [0u16, 1, 2] {
            vote_bootstrap(&module, &mut dbtx.to_ref_nc(), p, ready_observation()).await;
        }

        assert_eq!(
            module.bootstrap_state(&mut dbtx.to_ref_nc()).await,
            BootstrapState::Ready
        );
        // The latch was set deterministically inside `process_consensus_item`.
        assert_eq!(
            dbtx.to_ref_nc().get_value(&HasEverBeenReadyKey).await,
            Some(())
        );

        // The status endpoint reports the same state + tally.
        let status = module.handle_status(&mut dbtx.to_ref_nc()).await;
        assert_eq!(status.state, BootstrapState::Ready);
        assert!(status.entry_point_ok && status.factory_ok && status.impl_ok);
        assert_eq!(status.funded_guardians, 3);
        assert_eq!(status.healthy_guardians, 3);
        assert_eq!(status.threshold, 3);
    }

    #[tokio::test]
    async fn bootstrap_state_regresses_to_degraded_after_ready() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let mut dbtx = module.db_for_test().begin_transaction().await;

        // Reach Ready (sets the latch).
        for p in [0u16, 1, 2] {
            vote_bootstrap(&module, &mut dbtx.to_ref_nc(), p, ready_observation()).await;
        }
        assert_eq!(
            module.bootstrap_state(&mut dbtx.to_ref_nc()).await,
            BootstrapState::Ready
        );

        // Peer 0's broadcaster runs low: funded count drops to 2 < threshold,
        // so the federation is no longer Ready -- but the latch persists, so
        // the state is Degraded (not AwaitingInfra).
        vote_bootstrap(
            &module,
            &mut dbtx.to_ref_nc(),
            0,
            BootstrapObservation {
                broadcaster_funded: false,
                ..ready_observation()
            },
        )
        .await;

        assert_eq!(
            module.bootstrap_state(&mut dbtx.to_ref_nc()).await,
            BootstrapState::Degraded
        );
    }

    /// Scripts `mock` so `Usdt::observe_bootstrap`, run against `cfg`, would
    /// observe a fully canonical factory: code present at
    /// `entry_point`/`account_factory`/`simple_account_impl`, the factory's
    /// `getAddress` matching the off-chain CREATE2 derivation for BOTH the
    /// fixed `pool_salt()` AND the deterministic `sample_claim_pk()` deposit
    /// salt, and its `accountImplementation()` matching `simple_account_impl`
    /// (sec-16 readiness deepening, finding 16). Individual tests then
    /// deviate one condition at a time to prove `factory_ok` catches each.
    fn script_canonical_factory(mock: &MockEvmRpc, cfg: &UsdtConfigConsensus) {
        mock.set_code_len(cfg.entry_point, 32);
        mock.set_code_len(cfg.account_factory, 32);
        mock.set_code_len(cfg.simple_account_impl, 32);

        let owner = evm_address(&cfg.group_public_key);
        let pool = derive_pool_account(
            &cfg.group_public_key,
            cfg.account_factory,
            cfg.simple_account_impl,
        );
        mock.set_factory_get_address(cfg.account_factory, owner, pool_salt(), pool);

        let sample = sample_claim_pk();
        let sample_deposit = derive_deposit_account(
            &cfg.group_public_key,
            cfg.account_factory,
            cfg.simple_account_impl,
            &sample,
        );
        mock.set_factory_get_address(
            cfg.account_factory,
            owner,
            deposit_salt(&sample),
            sample_deposit,
        );

        mock.set_factory_account_implementation(cfg.account_factory, cfg.simple_account_impl);
    }

    /// Positive control (sec-16 readiness deepening): a factory that is
    /// canonical for the fixed `pool_salt`, the deterministic sample deposit
    /// salt, AND `accountImplementation()` reports `factory_ok == true`.
    #[tokio::test]
    async fn readiness_ok_when_factory_fully_canonical() {
        let module = test_module_with_block_count(4, 0).await;
        let cfg = module.cfg.consensus.clone();
        let mock = MockEvmRpc::default();
        script_canonical_factory(&mock, &cfg);

        let observation = Usdt::observe_bootstrap(
            &mock,
            &cfg.group_public_key,
            cfg.entry_point,
            cfg.account_factory,
            cfg.simple_account_impl,
            cfg.broadcaster_min_balance_wei,
            false,
        )
        .await;

        assert!(observation.rpc_healthy);
        assert!(observation.factory_ok);
    }

    /// sec-16 readiness deepening (finding 16): a factory whose `getAddress`
    /// returns the CORRECT address for the fixed `pool_salt` but a WRONG
    /// address for the deterministic sample deposit salt -- i.e. it
    /// special-cases `pool_salt` while mis-deploying real (claim-key-derived)
    /// deposit accounts -- must NOT be reported ready. Before this task,
    /// `observe_bootstrap` sampled only `pool_salt` and would have missed
    /// this.
    #[tokio::test]
    async fn readiness_fails_when_factory_special_cases_pool_salt() {
        let module = test_module_with_block_count(4, 0).await;
        let cfg = module.cfg.consensus.clone();
        let mock = MockEvmRpc::default();
        script_canonical_factory(&mock, &cfg);

        // Overwrite the sample-deposit-salt entry with a WRONG address (the
        // pool-salt entry from `script_canonical_factory` stays correct).
        let owner = evm_address(&cfg.group_public_key);
        let sample = sample_claim_pk();
        let wrong = fedimint_usdt_common::EvmAddress([0xEE; 20]);
        mock.set_factory_get_address(cfg.account_factory, owner, deposit_salt(&sample), wrong);

        let observation = Usdt::observe_bootstrap(
            &mock,
            &cfg.group_public_key,
            cfg.entry_point,
            cfg.account_factory,
            cfg.simple_account_impl,
            cfg.broadcaster_min_balance_wei,
            false,
        )
        .await;

        assert!(observation.rpc_healthy);
        assert!(!observation.factory_ok);
    }

    /// sec-16 readiness deepening (finding 16): a factory whose `getAddress`
    /// is canonical for both sampled salts, but whose own
    /// `accountImplementation()` reports a DIFFERENT address than the
    /// module's configured `simple_account_impl`, must NOT be reported ready.
    #[tokio::test]
    async fn readiness_fails_when_account_implementation_mismatches() {
        let module = test_module_with_block_count(4, 0).await;
        let cfg = module.cfg.consensus.clone();
        let mock = MockEvmRpc::default();
        script_canonical_factory(&mock, &cfg);

        // Overwrite `accountImplementation()` with a DIFFERENT address than
        // the configured `simple_account_impl`.
        let wrong_impl = fedimint_usdt_common::EvmAddress([0xDD; 20]);
        mock.set_factory_account_implementation(cfg.account_factory, wrong_impl);

        let observation = Usdt::observe_bootstrap(
            &mock,
            &cfg.group_public_key,
            cfg.entry_point,
            cfg.account_factory,
            cfg.simple_account_impl,
            cfg.broadcaster_min_balance_wei,
            false,
        )
        .await;

        assert!(observation.rpc_healthy);
        assert!(!observation.factory_ok);
    }

    /// The immutable-read cache: once `contracts_verified` is latched,
    /// `observe_bootstrap` must NOT re-read `entry_point`/`factory`/`impl`
    /// code, the factory `getAddress` derivations, or
    /// `accountImplementation()`. Proven against a completely empty mock
    /// (no code, no scripted addresses): with the cache OFF every contract
    /// boolean is false, but with the cache ON all three report true
    /// against that same empty mock -- which is only possible if none of
    /// those RPC reads happened.
    #[tokio::test]
    async fn readiness_skips_immutable_reads_once_contracts_verified() {
        let module = test_module_with_block_count(4, 0).await;
        let cfg = module.cfg.consensus.clone();
        let mock = MockEvmRpc::default();

        let uncached = Usdt::observe_bootstrap(
            &mock,
            &cfg.group_public_key,
            cfg.entry_point,
            cfg.account_factory,
            cfg.simple_account_impl,
            cfg.broadcaster_min_balance_wei,
            false,
        )
        .await;
        assert!(uncached.rpc_healthy);
        assert!(!uncached.entry_point_ok);
        assert!(!uncached.factory_ok);
        assert!(!uncached.impl_ok);

        let cached = Usdt::observe_bootstrap(
            &mock,
            &cfg.group_public_key,
            cfg.entry_point,
            cfg.account_factory,
            cfg.simple_account_impl,
            cfg.broadcaster_min_balance_wei,
            true,
        )
        .await;
        assert!(cached.rpc_healthy);
        assert!(cached.entry_point_ok);
        assert!(cached.factory_ok);
        assert!(cached.impl_ok);
    }

    /// Deterministic `secp256k1::PublicKey` derived from `byte`, for tests
    /// that need a `claim_pk` but do not exercise the key's signing
    /// properties.
    fn test_pubkey(byte: u8) -> secp256k1::PublicKey {
        let secp = secp256k1::Secp256k1::new();
        secp256k1::SecretKey::from_slice(&[byte; 32])
            .expect("valid scalar")
            .public_key(&secp)
    }

    #[tokio::test]
    async fn deposit_credited_only_at_threshold_of_identical_observations() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();
        // Security finding 12: the freshness gate requires the observation's
        // block (50) to be `confirmation_depth`-deep and within the freshness
        // window relative to consensus, so seed a consensus block count at
        // `50 + confirmation_depth`.
        seed_block_count_votes(db, 4, 50 + module.cfg.consensus.confirmation_depth).await;
        let claim_pk = test_pubkey(0xaa);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        let obs = DepositObservation {
            account,
            balance: UsdtAmount(2_000_000),
            block: 50,
            block_hash: [0u8; 32],
            claim_pk,
        };
        let mut dbtx = db.begin_transaction().await;

        // Two identical votes: no credit yet.
        for p in [0u16, 1] {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::Deposit(obs.clone()),
                    PeerId::from(p),
                )
                .await
                .unwrap();
        }
        assert!(
            dbtx.to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .is_none()
        );

        // A DIFFERENT balance from peer 2 does not count toward the 2M quorum.
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::Deposit(DepositObservation {
                    balance: UsdtAmount(9),
                    ..obs.clone()
                }),
                PeerId::from(2),
            )
            .await
            .unwrap();
        assert!(
            dbtx.to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .is_none()
        );

        // Third identical 2M vote reaches threshold → credited, votes cleared.
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::Deposit(obs.clone()),
                PeerId::from(3),
            )
            .await
            .unwrap();
        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .unwrap();
        assert_eq!(record.credited, UsdtAmount(2_000_000));
        assert_eq!(record.claimed, UsdtAmount(0));
        assert_eq!(
            dbtx.to_ref_nc()
                .find_by_prefix(&DepositObservationVoteAccountPrefix(account))
                .await
                .count()
                .await,
            0
        );
    }

    #[tokio::test]
    async fn redundant_deposit_vote_errors() {
        // Same peer submitting the same observation twice must Err.
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        // Freshness gate (finding 12): keep the block-10 observation in-window.
        seed_block_count_votes(db, 4, 10 + module.cfg.consensus.confirmation_depth).await;
        let claim_pk = test_pubkey(0xbb);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        let obs = DepositObservation {
            account,
            balance: UsdtAmount(1_000_000),
            block: 10,
            block_hash: [0u8; 32],
            claim_pk,
        };
        let mut dbtx = db.begin_transaction().await;

        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::Deposit(obs.clone()),
                PeerId::from(0),
            )
            .await
            .unwrap();

        let err = module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::Deposit(obs.clone()),
                PeerId::from(0),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("redundant"));
    }

    /// **Security finding 14.** A `Deposit` observation whose `claim_pk`
    /// does NOT derive `account` must be rejected with `Err` BEFORE the
    /// vote is stored, so a Byzantine guardian cannot bloat
    /// `DepositObservationVote` with junk observations for random accounts
    /// that never reach threshold (that check previously ran only inside
    /// `credit_deposit`, i.e. only after threshold-many identical votes).
    #[tokio::test]
    async fn deposit_vote_with_mismatched_claim_pk_is_rejected() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0xcc);
        // `account` is derived from a DIFFERENT claim_pk, so `obs.claim_pk`
        // (below) does not derive it.
        let other_claim_pk = test_pubkey(0xdd);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &other_claim_pk,
        );

        let obs = DepositObservation {
            account,
            balance: UsdtAmount(1_000_000),
            block: 10,
            block_hash: [0u8; 32],
            claim_pk,
        };
        let mut dbtx = db.begin_transaction().await;

        let err = module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::Deposit(obs.clone()),
                PeerId::from(0),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("claim_pk"),
            "unexpected error: {err}"
        );

        assert!(
            dbtx.to_ref_nc()
                .get_value(&DepositObservationVoteKey(account, PeerId::from(0)))
                .await
                .is_none(),
            "malformed observation must not be stored as a vote"
        );
    }

    /// A `Deposit` observation whose `claim_pk` does not actually derive its
    /// `account` must be rejected by the self-authentication check in
    /// `credit_deposit`, deterministically (a pure function of `obs` and the
    /// consensus config, so every honest guardian rejects it identically —
    /// this also guards against a byzantine guardian crediting an
    /// attacker-chosen claim key onto someone else's deposit account).
    #[tokio::test]
    async fn deposit_with_mismatched_claim_pk_is_rejected() {
        // Security finding 14 (Task 2.2) moved this self-authentication
        // check from `credit_deposit` (threshold time) to the very top of
        // the `Deposit` arm of `process_consensus_item`, so a mismatched
        // `claim_pk`/`account` pairing is now rejected on the FIRST vote --
        // it can no longer accumulate below-threshold votes at all. This
        // test now covers `credit_deposit`'s own check directly (called
        // out-of-band, bypassing `process_consensus_item`) as the
        // defense-in-depth path the brief asked to keep; see
        // `deposit_vote_with_mismatched_claim_pk_is_rejected` for the
        // arm-level, vote-storage-time coverage of the same finding.
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x43);
        let wrong_account = EvmAddress([0x99; 20]); // does NOT derive from claim_pk

        let obs = DepositObservation {
            account: wrong_account,
            balance: UsdtAmount(2_000_000),
            block: 50,
            block_hash: [0u8; 32],
            claim_pk,
        };

        // Every vote for this malformed observation is rejected immediately
        // -- it never reaches the vote table, so it can never accumulate
        // towards threshold.
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1, 2] {
            let err = module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::Deposit(obs.clone()),
                    PeerId::from(p),
                )
                .await
                .unwrap_err();
            assert!(err.to_string().contains("does not derive its account"));
        }
        assert!(
            dbtx.to_ref_nc()
                .get_value(&DepositRecordKey(wrong_account))
                .await
                .is_none(),
            "no DepositRecord must be created for a self-authentication failure"
        );
        assert_eq!(
            dbtx.to_ref_nc()
                .find_by_prefix(&DepositObservationVoteAccountPrefix(wrong_account))
                .await
                .count()
                .await,
            0,
            "a malformed observation must never be stored as a vote"
        );

        // Defense-in-depth: `credit_deposit` itself still rejects the same
        // mismatch if ever reached directly (e.g. in a future code path
        // that calls it other than via the arm-level check above).
        let err = module
            .credit_deposit(&mut dbtx.to_ref_nc(), &obs)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not derive its account"));
    }

    /// Sets up a fresh in-memory DB with `BlockCountVote`s from a majority of
    /// `num_peers` peers so that the free `consensus_block_count(dbtx,
    /// num_peers)` computes exactly `ccount`.
    async fn seed_block_count_votes(db: &Database, num_peers: u16, ccount: u64) {
        let mut dbtx = db.begin_transaction().await;
        // A majority (more than half) voting `ccount`, with the rest left
        // unvoted (defaulting to 0), makes the median exactly `ccount` for
        // any `num_peers` >= 1.
        for p in 0..=(num_peers / 2) {
            dbtx.insert_entry(&BlockCountVoteKey(PeerId::from(p)), &ccount)
                .await;
        }
        dbtx.commit_tx().await;
    }

    /// `timed_out` must be a deterministic pure function of `session` and
    /// the consensus block count (never wall-clock): an `InProgress`
    /// session times out only once `consensus_block_count` outruns its
    /// `last_progress_block` by more than `timeout_blocks()`, and a
    /// `Completed` session never times out regardless of how far the block
    /// count has advanced.
    #[tokio::test]
    async fn timed_out_detects_stalled_session_via_consensus_block_count() {
        let num_peers = 4u16;
        let module = test_module_with_block_count(num_peers, 0).await;
        let db = module.db_for_test();

        let session_id = signing_session_id(&[7; 32], 0);
        let session = SigningSession {
            purpose: SigningPurpose::UserOp([7; 32]),
            digest: [7; 32],
            signers: vec![PeerId::from(0), PeerId::from(1), PeerId::from(2)],
            round: 0,
            state: SessionState::InProgress,
            attempt: 0,
            last_progress_block: 10,
        };
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(&SigningSessionKey(session_id), &session)
                .await;
            dbtx.commit_tx().await;
        }

        // consensus_block_count = last_progress_block + timeout_blocks() + 1
        // strictly exceeds the threshold -> timed out.
        seed_block_count_votes(db, num_peers, 10 + timeout_blocks() + 1).await;
        {
            let mut dbtx = db.begin_transaction_nc().await;
            assert!(module.timed_out(&mut dbtx.to_ref_nc(), &session).await);
        }

        // Drop the block count back to exactly the threshold (not strictly
        // past it) -> not timed out.
        seed_block_count_votes(db, num_peers, 10 + timeout_blocks()).await;
        {
            let mut dbtx = db.begin_transaction_nc().await;
            assert!(!module.timed_out(&mut dbtx.to_ref_nc(), &session).await);
        }

        // A Completed session never times out, no matter how far the block
        // count has advanced.
        let mut completed = session.clone();
        completed.state = SessionState::Completed(vec![]);
        seed_block_count_votes(db, num_peers, 10 + timeout_blocks() + 1_000).await;
        {
            let mut dbtx = db.begin_transaction_nc().await;
            assert!(!module.timed_out(&mut dbtx.to_ref_nc(), &completed).await);
        }
    }

    /// `signer_subset` is a deterministic combination schedule: for n=4, t=3,
    /// `C(4,3)=4` and the lexicographic combination order is
    /// `[0,1,2],[0,1,3],[0,2,3],[1,2,3]`. With `digest = [0u8;32]` the seed
    /// derived from the digest is 0, so `idx = attempt % 4` walks that order
    /// directly and attempt 4 wraps back to attempt 0's subset.
    #[tokio::test]
    async fn signer_subset_rotates_and_wraps_deterministically() {
        let module = test_module_with_block_count(4, 0).await;
        let p = |i: u16| PeerId::from(i);
        let digest = [0u8; 32];

        assert_eq!(module.signer_subset(&digest, 0), vec![p(0), p(1), p(2)]);
        assert_eq!(module.signer_subset(&digest, 1), vec![p(0), p(1), p(3)]);
        assert_eq!(module.signer_subset(&digest, 2), vec![p(0), p(2), p(3)]);
        assert_eq!(module.signer_subset(&digest, 3), vec![p(1), p(2), p(3)]);
        // Wraps: attempt 4 == attempt 0 (idx 4 % 4 == 0).
        assert_eq!(
            module.signer_subset(&digest, 4),
            module.signer_subset(&digest, 0)
        );
    }

    /// The finding-10 regression: for `n=7, t=5`, a Byzantine/offline set
    /// `{0,3}` made every CONTIGUOUS rotation window contain a faulty
    /// signer, so the all-honest subset `{1,2,4,5,6}` was never tried. The
    /// combination schedule must eventually reach it.
    #[tokio::test]
    async fn rotation_eventually_selects_all_honest_subset() {
        let module = test_module_with_block_count(7, 0).await;
        let p = |i: u16| PeerId::from(i);
        let digest = [7u8; 32];
        let all_honest = vec![p(1), p(2), p(4), p(5), p(6)];

        let period = usize::try_from(n_choose_k(7, 5)).expect("fits usize");
        assert_eq!(period, 21, "C(7,5) == 21");

        let period_u32 = u32::try_from(period).expect("C(7,5)=21 fits u32");
        let found =
            (0..period_u32).any(|attempt| module.signer_subset(&digest, attempt) == all_honest);
        assert!(
            found,
            "the all-honest subset {{1,2,4,5,6}} must be reached within one full period"
        );
    }

    /// Over one full period (`C(n,t)` attempts), the schedule must visit
    /// EVERY size-`t` subset exactly once — a stride-1 walk over a
    /// lexicographically-ordered combination list is a full permutation of
    /// the combination indices, so no subset is skipped and none repeats
    /// before the period completes.
    #[tokio::test]
    async fn rotation_covers_every_combination_within_period() {
        let module = test_module_with_block_count(7, 0).await;
        let digest = [42u8; 32];
        let period = usize::try_from(n_choose_k(7, 5)).expect("fits usize");

        let mut seen: std::collections::HashSet<Vec<PeerId>> = std::collections::HashSet::new();
        let period_u32 = u32::try_from(period).expect("C(7,5)=21 fits u32");
        for attempt in 0..period_u32 {
            let subset = module.signer_subset(&digest, attempt);
            assert_eq!(subset.len(), 5, "every subset must have size t=5");
            let mut sorted = subset.clone();
            sorted.sort_unstable();
            assert_eq!(subset, sorted, "every subset must already be sorted");
            assert!(
                seen.insert(subset),
                "attempt {attempt} repeated a subset within a single period"
            );
        }
        assert_eq!(
            seen.len(),
            period,
            "every one of the C(7,5)=21 combinations must appear exactly once"
        );
    }

    /// `signer_subset` is a pure, deterministic function of
    /// `(num_peers, digest, attempt)`: the same inputs always produce the
    /// same sorted, correctly-sized subset.
    #[tokio::test]
    async fn signer_subset_is_deterministic_and_sorted() {
        let module = test_module_with_block_count(7, 0).await;
        let digest = [9u8; 32];

        for attempt in 0..10u32 {
            let a = module.signer_subset(&digest, attempt);
            let b = module.signer_subset(&digest, attempt);
            assert_eq!(a, b, "identical inputs must yield identical subsets");
            assert_eq!(a.len(), module.num_peers.threshold());
            let mut sorted = a.clone();
            sorted.sort_unstable();
            assert_eq!(a, sorted, "subset must be returned in sorted order");
        }
    }

    /// Test-only helper mirroring `n_choose_k` used to derive expected
    /// period lengths (`C(n,t)`) independently of the production
    /// combinations generator.
    fn n_choose_k(n: u64, k: u64) -> u64 {
        if k > n {
            return 0;
        }
        let k = k.min(n - k);
        let mut result: u64 = 1;
        for i in 0..k {
            result = result * (n - i) / (i + 1);
        }
        result
    }

    /// A stalled (`InProgress`, timed-out) signing session is deterministically
    /// retried under a ROTATED signer subset: `consensus_proposal` proposes a
    /// `RotateSigning` for the timed-out attempt, and processing it on EVERY
    /// guardian (signer and non-signer alike) fails the old attempt and starts
    /// the next one (`attempt + 1`, rotated subset, fresh id) with identical
    /// consensus-DB writes.
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn rotate_signing_fails_timed_out_attempt_and_retries_rotated_subset() {
        use sha2::{Digest as _, Sha256};

        const N: u16 = 4;
        let peers: Vec<PeerId> = (0..N).map(PeerId::from).collect();
        let num_peers = peers.to_num_peers();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );

        // One module per guardian, each with its own in-memory DB.
        let mut modules: BTreeMap<PeerId, Usdt> = BTreeMap::new();
        for &peer in &peers {
            let cfg = server_cfgs[&peer]
                .clone()
                .to_typed::<UsdtConfig>()
                .expect("config was just generated by the same configgen");
            let db = fedimint_core::db::Database::new(
                fedimint_core::db::mem_impl::MemDatabase::new(),
                fedimint_core::module::registry::ModuleDecoderRegistry::default(),
            );
            modules.insert(
                peer,
                Usdt::new_for_test(cfg, MockEvmRpc::default().into_dyn(), db, peer, num_peers),
            );
        }

        let digest: [u8; 32] = Sha256::digest(b"usdt rotate-signing timeout test").into();
        let attempt0_id = fedimint_usdt_common::signing_session_id(&digest, 0);
        let attempt1_id = fedimint_usdt_common::signing_session_id(&digest, 1);
        let purpose = SigningPurpose::UserOp(digest);

        // The digest-seeded subsets for attempt 0 and attempt 1 — derived
        // rather than hard-coded, since the seed depends on `digest`. The
        // rotation must land on a *different* subset (that's the whole point
        // of rotating).
        let subset0 = modules[&PeerId::from(0)].signer_subset(&digest, 0);
        let subset1 = modules[&PeerId::from(0)].signer_subset(&digest, 1);
        assert_ne!(
            subset0, subset1,
            "rotation must select a different signer subset for attempt 1"
        );

        // Attempt 0: every guardian starts the identical session over the
        // digest-seeded subset. `consensus_block_count` is 0 here (no votes
        // yet), so each session's `last_progress_block` is 0.
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .start_session(&mut dbtx.to_ref_nc(), purpose.clone(), digest, 0)
                .await;
            dbtx.commit_tx().await;
        }
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction_nc().await;
            let session = dbtx
                .get_value(&SigningSessionKey(attempt0_id))
                .await
                .expect("attempt-0 session present");
            assert_eq!(session.signers, subset0);
            assert_eq!(session.attempt, 0);
        }

        // Advance the consensus block count strictly past the timeout WITHOUT
        // completing any round — the session stalls.
        for module in modules.values() {
            seed_block_count_votes(module.db_for_test(), N, timeout_blocks() + 1).await;
        }

        // One guardian proposes `RotateSigning` for the timed-out attempt.
        let proposal = {
            let module = &modules[&PeerId::from(0)];
            let mut dbtx = module.db_for_test().begin_transaction().await;
            let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
            dbtx.commit_tx().await;
            items
        };
        assert!(
            proposal.contains(&UsdtConsensusItem::RotateSigning {
                session_id: attempt0_id,
            }),
            "consensus_proposal must propose RotateSigning for the timed-out attempt: {proposal:?}"
        );

        // Feed the RotateSigning item to EVERY guardian (proposer identity is
        // irrelevant to this item's processing).
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::RotateSigning {
                        session_id: attempt0_id,
                    },
                    PeerId::from(0),
                )
                .await
                .expect("RotateSigning for a timed-out in-progress session must process cleanly");
            dbtx.commit_tx().await;
        }

        // Every guardian's consensus DB is identical: attempt-0 Failed, a new
        // attempt-1 session InProgress at round 0 under the rotated subset.
        for &peer in &peers {
            let mut dbtx = modules[&peer].db_for_test().begin_transaction_nc().await;

            let failed = dbtx
                .get_value(&SigningSessionKey(attempt0_id))
                .await
                .expect("attempt-0 session still present");
            assert_eq!(
                failed.state,
                SessionState::Failed,
                "peer {peer} must mark the timed-out attempt Failed"
            );

            let retry = dbtx
                .get_value(&SigningSessionKey(attempt1_id))
                .await
                .expect("attempt-1 session created");
            assert_eq!(retry.attempt, 1);
            assert_eq!(retry.round, 0);
            assert_eq!(retry.state, SessionState::InProgress);
            assert_eq!(
                retry.signers, subset1,
                "the retry must run under the rotated (digest-seeded attempt-1) signer subset"
            );
        }

        // A second, identical RotateSigning is now rejected: the attempt-0
        // session is already Failed, not InProgress.
        {
            let module = &modules[&PeerId::from(0)];
            let mut dbtx = module.db_for_test().begin_transaction().await;
            let err = module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::RotateSigning {
                        session_id: attempt0_id,
                    },
                    PeerId::from(0),
                )
                .await
                .expect_err("re-rotating an already-Failed attempt must Err");
            assert!(err.to_string().contains("non-in-progress"));
        }
    }

    /// **Phase 9, Drill D** (hardening-acceptance-audit plan Task 2):
    /// Byzantine chunk-count/withholding liveness. Complements
    /// `rotate_signing_fails_timed_out_attempt_and_retries_rotated_subset`
    /// above (which models a signer that withholds EVERY `MpcRound` chunk --
    /// total silence) and
    /// `degraded_federation_recovers_signing_via_timeout_and_rotation`
    /// (`fedimint-usdt-tests/tests/tests.rs`, the same total-withholding
    /// scenario over a real federation) by covering the distinct scenario the
    /// Phase-9 plan calls out: a signer that DOES send a chunk, but with an
    /// inconsistent/malformed `chunk_count` -- specifically, a self-serving
    /// bogus large count that it then never finishes delivering.
    ///
    /// `process_mpc_round`'s `peer_complete` closure (see its own doc
    /// comment) derives each peer's expected `chunk_count` from that SAME
    /// peer's own lowest-index chunk, never from a value shared/agreed with
    /// other peers -- so a Byzantine peer's fabricated count can only ever
    /// make ITS OWN completion condition (`0..count` all present) harder to
    /// satisfy; it cannot corrupt or block the other, honest signers'
    /// independently-tracked completion, and it cannot make the round
    /// consensus-DB write depend on anything but the ordered items every
    /// guardian sees identically. This test proves exactly that: honest
    /// peers 0 and 1 complete round 0 normally (their chunks are stored and
    /// independently verified complete), the Byzantine peer 2 sends a
    /// single chunk claiming `chunk_count = 5` (comfortably under
    /// `MAX_MPC_CHUNKS`, sec-11's cap on a syntactically well-formed but
    /// hostile count -- see [`MAX_MPC_CHUNKS`]) and stops there, the round
    /// consequently never advances (`signers.iter().all(peer_complete)`
    /// requires ALL signers, honest or not), and the resulting stall
    /// recovers via the same generic timeout+rotation path proven above --
    /// this is not new recovery machinery, just a different way to reach
    /// the same `timed_out`/`RotateSigning` gate.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn drill_d_byzantine_inconsistent_chunk_count_stalls_only_that_attempt_and_recovers_via_rotation()
     {
        use sha2::{Digest as _, Sha256};

        const N: u16 = 4;
        let peers: Vec<PeerId> = (0..N).map(PeerId::from).collect();
        let num_peers = peers.to_num_peers();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );

        let mut modules: BTreeMap<PeerId, Usdt> = BTreeMap::new();
        for &peer in &peers {
            let cfg = server_cfgs[&peer]
                .clone()
                .to_typed::<UsdtConfig>()
                .expect("config was just generated by the same configgen");
            let db = fedimint_core::db::Database::new(
                fedimint_core::db::mem_impl::MemDatabase::new(),
                fedimint_core::module::registry::ModuleDecoderRegistry::default(),
            );
            modules.insert(
                peer,
                Usdt::new_for_test(cfg, MockEvmRpc::default().into_dyn(), db, peer, num_peers),
            );
        }

        let digest: [u8; 32] = Sha256::digest(b"usdt byzantine chunk-count test").into();
        let attempt0_id = fedimint_usdt_common::signing_session_id(&digest, 0);
        let attempt1_id = fedimint_usdt_common::signing_session_id(&digest, 1);
        let purpose = SigningPurpose::UserOp(digest);

        // The digest-seeded subsets for attempt 0 and attempt 1 -- derived
        // rather than hard-coded, since the seed depends on `digest`. Two of
        // attempt 0's three signers act honestly; the third is Byzantine.
        let subset0 = modules[&PeerId::from(0)].signer_subset(&digest, 0);
        let subset1 = modules[&PeerId::from(0)].signer_subset(&digest, 1);
        let honest_peer_a = subset0[0];
        let honest_peer_b = subset0[1];
        let byzantine_peer = subset0[2];

        // Attempt 0: every guardian starts the identical session over the
        // digest-seeded subset.
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .start_session(&mut dbtx.to_ref_nc(), purpose.clone(), digest, 0)
                .await;
            dbtx.commit_tx().await;
        }

        // Round 0: two HONEST signers (`honest_peer_a`, `honest_peer_b`) each
        // send a single, self-consistent chunk (chunk_count=1, chunk=0). The
        // consensus-level payload bytes are opaque to `process_mpc_round`
        // (see its own doc comment: reassembly/off-thread interpretation is
        // guardian-local), so arbitrary content is fine here.
        let honest_items = [
            (
                honest_peer_a,
                MpcRoundItem {
                    session_id: attempt0_id,
                    round: 0,
                    chunk: 0,
                    chunk_count: 1,
                    payload: vec![0xAA],
                },
            ),
            (
                honest_peer_b,
                MpcRoundItem {
                    session_id: attempt0_id,
                    round: 0,
                    chunk: 0,
                    chunk_count: 1,
                    payload: vec![0xBB],
                },
            ),
        ];
        // The BYZANTINE signer (`byzantine_peer`, a genuine member of
        // attempt 0's subset) sends exactly one chunk claiming an
        // inconsistent `chunk_count` of 5, then withholds the rest -- this is
        // a self-inflicted stall (`0..5` can never all be present), not a
        // crash or a consensus-divergence: `process_mpc_round`'s explicit
        // range check (`chunk_count >= 1 && chunk < chunk_count`) and sec-11's
        // `chunk_count <= MAX_MPC_CHUNKS` cap both accept this item as
        // well-formed (0 < 5 <= MAX_MPC_CHUNKS), exactly as they must accept
        // any syntactically valid but semantically hostile chunk count that
        // stays within the federation-wide cap.
        let byzantine_item = (
            byzantine_peer,
            MpcRoundItem {
                session_id: attempt0_id,
                round: 0,
                chunk: 0,
                chunk_count: 5,
                payload: vec![0xCC],
            },
        );

        // Deliver all three items to EVERY guardian (their consensus-DB
        // effect is peer_id-of-the-guardian-agnostic -- see
        // `process_mpc_round`'s determinism doc comment).
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            for (sender, item) in honest_items.iter().chain(std::iter::once(&byzantine_item)) {
                module
                    .process_consensus_item(
                        &mut dbtx.to_ref_nc(),
                        UsdtConsensusItem::MpcRound(item.clone()),
                        *sender,
                    )
                    .await
                    .expect("a well-formed (if hostile) MpcRound chunk must process cleanly");
            }
            dbtx.commit_tx().await;
        }

        // Every guardian's view: the honest peers' chunks ARE recorded (the
        // Byzantine peer did not block or corrupt them)...
        for &peer in &peers {
            let mut dbtx = modules[&peer].db_for_test().begin_transaction_nc().await;
            for honest_peer in [honest_peer_a, honest_peer_b] {
                let chunk = dbtx
                    .get_value(&MpcRoundChunkKey(attempt0_id, 0, honest_peer, 0))
                    .await;
                assert!(
                    chunk.is_some(),
                    "peer {peer}'s view must still record honest peer {honest_peer}'s round-0 \
                     chunk"
                );
            }
        }

        // ...but the round never advances, on every guardian identically:
        // the Byzantine peer's declared 5 chunks are never all present, so
        // `signers.iter().all(peer_complete)` is false federation-wide, even
        // though 2 of 3 signers are individually complete.
        for &peer in &peers {
            let mut dbtx = modules[&peer].db_for_test().begin_transaction_nc().await;
            let session = dbtx
                .get_value(&SigningSessionKey(attempt0_id))
                .await
                .expect("attempt-0 session present");
            assert_eq!(
                session.round, 0,
                "peer {peer}: the round must not advance while the Byzantine signer's \
                 declared chunk count remains unsatisfied"
            );
            assert_eq!(session.state, SessionState::InProgress);
        }

        // The stall recovers via the SAME generic timeout+rotation path as
        // total withholding: advance the consensus block count strictly past
        // the timeout, propose + process RotateSigning.
        for module in modules.values() {
            seed_block_count_votes(module.db_for_test(), N, timeout_blocks() + 1).await;
        }

        let proposal = {
            let module = &modules[&PeerId::from(0)];
            let mut dbtx = module.db_for_test().begin_transaction().await;
            let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
            dbtx.commit_tx().await;
            items
        };
        assert!(
            proposal.contains(&UsdtConsensusItem::RotateSigning {
                session_id: attempt0_id,
            }),
            "consensus_proposal must propose RotateSigning for the chunk-count-stalled attempt: \
             {proposal:?}"
        );

        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::RotateSigning {
                        session_id: attempt0_id,
                    },
                    PeerId::from(0),
                )
                .await
                .expect("RotateSigning for a timed-out in-progress session must process cleanly");
            dbtx.commit_tx().await;
        }

        // Every guardian: attempt-0 Failed (only that attempt, and only
        // because of the stall -- not a crash or divergence anywhere), a
        // fresh attempt-1 InProgress at round 0 under the rotated subset
        // (whether or not that subset happens to still include the
        // Byzantine peer is immaterial: a fresh attempt starts its
        // `MpcRoundChunk` table empty, so its earlier chunk-count
        // shenanigans do not carry over).
        for &peer in &peers {
            let mut dbtx = modules[&peer].db_for_test().begin_transaction_nc().await;
            let failed = dbtx
                .get_value(&SigningSessionKey(attempt0_id))
                .await
                .expect("attempt-0 session still present");
            assert_eq!(failed.state, SessionState::Failed);

            let retry = dbtx
                .get_value(&SigningSessionKey(attempt1_id))
                .await
                .expect("attempt-1 session created");
            assert_eq!(retry.attempt, 1);
            assert_eq!(retry.round, 0);
            assert_eq!(retry.state, SessionState::InProgress);
            assert_eq!(
                retry.signers, subset1,
                "the retry must run under the rotated (offset-1) signer subset"
            );
        }
    }

    #[tokio::test]
    async fn block_hash_ring_write_read_and_prune() {
        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );

        // Write two nearby heights; both must read back and `ring_latest_height`
        // must report the newer one.
        let mut dbtx = db.begin_transaction().await;
        write_block_hash_ring(&mut dbtx.to_ref_nc(), 10, [0x10; 32]).await;
        write_block_hash_ring(&mut dbtx.to_ref_nc(), 11, [0x11; 32]).await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            ring_hash_at(&mut dbtx.to_ref_nc(), 10).await,
            Some([0x10; 32])
        );
        assert_eq!(
            ring_hash_at(&mut dbtx.to_ref_nc(), 11).await,
            Some([0x11; 32])
        );
        assert_eq!(ring_latest_height(&mut dbtx.to_ref_nc()).await, Some(11));
        drop(dbtx);

        // Writing a height far enough ahead (>= oldest + BLOCK_HASH_RING_LEN)
        // prunes the oldest entry out of the window, but must not disturb an
        // entry that is still within it.
        let newest = 10 + BLOCK_HASH_RING_LEN;
        let mut dbtx = db.begin_transaction().await;
        write_block_hash_ring(&mut dbtx.to_ref_nc(), newest, [0x99; 32]).await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            ring_hash_at(&mut dbtx.to_ref_nc(), 10).await,
            None,
            "height 10 is exactly BLOCK_HASH_RING_LEN behind the new newest height and must \
             be pruned"
        );
        assert_eq!(
            ring_hash_at(&mut dbtx.to_ref_nc(), 11).await,
            Some([0x11; 32]),
            "height 11 is still within the window and must survive the prune"
        );
        assert_eq!(
            ring_hash_at(&mut dbtx.to_ref_nc(), newest).await,
            Some([0x99; 32])
        );
        assert_eq!(
            ring_latest_height(&mut dbtx.to_ref_nc()).await,
            Some(newest)
        );
    }

    // --- Phase 9, Drill A: deposit reorg safety -----------------------------
    //
    // Hardening-acceptance-audit plan (`docs/superpowers/plans/
    // 2026-07-21-hardening-acceptance-audit.md`), Task 1.
    //
    // The confirmation-depth gating that used to prevent an unconfirmed /
    // shallow-reorg deposit from ever being credited off a guardian-local
    // poll no longer lives on a deposit path at all: crediting is now
    // proof-driven (a client submits a
    // [`fedimint_usdt_common::DepositProof`] verified against the federation's
    // block-hash ring anchor), and the block-hash observer only ever anchors a
    // block once it is `confirmation_depth` deep AND threshold-many guardians
    // agree its canonical hash. A proof therefore cannot verify against an
    // unconfirmed or sub-`confirmation_depth`-reorged block -- there is no
    // anchor for it -- so the two former scanner-level drill tests
    // (`..._within_confirmation_depth_is_not_credited` and
    // `..._reorged_out_before_confirmation_depth_is_never_credited`) were
    // removed alongside the polling machinery they exercised; that gating is
    // now covered structurally by the block-hash-ring anchor + proof tests.
    //
    // What remains worth proving here is the deep-reorg boundary: once a
    // deposit HAS been credited, `credited` is monotonic-forward-only (see
    // [`Usdt::credit_deposit`]'s own doc comment: "Only credit forward;
    // balance is monotonic between sweeps") and there is no consensus arm that
    // un-credits it.
    // `drill_a_credited_deposit_is_monotonic_and_never_moves_backward` below
    // proves that monotonicity directly. Whether to build a credit-reversal
    // path for the deep-reorg case (which also has to interact with
    // already-claimed e-cash) is the maintainer policy decision recorded in
    // the Phase-9 plan's "Reorg credit-reversal policy" sign-off item
    // (elsirion); the default, and what this module implements today, is to
    // rely on an operator choosing `confirmation_depth` conservatively
    // enough, for the target chain, that a reorg past it is not practically
    // achievable.

    #[tokio::test]
    async fn drill_a_credited_deposit_is_monotonic_and_never_moves_backward() {
        // Once a deposit has been credited, `credited` is monotonic-
        // forward-only (see `Usdt::credit_deposit`'s own doc comment) --
        // there is no credit-reversal consensus arm. This proves that
        // guarantee directly: even if a LATER threshold-agreed
        // `DepositObservation` reports a LOWER balance for the same account
        // (on a real deployment, that would require a reorg deep enough to
        // have reduced the balance below what was already credited a
        // confirmation_depth-satisfying read ago -- see this section's
        // header comment for why that specific scenario cannot arise from a
        // reorg SHALLOWER than confirmation_depth), the module's `credited`
        // field never moves down.
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        // Freshness gate (finding 12): seed a consensus block count that keeps
        // BOTH the block-50 and (later) block-80 observations in-window.
        seed_block_count_votes(db, 4, 80 + module.cfg.consensus.confirmation_depth).await;
        let claim_pk = test_pubkey(0x75);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        let high_obs = DepositObservation {
            account,
            balance: UsdtAmount(2_000_000),
            block: 50,
            block_hash: [0u8; 32],
            claim_pk,
        };
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::Deposit(high_obs.clone()),
                    PeerId::from(p),
                )
                .await
                .unwrap();
        }
        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("threshold reached, record must exist");
        assert_eq!(record.credited, UsdtAmount(2_000_000));

        // A later round observes a LOWER balance at a later block (modeling
        // a deep reorg, or a byzantine/erroneous read) -- reaching the SAME
        // 3-of-4 threshold.
        let low_obs = DepositObservation {
            account,
            balance: UsdtAmount(500_000),
            block: 80,
            block_hash: [0u8; 32],
            claim_pk,
        };
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::Deposit(low_obs.clone()),
                    PeerId::from(p),
                )
                .await
                .unwrap();
        }

        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record still exists");
        assert_eq!(
            record.credited,
            UsdtAmount(2_000_000),
            "credited must never move backward even given a later, lower-balance \
             threshold-agreed observation"
        );
        // Freshness tracking (`last_observed_block`) is independent of the
        // monotonic credit amount, and does still advance.
        assert_eq!(record.last_observed_block, 80);
    }

    /// Builds a synthetic single-leaf Merkle-Patricia deposit proof that the
    /// real [`crate::proof::verify_deposit_proof`] accepts, wholly offline: a
    /// state trie holding exactly `usdt_contract`'s account (whose storage
    /// trie holds exactly `account`'s USDT balance slot), wrapped in a header
    /// whose keccak is the returned canonical block hash.
    ///
    /// A single-key trie is just its one leaf node, so its root is
    /// `keccak256(rlp(leaf))` and its proof is `[rlp(leaf)]` -- `verify_proof`
    /// walks that one node to the full key. The committed mainnet fixtures
    /// (Task 2) prove an EXCHANGE hot wallet, which by design no `claim_pk` can
    /// derive an account for, so they cannot drive a POSITIVE credit through
    /// the claim-key-derived-account binding; this hermetic builder lets us
    /// prove a balance for a genuinely-derived deposit account instead.
    fn synthetic_deposit_proof(
        usdt_contract: fedimint_usdt_common::EvmAddress,
        account: fedimint_usdt_common::EvmAddress,
        balance: u64,
        block_number: u64,
    ) -> (fedimint_usdt_common::DepositProof, [u8; 32]) {
        use alloy_consensus::Header;
        use alloy_primitives::{B256, U256, keccak256};
        use alloy_rlp::Encodable as _;
        use alloy_trie::nodes::LeafNode;
        use alloy_trie::{Nibbles, TrieAccount};

        // Storage trie: one leaf at keccak(balances_storage_key(account)),
        // value = rlp(balance word), root = keccak(rlp(leaf)).
        let storage_key = Nibbles::unpack(keccak256(fedimint_usdt_common::balances_storage_key(
            &account,
        )));
        let mut storage_value = Vec::new();
        U256::from(balance).encode(&mut storage_value);
        let mut storage_leaf_rlp = Vec::new();
        LeafNode::new(storage_key, storage_value).encode(&mut storage_leaf_rlp);
        let storage_root = B256::from(keccak256(&storage_leaf_rlp));

        // Account trie: one leaf at keccak(usdt_contract), value =
        // rlp(TrieAccount { storage_root, .. }), root = state root.
        let account_key = Nibbles::unpack(keccak256(usdt_contract.0));
        let mut account_value = Vec::new();
        TrieAccount {
            storage_root,
            ..Default::default()
        }
        .encode(&mut account_value);
        let mut account_leaf_rlp = Vec::new();
        LeafNode::new(account_key, account_value).encode(&mut account_leaf_rlp);
        let state_root = B256::from(keccak256(&account_leaf_rlp));

        // Header committing to that state root; its keccak is the block hash
        // the ring must anchor for the proof to verify.
        let mut header_rlp = Vec::new();
        Header {
            state_root,
            number: block_number,
            ..Default::default()
        }
        .encode(&mut header_rlp);
        let block_hash = keccak256(&header_rlp).0;

        (
            fedimint_usdt_common::DepositProof {
                block_number,
                header_rlp,
                account_proof: vec![account_leaf_rlp],
                storage_proof: vec![storage_leaf_rlp],
            },
            block_hash,
        )
    }

    /// Derives `claim_pk`'s deposit account under `module`'s config, exactly
    /// as `process_deposit_proof` does internally.
    fn derived_account(module: &Usdt, claim_pk: &secp256k1::PublicKey) -> EvmAddress {
        derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            claim_pk,
        )
    }

    /// Happy path: a proof of a genuinely-derived deposit account's on-chain
    /// balance, anchored in the ring, credits the newly-proven delta as
    /// spendable e-cash, advances the monotonic high-water `credited` to the
    /// proven balance, and advances `claimed` by the same delta (so the minted
    /// value cannot be re-claimed). A resubmission of the same proof is
    /// rejected (delta 0), while a later proof of a HIGHER balance credits
    /// only the additional delta.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn deposit_proof_input_credits_delta_and_sets_high_water() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x71);
        let account = derived_account(&module, &claim_pk);
        let usdt_contract = module.cfg.consensus.usdt_contract;

        // First proof: 500 USDT (in 1e-6 units) at block 100.
        let (proof1, hash1) = synthetic_deposit_proof(usdt_contract, account, 500_000_000, 100);
        {
            let mut dbtx = db.begin_transaction().await;
            write_block_hash_ring(&mut dbtx.to_ref_nc(), 100, hash1).await;
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;
        let meta = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::DepositProofV0 {
                    claim_pk,
                    proof: proof1.clone(),
                },
                test_in_point(),
            )
            .await
            .expect("anchored proof of a derived account must credit");
        assert_eq!(
            meta.amount.amounts,
            Amounts::new_custom(USDT_UNIT, Amount::from_msats(500_000_000)),
            "the full newly-proven delta funds USDT_UNIT value (paired 1:1 with a mint output)"
        );
        assert_eq!(
            meta.amount.fees,
            Amounts::ZERO,
            "deposit-by-proof charges no fee"
        );
        assert_eq!(
            meta.pub_key, claim_pk,
            "e-cash is bound to the depositor's claim key"
        );
        dbtx.commit_tx().await;

        let record = db
            .begin_transaction_nc()
            .await
            .get_value(&DepositRecordKey(account))
            .await
            .expect("credit created the record");
        assert_eq!(
            record.credited,
            UsdtAmount(500_000_000),
            "credited = proven"
        );
        assert_eq!(
            record.claimed,
            UsdtAmount(500_000_000),
            "claimed advanced by the minted delta"
        );
        assert_eq!(record.last_observed_block, 100);

        // Resubmitting the same proof: credited already == proven, delta 0.
        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::DepositProofV0 {
                    claim_pk,
                    proof: proof1,
                },
                test_in_point(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            UsdtInputError::DepositProofStale {
                proven: UsdtAmount(500_000_000),
                credited: UsdtAmount(500_000_000),
            }
        );
        dbtx.commit_tx().await;

        // A later proof of a HIGHER balance (the address received more USDT)
        // credits only the additional delta and advances the high-water.
        let (proof2, hash2) = synthetic_deposit_proof(usdt_contract, account, 800_000_000, 110);
        {
            let mut dbtx = db.begin_transaction().await;
            write_block_hash_ring(&mut dbtx.to_ref_nc(), 110, hash2).await;
            dbtx.commit_tx().await;
        }
        let mut dbtx = db.begin_transaction().await;
        let meta = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::DepositProofV0 {
                    claim_pk,
                    proof: proof2,
                },
                test_in_point(),
            )
            .await
            .expect("higher-balance proof credits the growth");
        assert_eq!(
            meta.amount.amounts,
            Amounts::new_custom(USDT_UNIT, Amount::from_msats(300_000_000)),
            "only the 300M delta over the 500M high-water is minted"
        );
        dbtx.commit_tx().await;

        let record = db
            .begin_transaction_nc()
            .await
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record still exists");
        assert_eq!(record.credited, UsdtAmount(800_000_000));
        assert_eq!(record.claimed, UsdtAmount(800_000_000));
        assert_eq!(record.last_observed_block, 110);
    }

    /// A proof for a block the federation has not anchored in its block-hash
    /// ring is rejected outright -- there is no trusted hash to verify against.
    #[tokio::test]
    async fn deposit_proof_input_rejects_block_not_in_ring() {
        let module = test_module_with_block_count(4, 0).await;
        let claim_pk = test_pubkey(0x72);
        let account = derived_account(&module, &claim_pk);
        let (proof, _hash) = synthetic_deposit_proof(
            module.cfg.consensus.usdt_contract,
            account,
            123_000_000,
            100,
        );
        // Ring left empty: block 100 was never anchored.
        let mut dbtx = module.db_for_test().begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::DepositProofV0 { claim_pk, proof },
                test_in_point(),
            )
            .await
            .unwrap_err();
        assert_eq!(err, UsdtInputError::DepositProofNotAnchored { block: 100 });
    }

    /// A tampered proof (header no longer hashes to the anchored block hash)
    /// fails verification and is rejected, never crediting anything.
    #[tokio::test]
    async fn deposit_proof_input_rejects_tampered_proof() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x73);
        let account = derived_account(&module, &claim_pk);
        let (mut proof, hash) = synthetic_deposit_proof(
            module.cfg.consensus.usdt_contract,
            account,
            400_000_000,
            100,
        );
        {
            let mut dbtx = db.begin_transaction().await;
            // Anchor the ORIGINAL (untampered) block hash.
            write_block_hash_ring(&mut dbtx.to_ref_nc(), 100, hash).await;
            dbtx.commit_tx().await;
        }
        // Flip a byte deep inside the header: keccak(header_rlp) != anchored hash.
        let mid = proof.header_rlp.len() / 2;
        proof.header_rlp[mid] ^= 0xff;

        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::DepositProofV0 { claim_pk, proof },
                test_in_point(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, UsdtInputError::DepositProofInvalid { .. }),
            "expected DepositProofInvalid, got {err:?}"
        );
        // No record was created by the rejected input.
        assert!(
            db.begin_transaction_nc()
                .await
                .get_value(&DepositRecordKey(account))
                .await
                .is_none()
        );
    }

    /// SECURITY: a valid proof for an on-chain account the submitter's
    /// `claim_pk` does NOT derive (e.g. an exchange wallet) credits nothing.
    /// `process_deposit_proof` verifies against the DERIVED account's storage
    /// key, so the unrelated account's balance proof reads as proof-of-absence
    /// (0) -- an attacker cannot mint against funds they cannot also derive a
    /// claim key for.
    #[tokio::test]
    async fn deposit_proof_input_for_unrelated_account_credits_nothing() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x74);
        // Build a genuine, verifiable proof -- but for an account that is NOT
        // derive_deposit_account(claim_pk).
        let unrelated = EvmAddress([0x99; 20]);
        assert_ne!(unrelated, derived_account(&module, &claim_pk));
        let (proof, hash) = synthetic_deposit_proof(
            module.cfg.consensus.usdt_contract,
            unrelated,
            17_764_402_170_699_000,
            100,
        );
        {
            let mut dbtx = db.begin_transaction().await;
            write_block_hash_ring(&mut dbtx.to_ref_nc(), 100, hash).await;
            dbtx.commit_tx().await;
        }
        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::DepositProofV0 { claim_pk, proof },
                test_in_point(),
            )
            .await
            .unwrap_err();
        // Verifies against the DERIVED account -> absence -> proven 0 -> delta 0.
        assert_eq!(
            err,
            UsdtInputError::DepositProofStale {
                proven: UsdtAmount(0),
                credited: UsdtAmount(0),
            }
        );
    }

    /// SECURITY (Task 5 review): the whole point of `DepositProofV0` bumping
    /// `claimed` alongside `credited` is to close off a legacy `UsdtInput::V0`
    /// claim on the SAME account for the value the proof just minted. Prove
    /// that end-to-end: credit an account via a proof, then immediately
    /// attempt a real `V0` claim against it and confirm there is nothing left
    /// to claim (`available == 0`). If `process_deposit_proof` only bumped
    /// `credited` (forgetting `claimed += delta`), this V0 claim would
    /// succeed and re-mint the already-minted 500M -- a double-spend.
    #[tokio::test]
    async fn deposit_proof_then_v0_cannot_double_claim() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x75);
        let account = derived_account(&module, &claim_pk);
        let usdt_contract = module.cfg.consensus.usdt_contract;

        // Anchor and submit a proof of a 500 USDT (1e-6 units) on-chain balance.
        let (proof, hash) = synthetic_deposit_proof(usdt_contract, account, 500_000_000, 100);
        {
            let mut dbtx = db.begin_transaction().await;
            write_block_hash_ring(&mut dbtx.to_ref_nc(), 100, hash).await;
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;
        let meta = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::DepositProofV0 {
                    claim_pk,
                    proof: proof.clone(),
                },
                test_in_point(),
            )
            .await
            .expect("anchored proof of a derived account must credit");
        assert_eq!(
            meta.amount.amounts,
            Amounts::new_custom(USDT_UNIT, Amount::from_msats(500_000_000)),
            "the proof mints the full delta"
        );
        dbtx.commit_tx().await;

        let record = db
            .begin_transaction_nc()
            .await
            .get_value(&DepositRecordKey(account))
            .await
            .expect("credit created the record");
        assert_eq!(
            record.credited,
            UsdtAmount(500_000_000),
            "credited = proven"
        );
        assert_eq!(
            record.claimed,
            UsdtAmount(500_000_000),
            "claimed advanced by the SAME delta the proof minted -- this is the \
             guard under test"
        );

        // Now attempt a legacy V0 claim on the SAME account. `available =
        // credited - claimed` must be 0: the proof already minted this value,
        // so there is nothing left for a V0 input to re-mint. Even a
        // 1-unit claim must be rejected as insufficient credit; no fee vote
        // is seeded because the `InsufficientCredit` check runs before the
        // fee-quote lookup in `process_input`, so it cannot mask this guard.
        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: UsdtAmount(1),
                    fee: UsdtAmount(0),
                }),
                test_in_point(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            UsdtInputError::InsufficientCredit {
                available: UsdtAmount(0),
                requested: UsdtAmount(1),
            },
            "a V0 claim must not be able to re-mint value a DepositProofV0 \
             already minted for this account"
        );

        // `claimed` (and `credited`) must be unchanged by the rejected claim.
        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record still exists");
        assert_eq!(record.credited, UsdtAmount(500_000_000));
        assert_eq!(record.claimed, UsdtAmount(500_000_000));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn process_input_claims_credited_deposit_and_guards_against_double_claim() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let account = EvmAddress([0x55; 20]);
        let claim_pk = test_pubkey(0xee);

        // A `FeeVote` median must exist for `process_input` to quote a
        // deposit fee at all (mirrors `process_output_debits_and_enqueues_
        // withdrawal` seeding a median before withdrawing).
        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let fee = deposit_fee_quote(&sample_fee_vote()).expect("realistic vote must quote");

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(500_000_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        // First claim of 200M (paying exactly the quoted fee) succeeds,
        // funding USDT_UNIT and bumping `claimed` by the FULL amount (the
        // fee stays credited-but-unissued until the sweep, per
        // `process_input`'s doc comment).
        let mut dbtx = db.begin_transaction().await;
        let meta = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: UsdtAmount(200_000_000),
                    fee,
                }),
                test_in_point(),
            )
            .await
            .expect("first claim within credited balance must succeed");
        assert_eq!(
            meta.amount.amounts,
            Amounts::new_custom(USDT_UNIT, Amount::from_msats(200_000_000)),
            "amounts is the FULL/gross claimed amount, mirroring process_output's \
             amounts -- FundingVerifier nets the separate `fees` pool"
        );
        assert_eq!(
            meta.amount.fees,
            Amounts::new_custom(USDT_UNIT, Amount::from_msats(fee.0))
        );
        assert_eq!(meta.pub_key, claim_pk);
        dbtx.commit_tx().await;

        let record = db
            .begin_transaction_nc()
            .await
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record still exists");
        assert_eq!(record.claimed, UsdtAmount(200_000_000));

        // Second claim of 200M succeeds (400M of 500M now claimed).
        let mut dbtx = db.begin_transaction().await;
        module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: UsdtAmount(200_000_000),
                    fee,
                }),
                test_in_point(),
            )
            .await
            .expect("second claim within remaining credited balance must succeed");
        dbtx.commit_tx().await;

        let record = db
            .begin_transaction_nc()
            .await
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record still exists");
        assert_eq!(record.claimed, UsdtAmount(400_000_000));

        // Third claim of 200M exceeds the remaining 100M: double-claim/over-claim
        // guard.
        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: UsdtAmount(200_000_000),
                    fee,
                }),
                test_in_point(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            UsdtInputError::InsufficientCredit {
                available: UsdtAmount(100_000_000),
                requested: UsdtAmount(200_000_000),
            }
        );

        // `claimed` must not have been bumped by the rejected claim.
        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record still exists");
        assert_eq!(record.claimed, UsdtAmount(400_000_000));
    }

    #[tokio::test]
    async fn process_input_rejects_deposit_fee_below_quote() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let account = EvmAddress([0x57; 20]);
        let claim_pk = test_pubkey(0xef);

        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let quote = deposit_fee_quote(&sample_fee_vote()).expect("realistic vote must quote");

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(500_000_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: UsdtAmount(200_000_000),
                    fee: UsdtAmount(quote.0 - 1),
                }),
                test_in_point(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            UsdtInputError::DepositFeeInsufficient {
                quote,
                offered: UsdtAmount(quote.0 - 1),
            }
        );

        // Rejected claim must not have bumped `claimed`.
        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record still exists");
        assert_eq!(record.claimed, UsdtAmount(0));
    }

    #[tokio::test]
    async fn process_input_rejects_fee_gte_amount() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let account = EvmAddress([0x58; 20]);
        let claim_pk = test_pubkey(0xf0);

        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let quote = deposit_fee_quote(&sample_fee_vote()).expect("realistic vote must quote");

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(500_000_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        // `amount == fee` exactly: the deposit would fund nothing after the
        // fee, so it must be rejected rather than silently minting zero
        // e-cash.
        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: quote,
                    fee: quote,
                }),
                test_in_point(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            UsdtInputError::FeeExceedsAmount {
                amount: quote,
                fee: quote,
            }
        );

        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record still exists");
        assert_eq!(record.claimed, UsdtAmount(0));
    }

    #[tokio::test]
    async fn process_input_rejects_when_no_fee_median_exists() {
        // Mirrors `process_output_rejects_when_no_fee_median_exists` exactly:
        // an absent median is now a distinct, explicit rejection
        // (`NoFeeQuoteAvailable`) rather than being folded into
        // `DepositFeeInsufficient` via an effectively-infinite sentinel quote.
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let account = EvmAddress([0x59; 20]);
        let claim_pk = test_pubkey(0xf1);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(500_000_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: UsdtAmount(200_000_000),
                    fee: UsdtAmount(u64::MAX - 1),
                }),
                test_in_point(),
            )
            .await
            .unwrap_err();
        assert_eq!(err, UsdtInputError::NoFeeQuoteAvailable);

        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record still exists");
        assert_eq!(record.claimed, UsdtAmount(0));
    }

    #[tokio::test]
    async fn process_input_unknown_account_errors() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let account = EvmAddress([0x66; 20]);

        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: UsdtAmount(1),
                    fee: UsdtAmount(0),
                }),
                test_in_point(),
            )
            .await
            .unwrap_err();
        assert_eq!(err, UsdtInputError::UnknownDepositAccount);
    }

    #[tokio::test]
    async fn process_input_default_variant_errors() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::Default {
                    variant: 99,
                    bytes: Vec::new(),
                },
                test_in_point(),
            )
            .await
            .unwrap_err();
        assert_eq!(err, UsdtInputError::UnknownDepositAccount);
    }

    fn test_out_point(idx: u64) -> OutPoint {
        OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: idx,
        }
    }

    fn sample_fee_vote() -> fedimint_usdt_common::FeeVote {
        fedimint_usdt_common::FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        }
    }

    /// Security finding 06's quorum facet: `fee_vote_median` must be `None`
    /// while fewer than `num_peers.threshold()` (fresh) votes are stored,
    /// even though the table is non-empty -- this is the fix for the
    /// startup/partial-vote window the finding describes (previously ANY
    /// single stored vote was already treated as the authoritative median).
    #[tokio::test]
    async fn median_none_below_quorum() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let mut dbtx = module.db_for_test().begin_transaction().await;

        // No votes yet -> None.
        assert_eq!(module.fee_vote_median(&mut dbtx.to_ref_nc()).await, None);

        // Three peers vote with distinct field combinations; each field's
        // median is computed independently.
        let votes = [
            FeeVote {
                max_fee_per_gas_wei: 10,
                usdt_per_eth_e6: 3_000_000_000,
            },
            FeeVote {
                max_fee_per_gas_wei: 20,
                usdt_per_eth_e6: 1_000_000_000,
            },
            FeeVote {
                max_fee_per_gas_wei: 30,
                usdt_per_eth_e6: 5_000_000_000,
            },
        ];
        for (i, vote) in votes.iter().take(2).enumerate() {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::FeeVote(*vote),
                    PeerId::from(u16::try_from(i).expect("small")),
                )
                .await
                .expect("first vote from each peer must succeed");
        }

        // Only 2 of 4 peers have voted -- below the 3-vote threshold -> still
        // None, EVEN THOUGH the table is non-empty (the pre-fix bug: any
        // non-empty vote set was already authoritative).
        assert_eq!(module.fee_vote_median(&mut dbtx.to_ref_nc()).await, None);

        // The third vote clears the quorum threshold.
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::FeeVote(votes[2]),
                PeerId::from(2),
            )
            .await
            .expect("third vote must succeed");

        // max_fee_per_gas_wei median of [10, 20, 30] = 20 (index 1).
        // usdt_per_eth_e6 median of [1e9, 3e9, 5e9] = 3e9 (index 1).
        assert_eq!(
            module.fee_vote_median(&mut dbtx.to_ref_nc()).await,
            Some(FeeVote {
                max_fee_per_gas_wei: 20,
                usdt_per_eth_e6: 3_000_000_000,
            })
        );
    }

    /// Security finding 06's freshness facet: a vote whose `recorded_block`
    /// has aged past `FEE_VOTE_TTL_BLOCKS` no longer counts toward the
    /// median (or the quorum) -- so a stale honest vote from a guardian
    /// whose fee source went offline cannot stay authoritative forever.
    #[tokio::test]
    async fn median_excludes_stale_votes() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        // 3 fresh votes (at consensus block 0) clear the quorum.
        let mut dbtx = db.begin_transaction().await;
        for p in 0..3u16 {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::FeeVote(sample_fee_vote()),
                    PeerId::from(p),
                )
                .await
                .expect("fee vote succeeds");
        }
        assert_eq!(
            module.fee_vote_median(&mut dbtx.to_ref_nc()).await,
            Some(sample_fee_vote())
        );
        dbtx.commit_tx().await;

        // Advance the consensus block count past the TTL without refreshing
        // any vote -- every stored vote is now stale.
        let mut dbtx = db.begin_transaction().await;
        for p in 0..4u16 {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::BlockCount(FEE_VOTE_TTL_BLOCKS + 1),
                    PeerId::from(p),
                )
                .await
                .expect("block count vote succeeds");
        }
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        assert_eq!(
            module.fee_vote_median(&mut dbtx.to_ref_nc()).await,
            None,
            "every stored vote aged past FEE_VOTE_TTL_BLOCKS -> below quorum -> None"
        );
    }

    /// Security finding 06's bounds facet: a `FeeVote` outside the
    /// configured sane range is rejected by `process_consensus_item` as a
    /// non-state-changing `Err` and never stored, closing the
    /// `FeeQuoteOverflow`-as-DoS path a single extreme Byzantine vote could
    /// otherwise open.
    #[tokio::test]
    async fn median_rejects_out_of_range_vote() {
        let module = test_module_with_block_count(4, 0).await;
        let mut dbtx = module.db_for_test().begin_transaction().await;

        let too_high_gas = FeeVote {
            max_fee_per_gas_wei: fedimint_usdt_common::MAX_SANE_MAX_FEE_PER_GAS_WEI + 1,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let err = module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::FeeVote(too_high_gas),
                PeerId::from(0),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("sane range"));

        let too_high_price = FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: fedimint_usdt_common::MAX_SANE_USDT_PER_ETH_E6 + 1,
        };
        let err = module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::FeeVote(too_high_price),
                PeerId::from(0),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("sane range"));

        let zero_vote = FeeVote {
            max_fee_per_gas_wei: 0,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let err = module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::FeeVote(zero_vote),
                PeerId::from(0),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("sane range"));

        // None of the rejected votes were stored.
        assert_eq!(
            dbtx.to_ref_nc()
                .get_value(&FeeVoteKey(PeerId::from(0)))
                .await,
            None
        );
    }

    /// Security finding 06's freshness facet: `consensus_proposal` must
    /// re-propose a guardian's current fee estimate even when its polled
    /// VALUE is unchanged, once the previously stored vote's `recorded_block`
    /// has fallen `FEE_VOTE_REFRESH_BLOCKS` behind the current consensus
    /// block count -- otherwise a perfectly healthy guardian whose fee
    /// market simply hasn't moved would eventually age its own vote out of
    /// `fee_vote_median`'s TTL for no good reason.
    #[tokio::test]
    async fn healthy_vote_is_refreshed_before_ttl() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let vote = sample_fee_vote();
        *module.fee_estimate.lock().expect("not poisoned") = Some(vote);

        // First proposal + apply: stores the vote at consensus block 0.
        let mut dbtx = db.begin_transaction().await;
        let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
        assert!(items.contains(&UsdtConsensusItem::FeeVote(vote)));
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::FeeVote(vote),
                module.our_peer_id,
            )
            .await
            .expect("apply this guardian's own proposed vote");
        dbtx.commit_tx().await;

        // Advance the consensus block count by less than the refresh
        // cadence: the unchanged value must NOT be re-proposed yet.
        let mut dbtx = db.begin_transaction().await;
        for p in 0..4u16 {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::BlockCount(FEE_VOTE_REFRESH_BLOCKS - 1),
                    PeerId::from(p),
                )
                .await
                .expect("block count vote succeeds");
        }
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
        assert!(
            !items
                .iter()
                .any(|i| matches!(i, UsdtConsensusItem::FeeVote(_))),
            "still within the refresh cadence -> unchanged value not re-proposed"
        );
        dbtx.commit_tx().await;

        // Advance past the refresh cadence (but still well within the TTL):
        // the unchanged value MUST now be re-proposed and re-accepted.
        let mut dbtx = db.begin_transaction().await;
        for p in 0..4u16 {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::BlockCount(FEE_VOTE_REFRESH_BLOCKS),
                    PeerId::from(p),
                )
                .await
                .expect("block count vote succeeds");
        }
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
        assert!(
            items.contains(&UsdtConsensusItem::FeeVote(vote)),
            "past the refresh cadence -> unchanged value IS re-proposed to stay fresh"
        );
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::FeeVote(vote),
                module.our_peer_id,
            )
            .await
            .expect("a due refresh (same value, newer block) must be accepted, not rejected as redundant");

        let refreshed = dbtx
            .to_ref_nc()
            .get_value(&FeeVoteKey(module.our_peer_id))
            .await
            .expect("vote still stored");
        assert_eq!(refreshed.vote, vote);
        assert_eq!(refreshed.recorded_block, FEE_VOTE_REFRESH_BLOCKS);
    }

    /// (misc #4, finding 06's client-confusion facet.) With no `FeeVote`
    /// stored at all, both fee-quote handlers must report `available: false`
    /// and a `UsdtAmount(0)` placeholder -- NOT a sentinel a caller could
    /// mistake for a real, free quote.
    #[tokio::test]
    async fn fee_quote_unavailable_when_no_median() {
        let module = test_module_with_block_count(4, 0).await;
        let mut dbtx = module.db_for_test().begin_transaction().await;

        assert_eq!(module.fee_vote_median(&mut dbtx.to_ref_nc()).await, None);

        let withdraw_quote = module
            .handle_withdraw_fee_quote(&mut dbtx.to_ref_nc())
            .await;
        assert!(!withdraw_quote.available);
        assert_eq!(withdraw_quote.max_fee, UsdtAmount(0));
        assert_eq!(withdraw_quote.valid_blocks, FEE_QUOTE_VALID_BLOCKS);

        let deposit_quote = module.handle_deposit_fee_quote(&mut dbtx.to_ref_nc()).await;
        assert!(!deposit_quote.available);
        assert_eq!(deposit_quote.fee, UsdtAmount(0));
        assert_eq!(deposit_quote.valid_blocks, FEE_QUOTE_VALID_BLOCKS);
    }

    /// Positive control (guardrail: behavior-neutral except `available`):
    /// once a median exists, both handlers must report `available: true`
    /// with a `max_fee`/`fee` numerically IDENTICAL to calling
    /// `withdrawal_fee_quote`/`deposit_fee_quote` directly against that same
    /// median -- the fee math itself must not change.
    #[tokio::test]
    async fn fee_quote_available_and_unchanged_when_median_exists() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let mut dbtx = module.db_for_test().begin_transaction().await;
        let vote = sample_fee_vote();

        // Quorum requires >= threshold() (3 of 4) fresh votes (security
        // finding 06); identical votes trivially median to themselves.
        for p in 0..3u16 {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::FeeVote(vote),
                    PeerId::from(p),
                )
                .await
                .expect("vote must succeed");
        }

        let median = module
            .fee_vote_median(&mut dbtx.to_ref_nc())
            .await
            .expect("threshold-many identical votes are their own median");
        assert_eq!(median, vote);

        let expected_max_fee =
            withdrawal_fee_quote(&median).expect("sample_fee_vote must produce a quote");
        let withdraw_quote = module
            .handle_withdraw_fee_quote(&mut dbtx.to_ref_nc())
            .await;
        assert!(withdraw_quote.available);
        assert_eq!(withdraw_quote.max_fee, expected_max_fee);
        assert_eq!(withdraw_quote.valid_blocks, FEE_QUOTE_VALID_BLOCKS);

        let expected_fee =
            deposit_fee_quote(&median).expect("sample_fee_vote must produce a quote");
        let deposit_quote = module.handle_deposit_fee_quote(&mut dbtx.to_ref_nc()).await;
        assert!(deposit_quote.available);
        assert_eq!(deposit_quote.fee, expected_fee);
        assert_eq!(deposit_quote.valid_blocks, FEE_QUOTE_VALID_BLOCKS);
    }

    #[tokio::test]
    async fn fee_vote_redundancy_guard_rejects_exact_repeat_but_allows_a_change() {
        let module = test_module_with_block_count(4, 0).await;
        let mut dbtx = module.db_for_test().begin_transaction().await;
        let vote = sample_fee_vote();

        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::FeeVote(vote),
                PeerId::from(0),
            )
            .await
            .expect("first vote succeeds");

        // Exact repeat is rejected (unbounded-history rule).
        let err = module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::FeeVote(vote),
                PeerId::from(0),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("redundant"));

        // A genuinely different vote (fee market moved DOWN, unlike
        // BlockCount which only ever moves up) from the same peer succeeds.
        let lower_vote = FeeVote {
            max_fee_per_gas_wei: vote.max_fee_per_gas_wei - 1,
            usdt_per_eth_e6: vote.usdt_per_eth_e6,
        };
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::FeeVote(lower_vote),
                PeerId::from(0),
            )
            .await
            .expect("a changed vote (even a lower one) must succeed");
    }

    #[tokio::test]
    async fn consensus_proposal_drains_fee_estimate_only_when_changed() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        // No cached fee estimate yet -> no FeeVote item proposed.
        let mut dbtx = db.begin_transaction().await;
        let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
        assert!(
            !items
                .iter()
                .any(|i| matches!(i, UsdtConsensusItem::FeeVote(_)))
        );
        dbtx.commit_tx().await;

        // Poller "reads" a vote -> proposed once.
        let vote = sample_fee_vote();
        *module.fee_estimate.lock().expect("not poisoned") = Some(vote);
        let mut dbtx = db.begin_transaction().await;
        let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
        assert!(items.contains(&UsdtConsensusItem::FeeVote(vote)));

        // Simulate the item having been ordered and applied.
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::FeeVote(vote),
                module.our_peer_id,
            )
            .await
            .expect("apply this guardian's own proposed vote");
        dbtx.commit_tx().await;

        // Same reading again -> not re-proposed (dedup against stored vote).
        let mut dbtx = db.begin_transaction().await;
        let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
        assert!(
            !items
                .iter()
                .any(|i| matches!(i, UsdtConsensusItem::FeeVote(_)))
        );
    }

    /// Seeds every peer's `FeeVoteKey` with `vote`, stamped FRESH (at the
    /// current `consensus_block_count`), so `Usdt::fee_vote_median` resolves
    /// to exactly `vote` (all fields identical across peers -> trivially
    /// their own median, and `num_peers` fresh votes always clears the
    /// quorum threshold).
    async fn seed_fee_votes(db: &fedimint_core::db::Database, num_peers: u16, vote: FeeVote) {
        let peers = (0..num_peers)
            .map(PeerId::from)
            .collect::<Vec<_>>()
            .to_num_peers();
        let mut dbtx = db.begin_transaction().await;
        let recorded_block = consensus_block_count(&mut dbtx.to_ref_nc(), peers).await;
        let stored = StoredFeeVote {
            vote,
            recorded_block,
        };
        for p in 0..num_peers {
            dbtx.insert_new_entry(&FeeVoteKey(PeerId::from(p)), &stored)
                .await;
        }
        dbtx.commit_tx().await;
    }

    #[tokio::test]
    async fn process_output_rejects_when_no_fee_median_exists() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_output(
                &mut dbtx.to_ref_nc(),
                &UsdtOutput::V0(fedimint_usdt_common::UsdtOutputV0 {
                    recipient: EvmAddress([0x22; 20]),
                    amount: UsdtAmount(1_000_000),
                    max_fee: UsdtAmount(u64::MAX),
                    refund_pubkey: sample_claim_pk(),
                }),
                test_out_point(0),
            )
            .await
            .unwrap_err();
        assert_eq!(err, UsdtOutputError::NoFeeQuoteAvailable);
    }

    #[tokio::test]
    async fn process_output_rejects_max_fee_below_quote() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        seed_fee_votes(db, 4, sample_fee_vote()).await;

        let quote = withdrawal_fee_quote(&sample_fee_vote()).expect("realistic vote must quote");

        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_output(
                &mut dbtx.to_ref_nc(),
                &UsdtOutput::V0(fedimint_usdt_common::UsdtOutputV0 {
                    recipient: EvmAddress([0x22; 20]),
                    amount: UsdtAmount(1_000_000),
                    max_fee: UsdtAmount(quote.0 - 1),
                    refund_pubkey: sample_claim_pk(),
                }),
                test_out_point(0),
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            UsdtOutputError::FeeQuoteExceeded {
                quote,
                max_fee: UsdtAmount(quote.0 - 1),
            }
        );

        // The rejected output must not have written anything.
        let mut dbtx = db.begin_transaction_nc().await;
        assert!(
            dbtx.get_value(&UnclaimedWithdrawalKey(test_out_point(0)))
                .await
                .is_none()
        );
        assert!(
            dbtx.get_value(&WithdrawalStateKey(test_out_point(0)))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn process_output_debits_and_enqueues_withdrawal() {
        let module = test_module_with_block_count(4, 100).await;
        let db = module.db_for_test();
        seed_fee_votes(db, 4, sample_fee_vote()).await;
        // Advance the consensus block count so `requested_block` is
        // observably non-zero.
        {
            let mut dbtx = db.begin_transaction().await;
            for p in 0..4u16 {
                module
                    .process_consensus_item(
                        &mut dbtx.to_ref_nc(),
                        UsdtConsensusItem::BlockCount(50),
                        PeerId::from(p),
                    )
                    .await
                    .expect("block count vote succeeds");
            }
            dbtx.commit_tx().await;
        }

        let quote = withdrawal_fee_quote(&sample_fee_vote()).expect("realistic vote must quote");
        let recipient = EvmAddress([0x77; 20]);
        let amount = UsdtAmount(4_200_000);
        let out_point = test_out_point(7);

        let mut dbtx = db.begin_transaction().await;
        let meta = module
            .process_output(
                &mut dbtx.to_ref_nc(),
                &UsdtOutput::V0(fedimint_usdt_common::UsdtOutputV0 {
                    recipient,
                    amount,
                    max_fee: quote,
                    refund_pubkey: sample_claim_pk(),
                }),
                out_point,
            )
            .await
            .expect("max_fee == quote must clear the FeeQuoteExceeded check");
        dbtx.commit_tx().await;

        assert_eq!(
            meta.amounts,
            Amounts::new_custom(USDT_UNIT, Amount::from_msats(amount.0))
        );
        assert_eq!(
            meta.fees,
            Amounts::new_custom(USDT_UNIT, Amount::from_msats(quote.0))
        );

        let mut dbtx = db.begin_transaction_nc().await;
        let withdrawal = dbtx
            .get_value(&UnclaimedWithdrawalKey(out_point))
            .await
            .expect("UnclaimedWithdrawal must be written");
        assert_eq!(withdrawal.recipient, recipient);
        assert_eq!(withdrawal.amount, amount);
        assert_eq!(withdrawal.max_fee, quote);
        assert_eq!(withdrawal.requested_block, 50);

        let state = dbtx
            .get_value(&WithdrawalStateKey(out_point))
            .await
            .expect("WithdrawalState must be written");
        assert_eq!(state, WithdrawalState::Queued);
    }

    #[tokio::test]
    async fn process_output_default_variant_errors() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_output(
                &mut dbtx.to_ref_nc(),
                &UsdtOutput::Default {
                    variant: 99,
                    bytes: Vec::new(),
                },
                test_out_point(0),
            )
            .await
            .unwrap_err();
        assert_eq!(err, UsdtOutputError::UnsupportedOutputVariant);
    }

    // `ServerModule::output_status` is deprecated upstream (modules are
    // steered toward dedicated status endpoints instead -- see its trait
    // doc comment); this module still implements it minimally per this
    // task's spec (`UsdtOutputOutcome`'s doc comment explains why it stays
    // minimal), so this test intentionally exercises the deprecated method
    // directly.
    #[allow(deprecated)]
    #[tokio::test]
    async fn output_status_reflects_withdrawal_state_presence() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let out_point = test_out_point(0);

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            module.output_status(&mut dbtx.to_ref_nc(), out_point).await,
            None,
            "no outcome before the output is processed"
        );
        drop(dbtx);

        let quote = withdrawal_fee_quote(&sample_fee_vote()).expect("realistic vote must quote");
        let mut dbtx = db.begin_transaction().await;
        module
            .process_output(
                &mut dbtx.to_ref_nc(),
                &UsdtOutput::V0(fedimint_usdt_common::UsdtOutputV0 {
                    recipient: EvmAddress([0x44; 20]),
                    amount: UsdtAmount(1_000_000),
                    max_fee: quote,
                    refund_pubkey: sample_claim_pk(),
                }),
                out_point,
            )
            .await
            .expect("must succeed with a valid quote");
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        assert_eq!(
            module.output_status(&mut dbtx.to_ref_nc(), out_point).await,
            Some(UsdtOutputOutcome),
            "an outcome exists once the withdrawal is queued"
        );
    }

    #[tokio::test]
    async fn deposit_status_returns_zeros_for_unknown_account() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x02);
        let expected_account = fedimint_usdt_common::derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        let mut dbtx = db.begin_transaction_nc().await;
        let response = module
            .handle_deposit_status(&mut dbtx.to_ref_nc(), claim_pk)
            .await;

        assert_eq!(response.account, expected_account);
        assert_eq!(response.credited, UsdtAmount(0));
        assert_eq!(response.claimed, UsdtAmount(0));
        assert_eq!(response.claimable, UsdtAmount(0));
    }

    #[tokio::test]
    async fn deposit_status_reports_claimable_as_credited_minus_claimed() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x03);
        let account = fedimint_usdt_common::derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(5_000_000),
                    claimed: UsdtAmount(2_000_000),
                    last_observed_block: 42,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction_nc().await;
        let response = module
            .handle_deposit_status(&mut dbtx.to_ref_nc(), claim_pk)
            .await;

        assert_eq!(response.account, account);
        assert_eq!(response.credited, UsdtAmount(5_000_000));
        assert_eq!(response.claimed, UsdtAmount(2_000_000));
        assert_eq!(response.claimable, UsdtAmount(3_000_000));
    }

    #[tokio::test]
    async fn withdrawal_status_reports_unknown_for_an_out_point_with_no_record() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let mut dbtx = db.begin_transaction_nc().await;
        let response = module
            .handle_withdrawal_status(&mut dbtx.to_ref_nc(), test_out_point(0))
            .await;

        assert_eq!(response.status, WithdrawalStatus::Unknown);
    }

    #[tokio::test]
    async fn withdrawal_status_maps_every_withdrawal_state_variant_1_to_1() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let cases = [
            (WithdrawalState::Queued, WithdrawalStatus::Queued),
            (
                WithdrawalState::Signing([1; 32]),
                WithdrawalStatus::Signing { op_hash: [1; 32] },
            ),
            (
                WithdrawalState::Submitted([2; 32]),
                WithdrawalStatus::Submitted { op_hash: [2; 32] },
            ),
            (
                WithdrawalState::Confirmed { block: 99 },
                WithdrawalStatus::Confirmed { block: 99 },
            ),
            (
                WithdrawalState::Failed {
                    reason: "gas spike".to_string(),
                },
                WithdrawalStatus::Failed {
                    reason: "gas spike".to_string(),
                },
            ),
        ];

        for (i, (state, expected_status)) in cases.into_iter().enumerate() {
            let out_point = test_out_point(i as u64);
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out_point), &state)
                .await;
            dbtx.commit_tx().await;

            let mut dbtx = db.begin_transaction_nc().await;
            let response = module
                .handle_withdrawal_status(&mut dbtx.to_ref_nc(), out_point)
                .await;

            assert_eq!(response.status, expected_status);
        }
    }

    /// End-to-end drive of a runtime threshold-ECDSA signing session over
    /// `MpcRound` consensus items, simulating ALL `n=4` guardians —
    /// including the NON-signer peer 3 (the lowest-`t=3` subset `{0,1,2}`
    /// signs) — by holding one [`Usdt`] module (each with its own DB + store)
    /// per guardian and shuttling every guardian's proposed `MpcRound` items
    /// to every guardian's `process_consensus_item`, round by round, exactly
    /// as ordered consensus would.
    ///
    /// Asserts (a) every SIGNER assembled a signature that verifies against
    /// the group key, (b) EVERY guardian's `SigningSession.round` advanced to
    /// the SAME final value — the determinism guard, in particular the
    /// non-signer's consensus DB matches the signers' — and (c) the non-signer
    /// holds NO `completed_signatures` entry (it cannot compute the sig, so it
    /// must never touch that guardian-local, non-consensus state).
    ///
    /// Slow: this runs real cggmp21 signing across several parked rounds.
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn mpc_round_consensus_drives_signing_to_completion() {
        use sha2::{Digest as _, Sha256};

        const N: u16 = 4;
        let peers: Vec<PeerId> = (0..N).map(PeerId::from).collect();
        let num_peers = peers.to_num_peers();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );

        // One module per guardian, each with its own in-memory DB and its own
        // signing-session store. Which peer ends up outside the signer
        // subset is digest-seeded (see `signer_subset`), so it's derived
        // below rather than assumed.
        let mut modules: BTreeMap<PeerId, Usdt> = BTreeMap::new();
        for &peer in &peers {
            let cfg = server_cfgs[&peer]
                .clone()
                .to_typed::<UsdtConfig>()
                .expect("config was just generated by the same configgen");
            let db = fedimint_core::db::Database::new(
                fedimint_core::db::mem_impl::MemDatabase::new(),
                fedimint_core::module::registry::ModuleDecoderRegistry::default(),
            );
            modules.insert(
                peer,
                Usdt::new_for_test(cfg, MockEvmRpc::default().into_dyn(), db, peer, num_peers),
            );
        }

        let digest: [u8; 32] = Sha256::digest(b"usdt mpc-round consensus signing test").into();
        let session_id = fedimint_usdt_common::signing_session_id(&digest, 0);
        let purpose = SigningPurpose::UserOp(digest);

        // The digest-seeded signer subset for attempt 0, and the single peer
        // it excludes (n=4, t=3, so exactly one peer is a non-signer).
        let subset = modules[&PeerId::from(0)].signer_subset(&digest, 0);
        let non_signer = peers
            .iter()
            .copied()
            .find(|p| !subset.contains(p))
            .expect("t < n, so signer_subset always excludes exactly one peer here");

        // Every guardian starts the (identical) session: writes its own
        // consensus `SigningSession` and, if in the subset, spawns its
        // off-thread signer + pre-pumps round 0.
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .start_session(&mut dbtx.to_ref_nc(), purpose.clone(), digest, 0)
                .await;
            dbtx.commit_tx().await;
        }

        // Consensus round loop: collect every guardian's proposed `MpcRound`
        // items, order them deterministically (the in-test analogue of
        // consensus ordering), then feed EVERY item to EVERY guardian's
        // `process_consensus_item` in its own committed transaction. Continue
        // until no guardian proposes anything (the signers have finished).
        let mut consensus_rounds = 0u32;
        loop {
            let mut proposed: Vec<(PeerId, MpcRoundItem)> = Vec::new();
            for (&peer, module) in &modules {
                let mut dbtx = module.db_for_test().begin_transaction().await;
                let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
                dbtx.commit_tx().await;
                for item in items {
                    if let UsdtConsensusItem::MpcRound(mpc) = item {
                        proposed.push((peer, mpc));
                    }
                }
            }

            if proposed.is_empty() {
                break;
            }

            // Each guardian now proposes MULTIPLE `MpcRound` chunk items per
            // round for the large rounds (round 2's ≈63 KB payload splits into
            // several `MPC_ROUND_CHUNK_SIZE` chunks); order them totally,
            // chunk index included, as the in-test analogue of consensus
            // ordering.
            proposed.sort_by(|(a, ia), (b, ib)| {
                (a, ia.session_id.0, ia.round, ia.chunk).cmp(&(
                    b,
                    ib.session_id.0,
                    ib.round,
                    ib.chunk,
                ))
            });

            for (proposer, item) in &proposed {
                for module in modules.values() {
                    let mut dbtx = module.db_for_test().begin_transaction().await;
                    module
                        .process_consensus_item(
                            &mut dbtx.to_ref_nc(),
                            UsdtConsensusItem::MpcRound(item.clone()),
                            *proposer,
                        )
                        .await
                        .expect("every proposed MpcRound item must process cleanly");
                    dbtx.commit_tx().await;
                }
            }

            consensus_rounds += 1;
            assert!(consensus_rounds < 1_000, "signing failed to converge");
        }
        assert!(
            consensus_rounds >= 1,
            "signing must have taken at least one consensus round"
        );

        // (a) Every signer holds a compact signature that verifies against the
        // group public key.
        let group_pk = server_cfgs[&peers[0]]
            .clone()
            .to_typed::<UsdtConfig>()
            .expect("valid config")
            .consensus
            .group_public_key;
        let msg = secp256k1::Message::from_digest(digest);
        let verifier = secp256k1::Secp256k1::verification_only();
        for &peer in &subset {
            let sig_bytes = modules[&peer]
                .completed_signatures
                .lock()
                .expect("not poisoned")
                .get(&session_id)
                .cloned()
                .expect("each signer assembled its signature");
            assert_eq!(sig_bytes.len(), 64, "compact signature is 64 bytes");
            let sig = secp256k1::ecdsa::Signature::from_compact(&sig_bytes)
                .expect("stored bytes are a valid compact signature");
            verifier
                .verify_ecdsa(&msg, &sig, &group_pk)
                .expect("assembled signature must verify against the group key");
        }

        // (c) The non-signer holds NO signature (it cannot compute one).
        assert!(
            modules[&non_signer]
                .completed_signatures
                .lock()
                .expect("not poisoned")
                .is_empty(),
            "the non-signer must never populate completed_signatures"
        );

        // (b) Determinism guard: every guardian's consensus `SigningSession`
        // advanced to the SAME final round — signer and non-signer DBs
        // identical.
        let mut final_rounds = Vec::new();
        for &peer in &peers {
            let mut dbtx = modules[&peer].db_for_test().begin_transaction_nc().await;
            let session = dbtx
                .get_value(&SigningSessionKey(session_id))
                .await
                .expect("SigningSession present on every guardian");
            final_rounds.push(session.round);
        }
        assert!(
            final_rounds.iter().all(|r| *r == final_rounds[0]),
            "every guardian (signer AND non-signer) must reach the same final round: \
             {final_rounds:?}"
        );
        assert!(
            final_rounds[0] >= 1,
            "the session must have advanced at least one round"
        );
    }

    /// Task 1 (Phase 6b): once a signer's off-thread state machine finishes,
    /// `advance_local_signer` queues the assembled signature onto
    /// `pending_signature_proposals`, which `consensus_proposal` drains into
    /// an `UsdtConsensusItem::MpcSignature`. Processing that item must
    /// deterministically verify the signature against the group key and
    /// write `SessionState::Completed(sig)` to the consensus `SigningSession`
    /// on EVERY guardian -- including the non-signer peer 3, which cannot
    /// compute the signature itself but must still end up holding the
    /// federation-agreed record once a signer proposes it. Also asserts a
    /// second, identical `MpcSignature` proposal is rejected as redundant.
    ///
    /// Slow: drives real cggmp21 signing to completion first (see
    /// `mpc_round_consensus_drives_signing_to_completion`).
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn mpc_signature_consensus_item_completes_session_on_every_guardian() {
        use sha2::{Digest as _, Sha256};

        const N: u16 = 4;
        let peers: Vec<PeerId> = (0..N).map(PeerId::from).collect();
        let num_peers = peers.to_num_peers();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );

        let mut modules: BTreeMap<PeerId, Usdt> = BTreeMap::new();
        for &peer in &peers {
            let cfg = server_cfgs[&peer]
                .clone()
                .to_typed::<UsdtConfig>()
                .expect("config was just generated by the same configgen");
            let db = fedimint_core::db::Database::new(
                fedimint_core::db::mem_impl::MemDatabase::new(),
                fedimint_core::module::registry::ModuleDecoderRegistry::default(),
            );
            modules.insert(
                peer,
                Usdt::new_for_test(cfg, MockEvmRpc::default().into_dyn(), db, peer, num_peers),
            );
        }

        let digest: [u8; 32] = Sha256::digest(b"usdt mpc-signature consensus item test").into();
        let op_hash: [u8; 32] =
            Sha256::digest(b"usdt mpc-signature consensus item test op_hash").into();
        let session_id = fedimint_usdt_common::signing_session_id(&digest, 0);
        let purpose = SigningPurpose::UserOp(op_hash);

        // A live `PendingUserOp` must back this session on EVERY guardian's
        // DB for `process_mpc_signature` to finalize it (sec-01 hardening:
        // `SigningPurpose` no longer has a `Test` variant that bypasses this
        // check).
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            dbtx.insert_new_entry(
                &PendingUserOpKey(op_hash),
                &PendingUserOp {
                    op: sample_unsigned_user_op_for_test(),
                    purpose: UserOpPurpose::DeployAndSweep {
                        source: EvmAddress([0x71; 20]),
                    },
                    created_block: 0,
                },
            )
            .await;
            module
                .start_session(&mut dbtx.to_ref_nc(), purpose.clone(), digest, 0)
                .await;
            dbtx.commit_tx().await;
        }

        // Drive the `MpcRound` consensus loop to completion (mirrors
        // `mpc_round_consensus_drives_signing_to_completion`). A finished
        // signer's `consensus_proposal` call ALSO drains its
        // `pending_signature_proposals` in the very same call that stops
        // producing `MpcRound` items -- so the resulting `MpcSignature` item
        // must be captured inline, here, or it is drained and lost before a
        // later call could see it again.
        let mut consensus_rounds = 0u32;
        let mut captured_mpc_signature: Option<(PeerId, UsdtConsensusItem)> = None;
        loop {
            let mut proposed: Vec<(PeerId, MpcRoundItem)> = Vec::new();
            for (&peer, module) in &modules {
                let mut dbtx = module.db_for_test().begin_transaction().await;
                let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
                dbtx.commit_tx().await;
                for item in items {
                    match item {
                        UsdtConsensusItem::MpcRound(mpc) => proposed.push((peer, mpc)),
                        UsdtConsensusItem::MpcSignature {
                            session_id: sid, ..
                        } if sid == session_id && captured_mpc_signature.is_none() => {
                            captured_mpc_signature = Some((peer, item));
                        }
                        _ => {}
                    }
                }
            }

            if proposed.is_empty() {
                break;
            }

            proposed.sort_by(|(a, ia), (b, ib)| {
                (a, ia.session_id.0, ia.round, ia.chunk).cmp(&(
                    b,
                    ib.session_id.0,
                    ib.round,
                    ib.chunk,
                ))
            });

            for (proposer, item) in &proposed {
                for module in modules.values() {
                    let mut dbtx = module.db_for_test().begin_transaction().await;
                    module
                        .process_consensus_item(
                            &mut dbtx.to_ref_nc(),
                            UsdtConsensusItem::MpcRound(item.clone()),
                            *proposer,
                        )
                        .await
                        .expect("every proposed MpcRound item must process cleanly");
                    dbtx.commit_tx().await;
                }
            }

            consensus_rounds += 1;
            assert!(consensus_rounds < 1_000, "signing failed to converge");
        }
        assert!(
            consensus_rounds >= 1,
            "signing must have taken at least one consensus round"
        );

        // A finished signer's `consensus_proposal` call must have drained
        // its `pending_signature_proposals` into an `MpcSignature` item
        // during the round loop above (captured inline).
        let (proposer_peer, mpc_signature_item) =
            captured_mpc_signature.expect("a finished signer must propose an MpcSignature item");
        let signature_bytes = match &mpc_signature_item {
            UsdtConsensusItem::MpcSignature { signature, .. } => signature.clone(),
            other => panic!("expected MpcSignature, got {other:?}"),
        };
        assert_eq!(signature_bytes.len(), 64, "compact signature is 64 bytes");

        // Shuttle the SAME `MpcSignature` item to every guardian's
        // `process_consensus_item`, as ordered consensus would.
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    mpc_signature_item.clone(),
                    proposer_peer,
                )
                .await
                .expect("MpcSignature must process cleanly on every guardian");
            dbtx.commit_tx().await;
        }

        // The agreed signature verifies against the group key.
        let group_pk = server_cfgs[&peers[0]]
            .clone()
            .to_typed::<UsdtConfig>()
            .expect("valid config")
            .consensus
            .group_public_key;
        let msg = secp256k1::Message::from_digest(digest);
        let verifier = secp256k1::Secp256k1::verification_only();
        let sig = secp256k1::ecdsa::Signature::from_compact(&signature_bytes)
            .expect("proposed signature bytes are a valid compact signature");
        verifier
            .verify_ecdsa(&msg, &sig, &group_pk)
            .expect("agreed signature must verify against the group key");

        // EVERY guardian -- including non-signer peer 3 -- now holds the
        // identical `Completed(sig)` consensus record.
        for &peer in &peers {
            let mut dbtx = modules[&peer].db_for_test().begin_transaction_nc().await;
            let session = dbtx
                .get_value(&SigningSessionKey(session_id))
                .await
                .expect("SigningSession present on every guardian");
            assert_eq!(
                session.state,
                SessionState::Completed(signature_bytes.clone()),
                "guardian {peer} must hold the federation-agreed signature"
            );
        }

        // A second, identical `MpcSignature` proposal is redundant.
        let mut dbtx = modules[&proposer_peer]
            .db_for_test()
            .begin_transaction()
            .await;
        let result = modules[&proposer_peer]
            .process_consensus_item(&mut dbtx.to_ref_nc(), mpc_signature_item, proposer_peer)
            .await;
        dbtx.commit_tx().await;
        assert!(
            result.is_err(),
            "a second identical MpcSignature must be rejected as redundant"
        );
    }

    /// **Sec-01 regression guard.** A signing session's `purpose` is the
    /// ONLY thing that can authorize `process_mpc_signature` to finalize
    /// anything: a `SigningPurpose::UserOp(op_hash)` session whose
    /// `PendingUserOpKey(op_hash)` was NEVER written (i.e. no consensus-
    /// approved record backs this session) must be REJECTED even once a
    /// validly group-signed compact signature is presented for it -- and,
    /// critically, must NOT be marked `SessionState::Completed`. Before this
    /// fix, the now-removed debug-signing-purpose variant's `else { None }`
    /// branch stored `Completed` unconditionally; this test pins the
    /// replacement invariant directly against `SigningPurpose::UserOp`,
    /// which is now the only purpose there is.
    ///
    /// Drives a REAL threshold-ECDSA signing session to completion (mirrors
    /// `mpc_signature_consensus_item_completes_session_on_every_guardian`) so
    /// the presented signature is genuinely valid against the group key --
    /// proving that verifying-against-the-group-key is NOT sufficient
    /// authorization on its own.
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn mpc_signature_without_pending_user_op_is_rejected() {
        use sha2::{Digest as _, Sha256};

        const N: u16 = 4;
        let peers: Vec<PeerId> = (0..N).map(PeerId::from).collect();
        let num_peers = peers.to_num_peers();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );

        let mut modules: BTreeMap<PeerId, Usdt> = BTreeMap::new();
        for &peer in &peers {
            let cfg = server_cfgs[&peer]
                .clone()
                .to_typed::<UsdtConfig>()
                .expect("config was just generated by the same configgen");
            let db = fedimint_core::db::Database::new(
                fedimint_core::db::mem_impl::MemDatabase::new(),
                fedimint_core::module::registry::ModuleDecoderRegistry::default(),
            );
            modules.insert(
                peer,
                Usdt::new_for_test(cfg, MockEvmRpc::default().into_dyn(), db, peer, num_peers),
            );
        }

        // A `UserOp`-purpose session whose `op_hash` deliberately never gets a
        // `PendingUserOpKey` written anywhere -- simulating an attacker (or a
        // stray/rogue proposal) starting a session over an op that consensus
        // never actually authorized.
        let op_hash: [u8; 32] =
            Sha256::digest(b"usdt unbound-userop-rejection test op_hash").into();
        let digest: [u8; 32] = Sha256::digest(b"usdt unbound-userop-rejection test digest").into();
        let session_id = fedimint_usdt_common::signing_session_id(&digest, 0);
        let purpose = SigningPurpose::UserOp(op_hash);

        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .start_session(&mut dbtx.to_ref_nc(), purpose.clone(), digest, 0)
                .await;
            dbtx.commit_tx().await;
        }

        // Drive the real `MpcRound` consensus loop to completion (mirrors
        // `mpc_round_consensus_drives_signing_to_completion`).
        let mut consensus_rounds = 0u32;
        loop {
            let mut proposed: Vec<(PeerId, MpcRoundItem)> = Vec::new();
            for (&peer, module) in &modules {
                let mut dbtx = module.db_for_test().begin_transaction().await;
                let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
                dbtx.commit_tx().await;
                for item in items {
                    if let UsdtConsensusItem::MpcRound(mpc) = item {
                        proposed.push((peer, mpc));
                    }
                }
            }

            if proposed.is_empty() {
                break;
            }

            proposed.sort_by(|(a, ia), (b, ib)| {
                (a, ia.session_id.0, ia.round, ia.chunk).cmp(&(
                    b,
                    ib.session_id.0,
                    ib.round,
                    ib.chunk,
                ))
            });

            for (proposer, item) in &proposed {
                for module in modules.values() {
                    let mut dbtx = module.db_for_test().begin_transaction().await;
                    module
                        .process_consensus_item(
                            &mut dbtx.to_ref_nc(),
                            UsdtConsensusItem::MpcRound(item.clone()),
                            *proposer,
                        )
                        .await
                        .expect("every proposed MpcRound item must process cleanly");
                    dbtx.commit_tx().await;
                }
            }

            consensus_rounds += 1;
            assert!(consensus_rounds < 1_000, "signing failed to converge");
        }
        assert!(
            consensus_rounds >= 1,
            "signing must have taken at least one consensus round"
        );

        // Grab a signer's genuinely-assembled, group-key-valid compact
        // signature for the unbound session.
        let signer_peer = peers[0];
        let signature_bytes = modules[&signer_peer]
            .completed_signatures
            .lock()
            .expect("not poisoned")
            .get(&session_id)
            .cloned()
            .expect("a signer must have assembled a signature for the unbound session");
        assert_eq!(signature_bytes.len(), 64, "compact signature is 64 bytes");

        // Sanity: the signature genuinely verifies against the group key --
        // so a naive "verify against group key -> Completed" implementation
        // would wrongly accept it.
        let group_pk = server_cfgs[&signer_peer]
            .clone()
            .to_typed::<UsdtConfig>()
            .expect("valid config")
            .consensus
            .group_public_key;
        let msg = secp256k1::Message::from_digest(digest);
        let sig = secp256k1::ecdsa::Signature::from_compact(&signature_bytes)
            .expect("stored bytes are a valid compact signature");
        secp256k1::Secp256k1::verification_only()
            .verify_ecdsa(&msg, &sig, &group_pk)
            .expect("the presented signature genuinely verifies against the group key");

        // Feed it directly to `process_mpc_signature` -- no `PendingUserOpKey`
        // for `op_hash` was ever written on this (or any) guardian's DB.
        let mut dbtx = modules[&signer_peer]
            .db_for_test()
            .begin_transaction()
            .await;
        let result = modules[&signer_peer]
            .process_mpc_signature(&mut dbtx.to_ref_nc(), session_id, signature_bytes)
            .await;
        dbtx.commit_tx().await;

        assert!(
            result.is_err(),
            "a signature for a session with no backing PendingUserOp must be rejected, not finalized"
        );

        let mut dbtx = modules[&signer_peer]
            .db_for_test()
            .begin_transaction_nc()
            .await;
        let session = dbtx
            .get_value(&SigningSessionKey(session_id))
            .await
            .expect("the session itself must still be present");
        assert!(
            !matches!(session.state, SessionState::Completed(_)),
            "an unbound session must never be marked Completed, even though the signature \
             itself is genuinely valid: {:?}",
            session.state
        );
    }

    /// Sec-11 hardening: `process_mpc_round` must reject, BEFORE persisting
    /// anything, any chunk that violates the receive-side bounds a Byzantine
    /// selected signer could otherwise abuse (unbounded chunk size, chunk
    /// count, or a `chunk_count` that changes mid-stream for the same peer).
    /// Driven directly via `process_consensus_item` against a real
    /// `InProgress` `SigningSession` the peer is a member of (mirrors
    /// `timed_out_detects_stalled_session_via_consensus_block_count`'s
    /// synthetic-session-construction style; a full cggmp21 run is not
    /// needed to exercise these purely-DB-and-item-shaped guards).
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn mpc_round_rejects_oversized_and_inconsistent_chunks() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let session_id = signing_session_id(&[42; 32], 0);
        let session = SigningSession {
            purpose: SigningPurpose::UserOp([42; 32]),
            digest: [42; 32],
            signers: vec![PeerId::from(0), PeerId::from(1), PeerId::from(2)],
            round: 0,
            state: SessionState::InProgress,
            attempt: 0,
            last_progress_block: 0,
        };
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(&SigningSessionKey(session_id), &session)
                .await;
            dbtx.commit_tx().await;
        }

        // (a) A chunk whose payload exceeds `MPC_ROUND_CHUNK_SIZE` is
        // rejected, and nothing is persisted for it.
        {
            let mut dbtx = db.begin_transaction().await;
            let item = MpcRoundItem {
                session_id,
                round: 0,
                chunk: 0,
                chunk_count: 1,
                payload: vec![0u8; MPC_ROUND_CHUNK_SIZE + 1],
            };
            let err = module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::MpcRound(item),
                    PeerId::from(1),
                )
                .await
                .expect_err("an oversized chunk payload must be rejected");
            dbtx.commit_tx().await;
            assert!(
                err.to_string().contains("MPC_ROUND_CHUNK_SIZE"),
                "unexpected error: {err}"
            );

            let mut dbtx = db.begin_transaction_nc().await;
            assert!(
                dbtx.to_ref_nc()
                    .find_by_prefix(&MpcRoundChunkSessionRoundPeerPrefix(
                        session_id,
                        0,
                        PeerId::from(1)
                    ))
                    .await
                    .collect::<Vec<_>>()
                    .await
                    .is_empty(),
                "a rejected oversized chunk must not be persisted"
            );
        }

        // (b) A peer's first chunk fixes its `chunk_count`; a later chunk
        // from the SAME peer for the SAME round with a DIFFERENT
        // `chunk_count` is rejected, even though it is individually
        // well-formed.
        {
            let mut dbtx = db.begin_transaction().await;
            let first = MpcRoundItem {
                session_id,
                round: 0,
                chunk: 0,
                chunk_count: 2,
                payload: vec![1, 2, 3],
            };
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::MpcRound(first),
                    PeerId::from(0),
                )
                .await
                .expect("the first, well-formed chunk from peer 0 must be accepted");
            dbtx.commit_tx().await;

            let mut dbtx = db.begin_transaction().await;
            let inconsistent = MpcRoundItem {
                session_id,
                round: 0,
                chunk: 1,
                chunk_count: 3,
                payload: vec![4, 5, 6],
            };
            let err = module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::MpcRound(inconsistent),
                    PeerId::from(0),
                )
                .await
                .expect_err(
                    "a chunk_count that differs from this peer's prior chunks must be rejected",
                );
            dbtx.commit_tx().await;
            assert!(
                err.to_string().contains("chunk_count inconsistent"),
                "unexpected error: {err}"
            );
        }

        // (c) `chunk_count` above `MAX_MPC_CHUNKS` is rejected outright, even
        // as a peer's very first chunk.
        {
            let mut dbtx = db.begin_transaction().await;
            let item = MpcRoundItem {
                session_id,
                round: 0,
                chunk: 0,
                chunk_count: MAX_MPC_CHUNKS + 1,
                payload: Vec::new(),
            };
            let err = module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::MpcRound(item),
                    PeerId::from(2),
                )
                .await
                .expect_err("a chunk_count above MAX_MPC_CHUNKS must be rejected");
            dbtx.commit_tx().await;
            assert!(
                err.to_string().contains("MAX_MPC_CHUNKS"),
                "unexpected error: {err}"
            );
        }
    }

    /// Sec-11 hardening: a `(session, round, peer)`'s cumulative stored bytes
    /// (across ALL of that peer's individually-`MPC_ROUND_CHUNK_SIZE`-sized
    /// chunks) must never be allowed to exceed `MAX_MPC_ROUND_BYTES`, even
    /// though `MAX_MPC_CHUNKS` alone would otherwise permit it (chunks need
    /// not be maximally sized).
    #[tokio::test]
    async fn mpc_round_rejects_cumulative_bytes_beyond_max_round_bytes() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let session_id = signing_session_id(&[43; 32], 0);
        let session = SigningSession {
            purpose: SigningPurpose::UserOp([43; 32]),
            digest: [43; 32],
            signers: vec![PeerId::from(0), PeerId::from(1), PeerId::from(2)],
            round: 0,
            state: SessionState::InProgress,
            attempt: 0,
            last_progress_block: 0,
        };
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(&SigningSessionKey(session_id), &session)
                .await;
            dbtx.commit_tx().await;
        }

        // A `chunk_count` large enough that MAX_MPC_CHUNKS alone would allow
        // it, but each chunk sized so the running total blows past
        // `MAX_MPC_ROUND_BYTES` well before `chunk_count` chunks are sent.
        let per_chunk = MPC_ROUND_CHUNK_SIZE;
        let chunk_count = MAX_MPC_CHUNKS;
        let chunks_until_over_budget =
            u16::try_from(MAX_MPC_ROUND_BYTES / per_chunk + 1).expect("fits in u16");
        assert!(
            chunks_until_over_budget <= chunk_count,
            "test assumption: the budget must be exhausted before chunk_count chunks arrive"
        );

        for chunk in 0..chunks_until_over_budget {
            let mut dbtx = db.begin_transaction().await;
            let item = MpcRoundItem {
                session_id,
                round: 0,
                chunk,
                chunk_count,
                payload: vec![0u8; per_chunk],
            };
            let result = module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::MpcRound(item),
                    PeerId::from(1),
                )
                .await;
            dbtx.commit_tx().await;

            if chunk + 1 == chunks_until_over_budget {
                let err = result.expect_err(
                    "the chunk that pushes cumulative bytes past MAX_MPC_ROUND_BYTES must be rejected",
                );
                assert!(
                    err.to_string().contains("MAX_MPC_ROUND_BYTES"),
                    "unexpected error: {err}"
                );
            } else {
                result.expect("chunks within the byte budget must be accepted");
            }
        }
    }

    /// Sec-11 hardening: finished (completed or failed/rotated) signing
    /// attempts must not leave their `MpcRoundChunk` records behind in the
    /// consensus DB. Drives a real `MpcRound` signing loop (mirrors
    /// `mpc_round_consensus_drives_signing_to_completion`) so genuine chunks
    /// exist to be GC'd, then exercises BOTH GC triggers: a timed-out
    /// session's chunks are swept by `process_rotate_signing`, and a
    /// completed session's chunks are swept by `process_mpc_signature`.
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn mpc_chunks_are_gced_on_rotate_and_complete() {
        use sha2::{Digest as _, Sha256};

        const N: u16 = 4;
        let peers: Vec<PeerId> = (0..N).map(PeerId::from).collect();
        let num_peers = peers.to_num_peers();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );

        let mut modules: BTreeMap<PeerId, Usdt> = BTreeMap::new();
        for &peer in &peers {
            let cfg = server_cfgs[&peer]
                .clone()
                .to_typed::<UsdtConfig>()
                .expect("config was just generated by the same configgen");
            let db = fedimint_core::db::Database::new(
                fedimint_core::db::mem_impl::MemDatabase::new(),
                fedimint_core::module::registry::ModuleDecoderRegistry::default(),
            );
            modules.insert(
                peer,
                Usdt::new_for_test(cfg, MockEvmRpc::default().into_dyn(), db, peer, num_peers),
            );
        }

        // --- Scenario 1: rotate-on-timeout GC. --------------------------
        let digest_a: [u8; 32] = Sha256::digest(b"usdt sec-11 gc test session A").into();
        let op_hash_a: [u8; 32] = Sha256::digest(b"usdt sec-11 gc test session A op_hash").into();
        let session_id_a = fedimint_usdt_common::signing_session_id(&digest_a, 0);
        let purpose_a = SigningPurpose::UserOp(op_hash_a);

        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .start_session(&mut dbtx.to_ref_nc(), purpose_a.clone(), digest_a, 0)
                .await;
            dbtx.commit_tx().await;
        }

        // Drive round 0's real MpcRound chunk exchange so genuine chunks
        // land in the DB, without waiting for full completion.
        {
            let mut proposed: Vec<(PeerId, MpcRoundItem)> = Vec::new();
            for (&peer, module) in &modules {
                let mut dbtx = module.db_for_test().begin_transaction().await;
                let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
                dbtx.commit_tx().await;
                for item in items {
                    if let UsdtConsensusItem::MpcRound(mpc) = item
                        && mpc.session_id == session_id_a
                    {
                        proposed.push((peer, mpc));
                    }
                }
            }
            assert!(
                !proposed.is_empty(),
                "round 0 must produce at least one MpcRound chunk to GC"
            );
            for (proposer, item) in &proposed {
                for module in modules.values() {
                    let mut dbtx = module.db_for_test().begin_transaction().await;
                    module
                        .process_consensus_item(
                            &mut dbtx.to_ref_nc(),
                            UsdtConsensusItem::MpcRound(item.clone()),
                            *proposer,
                        )
                        .await
                        .expect("every genuinely-proposed MpcRound item must process cleanly");
                    dbtx.commit_tx().await;
                }
            }
        }

        // Sanity: chunks for session A are genuinely present before rotation.
        {
            let mut dbtx = modules[&peers[0]]
                .db_for_test()
                .begin_transaction_nc()
                .await;
            let before: Vec<_> = dbtx
                .to_ref_nc()
                .find_by_prefix(&MpcRoundChunkSessionPrefix(session_id_a))
                .await
                .collect()
                .await;
            assert!(
                !before.is_empty(),
                "sanity: session A must have stored chunks before GC"
            );
        }

        // Push every guardian's block count far enough past the timeout
        // threshold that `RotateSigning` is accepted, then process it on
        // every guardian (as ordered consensus would).
        for module in modules.values() {
            let db = module.db_for_test();
            seed_block_count_votes(db, N, timeout_blocks() + 1).await;
        }
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .process_rotate_signing(&mut dbtx.to_ref_nc(), session_id_a)
                .await
                .expect("the timed-out session must accept RotateSigning");
            dbtx.commit_tx().await;
        }

        for &peer in &peers {
            let mut dbtx = modules[&peer].db_for_test().begin_transaction_nc().await;
            let remaining: Vec<_> = dbtx
                .to_ref_nc()
                .find_by_prefix(&MpcRoundChunkSessionPrefix(session_id_a))
                .await
                .collect()
                .await;
            assert!(
                remaining.is_empty(),
                "guardian {peer}: rotating a timed-out session must GC ALL of its chunks, \
                 found {remaining:?}"
            );
        }

        // --- Scenario 2: complete-on-signature GC. -----------------------
        let digest_b: [u8; 32] = Sha256::digest(b"usdt sec-11 gc test session B").into();
        let op_hash_b: [u8; 32] = Sha256::digest(b"usdt sec-11 gc test session B op_hash").into();
        let session_id_b = fedimint_usdt_common::signing_session_id(&digest_b, 0);
        let purpose_b = SigningPurpose::UserOp(op_hash_b);

        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            dbtx.insert_new_entry(
                &PendingUserOpKey(op_hash_b),
                &PendingUserOp {
                    op: sample_unsigned_user_op_for_test(),
                    purpose: UserOpPurpose::DeployAndSweep {
                        source: EvmAddress([0x72; 20]),
                    },
                    created_block: 0,
                },
            )
            .await;
            module
                .start_session(&mut dbtx.to_ref_nc(), purpose_b.clone(), digest_b, 0)
                .await;
            dbtx.commit_tx().await;
        }

        let mut consensus_rounds = 0u32;
        let mut captured_mpc_signature: Option<(PeerId, UsdtConsensusItem)> = None;
        loop {
            let mut proposed: Vec<(PeerId, MpcRoundItem)> = Vec::new();
            for (&peer, module) in &modules {
                let mut dbtx = module.db_for_test().begin_transaction().await;
                let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
                dbtx.commit_tx().await;
                for item in items {
                    match item {
                        UsdtConsensusItem::MpcRound(mpc) if mpc.session_id == session_id_b => {
                            proposed.push((peer, mpc));
                        }
                        UsdtConsensusItem::MpcSignature {
                            session_id: sid, ..
                        } if sid == session_id_b && captured_mpc_signature.is_none() => {
                            captured_mpc_signature = Some((peer, item));
                        }
                        _ => {}
                    }
                }
            }

            if proposed.is_empty() {
                break;
            }

            proposed.sort_by(|(a, ia), (b, ib)| {
                (a, ia.session_id.0, ia.round, ia.chunk).cmp(&(
                    b,
                    ib.session_id.0,
                    ib.round,
                    ib.chunk,
                ))
            });

            for (proposer, item) in &proposed {
                for module in modules.values() {
                    let mut dbtx = module.db_for_test().begin_transaction().await;
                    module
                        .process_consensus_item(
                            &mut dbtx.to_ref_nc(),
                            UsdtConsensusItem::MpcRound(item.clone()),
                            *proposer,
                        )
                        .await
                        .expect("every proposed MpcRound item must process cleanly");
                    dbtx.commit_tx().await;
                }
            }

            consensus_rounds += 1;
            assert!(consensus_rounds < 1_000, "signing failed to converge");
        }

        let (proposer_peer, mpc_signature_item) =
            captured_mpc_signature.expect("a finished signer must propose an MpcSignature item");

        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    mpc_signature_item.clone(),
                    proposer_peer,
                )
                .await
                .expect("MpcSignature must process cleanly on every guardian");
            dbtx.commit_tx().await;
        }

        for &peer in &peers {
            let mut dbtx = modules[&peer].db_for_test().begin_transaction_nc().await;
            let remaining: Vec<_> = dbtx
                .to_ref_nc()
                .find_by_prefix(&MpcRoundChunkSessionPrefix(session_id_b))
                .await
                .collect()
                .await;
            assert!(
                remaining.is_empty(),
                "guardian {peer}: completing a session must GC ALL of its chunks, found \
                 {remaining:?}"
            );
        }
    }

    /// Sec-11 drift guard (misc #21): pins `MAX_MPC_ROUND_BYTES` against the
    /// actual size of REAL cggmp21 signing rounds over the two real
    /// production-shaped payloads this module ever signs -- a
    /// deploy-and-sweep `UserOp` and a 20-item withdrawal-batch `UserOp`,
    /// built with the SAME builders/hashing `Usdt::maybe_trigger_sweep`/
    /// `Usdt::build_and_enqueue_withdrawal_batch` use in production. If this
    /// test ever fails, `MAX_MPC_ROUND_BYTES` is too small for reality and
    /// must be RAISED (with an updated doc comment explaining why), not this
    /// test loosened.
    ///
    /// Threshold-ECDSA signs a fixed-size 32-byte digest, so in principle
    /// the round-message sizes should be identical regardless of what
    /// produced that digest -- this test exists to catch a future change
    /// (larger party count, protocol upgrade, etc.) that breaks that
    /// assumption for either of this module's two real op shapes, not
    /// because the two are expected to differ from each other today.
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn real_signing_round_fits_chunk_budget() {
        const N: u16 = 4;
        let peers: Vec<PeerId> = (0..N).map(PeerId::from).collect();
        let num_peers = peers.to_num_peers();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );

        let mut modules: BTreeMap<PeerId, Usdt> = BTreeMap::new();
        for &peer in &peers {
            let cfg = server_cfgs[&peer]
                .clone()
                .to_typed::<UsdtConfig>()
                .expect("config was just generated by the same configgen");
            let db = fedimint_core::db::Database::new(
                fedimint_core::db::mem_impl::MemDatabase::new(),
                fedimint_core::module::registry::ModuleDecoderRegistry::default(),
            );
            modules.insert(
                peer,
                Usdt::new_for_test(cfg, MockEvmRpc::default().into_dyn(), db, peer, num_peers),
            );
        }

        let cfg0 = server_cfgs[&peers[0]]
            .clone()
            .to_typed::<UsdtConfig>()
            .expect("valid config");
        let entry_point = cfg0.consensus.entry_point;
        let chain_id = cfg0.consensus.chain_id;
        let account_factory = cfg0.consensus.account_factory;
        let usdt_contract = cfg0.consensus.usdt_contract;
        let simple_account_impl = cfg0.consensus.simple_account_impl;
        let pool = derive_pool_account(
            &cfg0.consensus.group_public_key,
            account_factory,
            simple_account_impl,
        );
        let owner = evm_address(&cfg0.consensus.group_public_key);

        let claim_secret =
            secp256k1::SecretKey::from_slice(&[0x33; 32]).expect("nonzero byte is a valid scalar");
        let claim_pk = claim_secret.public_key(secp256k1::SECP256K1);
        let deposit_account = derive_deposit_account(
            &cfg0.consensus.group_public_key,
            account_factory,
            simple_account_impl,
            &claim_pk,
        );

        // A real deploy-and-sweep sweep op, built exactly as
        // `Usdt::maybe_trigger_sweep` builds it in production.
        let deploy_and_sweep_op =
            crate::user_op::build_deploy_and_sweep_userop(DeployAndSweepParams {
                account_factory,
                usdt_contract,
                deposit_account,
                owner,
                claim_pk,
                amount: UsdtAmount(1_500_000),
                pool,
                nonce: alloy::primitives::U256::ZERO,
                needs_deploy: true,
                paymaster_and_data: Vec::new(),
                gas_bounds: GasBounds::DEPLOY_AND_SWEEP_DEVNET,
            });

        // A real 20-item withdrawal-batch op, built exactly as
        // `Usdt::build_and_enqueue_withdrawal_batch` builds it in
        // production.
        let withdrawals: Vec<(fedimint_usdt_common::EvmAddress, UsdtAmount)> = (0u8..20)
            .map(|i| (EvmAddress([i; 20]), UsdtAmount(1_000_000 + u64::from(i))))
            .collect();
        let withdrawal_batch_op =
            crate::user_op::build_withdrawal_batch_userop(WithdrawalBatchParams {
                account_factory,
                usdt_contract,
                pool,
                owner,
                withdrawals,
                nonce: alloy::primitives::U256::from(3u64),
                needs_deploy: false,
                paymaster_and_data: Vec::new(),
                gas_bounds: GasBounds::withdrawal_batch(20, false),
            });

        for (label, op) in [
            ("deploy-and-sweep", deploy_and_sweep_op),
            ("20-item withdrawal-batch", withdrawal_batch_op),
        ] {
            let op_hash = user_op_hash(&op, entry_point, chain_id);
            let digest = eth_signed_message_hash(op_hash);
            let session_id = signing_session_id(&digest, 0);
            let purpose = SigningPurpose::UserOp(op_hash);

            for module in modules.values() {
                let mut dbtx = module.db_for_test().begin_transaction().await;
                module
                    .start_session(&mut dbtx.to_ref_nc(), purpose.clone(), digest, 0)
                    .await;
                dbtx.commit_tx().await;
            }

            let mut consensus_rounds = 0u32;
            loop {
                let mut proposed: Vec<(PeerId, MpcRoundItem)> = Vec::new();
                for (&peer, module) in &modules {
                    let mut dbtx = module.db_for_test().begin_transaction().await;
                    let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
                    dbtx.commit_tx().await;
                    for item in items {
                        if let UsdtConsensusItem::MpcRound(mpc) = item
                            && mpc.session_id == session_id
                        {
                            proposed.push((peer, mpc));
                        }
                    }
                }

                if proposed.is_empty() {
                    break;
                }

                proposed.sort_by(|(a, ia), (b, ib)| {
                    (a, ia.session_id.0, ia.round, ia.chunk).cmp(&(
                        b,
                        ib.session_id.0,
                        ib.round,
                        ib.chunk,
                    ))
                });

                for (proposer, item) in &proposed {
                    for module in modules.values() {
                        let mut dbtx = module.db_for_test().begin_transaction().await;
                        module
                            .process_consensus_item(
                                &mut dbtx.to_ref_nc(),
                                UsdtConsensusItem::MpcRound(item.clone()),
                                *proposer,
                            )
                            .await
                            .expect("every proposed MpcRound item must process cleanly");
                        dbtx.commit_tx().await;
                    }
                }

                consensus_rounds += 1;
                assert!(consensus_rounds < 1_000, "signing failed to converge");
            }
            assert!(
                consensus_rounds >= 1,
                "{label}: signing must have taken at least one consensus round"
            );

            // Every round's every peer's reassembled payload (summed across
            // that peer's chunks) must fit under MAX_MPC_ROUND_BYTES -- read
            // straight from one guardian's consensus DB, before any GC has a
            // chance to run (this test never processes an MpcSignature/
            // RotateSigning item).
            let mut per_peer_round_bytes: BTreeMap<(u16, PeerId), usize> = BTreeMap::new();
            let mut dbtx = modules[&peers[0]]
                .db_for_test()
                .begin_transaction_nc()
                .await;
            let all_chunks: Vec<(MpcRoundChunkKey, MpcRoundChunk)> = dbtx
                .to_ref_nc()
                .find_by_prefix(&MpcRoundChunkSessionPrefix(session_id))
                .await
                .collect()
                .await;
            assert!(
                !all_chunks.is_empty(),
                "{label}: at least one chunk must have been stored"
            );
            for (MpcRoundChunkKey(_, round, peer, _), value) in all_chunks {
                *per_peer_round_bytes.entry((round, peer)).or_insert(0) += value.bytes.len();
            }

            let max_bytes = per_peer_round_bytes.values().copied().max().unwrap_or(0);
            assert!(
                max_bytes <= MAX_MPC_ROUND_BYTES,
                "{label}: a real signing round's max per-peer reassembled payload ({max_bytes} \
                 bytes) exceeds MAX_MPC_ROUND_BYTES ({MAX_MPC_ROUND_BYTES} bytes) -- raise the \
                 constant to match reality"
            );
        }
    }

    /// Phase 7 Task 4: `MockEvmRpc::submit_user_ops`/`get_user_op_receipt`
    /// round-trip -- submitted batches are recorded in call order, and a
    /// scripted receipt is returned for its hash while an unscripted hash
    /// reads back `None`.
    #[tokio::test]
    async fn mock_evm_rpc_submit_and_receipt_round_trip() {
        use fedimint_usdt_common::user_op::{SignedUserOp, UnsignedUserOp, UserOpReceipt};

        let mock = MockEvmRpc::default();

        let unsigned = UnsignedUserOp {
            sender: fedimint_usdt_common::EvmAddress([0x11; 20]),
            nonce: alloy::primitives::U256::ZERO,
            init_code: vec![],
            call_data: vec![0xde, 0xad],
            verification_gas_limit: 1,
            call_gas_limit: 1,
            pre_verification_gas: alloy::primitives::U256::ZERO,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            paymaster_and_data: vec![],
        };
        let signed = SignedUserOp {
            unsigned,
            signature: vec![0xaa; 65],
        };

        mock.submit_user_ops(vec![signed.clone()])
            .await
            .expect("MockEvmRpc::submit_user_ops never fails");
        assert_eq!(mock.submitted_user_ops(), vec![vec![signed]]);

        let user_op_hash = [0x22u8; 32];
        assert_eq!(
            mock.get_user_op_receipt(user_op_hash)
                .await
                .expect("infallible"),
            None,
            "an unscripted user_op_hash must read back as not-yet-included"
        );

        let receipt = UserOpReceipt {
            success: true,
            block: 42,
            block_hash: [0u8; 32],
            actual_gas_cost_wei: fedimint_usdt_common::UsdtAmount(1_000),
        };
        mock.set_user_op_receipt(user_op_hash, receipt);
        assert_eq!(
            mock.get_user_op_receipt(user_op_hash)
                .await
                .expect("infallible"),
            Some(receipt)
        );
    }

    /// **Phase 7 Task 5.** Drives the FULL deposit-credited -> deterministic
    /// `PendingUserOp`+`SigningPurpose::UserOp` session trigger -> real
    /// cggmp21 MPC signing -> deterministic `SubmittedUserOp` finalization
    /// pipeline across 4 independently-simulated guardians, asserting every
    /// consensus-DB write this task introduces is byte-identical across ALL
    /// FOUR guardians -- including the non-signer peer 3, which cannot
    /// itself compute a signature but must still end up holding the
    /// identical federation-agreed `SubmittedUserOp`. Also verifies the
    /// assembled 65-byte Ethereum signature actually recovers to the
    /// group-key owner.
    ///
    /// Slow: drives real cggmp21 signing to completion (mirrors
    /// `mpc_signature_consensus_item_completes_session_on_every_guardian`).
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::too_many_lines)]
    async fn deposit_credit_deterministically_drives_pending_user_op_through_real_mpc_to_submitted()
    {
        const N: u16 = 4;
        let peers: Vec<PeerId> = (0..N).map(PeerId::from).collect();
        let num_peers = peers.to_num_peers();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };
        let server_cfgs = UsdtInit::default().trusted_dealer_gen(
            &peers,
            &args,
            &fedimint_usdt_common::UsdtGenParams::default(),
        );

        let mut modules: BTreeMap<PeerId, Usdt> = BTreeMap::new();
        for &peer in &peers {
            let cfg = server_cfgs[&peer]
                .clone()
                .to_typed::<UsdtConfig>()
                .expect("config was just generated by the same configgen");
            let db = fedimint_core::db::Database::new(
                fedimint_core::db::mem_impl::MemDatabase::new(),
                fedimint_core::module::registry::ModuleDecoderRegistry::default(),
            );
            modules.insert(
                peer,
                Usdt::new_for_test(cfg, MockEvmRpc::default().into_dyn(), db, peer, num_peers),
            );
        }

        let claim_pk = test_pubkey(0x70);
        let group_public_key = server_cfgs[&peers[0]]
            .clone()
            .to_typed::<UsdtConfig>()
            .expect("valid config")
            .consensus
            .group_public_key;
        let account_factory = modules[&peers[0]].cfg.consensus.account_factory;
        let simple_account_impl = modules[&peers[0]].cfg.consensus.simple_account_impl;
        let account = derive_deposit_account(
            &group_public_key,
            account_factory,
            simple_account_impl,
            &claim_pk,
        );

        let obs = DepositObservation {
            account,
            balance: UsdtAmount(4_500_000),
            block: 5,
            block_hash: [0u8; 32],
            claim_pk,
        };

        // Security finding 02 (Task 4.3): `maybe_trigger_sweep` now defers
        // any sweep until a fee median exists (it cannot economically gate
        // an unpriceable op), so every guardian needs one FIRST. A low
        // (0.1 gwei) median still 2x's below the 1 gwei op-fee floor, so
        // this preserves the gas-pricing regression assertion below (floor,
        // not the 30 gwei devnet constant) while quoting a deposit fee
        // (~288_000, well under the 4_500_000 balance) that clears the new
        // dust gate.
        let low_fee_vote = fedimint_usdt_common::FeeVote {
            max_fee_per_gas_wei: 100_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        for module in modules.values() {
            seed_fee_votes(module.db_for_test(), N, low_fee_vote).await;
            // Security finding 12 freshness gate: keep the block-5 deposit
            // observation in-window on every guardian.
            seed_block_count_votes(
                module.db_for_test(),
                N,
                5 + module.cfg.consensus.confirmation_depth,
            )
            .await;
        }

        // Every guardian independently processes the identical ordered
        // Deposit votes (threshold 3-of-4), triggering `maybe_trigger_sweep`.
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            for &voter in &[PeerId::from(0), PeerId::from(1), PeerId::from(2)] {
                module
                    .process_consensus_item(
                        &mut dbtx.to_ref_nc(),
                        UsdtConsensusItem::Deposit(obs.clone()),
                        voter,
                    )
                    .await
                    .expect("Deposit item processes cleanly");
            }
            dbtx.commit_tx().await;
        }

        // Every guardian deterministically triggered the identical
        // DeployAndSweep PendingUserOp.
        let mut op_hash: Option<[u8; 32]> = None;
        for &peer in &peers {
            let mut dbtx = modules[&peer].db_for_test().begin_transaction_nc().await;
            let pending: Vec<(PendingUserOpKey, PendingUserOp)> = dbtx
                .find_by_prefix(&PendingUserOpPrefix)
                .await
                .collect()
                .await;
            assert_eq!(
                pending.len(),
                1,
                "guardian {peer} must have exactly one PendingUserOp"
            );
            let (PendingUserOpKey(hash), record) = &pending[0];
            assert_eq!(
                record.purpose,
                UserOpPurpose::DeployAndSweep { source: account }
            );
            assert_eq!(record.op.sender, account);
            // Gas-pricing regression guard (the mainnet on-chain wedge): the
            // seeded `low_fee_vote` median (0.1 gwei) 2x's to below the 1
            // gwei op-fee floor, so the op must be priced at that FLOOR via
            // `GasBounds::with_median_fees`, NOT the 30 gwei devnet constant
            // that over-provisioned the broadcaster prefund on mainnet. This
            // asserts the sweep trigger actually threads the consensus median
            // into the op (not just that `with_median_fees` works in isolation).
            assert_eq!(
                record.op.max_fee_per_gas, 1_000_000_000,
                "sweep op must be priced from the consensus gas median (floored to 1 gwei here), not the 30 gwei devnet constant"
            );
            assert_ne!(record.op.max_fee_per_gas, 30_000_000_000);
            if let Some(expected) = op_hash {
                assert_eq!(
                    *hash, expected,
                    "op_hash must be identical across guardians"
                );
            } else {
                op_hash = Some(*hash);
            }
        }
        let op_hash = op_hash.expect("at least one guardian in the federation");
        let digest = eth_signed_message_hash(op_hash);
        let session_id = signing_session_id(&digest, 0);

        // Every guardian also deterministically started the identical
        // UserOp-purpose signing session.
        for &peer in &peers {
            let mut dbtx = modules[&peer].db_for_test().begin_transaction_nc().await;
            let session = dbtx
                .get_value(&SigningSessionKey(session_id))
                .await
                .expect("SigningSession present on every guardian");
            assert_eq!(session.purpose, SigningPurpose::UserOp(op_hash));
            assert_eq!(session.digest, digest);
            assert_eq!(session.state, SessionState::InProgress);
        }

        // Drive the `MpcRound` consensus loop to completion (mirrors
        // `mpc_signature_consensus_item_completes_session_on_every_guardian`).
        let mut consensus_rounds = 0u32;
        let mut captured_mpc_signature: Option<(PeerId, UsdtConsensusItem)> = None;
        loop {
            let mut proposed: Vec<(PeerId, MpcRoundItem)> = Vec::new();
            for (&peer, module) in &modules {
                let mut dbtx = module.db_for_test().begin_transaction().await;
                let items = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
                dbtx.commit_tx().await;
                for item in items {
                    match item {
                        UsdtConsensusItem::MpcRound(mpc) if mpc.session_id == session_id => {
                            proposed.push((peer, mpc));
                        }
                        UsdtConsensusItem::MpcSignature {
                            session_id: sid, ..
                        } if sid == session_id && captured_mpc_signature.is_none() => {
                            captured_mpc_signature = Some((peer, item));
                        }
                        _ => {}
                    }
                }
            }

            if proposed.is_empty() {
                break;
            }

            proposed.sort_by(|(a, ia), (b, ib)| {
                (a, ia.session_id.0, ia.round, ia.chunk).cmp(&(
                    b,
                    ib.session_id.0,
                    ib.round,
                    ib.chunk,
                ))
            });

            for (proposer, item) in &proposed {
                for module in modules.values() {
                    let mut dbtx = module.db_for_test().begin_transaction().await;
                    module
                        .process_consensus_item(
                            &mut dbtx.to_ref_nc(),
                            UsdtConsensusItem::MpcRound(item.clone()),
                            *proposer,
                        )
                        .await
                        .expect("every proposed MpcRound item must process cleanly");
                    dbtx.commit_tx().await;
                }
            }

            consensus_rounds += 1;
            assert!(consensus_rounds < 1_000, "signing failed to converge");
        }

        let (proposer_peer, mpc_signature_item) =
            captured_mpc_signature.expect("a finished signer must propose an MpcSignature item");

        // Shuttle the SAME `MpcSignature` item to every guardian.
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    mpc_signature_item.clone(),
                    proposer_peer,
                )
                .await
                .expect("MpcSignature must process cleanly on every guardian");
            dbtx.commit_tx().await;
        }

        // Every guardian -- signer and non-signer alike -- now holds an
        // identical `SubmittedUserOp`, and the `PendingUserOp` is cleared.
        let mut expected_signed: Option<fedimint_usdt_common::user_op::SignedUserOp> = None;
        for &peer in &peers {
            let mut dbtx = modules[&peer].db_for_test().begin_transaction_nc().await;
            assert!(
                dbtx.get_value(&PendingUserOpKey(op_hash)).await.is_none(),
                "guardian {peer}'s PendingUserOp must be cleared"
            );
            let submitted = dbtx
                .get_value(&SubmittedUserOpKey(op_hash))
                .await
                .unwrap_or_else(|| panic!("guardian {peer} must hold a SubmittedUserOp"));
            if let Some(expected) = &expected_signed {
                assert_eq!(
                    &submitted.signed, expected,
                    "guardian {peer}'s SignedUserOp must be byte-identical to every other \
                     guardian's"
                );
            } else {
                expected_signed = Some(submitted.signed.clone());
            }
        }

        // The assembled Ethereum signature recovers to the group-key owner
        // over the EIP-191-wrapped digest.
        let signed = expected_signed.expect("at least one guardian in the federation");
        assert_eq!(signed.signature.len(), 65);
        let owner = evm_address(&group_public_key);
        let recid = secp256k1::ecdsa::RecoveryId::from_i32(i32::from(signed.signature[64] - 27))
            .expect("valid recovery id");
        let recoverable =
            secp256k1::ecdsa::RecoverableSignature::from_compact(&signed.signature[..64], recid)
                .expect("valid compact sig");
        let recovered_pk = recoverable
            .recover(&secp256k1::Message::from_digest(digest))
            .expect("recovery succeeds for the signature's own digest");
        assert_eq!(
            evm_address(&recovered_pk),
            owner,
            "assembled signature must recover to the group-key owner"
        );
    }

    /// **Phase 7 Task 5.** `UserOpConfirmed` mirrors `Deposit`'s exact
    /// observation-quorum shape: below threshold, no state change beyond the
    /// per-peer vote; a DIFFERING vote does not count toward the same
    /// tally; at threshold, `PoolState.balance` is credited and the swept
    /// deposit's `DepositRecord.swept` advances, and the `SubmittedUserOp` +
    /// vote prefix are cleared. Also verifies replay-safety: a vote
    /// re-delivered after the vote prefix was cleared is processed as a
    /// fresh (below-threshold) vote rather than erroring, and a direct
    /// re-invocation of `apply_user_op_confirmed` itself (the stronger
    /// property: idempotent even if `agreeing >= threshold` were somehow
    /// reached a second time) does not double-credit `PoolState` or
    /// `DepositRecord.swept`.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn user_op_confirmed_applies_at_threshold_and_is_replay_safe() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        let op_hash = [0x81; 32];
        let source = EvmAddress([0x82; 20]);
        let claim_pk = test_pubkey(0x83);
        let pool_account = module.pool_account();

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(source),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(4_000_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        // Real, decodable calldata (Phase 9 hardening,
                        // sec-21): `apply_user_op_confirmed` re-derives
                        // `swept` from this and rejects a mismatch against
                        // the votes below, which claim `4_000_000`.
                        unsigned: real_deploy_and_sweep_op_for_test(source, UsdtAmount(4_000_000)),
                        signature: vec![0xaa; 65],
                    },
                    purpose: UserOpPurpose::DeployAndSweep { source },
                    submitted_block: 3,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: true,
            block: 20,
            block_hash: [0u8; 32],
            swept: UsdtAmount(4_000_000),
            actual_gas_cost_wei: UsdtAmount(0),
        };
        let mut dbtx = db.begin_transaction().await;

        // Two identical votes: below threshold, no PoolState/DepositRecord
        // change yet, but each vote itself is recorded (`Ok`).
        for p in [0u16, 1] {
            module
                .process_consensus_item(&mut dbtx.to_ref_nc(), obs.clone(), PeerId::from(p))
                .await
                .expect("below-threshold vote processes cleanly");
        }
        assert!(
            dbtx.to_ref_nc().get_value(&PoolStateKey).await.is_none(),
            "PoolState must not exist before threshold"
        );

        // A DIFFERING vote (different `swept`) from peer 2 does not count
        // toward the same tally.
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::UserOpConfirmed {
                    op_hash,
                    success: true,
                    block: 20,
                    block_hash: [0u8; 32],
                    swept: UsdtAmount(1),
                    actual_gas_cost_wei: UsdtAmount(0),
                },
                PeerId::from(2),
            )
            .await
            .expect("differing vote processes cleanly");
        assert!(dbtx.to_ref_nc().get_value(&PoolStateKey).await.is_none());

        // Third IDENTICAL vote reaches threshold -> applied.
        module
            .process_consensus_item(&mut dbtx.to_ref_nc(), obs.clone(), PeerId::from(3))
            .await
            .expect("threshold-reaching vote processes cleanly");

        let pool = dbtx
            .to_ref_nc()
            .get_value(&PoolStateKey)
            .await
            .expect("PoolState created at threshold");
        assert_eq!(pool.account, pool_account);
        assert_eq!(pool.balance, UsdtAmount(4_000_000));

        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(source))
            .await
            .expect("DepositRecord still present");
        assert_eq!(record.swept, UsdtAmount(4_000_000));

        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(op_hash))
                .await
                .is_none(),
            "SubmittedUserOp must be cleared once confirmed"
        );
        assert_eq!(
            dbtx.to_ref_nc()
                .find_by_prefix(&UserOpConfirmedVoteOpPrefix(op_hash))
                .await
                .count()
                .await,
            0,
            "vote prefix must be cleared once confirmed"
        );

        // `apply_user_op_confirmed` clears the ENTIRE vote prefix AND the
        // `SubmittedUserOp` itself once threshold is reached (mirroring
        // `credit_deposit`'s `DepositObservationVoteAccountPrefix` clear).
        // Security finding 14 (Task 2.2) requires every `UserOpConfirmed`
        // vote to correspond to a live `SubmittedUserOp`, so a vote
        // re-delivered for this op AFTER it has already been fully applied
        // and cleared is now rejected outright (not silently accepted as a
        // "fresh" below-threshold vote for an op that no longer exists) --
        // it must not be stored, and it must NOT re-trigger
        // `apply_user_op_confirmed` or touch `PoolState`.
        module
            .process_consensus_item(&mut dbtx.to_ref_nc(), obs.clone(), PeerId::from(0))
            .await
            .expect_err(
                "a vote for an op already applied and cleared must be rejected, not treated as \
                 a fresh vote",
            );
        let pool_still_single_credit = dbtx
            .to_ref_nc()
            .get_value(&PoolStateKey)
            .await
            .expect("PoolState still present");
        assert_eq!(
            pool_still_single_credit.balance,
            UsdtAmount(4_000_000),
            "a rejected post-application vote must not re-credit the pool"
        );

        // Stronger replay-safety property, exercised directly:
        // `apply_user_op_confirmed` itself is idempotent even if somehow
        // invoked again after the `SubmittedUserOp` is already gone (e.g. a
        // late peer's vote independently pushes `agreeing` past threshold a
        // second time) -- it must not double-credit `PoolState` or
        // `DepositRecord.swept`.
        module
            .apply_user_op_confirmed(
                &mut dbtx.to_ref_nc(),
                op_hash,
                &UserOpConfirmedObservation {
                    success: true,
                    block: 20,
                    block_hash: [0u8; 32],
                    swept: UsdtAmount(4_000_000),
                    actual_gas_cost_wei: UsdtAmount(0),
                },
            )
            .await;

        let pool_after = dbtx
            .to_ref_nc()
            .get_value(&PoolStateKey)
            .await
            .expect("PoolState still present");
        assert_eq!(
            pool_after.balance,
            UsdtAmount(4_000_000),
            "a replayed apply must not double-credit the pool"
        );
        let record_after = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(source))
            .await
            .expect("DepositRecord still present");
        assert_eq!(
            record_after.swept,
            UsdtAmount(4_000_000),
            "a replayed apply must not double-advance swept"
        );
    }

    /// **Security finding 14.** A `UserOpConfirmed` vote for an `op_hash`
    /// that was never submitted (no `SubmittedUserOp` record) must be
    /// rejected with `Err` BEFORE the vote is stored, so a Byzantine
    /// guardian cannot bloat `UserOpConfirmedVote` with junk confirmations
    /// for random op hashes that never reach threshold. A well-formed vote
    /// for a real submitted op must still store normally (not
    /// over-rejected).
    #[tokio::test]
    async fn userop_confirmed_vote_for_unknown_op_is_rejected() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let unknown_op_hash = [0x77; 32];
        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash: unknown_op_hash,
            success: true,
            block: 20,
            block_hash: [0u8; 32],
            swept: UsdtAmount(1_000_000),
            actual_gas_cost_wei: UsdtAmount(0),
        };

        // Positive-control fixture (a REAL submitted op), inserted and
        // committed BEFORE the long-lived `dbtx` below is opened so it is
        // visible within that snapshot.
        let known_op_hash = [0x78; 32];
        let source = EvmAddress([0x79; 20]);
        {
            let mut setup = db.begin_transaction().await;
            let mut sample = sample_unsigned_user_op_for_test();
            sample.sender = source;
            setup
                .insert_new_entry(
                    &SubmittedUserOpKey(known_op_hash),
                    &SubmittedUserOp {
                        signed: fedimint_usdt_common::user_op::SignedUserOp {
                            unsigned: sample,
                            signature: vec![0xaa; 65],
                        },
                        purpose: UserOpPurpose::DeployAndSweep { source },
                        submitted_block: 3,
                        superseded: false,
                    },
                )
                .await;
            setup.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;

        let err = module
            .process_consensus_item(&mut dbtx.to_ref_nc(), obs, PeerId::from(0))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("never submitted") || err.to_string().contains("submitted"),
            "unexpected error: {err}"
        );

        assert!(
            dbtx.to_ref_nc()
                .get_value(&UserOpConfirmedVoteKey(unknown_op_hash, PeerId::from(0)))
                .await
                .is_none(),
            "vote for an unknown op must not be stored"
        );

        // Positive control: a well-formed vote for the REAL submitted op
        // (fixture set up above) must still store (not over-rejected by
        // this change).
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::UserOpConfirmed {
                    op_hash: known_op_hash,
                    success: true,
                    block: 20,
                    block_hash: [0u8; 32],
                    swept: UsdtAmount(1_000_000),
                    actual_gas_cost_wei: UsdtAmount(0),
                },
                PeerId::from(0),
            )
            .await
            .expect("a vote for a known submitted op must still store");
        assert!(
            dbtx.to_ref_nc()
                .get_value(&UserOpConfirmedVoteKey(known_op_hash, PeerId::from(0)))
                .await
                .is_some(),
            "well-formed vote for a known op must be stored"
        );
    }

    /// A failed `UserOp` (`success: false`) must NOT credit `PoolState` or
    /// bump `DepositRecord.swept`, but must still clear the `SubmittedUserOp`
    /// once threshold-agreed (Phase 7 scope: a failed sweep is not retried
    /// within this phase -- see `maybe_trigger_sweep`'s doc comment).
    #[tokio::test]
    async fn user_op_confirmed_failure_clears_submitted_without_crediting_pool() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        let op_hash = [0x91; 32];
        let source = EvmAddress([0x92; 20]);
        let claim_pk = test_pubkey(0x93);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(source),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(2_000_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            let mut sample = sample_unsigned_user_op_for_test();
            sample.sender = source;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: sample,
                        signature: vec![0xbb; 65],
                    },
                    purpose: UserOpPurpose::DeployAndSweep { source },
                    submitted_block: 3,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: false,
            block: 21,
            block_hash: [0u8; 32],
            swept: UsdtAmount(0),
            actual_gas_cost_wei: UsdtAmount(0),
        };
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(&mut dbtx.to_ref_nc(), obs.clone(), PeerId::from(p))
                .await
                .expect("vote processes cleanly");
        }

        assert!(
            dbtx.to_ref_nc().get_value(&PoolStateKey).await.is_none(),
            "a failed sweep must never create/credit PoolState"
        );
        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(source))
            .await
            .expect("DepositRecord still present");
        assert_eq!(
            record.swept,
            UsdtAmount(0),
            "a failed sweep must not advance DepositRecord.swept"
        );
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(op_hash))
                .await
                .is_none(),
            "SubmittedUserOp must still be cleared once confirmed (even on failure)"
        );
    }

    /// Every currently-`Pending` `DeployAndSweep` op whose `source` is
    /// `account`, as `(op_hash, op)` pairs -- the re-sweep tests' lens onto
    /// what `maybe_trigger_sweep` enqueued.
    async fn pending_deploy_and_sweeps(
        dbtx: &mut DatabaseTransaction<'_>,
        account: EvmAddress,
    ) -> Vec<([u8; 32], fedimint_usdt_common::user_op::UnsignedUserOp)> {
        let pending: Vec<(PendingUserOpKey, PendingUserOp)> = dbtx
            .find_by_prefix(&PendingUserOpPrefix)
            .await
            .collect()
            .await;
        pending
            .into_iter()
            .filter(|(_, p)| {
                matches!(p.purpose, UserOpPurpose::DeployAndSweep { source } if source == account)
            })
            .map(|(PendingUserOpKey(hash), p)| (hash, p.op))
            .collect()
    }

    /// Asserts exactly one pending `DeployAndSweep` for `account` and returns
    /// its `(op_hash, op)`.
    async fn single_pending_deploy_and_sweep(
        dbtx: &mut DatabaseTransaction<'_>,
        account: EvmAddress,
    ) -> ([u8; 32], fedimint_usdt_common::user_op::UnsignedUserOp) {
        let mut ops = pending_deploy_and_sweeps(dbtx, account).await;
        assert_eq!(
            ops.len(),
            1,
            "expected exactly one pending DeployAndSweep for the account"
        );
        ops.pop().expect("just checked len == 1")
    }

    /// Simulates the MPC-signing promotion `process_mpc_signature` performs:
    /// moves `op_hash`'s `PendingUserOp` into a `SubmittedUserOp` (carrying
    /// its `op` verbatim, so `sender`/`purpose` are preserved) and clears the
    /// `PendingUserOp`, so `apply_user_op_confirmed` can then finalize it --
    /// without standing up the real threshold signer.
    async fn promote_pending_to_submitted(db: &Database, op_hash: [u8; 32]) {
        let mut dbtx = db.begin_transaction().await;
        let pending = dbtx
            .to_ref_nc()
            .get_value(&PendingUserOpKey(op_hash))
            .await
            .expect("pending op present to promote");
        dbtx.to_ref_nc()
            .insert_new_entry(
                &SubmittedUserOpKey(op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: pending.op,
                        signature: vec![0xaa; 65],
                    },
                    purpose: pending.purpose,
                    submitted_block: 3,
                    superseded: false,
                },
            )
            .await;
        dbtx.to_ref_nc()
            .remove_entry(&PendingUserOpKey(op_hash))
            .await;
        dbtx.commit_tx().await;
    }

    /// Writes a `DepositRecord` for `account` with `credited` and `swept`
    /// (`nonce`/`claimed`/`last_observed_block` all zero) -- the minimal
    /// setup the dust-gate tests below need before calling
    /// `maybe_trigger_sweep` directly.
    async fn insert_deposit_record(
        db: &Database,
        account: EvmAddress,
        claim_pk: secp256k1::PublicKey,
        credited: UsdtAmount,
    ) {
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &DepositRecordKey(account),
            &DepositRecord {
                claim_pk,
                credited,
                claimed: UsdtAmount(0),
                last_observed_block: 0,
                swept: UsdtAmount(0),
                nonce: 0,
            },
        )
        .await;
        dbtx.commit_tx().await;
    }

    /// **Security finding 02 (Task 4.3).** A deposit whose un-swept
    /// remainder does not exceed its own deploy+sweep gas cost
    /// (`deposit_fee_quote`) must NOT be swept: sweeping it would spend more
    /// federation-fronted ETH than the deposit is worth, which is exactly
    /// the dust-deposit gas-griefing drain the finding describes. The dust
    /// is left on-chain (untouched, unswept) rather than pooled -- costing
    /// the federation nothing. Covers both the exact boundary
    /// (`remainder == sweep_fee`) and clearly-below-fee dust.
    #[tokio::test]
    async fn dust_below_sweep_fee_is_not_swept() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let sweep_fee = deposit_fee_quote(&sample_fee_vote()).expect("realistic vote must quote");

        for (key_byte, label, credited) in [
            (0xb1u8, "exactly the fee (boundary, not > )", sweep_fee),
            (
                0xb2u8,
                "clearly below the fee",
                UsdtAmount(sweep_fee.0 / 10),
            ),
            (0xb3u8, "one raw unit", UsdtAmount(1)),
        ] {
            let claim_pk = test_pubkey(key_byte);
            let account = derive_deposit_account(
                &module.cfg.consensus.group_public_key,
                module.cfg.consensus.account_factory,
                module.cfg.consensus.simple_account_impl,
                &claim_pk,
            );
            insert_deposit_record(db, account, claim_pk, credited).await;

            let mut dbtx = db.begin_transaction().await;
            module
                .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
                .await;
            assert!(
                pending_deploy_and_sweeps(&mut dbtx.to_ref_nc(), account)
                    .await
                    .is_empty(),
                "dust case ({label}) must not be swept: credited={}, sweep_fee={}",
                credited.0,
                sweep_fee.0
            );
            dbtx.commit_tx().await;
        }
    }

    /// Positive control for `dust_below_sweep_fee_is_not_swept`: a deposit
    /// whose remainder clearly exceeds `deposit_fee_quote` must still be
    /// swept exactly as before -- the dust gate must not over-gate ordinary,
    /// economically-worthwhile deposits.
    #[tokio::test]
    async fn deposit_above_fee_still_sweeps() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let sweep_fee = deposit_fee_quote(&sample_fee_vote()).expect("realistic vote must quote");

        let claim_pk = test_pubkey(0xc7);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );
        let credited = UsdtAmount(sweep_fee.0 + 1);
        insert_deposit_record(db, account, claim_pk, credited).await;

        let mut dbtx = db.begin_transaction().await;
        module
            .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
            .await;
        let (_, op) = single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
        assert_eq!(
            crate::user_op::decode_transfer_amount(&op).expect("op call_data decodes"),
            credited,
            "a net-positive deposit must still be swept for its full remainder"
        );
        dbtx.commit_tx().await;
    }

    /// **Security finding 02 (Task 4.3), no-median facet.** With no fresh
    /// fee median at all (Task 4.2's quorum/freshness gate), the sweep
    /// cannot be economically priced/gated, so it must be DEFERRED rather
    /// than sweeping ungated (the pre-fix behavior, which floored to the 1
    /// gwei devnet floor and swept anyway). Once a median later becomes
    /// available, the very same un-swept remainder sweeps normally.
    #[tokio::test]
    async fn sweep_deferred_when_no_median() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        // Deliberately no `seed_fee_votes` call: no median exists yet.

        let claim_pk = test_pubkey(0xd7);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );
        // Comfortably above any realistic fee quote, so this is unambiguously
        // NOT a dust case -- the only reason to defer is the missing median.
        let credited = UsdtAmount(100_000_000);
        insert_deposit_record(db, account, claim_pk, credited).await;

        {
            let mut dbtx = db.begin_transaction().await;
            module
                .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
                .await;
            assert!(
                pending_deploy_and_sweeps(&mut dbtx.to_ref_nc(), account)
                    .await
                    .is_empty(),
                "without a fee median the sweep must be deferred, not priced at some fallback"
            );
            dbtx.commit_tx().await;
        }

        // A median now becomes available; a later retrigger (mirroring the
        // confirm-path/next-credit retrigger) sweeps the same remainder.
        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let mut dbtx = db.begin_transaction().await;
        module
            .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
            .await;
        let (_, op) = single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
        assert_eq!(
            crate::user_op::decode_transfer_amount(&op).expect("op call_data decodes"),
            credited,
            "once priceable, the deferred sweep proceeds for the full remainder"
        );
        dbtx.commit_tx().await;
    }

    /// **Security finding 02, adversarial (misc #14).** The finding's core
    /// attack: many freshly-derived deposit accounts each receive a tiny
    /// (1-raw-unit) dust credit and are never claimed. Before this fix,
    /// EVERY one of these would have enqueued its own deploy-and-sweep
    /// `PendingUserOp`, forcing the broadcaster to front ETH for each. After
    /// the fix, none of them are economically sweepable, so ZERO
    /// `DeployAndSweep` ops are ever created -- the drain is structurally
    /// impossible, not just rate-limited.
    #[tokio::test]
    async fn many_dust_deposits_produce_zero_sweep_ops() {
        const ATTACKER_ACCOUNTS: u8 = 50;

        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        seed_fee_votes(db, 4, sample_fee_vote()).await;

        for i in 1..=ATTACKER_ACCOUNTS {
            let claim_pk = test_pubkey(i);
            let account = derive_deposit_account(
                &module.cfg.consensus.group_public_key,
                module.cfg.consensus.account_factory,
                module.cfg.consensus.simple_account_impl,
                &claim_pk,
            );
            let obs = DepositObservation {
                account,
                balance: UsdtAmount(1),
                block: 10,
                block_hash: [0u8; 32],
                claim_pk,
            };
            let mut dbtx = db.begin_transaction().await;
            module
                .credit_deposit(&mut dbtx.to_ref_nc(), &obs)
                .await
                .expect("crediting dust must not itself error");
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction_nc().await;
        let pending_sweeps = dbtx
            .find_by_prefix(&PendingUserOpPrefix)
            .await
            .filter(|(_, p)| {
                std::future::ready(matches!(p.purpose, UserOpPurpose::DeployAndSweep { .. }))
            })
            .count()
            .await;
        assert_eq!(
            pending_sweeps, 0,
            "{ATTACKER_ACCOUNTS} dust deposits (1 raw unit each) must produce ZERO \
             DeployAndSweep ops"
        );
    }

    /// **Issue #6 (solvency).** A reused deposit address whose `credited`
    /// grows after an earlier, fixed-amount sweep must have the leftover
    /// (`credited - swept`) re-swept -- at the deposit account's advanced
    /// `SimpleAccount` nonce and without a second deploy -- rather than
    /// stranding it on-chain. Drives the full loop: first sweep (nonce 0,
    /// deploy, amount == full credited) → confirm → grow `credited` →
    /// re-sweep (nonce 1, no deploy, amount == the new remainder) → confirm →
    /// a further trigger is a no-op (remainder 0).
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn re_sweep_moves_the_remainder_after_credited_grows() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        // Security finding 02 (Task 4.3): a fee median must exist and every
        // remainder below must clear its `deposit_fee_quote` (86_400_000 for
        // `sample_fee_vote`), so amounts here are scaled up from this test's
        // pre-dust-gate 10/20 raw units to 100_000_000/200_000_000 (100/200
        // USDT) -- comfortably net-positive, not dust.
        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let account = EvmAddress([0xc1; 20]);
        let claim_pk = test_pubkey(0xc2);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(100_000_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        // First sweep: full credited (100_000_000), nonce 0, deploying
        // (initCode set).
        let op_hash_1 = {
            let mut dbtx = db.begin_transaction().await;
            module
                .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
                .await;
            let (hash, op) = single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
            assert_eq!(op.nonce, alloy::primitives::U256::ZERO);
            assert_eq!(
                crate::user_op::decode_transfer_amount(&op).expect("op call_data decodes"),
                UsdtAmount(100_000_000)
            );
            assert!(
                !op.init_code.is_empty(),
                "first sweep must deploy the account"
            );
            dbtx.commit_tx().await;
            hash
        };

        // Confirm the first sweep (swept 100_000_000).
        promote_pending_to_submitted(db, op_hash_1).await;
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_user_op_confirmed(
                    &mut dbtx.to_ref_nc(),
                    op_hash_1,
                    &UserOpConfirmedObservation {
                        success: true,
                        block: 20,
                        block_hash: [0u8; 32],
                        swept: UsdtAmount(100_000_000),
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                )
                .await;
            let record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("record present");
            assert_eq!(record.swept, UsdtAmount(100_000_000));
            assert_eq!(record.nonce, 1, "nonce advances on the confirmed sweep");
            let pool = dbtx
                .to_ref_nc()
                .get_value(&PoolStateKey)
                .await
                .expect("pool credited");
            assert_eq!(pool.balance, UsdtAmount(100_000_000));
            // Remainder is now 0, so the success auto-retrigger enqueued nothing.
            assert!(
                pending_deploy_and_sweeps(&mut dbtx.to_ref_nc(), account)
                    .await
                    .is_empty(),
                "no re-sweep while credited == swept"
            );
            dbtx.commit_tx().await;
        }

        // A second deposit bumps credited to 200_000_000.
        {
            let mut dbtx = db.begin_transaction().await;
            let mut record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("record present");
            record.credited = UsdtAmount(200_000_000);
            dbtx.to_ref_nc()
                .insert_entry(&DepositRecordKey(account), &record)
                .await;
            dbtx.commit_tx().await;
        }

        // Re-sweep: only the remainder (100_000_000), at nonce 1, WITHOUT
        // redeploying.
        let op_hash_2 = {
            let mut dbtx = db.begin_transaction().await;
            module
                .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
                .await;
            let (hash, op) = single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
            assert_ne!(hash, op_hash_1, "the re-sweep is a fresh op");
            assert_eq!(op.nonce, alloy::primitives::U256::from(1u64));
            assert_eq!(
                crate::user_op::decode_transfer_amount(&op).expect("op call_data decodes"),
                UsdtAmount(100_000_000),
                "re-sweep moves only the remainder, not the full credited"
            );
            assert!(
                op.init_code.is_empty(),
                "an already-deployed account must not redeploy"
            );
            dbtx.commit_tx().await;
            hash
        };

        // Confirm the re-sweep (swept another 100_000_000).
        promote_pending_to_submitted(db, op_hash_2).await;
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_user_op_confirmed(
                    &mut dbtx.to_ref_nc(),
                    op_hash_2,
                    &UserOpConfirmedObservation {
                        success: true,
                        block: 30,
                        block_hash: [0u8; 32],
                        swept: UsdtAmount(100_000_000),
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                )
                .await;
            let record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("record present");
            assert_eq!(record.swept, UsdtAmount(200_000_000));
            assert_eq!(record.nonce, 2);
            let pool = dbtx
                .to_ref_nc()
                .get_value(&PoolStateKey)
                .await
                .expect("pool present");
            assert_eq!(pool.balance, UsdtAmount(200_000_000));
            dbtx.commit_tx().await;
        }

        // Nothing owed -> a further trigger is a no-op.
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
                .await;
            assert!(
                pending_deploy_and_sweeps(&mut dbtx.to_ref_nc(), account)
                    .await
                    .is_empty(),
                "fully-swept account must not enqueue another sweep"
            );
            dbtx.commit_tx().await;
        }
    }

    /// **Nonce-collision safety.** At most one `DeployAndSweep` op per
    /// account may be in flight: while sweep A is pending, a `credited` that
    /// grows must NOT spawn a second op at the same (still-unconsumed) nonce
    /// (which would revert AA25 on-chain). The remainder is instead swept by
    /// the success auto-retrigger, once A confirms and the nonce advances --
    /// so exactly one op is outstanding at a time, each at its own nonce.
    #[tokio::test]
    async fn concurrent_sweep_of_the_same_account_is_serialized() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        // Security finding 02 (Task 4.3): scaled from 10/20 raw units (see
        // `re_sweep_moves_the_remainder_after_credited_grows`) so every
        // remainder here clears `deposit_fee_quote(&sample_fee_vote())`
        // (86_400_000) and is not gated as dust.
        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let account = EvmAddress([0xd1; 20]);
        let claim_pk = test_pubkey(0xd2);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(100_000_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        // Sweep A enqueued (in-flight, nonce 0).
        let op_a = {
            let mut dbtx = db.begin_transaction().await;
            module
                .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
                .await;
            let (hash, op) = single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
            assert_eq!(op.nonce, alloy::primitives::U256::ZERO);
            dbtx.commit_tx().await;
            hash
        };

        // credited grows to 200_000_000 while A is still in flight;
        // re-triggering must NOT create a second op -- the per-account guard
        // holds.
        {
            let mut dbtx = db.begin_transaction().await;
            let mut record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("record present");
            record.credited = UsdtAmount(200_000_000);
            dbtx.to_ref_nc()
                .insert_entry(&DepositRecordKey(account), &record)
                .await;
            module
                .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
                .await;
            let (hash, _) = single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
            assert_eq!(
                hash, op_a,
                "the still-pending sweep A is the only in-flight op; no colliding second one"
            );
            dbtx.commit_tx().await;
        }

        // Confirm A (swept 100_000_000). The success auto-retrigger now
        // sweeps the remainder as op B: nonce 1, amount 100_000_000 --
        // exactly one in flight.
        promote_pending_to_submitted(db, op_a).await;
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_user_op_confirmed(
                    &mut dbtx.to_ref_nc(),
                    op_a,
                    &UserOpConfirmedObservation {
                        success: true,
                        block: 25,
                        block_hash: [0u8; 32],
                        swept: UsdtAmount(100_000_000),
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                )
                .await;
            let (hash_b, op_b) =
                single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
            assert_ne!(hash_b, op_a, "the auto-retrigger enqueued a fresh op");
            assert_eq!(op_b.nonce, alloy::primitives::U256::from(1u64));
            assert_eq!(
                crate::user_op::decode_transfer_amount(&op_b).expect("decodes"),
                UsdtAmount(100_000_000),
                "op B sweeps exactly the remainder that grew while A was in flight"
            );
            dbtx.commit_tx().await;
        }
    }

    /// **Nonce discipline on failure.** A reverted sweep still consumes its
    /// on-chain nonce (the `EntryPoint` validates+increments it before the
    /// `callData` runs), so `DepositRecord.nonce` must advance even on
    /// failure -- but `swept`/`PoolState` must NOT move (nothing left the
    /// account), and the failure must NOT auto-retrigger (a persistently
    /// reverting sweep would otherwise tight-loop and burn gas). A later
    /// manual trigger still builds the retry at the advanced nonce.
    #[tokio::test]
    async fn failed_sweep_advances_nonce_without_retrigger_or_double_credit() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        // Security finding 02 (Task 4.3): scaled from 10 raw units (see
        // `re_sweep_moves_the_remainder_after_credited_grows`) so the
        // remainder clears `deposit_fee_quote(&sample_fee_vote())`
        // (86_400_000) and is not gated as dust.
        seed_fee_votes(db, 4, sample_fee_vote()).await;
        let account = EvmAddress([0xe1; 20]);
        let claim_pk = test_pubkey(0xe2);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(100_000_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let op_hash = {
            let mut dbtx = db.begin_transaction().await;
            module
                .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
                .await;
            let (hash, op) = single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
            assert_eq!(op.nonce, alloy::primitives::U256::ZERO);
            dbtx.commit_tx().await;
            hash
        };

        // Confirm a FAILURE (success: false, swept 0).
        promote_pending_to_submitted(db, op_hash).await;
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_user_op_confirmed(
                    &mut dbtx.to_ref_nc(),
                    op_hash,
                    &UserOpConfirmedObservation {
                        success: false,
                        block: 21,
                        block_hash: [0u8; 32],
                        swept: UsdtAmount(0),
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                )
                .await;
            let record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("record present");
            assert_eq!(record.nonce, 1, "a reverted sweep still consumes its nonce");
            assert_eq!(
                record.swept,
                UsdtAmount(0),
                "failure must not advance swept"
            );
            assert!(
                dbtx.to_ref_nc().get_value(&PoolStateKey).await.is_none(),
                "failure must not credit the pool"
            );
            assert!(
                pending_deploy_and_sweeps(&mut dbtx.to_ref_nc(), account)
                    .await
                    .is_empty(),
                "failure must NOT auto-retrigger (no tight loop)"
            );
            dbtx.commit_tx().await;
        }

        // A later observation-driven trigger still retries -- at the advanced
        // nonce, no redeploy.
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
                .await;
            let (_, op) = single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
            assert_eq!(op.nonce, alloy::primitives::U256::from(1u64));
            assert!(
                op.init_code.is_empty(),
                "retry after the deploying attempt already consumed nonce 0 must not redeploy"
            );
            assert_eq!(
                crate::user_op::decode_transfer_amount(&op).expect("decodes"),
                UsdtAmount(100_000_000)
            );
            dbtx.commit_tx().await;
        }
    }

    /// **Solvency-critical.** `audit` must report each on-chain USDT unit
    /// EXACTLY once, whichever side of a sweep it currently sits on:
    /// `PoolState.balance` (already-swept) PLUS `sum(credited - swept)`
    /// (not-yet-swept remainder of every deposit) -- never `credited` and
    /// `PoolState.balance` both counting the same swept USDT.
    #[tokio::test]
    async fn audit_reports_pool_balance_plus_unswept_credited_without_double_counting() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0xa0);

        let fully_swept = EvmAddress([0xa1; 20]);
        let partially_swept = EvmAddress([0xa2; 20]);
        let never_swept = EvmAddress([0xa3; 20]);

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &DepositRecordKey(fully_swept),
            &DepositRecord {
                claim_pk,
                credited: UsdtAmount(5_000_000),
                claimed: UsdtAmount(0),
                last_observed_block: 0,
                swept: UsdtAmount(5_000_000),
                nonce: 0,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &DepositRecordKey(partially_swept),
            &DepositRecord {
                claim_pk,
                credited: UsdtAmount(3_000_000),
                claimed: UsdtAmount(0),
                last_observed_block: 0,
                swept: UsdtAmount(1_000_000),
                nonce: 0,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &DepositRecordKey(never_swept),
            &DepositRecord {
                claim_pk,
                credited: UsdtAmount(2_000_000),
                claimed: UsdtAmount(0),
                last_observed_block: 0,
                swept: UsdtAmount(0),
                nonce: 0,
            },
        )
        .await;
        // PoolState.balance holds exactly what's been swept so far (5M +
        // 1M = 6M), mirroring what `apply_user_op_confirmed` would have
        // produced.
        dbtx.insert_new_entry(
            &PoolStateKey,
            &PoolState {
                account: module.pool_account(),
                balance: UsdtAmount(6_000_000),
                nonce: 1,
            },
        )
        .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        let mut audit = fedimint_core::module::audit::Audit::default();
        module.audit(&mut dbtx.to_ref_nc(), &mut audit, 0).await;

        let net = audit.net_assets().expect("no overflow").milli_sat;
        // pool 6M + (5M-5M) + (3M-1M) + (2M-0) = 6M + 0 + 2M + 2M = 10M.
        assert_eq!(
            net, 10_000_000,
            "every on-chain USDT unit must be counted exactly once"
        );
    }

    /// **Phase 8, Task 2.** The deterministic batch trigger: before
    /// `batch_interval_blocks()` elapses (and with fewer than
    /// `BATCH_MAX_ITEMS` queued), nothing happens; once the oldest queued
    /// withdrawal has waited long enough, EVERY currently-`Queued`
    /// withdrawal is batched into one `Withdraw`-purpose `PendingUserOp`
    /// with `outpoints` sorted ascending by `OutPoint` (deterministic
    /// ordering) and each covered withdrawal's `WithdrawalState` flips to
    /// `Signing(op_hash)`; a withdrawal queued AFTER that batch started does
    /// not start a second, nonce-colliding batch (`withdraw_batch_in_flight`
    /// guard).
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn maybe_trigger_withdrawal_batch_waits_for_the_interval_then_batches_sorted_and_guards_against_a_second_batch()
     {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let out_a = test_out_point(5);
        let out_b = test_out_point(1); // sorts BEFORE out_a
        let withdrawal_a = UsdtWithdrawalV0 {
            recipient: EvmAddress([0xa1; 20]),
            amount: UsdtAmount(1_000_000),
            max_fee: UsdtAmount(1_000),
            requested_block: 0,
            refund_pubkey: sample_claim_pk(),
        };
        let withdrawal_b = UsdtWithdrawalV0 {
            recipient: EvmAddress([0xb1; 20]),
            amount: UsdtAmount(2_000_000),
            max_fee: UsdtAmount(2_000),
            requested_block: 0,
            refund_pubkey: sample_claim_pk(),
        };

        {
            let mut dbtx = db.begin_transaction().await;
            // Fund the pool so the pool-balance gate is satisfied (the batch
            // total is 1M + 2M = 3M; 6M covers it generously). `nonce: 0`
            // keeps the pool undeployed, so the `!init_code.is_empty()`
            // (needs-deploy) assertion below still holds.
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(6_000_000),
                    nonce: 0,
                },
            )
            .await;
            dbtx.insert_new_entry(&UnclaimedWithdrawalKey(out_a), &withdrawal_a)
                .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out_a), &WithdrawalState::Queued)
                .await;
            dbtx.insert_new_entry(&UnclaimedWithdrawalKey(out_b), &withdrawal_b)
                .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out_b), &WithdrawalState::Queued)
                .await;
            dbtx.commit_tx().await;
        }

        // Before the interval elapses (consensus block count is still 0,
        // matching both withdrawals' requested_block): no trigger.
        let mut dbtx = db.begin_transaction().await;
        module
            .maybe_trigger_withdrawal_batch(&mut dbtx.to_ref_nc())
            .await;
        assert_eq!(
            dbtx.to_ref_nc()
                .find_by_prefix(&PendingUserOpPrefix)
                .await
                .count()
                .await,
            0,
            "must not trigger before the interval elapses"
        );
        dbtx.commit_tx().await;

        // Advance consensus block count strictly past
        // `batch_interval_blocks()` (both withdrawals' `requested_block` is
        // `0`); the `BlockCount` arm calls the trigger itself. Reads
        // `batch_interval_blocks()` directly (rather than assuming its
        // small `is_running_in_test_env()` value) since plain `cargo test`
        // (unlike `cargo nextest run`) does not set the `NEXTEST` env var
        // that function also checks, mirroring
        // `timed_out_detects_stalled_session_via_consensus_block_count`'s
        // own use of `timeout_blocks()` for the identical reason.
        let vote = batch_interval_blocks() + 1;
        let mut dbtx = db.begin_transaction().await;
        for p in 0..4u16 {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::BlockCount(vote),
                    PeerId::from(p),
                )
                .await
                .expect("block count vote succeeds");
        }
        dbtx.commit_tx().await;

        let op_hash = {
            let mut dbtx = db.begin_transaction_nc().await;
            let pending: Vec<(PendingUserOpKey, PendingUserOp)> = dbtx
                .find_by_prefix(&PendingUserOpPrefix)
                .await
                .collect()
                .await;
            assert_eq!(pending.len(), 1, "exactly one batch must be triggered");
            let (PendingUserOpKey(op_hash), record) = &pending[0];
            let UserOpPurpose::Withdraw { outpoints } = &record.purpose else {
                panic!("must be a Withdraw-purpose op");
            };
            assert_eq!(
                outpoints,
                &vec![out_b, out_a],
                "outpoints must be sorted ascending by OutPoint"
            );
            assert_eq!(record.op.sender, module.pool_account());
            assert!(
                !record.op.init_code.is_empty(),
                "the pool has never submitted a UserOp yet (PoolState.nonce==0), so this op \
                 must deploy it"
            );

            for &out_point in &[out_a, out_b] {
                assert_eq!(
                    dbtx.get_value(&WithdrawalStateKey(out_point)).await,
                    Some(WithdrawalState::Signing(*op_hash))
                );
            }
            *op_hash
        };
        let digest = eth_signed_message_hash(op_hash);
        let session_id = signing_session_id(&digest, 0);
        let mut dbtx = db.begin_transaction_nc().await;
        let session = dbtx
            .get_value(&SigningSessionKey(session_id))
            .await
            .expect("SigningSession must be started");
        assert_eq!(session.purpose, SigningPurpose::UserOp(op_hash));
        drop(dbtx);

        // A third withdrawal queued WHILE the batch above is still in
        // flight (Pending) must not start a second, nonce-colliding batch.
        let out_c = test_out_point(99);
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &UnclaimedWithdrawalKey(out_c),
            &UsdtWithdrawalV0 {
                recipient: EvmAddress([0xc1; 20]),
                amount: UsdtAmount(3_000_000),
                max_fee: UsdtAmount(3_000),
                requested_block: 0,
                refund_pubkey: sample_claim_pk(),
            },
        )
        .await;
        dbtx.insert_new_entry(&WithdrawalStateKey(out_c), &WithdrawalState::Queued)
            .await;
        module
            .maybe_trigger_withdrawal_batch(&mut dbtx.to_ref_nc())
            .await;
        assert_eq!(
            dbtx.to_ref_nc()
                .find_by_prefix(&PendingUserOpPrefix)
                .await
                .count()
                .await,
            1,
            "must not start a second batch while one is Pending"
        );
        assert_eq!(
            dbtx.to_ref_nc().get_value(&WithdrawalStateKey(out_c)).await,
            Some(WithdrawalState::Queued),
            "the newly-queued withdrawal must be left untouched, to be picked up by a LATER batch"
        );
    }

    #[tokio::test]
    async fn maybe_trigger_withdrawal_batch_forces_a_batch_once_max_items_is_reached() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let mut dbtx = db.begin_transaction().await;
        // Fund the pool so the pool-balance gate is satisfied. The batch total
        // is BATCH_MAX_ITEMS * 1M = 20M; 40M covers it generously.
        dbtx.insert_new_entry(
            &PoolStateKey,
            &PoolState {
                account: module.pool_account(),
                balance: UsdtAmount(40_000_000),
                nonce: 0,
            },
        )
        .await;
        for i in 0..BATCH_MAX_ITEMS {
            let out_point = test_out_point(i as u64);
            let byte = u8::try_from(i).expect("BATCH_MAX_ITEMS fits in u8");
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out_point),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([byte; 20]),
                    amount: UsdtAmount(1_000_000),
                    max_fee: UsdtAmount(1_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out_point), &WithdrawalState::Queued)
                .await;
        }
        dbtx.commit_tx().await;

        // consensus_block_count is still 0 here (no BlockCount votes
        // seeded), so the interval alone would NOT trigger yet -- only the
        // item-count policy does.
        let mut dbtx = db.begin_transaction().await;
        module
            .maybe_trigger_withdrawal_batch(&mut dbtx.to_ref_nc())
            .await;
        let pending_count = dbtx
            .to_ref_nc()
            .find_by_prefix(&PendingUserOpPrefix)
            .await
            .count()
            .await;
        assert_eq!(
            pending_count, 1,
            "reaching BATCH_MAX_ITEMS must trigger a batch even before the interval elapses"
        );
    }

    /// **Phase 9.** The pool-balance gate in
    /// [`Usdt::maybe_trigger_withdrawal_batch`]: even with the interval
    /// trigger satisfied, NO batch is built while `PoolState.balance` is below
    /// the sum of the queued withdrawals' `amount`s; the batch fires the moment
    /// the balance covers that total. Asserts both directions AND the exact
    /// boundary (`balance == Σ amount` is sufficient, since the gate is a
    /// strict `<`) AND that `max_fee` is NOT part of the coverage requirement
    /// (a balance covering only `Σ amount`, strictly less than
    /// `Σ (amount + max_fee)`, still builds the batch -- the fee stays pooled).
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn maybe_trigger_withdrawal_batch_waits_until_pool_balance_covers_the_batch() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let out_a = test_out_point(5);
        let out_b = test_out_point(1); // sorts BEFORE out_a
        let amount_a = UsdtAmount(1_000_000);
        let amount_b = UsdtAmount(2_000_000);
        let total_amount = amount_a.0 + amount_b.0; // 3M
        // Total incl. fees (3M + 3k); the gate must NOT require this much.
        let total_with_fees = total_amount + 1_000 + 2_000;

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out_a),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([0xa1; 20]),
                    amount: amount_a,
                    max_fee: UsdtAmount(1_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out_a), &WithdrawalState::Queued)
                .await;
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out_b),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([0xb1; 20]),
                    amount: amount_b,
                    max_fee: UsdtAmount(2_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out_b), &WithdrawalState::Queued)
                .await;
            dbtx.commit_tx().await;
        }

        // Advance consensus block count strictly past `batch_interval_blocks()`
        // (both withdrawals' `requested_block` is `0`) so the interval trigger
        // is satisfied for the rest of the test. There is NO `PoolState` yet,
        // so the trigger the `BlockCount` arm runs internally builds nothing:
        // the pool-balance gate (`0 < 3M`) blocks it.
        let vote = batch_interval_blocks() + 1;
        {
            let mut dbtx = db.begin_transaction().await;
            for p in 0..4u16 {
                module
                    .process_consensus_item(
                        &mut dbtx.to_ref_nc(),
                        UsdtConsensusItem::BlockCount(vote),
                        PeerId::from(p),
                    )
                    .await
                    .expect("block count vote succeeds");
            }
            dbtx.commit_tx().await;
        }

        // Direction 1a: interval satisfied but no `PoolState` (balance 0 < 3M).
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .maybe_trigger_withdrawal_batch(&mut dbtx.to_ref_nc())
                .await;
            assert_eq!(
                dbtx.to_ref_nc()
                    .find_by_prefix(&PendingUserOpPrefix)
                    .await
                    .count()
                    .await,
                0,
                "no batch may build while the pool cannot cover the withdrawals"
            );
            for &out_point in &[out_a, out_b] {
                assert_eq!(
                    dbtx.to_ref_nc()
                        .get_value(&WithdrawalStateKey(out_point))
                        .await,
                    Some(WithdrawalState::Queued),
                    "withdrawals stay Queued while the batch waits for pool funding"
                );
            }
            dbtx.commit_tx().await;
        }

        // Direction 1b: a `PoolState` present but still one unit short of the
        // total `amount` (3M - 1). The strict `<` gate must still block.
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(total_amount - 1),
                    nonce: 0,
                },
            )
            .await;
            module
                .maybe_trigger_withdrawal_batch(&mut dbtx.to_ref_nc())
                .await;
            assert_eq!(
                dbtx.to_ref_nc()
                    .find_by_prefix(&PendingUserOpPrefix)
                    .await
                    .count()
                    .await,
                0,
                "one unit short of the total amount must still not build a batch"
            );
            for &out_point in &[out_a, out_b] {
                assert_eq!(
                    dbtx.to_ref_nc()
                        .get_value(&WithdrawalStateKey(out_point))
                        .await,
                    Some(WithdrawalState::Queued),
                );
            }
            dbtx.commit_tx().await;
        }

        // Direction 2: raise the balance to EXACTLY the sum of the `amount`s
        // (the gate's boundary: `balance == Σ amount` is sufficient because the
        // gate is a strict `<`). Crucially this balance is strictly LESS than
        // `Σ (amount + max_fee)`, proving `max_fee` is not part of the coverage
        // requirement -- the fee stays pooled as fee revenue.
        assert!(
            total_amount < total_with_fees,
            "sanity: covering only Σ amount is strictly less than Σ (amount + max_fee)"
        );
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(total_amount),
                    nonce: 0,
                },
            )
            .await;
            module
                .maybe_trigger_withdrawal_batch(&mut dbtx.to_ref_nc())
                .await;

            let pending: Vec<(PendingUserOpKey, PendingUserOp)> = dbtx
                .to_ref_nc()
                .find_by_prefix(&PendingUserOpPrefix)
                .await
                .collect()
                .await;
            assert_eq!(
                pending.len(),
                1,
                "the batch must build once balance covers Σ amount (fee not required)"
            );
            let (PendingUserOpKey(op_hash), record) = &pending[0];
            let UserOpPurpose::Withdraw { outpoints } = &record.purpose else {
                panic!("must be a Withdraw-purpose op");
            };
            assert_eq!(
                outpoints,
                &vec![out_b, out_a],
                "outpoints must be sorted ascending by OutPoint"
            );
            for &out_point in &[out_a, out_b] {
                assert_eq!(
                    dbtx.to_ref_nc()
                        .get_value(&WithdrawalStateKey(out_point))
                        .await,
                    Some(WithdrawalState::Signing(*op_hash)),
                    "covered withdrawals must flip to Signing once the batch builds"
                );
            }
            dbtx.commit_tx().await;
        }
    }

    /// **Phase 8, Task 2.** A confirmed `Withdraw`-purpose `UserOp` (mirrors
    /// `user_op_confirmed_applies_at_threshold_and_is_replay_safe`'s shape
    /// for the `DeployAndSweep` purpose): at threshold, `success` debits
    /// `PoolState.balance` by the total paid out, marks every covered
    /// withdrawal `Confirmed`, removes its now-settled `UnclaimedWithdrawal`,
    /// and bumps `PoolState.nonce`; replay-safe (a direct re-invocation of
    /// `apply_user_op_confirmed` after `SubmittedUserOp` is already gone
    /// must not double-debit/double-bump).
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn user_op_confirmed_withdraw_purpose_success_settles_withdrawals_and_debits_pool() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        let op_hash = [0xb1; 32];
        let out_a = test_out_point(1);
        let out_b = test_out_point(2);
        let outpoints = vec![out_a, out_b];
        let amount_a = UsdtAmount(1_000_000);
        let amount_b = UsdtAmount(2_000_000);
        let total = UsdtAmount(amount_a.0 + amount_b.0);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(5_000_000),
                    nonce: 0,
                },
            )
            .await;
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out_a),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([0xc1; 20]),
                    amount: amount_a,
                    max_fee: UsdtAmount(1_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(
                &WithdrawalStateKey(out_a),
                &WithdrawalState::Signing(op_hash),
            )
            .await;
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out_b),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([0xc2; 20]),
                    amount: amount_b,
                    max_fee: UsdtAmount(2_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(
                &WithdrawalStateKey(out_b),
                &WithdrawalState::Signing(op_hash),
            )
            .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        // Real, decodable calldata (Phase 9 hardening,
                        // sec-21): `apply_user_op_confirmed` re-derives
                        // `swept` from this and rejects a mismatch against
                        // the votes below, which claim `total`.
                        unsigned: real_withdraw_op_for_test(total),
                        signature: vec![0xdd; 65],
                    },
                    purpose: UserOpPurpose::Withdraw {
                        outpoints: outpoints.clone(),
                    },
                    submitted_block: 5,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: true,
            block: 99,
            block_hash: [0u8; 32],
            swept: total,
            actual_gas_cost_wei: UsdtAmount(0),
        };
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(&mut dbtx.to_ref_nc(), obs.clone(), PeerId::from(p))
                .await
                .expect("vote processes cleanly");
        }

        let pool = dbtx
            .to_ref_nc()
            .get_value(&PoolStateKey)
            .await
            .expect("PoolState present");
        assert_eq!(pool.balance, UsdtAmount(5_000_000 - total.0));
        assert_eq!(pool.nonce, 1);

        for &out_point in &outpoints {
            let state = dbtx
                .to_ref_nc()
                .get_value(&WithdrawalStateKey(out_point))
                .await
                .expect("WithdrawalState present");
            assert_eq!(state, WithdrawalState::Confirmed { block: 99 });
            assert!(
                dbtx.to_ref_nc()
                    .get_value(&UnclaimedWithdrawalKey(out_point))
                    .await
                    .is_none(),
                "UnclaimedWithdrawal must be removed once confirmed"
            );
        }
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(op_hash))
                .await
                .is_none()
        );

        // Replay-safety.
        module
            .apply_user_op_confirmed(
                &mut dbtx.to_ref_nc(),
                op_hash,
                &UserOpConfirmedObservation {
                    success: true,
                    block: 99,
                    block_hash: [0u8; 32],
                    swept: total,
                    actual_gas_cost_wei: UsdtAmount(0),
                },
            )
            .await;
        let pool_after = dbtx
            .to_ref_nc()
            .get_value(&PoolStateKey)
            .await
            .expect("PoolState present");
        assert_eq!(
            pool_after.balance,
            UsdtAmount(5_000_000 - total.0),
            "a replayed apply must not double-debit the pool"
        );
        assert_eq!(
            pool_after.nonce, 1,
            "a replayed apply must not double-bump the nonce"
        );
    }

    /// **Phase 8, Task 2; updated Phase 9 Task 5.3 (security finding 05).**
    /// A `!success` `Withdraw`-purpose confirmation covering MORE THAN ONE
    /// withdrawal (`n = 2`, not yet isolated) reverts its withdrawals back
    /// to `Queued` (for a later, capped-smaller batch to retry) rather than
    /// crediting/debiting anything -- but the pool's `nonce` is STILL
    /// bumped, since a `UserOpConfirmed` observation only ever exists for an
    /// op the `EntryPoint` actually validated/included (see
    /// `Usdt::apply_withdraw_confirmed`'s doc comment). Each covered
    /// outpoint's `WithdrawalBatchCapKey` is set to `max(1, n / 2) == 1`.
    /// The `n == 1` (singleton, terminal `Failed`) case is covered by
    /// `single_member_failed_batch_is_terminal_failed`.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn user_op_confirmed_withdraw_purpose_failure_reverts_to_queued_but_still_bumps_nonce() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        let op_hash = [0xb2; 32];
        let out_point_a = test_out_point(9);
        let out_point_b = test_out_point(10);
        let withdrawal_a = UsdtWithdrawalV0 {
            recipient: EvmAddress([0xd1; 20]),
            amount: UsdtAmount(1_500_000),
            max_fee: UsdtAmount(500),
            requested_block: 0,
            refund_pubkey: sample_claim_pk(),
        };
        let withdrawal_b = UsdtWithdrawalV0 {
            recipient: EvmAddress([0xd2; 20]),
            amount: UsdtAmount(500_000),
            max_fee: UsdtAmount(200),
            requested_block: 0,
            refund_pubkey: sample_claim_pk(),
        };

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(3_000_000),
                    nonce: 0,
                },
            )
            .await;
            dbtx.insert_new_entry(&UnclaimedWithdrawalKey(out_point_a), &withdrawal_a)
                .await;
            dbtx.insert_new_entry(&UnclaimedWithdrawalKey(out_point_b), &withdrawal_b)
                .await;
            for &out_point in &[out_point_a, out_point_b] {
                dbtx.insert_new_entry(
                    &WithdrawalStateKey(out_point),
                    &WithdrawalState::Signing(op_hash),
                )
                .await;
            }
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: sample_unsigned_user_op_for_test(),
                        signature: vec![0xee; 65],
                    },
                    purpose: UserOpPurpose::Withdraw {
                        outpoints: vec![out_point_a, out_point_b],
                    },
                    submitted_block: 5,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: false,
            block: 101,
            block_hash: [0u8; 32],
            swept: UsdtAmount(0),
            actual_gas_cost_wei: UsdtAmount(0),
        };
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(&mut dbtx.to_ref_nc(), obs.clone(), PeerId::from(p))
                .await
                .expect("vote processes cleanly");
        }

        let pool = dbtx
            .to_ref_nc()
            .get_value(&PoolStateKey)
            .await
            .expect("PoolState present");
        assert_eq!(
            pool.balance,
            UsdtAmount(3_000_000),
            "a failed batch must not debit the pool"
        );
        assert_eq!(
            pool.nonce, 1,
            "the on-chain nonce is consumed even when the callData execution reverts"
        );

        for (out_point, withdrawal) in [(out_point_a, &withdrawal_a), (out_point_b, &withdrawal_b)]
        {
            let state = dbtx
                .to_ref_nc()
                .get_value(&WithdrawalStateKey(out_point))
                .await
                .expect("WithdrawalState present");
            assert_eq!(
                state,
                WithdrawalState::Queued,
                "a not-yet-isolated (n>1) failed batch must revert its withdrawals to Queued \
                 for retry"
            );
            assert_eq!(
                dbtx.to_ref_nc()
                    .get_value(&UnclaimedWithdrawalKey(out_point))
                    .await,
                Some(withdrawal.clone()),
                "UnclaimedWithdrawal must survive a failed batch unchanged, for retry"
            );
            assert_eq!(
                dbtx.to_ref_nc()
                    .get_value(&WithdrawalBatchCapKey(out_point))
                    .await,
                Some(1),
                "a failed n=2 batch must halve (floor 1) the retry cap for each covered outpoint"
            );
        }
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(op_hash))
                .await
                .is_none()
        );
    }

    /// **Security finding 05 (poisoned-batch isolation).** A failed batch of
    /// exactly ONE withdrawal (`n == 1`) means that withdrawal reverts even
    /// in complete isolation from every other queued withdrawal -- it IS the
    /// poison. It must go terminal `WithdrawalState::Failed`, NOT be
    /// re-queued (re-queueing the identical singleton would rebuild the
    /// exact same failing batch forever, the original `DoS`). Its
    /// `UnclaimedWithdrawal` is kept (Phase 6.1 refunds it) and its
    /// `WithdrawalBatchCapKey` is removed (terminal, never read again).
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn single_member_failed_batch_is_terminal_failed() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        let op_hash = [0xb3; 32];
        let out_point = test_out_point(11);
        let withdrawal = UsdtWithdrawalV0 {
            recipient: EvmAddress([0xf1; 20]),
            amount: UsdtAmount(1_000_000),
            max_fee: UsdtAmount(300),
            requested_block: 0,
            refund_pubkey: sample_claim_pk(),
        };

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(3_000_000),
                    nonce: 0,
                },
            )
            .await;
            dbtx.insert_new_entry(&UnclaimedWithdrawalKey(out_point), &withdrawal)
                .await;
            dbtx.insert_new_entry(
                &WithdrawalStateKey(out_point),
                &WithdrawalState::Signing(op_hash),
            )
            .await;
            // Simulate an already-halved cap from a prior split, to prove
            // the terminal path removes it (rather than leaving it to leak).
            dbtx.insert_new_entry(&WithdrawalBatchCapKey(out_point), &1u32)
                .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: sample_unsigned_user_op_for_test(),
                        signature: vec![0xee; 65],
                    },
                    purpose: UserOpPurpose::Withdraw {
                        outpoints: vec![out_point],
                    },
                    submitted_block: 5,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: false,
            block: 101,
            block_hash: [0u8; 32],
            swept: UsdtAmount(0),
            actual_gas_cost_wei: UsdtAmount(0),
        };
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(&mut dbtx.to_ref_nc(), obs.clone(), PeerId::from(p))
                .await
                .expect("vote processes cleanly");
        }

        let state = dbtx
            .to_ref_nc()
            .get_value(&WithdrawalStateKey(out_point))
            .await
            .expect("WithdrawalState present");
        assert!(
            matches!(state, WithdrawalState::Failed { .. }),
            "a failed singleton batch must isolate its withdrawal as terminal Failed, got {state:?}"
        );
        // Security finding 09: on terminal failure the `UnclaimedWithdrawal` is
        // REPLACED by a reissued-e-cash `Refund` (claimable by the withdrawer's
        // refund key), not kept.
        assert!(
            dbtx.to_ref_nc()
                .get_value(&UnclaimedWithdrawalKey(out_point))
                .await
                .is_none(),
            "UnclaimedWithdrawal must be removed once the withdrawal is refunded"
        );
        let refund = dbtx
            .to_ref_nc()
            .get_value(&RefundKey(out_point))
            .await
            .expect("a refund must exist for the terminally-failed withdrawal");
        assert_eq!(
            refund.amount,
            UsdtAmount(withdrawal.amount.0 + withdrawal.max_fee.0),
            "no gas was recorded (actual_gas_cost_wei = 0) -> full amount + max_fee refunded"
        );
        assert_eq!(refund.refund_pubkey, withdrawal.refund_pubkey);
        assert_eq!(
            dbtx.to_ref_nc()
                .get_value(&WithdrawalBatchCapKey(out_point))
                .await,
            None,
            "a terminal withdrawal's batch cap must be cleaned up"
        );

        let pool = dbtx
            .to_ref_nc()
            .get_value(&PoolStateKey)
            .await
            .expect("PoolState present");
        assert_eq!(
            pool.balance,
            UsdtAmount(3_000_000),
            "a failed batch must not debit the pool"
        );
        assert_eq!(
            pool.nonce, 1,
            "the on-chain nonce is consumed even when the callData execution reverts"
        );
    }

    /// **Security finding 05.** After a failed batch of `n = 4`, every
    /// covered withdrawal's `WithdrawalBatchCapKey` becomes `max(1, 4/2) ==
    /// 2`; the NEXT `maybe_trigger_withdrawal_batch` call must then build a
    /// batch of size <= 2 for those withdrawals (not the full `n = 4`
    /// again), proving `effective_cap` actually shrinks the trigger's batch.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn batch_cap_halves_on_failure_and_shrinks_batches() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        let op_hash = [0xb4; 32];
        let out_points: Vec<OutPoint> = (0..4).map(|i| test_out_point(20 + i)).collect();

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(40_000_000),
                    nonce: 0,
                },
            )
            .await;
            for (i, &out_point) in out_points.iter().enumerate() {
                let byte = u8::try_from(i).expect("small index fits u8");
                dbtx.insert_new_entry(
                    &UnclaimedWithdrawalKey(out_point),
                    &UsdtWithdrawalV0 {
                        recipient: EvmAddress([byte; 20]),
                        amount: UsdtAmount(1_000_000),
                        max_fee: UsdtAmount(1_000),
                        requested_block: 0,
                        refund_pubkey: sample_claim_pk(),
                    },
                )
                .await;
                dbtx.insert_new_entry(
                    &WithdrawalStateKey(out_point),
                    &WithdrawalState::Signing(op_hash),
                )
                .await;
            }
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: sample_unsigned_user_op_for_test(),
                        signature: vec![0xee; 65],
                    },
                    purpose: UserOpPurpose::Withdraw {
                        outpoints: out_points.clone(),
                    },
                    submitted_block: 5,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: false,
            block: 101,
            block_hash: [0u8; 32],
            swept: UsdtAmount(0),
            actual_gas_cost_wei: UsdtAmount(0),
        };
        {
            let mut dbtx = db.begin_transaction().await;
            for p in [0u16, 1, 2] {
                module
                    .process_consensus_item(&mut dbtx.to_ref_nc(), obs.clone(), PeerId::from(p))
                    .await
                    .expect("vote processes cleanly");
            }
            dbtx.commit_tx().await;
        }

        {
            let mut dbtx = db.begin_transaction().await;
            for &out_point in &out_points {
                assert_eq!(
                    dbtx.to_ref_nc()
                        .get_value(&WithdrawalBatchCapKey(out_point))
                        .await,
                    Some(2),
                    "n=4 failure must halve the cap to 2 for every covered outpoint"
                );
                assert_eq!(
                    dbtx.to_ref_nc()
                        .get_value(&WithdrawalStateKey(out_point))
                        .await,
                    Some(WithdrawalState::Queued)
                );
            }
            dbtx.commit_tx().await;
        }

        // Item-threshold trigger needs an item count >= BATCH_MAX_ITEMS to
        // fire immediately regardless of the interval, but only 4 items are
        // queued here -- so advance the consensus block count past the
        // interval instead.
        {
            let mut dbtx = db.begin_transaction().await;
            let vote = batch_interval_blocks() + 1;
            for p in 0..4u16 {
                module
                    .process_consensus_item(
                        &mut dbtx.to_ref_nc(),
                        UsdtConsensusItem::BlockCount(vote),
                        PeerId::from(p),
                    )
                    .await
                    .expect("block count vote succeeds");
            }
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;
        module
            .maybe_trigger_withdrawal_batch(&mut dbtx.to_ref_nc())
            .await;
        let pending: Vec<(PendingUserOpKey, PendingUserOp)> = dbtx
            .to_ref_nc()
            .find_by_prefix(&PendingUserOpPrefix)
            .await
            .collect()
            .await;
        assert_eq!(pending.len(), 1, "the shrunk batch must still build");
        let (_, record) = &pending[0];
        let UserOpPurpose::Withdraw { outpoints } = &record.purpose else {
            panic!("must be a Withdraw-purpose op");
        };
        assert!(
            outpoints.len() <= 2,
            "the effective cap (2) must shrink the next batch to at most 2 items, got {}",
            outpoints.len()
        );
    }

    /// **Security finding 05.** On a successful confirmation, every covered
    /// withdrawal's `WithdrawalBatchCapKey` is removed (housekeeping), even
    /// if a prior failed split had left it capped.
    #[tokio::test]
    async fn successful_batch_clears_caps() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        let op_hash = [0xb5; 32];
        let out_point = test_out_point(30);
        let withdrawal = UsdtWithdrawalV0 {
            recipient: EvmAddress([0x9a; 20]),
            amount: UsdtAmount(1_000_000),
            max_fee: UsdtAmount(1_000),
            requested_block: 0,
            refund_pubkey: sample_claim_pk(),
        };

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(3_000_000),
                    nonce: 0,
                },
            )
            .await;
            dbtx.insert_new_entry(&UnclaimedWithdrawalKey(out_point), &withdrawal)
                .await;
            dbtx.insert_new_entry(
                &WithdrawalStateKey(out_point),
                &WithdrawalState::Signing(op_hash),
            )
            .await;
            // Simulate a prior failed split having left a cap of 1 behind.
            dbtx.insert_new_entry(&WithdrawalBatchCapKey(out_point), &1u32)
                .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: real_withdraw_op_for_test(withdrawal.amount),
                        signature: vec![0xee; 65],
                    },
                    purpose: UserOpPurpose::Withdraw {
                        outpoints: vec![out_point],
                    },
                    submitted_block: 5,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: true,
            block: 101,
            block_hash: [0u8; 32],
            swept: withdrawal.amount,
            actual_gas_cost_wei: UsdtAmount(0),
        };
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(&mut dbtx.to_ref_nc(), obs.clone(), PeerId::from(p))
                .await
                .expect("vote processes cleanly");
        }

        assert_eq!(
            dbtx.to_ref_nc()
                .get_value(&WithdrawalStateKey(out_point))
                .await,
            Some(WithdrawalState::Confirmed { block: 101 })
        );
        assert_eq!(
            dbtx.to_ref_nc()
                .get_value(&UnclaimedWithdrawalKey(out_point))
                .await,
            None,
            "UnclaimedWithdrawal must be removed once confirmed"
        );
        assert_eq!(
            dbtx.to_ref_nc()
                .get_value(&WithdrawalBatchCapKey(out_point))
                .await,
            None,
            "a successfully confirmed withdrawal's batch cap must be cleared"
        );
    }

    /// **Security finding 05 (poisoned-batch isolation), the finding's core
    /// scenario.** One poisoned recipient among several honest ones must be
    /// isolated -- not permanently wedge the whole withdrawal pipeline.
    /// Drives `Usdt::apply_withdraw_confirmed` directly with SCRIPTED
    /// success/failure per simulated batch (any batch containing the poison
    /// fails; any batch without it succeeds), mirroring how repeated
    /// on-chain `executeBatch` attempts would resolve, and asserts:
    /// (a) the isolation actually TERMINATES (the poison reaches terminal
    /// `Failed` within a bounded number of rounds, driven by the halving
    /// cap), (b) every honest withdrawal reaches `Confirmed`, and (c) a
    /// FRESH withdrawal queued afterwards is not permanently blocked (the
    /// trigger's in-flight guard and cap machinery do not wedge on
    /// unrelated, later withdrawals).
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn poisoned_recipient_is_isolated_not_permanent_wedge() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        let honest: Vec<OutPoint> = (0..3).map(|i| test_out_point(40 + i)).collect();
        let poison = test_out_point(50);
        let all: Vec<OutPoint> = honest
            .iter()
            .copied()
            .chain(std::iter::once(poison))
            .collect();

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(40_000_000),
                    nonce: 0,
                },
            )
            .await;
            for (i, &out_point) in all.iter().enumerate() {
                let byte = u8::try_from(i).expect("small index fits u8");
                dbtx.insert_new_entry(
                    &UnclaimedWithdrawalKey(out_point),
                    &UsdtWithdrawalV0 {
                        recipient: EvmAddress([byte; 20]),
                        amount: UsdtAmount(1_000_000),
                        max_fee: UsdtAmount(1_000),
                        requested_block: 0,
                        refund_pubkey: sample_claim_pk(),
                    },
                )
                .await;
                dbtx.insert_new_entry(&WithdrawalStateKey(out_point), &WithdrawalState::Queued)
                    .await;
            }
            dbtx.commit_tx().await;
        }

        // Round 1: the full batch of 4 (3 honest + poison) is attempted and
        // fails (the poison reverts the whole `executeBatch`). Cap -> 2 for
        // all 4.
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_withdraw_confirmed(
                    &mut dbtx.to_ref_nc(),
                    &all,
                    &UserOpConfirmedObservation {
                        success: false,
                        block: 10,
                        block_hash: [0u8; 32],
                        swept: UsdtAmount(0),
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                    UsdtAmount(0),
                )
                .await;
            dbtx.commit_tx().await;
        }
        {
            let mut dbtx = db.begin_transaction().await;
            for &out_point in &all {
                assert_eq!(
                    dbtx.to_ref_nc()
                        .get_value(&WithdrawalBatchCapKey(out_point))
                        .await,
                    Some(2),
                    "round 1 (n=4) failure must halve the cap to 2"
                );
            }
            dbtx.commit_tx().await;
        }

        // Round 2: split into two batches of 2 by sorted OutPoint (mirroring
        // `effective_cap`'s window truncation). Whichever half contains the
        // poison fails (cap -> 1 for its 2 members); the other half succeeds
        // and settles.
        let mut sorted_all = all.clone();
        sorted_all.sort();
        let (first_half, second_half) = sorted_all.split_at(2);
        let poison_half: Vec<OutPoint> = if first_half.contains(&poison) {
            first_half.to_vec()
        } else {
            second_half.to_vec()
        };
        let honest_half: Vec<OutPoint> = if first_half.contains(&poison) {
            second_half.to_vec()
        } else {
            first_half.to_vec()
        };
        assert_eq!(poison_half.len(), 2);
        assert_eq!(honest_half.len(), 2);

        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_withdraw_confirmed(
                    &mut dbtx.to_ref_nc(),
                    &honest_half,
                    &UserOpConfirmedObservation {
                        success: true,
                        block: 11,
                        block_hash: [0u8; 32],
                        swept: UsdtAmount(2_000_000),
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                    UsdtAmount(2_000_000),
                )
                .await;
            module
                .apply_withdraw_confirmed(
                    &mut dbtx.to_ref_nc(),
                    &poison_half,
                    &UserOpConfirmedObservation {
                        success: false,
                        block: 11,
                        block_hash: [0u8; 32],
                        swept: UsdtAmount(0),
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                    UsdtAmount(0),
                )
                .await;
            dbtx.commit_tx().await;
        }
        {
            let mut dbtx = db.begin_transaction().await;
            for &out_point in &honest_half {
                assert_eq!(
                    dbtx.to_ref_nc()
                        .get_value(&WithdrawalStateKey(out_point))
                        .await,
                    Some(WithdrawalState::Confirmed { block: 11 }),
                    "the honest half must settle once it lands in a batch without the poison"
                );
            }
            for &out_point in &poison_half {
                assert_eq!(
                    dbtx.to_ref_nc()
                        .get_value(&WithdrawalBatchCapKey(out_point))
                        .await,
                    Some(1),
                    "round 2 (n=2) failure must halve the cap to 1 (floor)"
                );
                assert_eq!(
                    dbtx.to_ref_nc()
                        .get_value(&WithdrawalStateKey(out_point))
                        .await,
                    Some(WithdrawalState::Queued)
                );
            }
            dbtx.commit_tx().await;
        }

        // Round 3: the poison half splits into two singletons. The poison
        // itself fails alone (terminal Failed); the other member of that
        // half is honest and succeeds alone.
        let last_honest = *poison_half
            .iter()
            .find(|&&o| o != poison)
            .expect("poison_half has exactly one non-poison member");
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_withdraw_confirmed(
                    &mut dbtx.to_ref_nc(),
                    &[last_honest],
                    &UserOpConfirmedObservation {
                        success: true,
                        block: 12,
                        block_hash: [0u8; 32],
                        swept: UsdtAmount(1_000_000),
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                    UsdtAmount(1_000_000),
                )
                .await;
            module
                .apply_withdraw_confirmed(
                    &mut dbtx.to_ref_nc(),
                    &[poison],
                    &UserOpConfirmedObservation {
                        success: false,
                        block: 12,
                        block_hash: [0u8; 32],
                        swept: UsdtAmount(0),
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                    UsdtAmount(0),
                )
                .await;
            dbtx.commit_tx().await;
        }

        // Terminal assertions: all 3 honest withdrawals Confirmed, the
        // poison terminal Failed, and no dangling caps anywhere.
        {
            let mut dbtx = db.begin_transaction().await;
            for &out_point in &honest {
                let state = dbtx
                    .to_ref_nc()
                    .get_value(&WithdrawalStateKey(out_point))
                    .await
                    .expect("WithdrawalState present");
                assert!(
                    matches!(state, WithdrawalState::Confirmed { block: 11 | 12 }),
                    "every honest withdrawal must reach Confirmed, got {state:?}"
                );
                assert_eq!(
                    dbtx.to_ref_nc()
                        .get_value(&WithdrawalBatchCapKey(out_point))
                        .await,
                    None,
                    "a settled withdrawal must not leave a dangling batch cap"
                );
            }
            let poison_state = dbtx
                .to_ref_nc()
                .get_value(&WithdrawalStateKey(poison))
                .await
                .expect("WithdrawalState present");
            assert!(
                matches!(poison_state, WithdrawalState::Failed { .. }),
                "the poison must reach terminal Failed, got {poison_state:?}"
            );
            // Security finding 09: the poison's UnclaimedWithdrawal is REPLACED
            // by a reissued-e-cash Refund on terminal failure.
            assert!(
                dbtx.to_ref_nc()
                    .get_value(&UnclaimedWithdrawalKey(poison))
                    .await
                    .is_none(),
                "the poison's UnclaimedWithdrawal must be replaced by a Refund"
            );
            assert!(
                dbtx.to_ref_nc()
                    .get_value(&RefundKey(poison))
                    .await
                    .is_some(),
                "the terminally-failed poison must have a reissued-e-cash Refund"
            );
            assert_eq!(
                dbtx.to_ref_nc()
                    .get_value(&WithdrawalBatchCapKey(poison))
                    .await,
                None,
                "the terminal poison must not leave a dangling batch cap"
            );
            dbtx.commit_tx().await;
        }

        // Liveness: a FRESH honest withdrawal queued after all this is not
        // permanently blocked -- the trigger builds a batch for it normally
        // (no in-flight PendingUserOp/SubmittedUserOp lingers from the
        // scripted rounds above, since this test drove
        // `apply_withdraw_confirmed` directly rather than through the full
        // signing/submission pipeline).
        let fresh = test_out_point(60);
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(fresh),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([0x77; 20]),
                    amount: UsdtAmount(1_000_000),
                    max_fee: UsdtAmount(1_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(fresh), &WithdrawalState::Queued)
                .await;
            let vote = batch_interval_blocks() + 1;
            for p in 0..4u16 {
                module
                    .process_consensus_item(
                        &mut dbtx.to_ref_nc(),
                        UsdtConsensusItem::BlockCount(vote),
                        PeerId::from(p),
                    )
                    .await
                    .expect("block count vote succeeds");
            }
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;
        module
            .maybe_trigger_withdrawal_batch(&mut dbtx.to_ref_nc())
            .await;
        let fresh_state = dbtx
            .to_ref_nc()
            .get_value(&WithdrawalStateKey(fresh))
            .await
            .expect("WithdrawalState present");
        assert!(
            matches!(fresh_state, WithdrawalState::Signing(_)),
            "a fresh, unrelated withdrawal must be picked up by the trigger normally, got \
             {fresh_state:?}"
        );
    }

    /// **Solvency-critical, Phase 8 Task 2.** `audit`'s net figure must stay
    /// CONSTANT (not just non-negative) across a withdrawal's entire
    /// queue -> batch(-Signing/-Submitted) -> confirm lifecycle -- see
    /// `Usdt::audit`'s own doc comment for the full reasoning this proves
    /// (the `UnclaimedWithdrawal` subtraction and the eventual
    /// `PoolState.balance` debit are exactly offsetting).
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn audit_net_assets_are_invariant_across_the_withdrawal_lifecycle() {
        async fn net_assets(module: &Usdt, db: &fedimint_core::db::Database) -> i64 {
            let mut dbtx = db.begin_transaction().await;
            let mut audit = fedimint_core::module::audit::Audit::default();
            module.audit(&mut dbtx.to_ref_nc(), &mut audit, 0).await;
            audit.net_assets().expect("no overflow").milli_sat
        }

        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let out_point = test_out_point(0);
        let recipient = EvmAddress([0x55; 20]);
        let amount = UsdtAmount(3_000_000);
        let max_fee = UsdtAmount(100_000);
        let op_hash = [7u8; 32];

        // Start with a fully-swept deposit's worth of pool balance, as if a
        // prior sweep already happened.
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &PoolStateKey,
            &PoolState {
                account: module.pool_account(),
                balance: UsdtAmount(10_000_000),
                nonce: 0,
            },
        )
        .await;
        dbtx.commit_tx().await;
        let before_queue = net_assets(&module, db).await;

        // Queue the withdrawal (mirrors `process_output`'s writes directly,
        // to isolate this test from fee-quote plumbing).
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &UnclaimedWithdrawalKey(out_point),
            &UsdtWithdrawalV0 {
                recipient,
                amount,
                max_fee,
                requested_block: 0,
                refund_pubkey: sample_claim_pk(),
            },
        )
        .await;
        dbtx.insert_new_entry(&WithdrawalStateKey(out_point), &WithdrawalState::Queued)
            .await;
        dbtx.commit_tx().await;
        let after_queue = net_assets(&module, db).await;
        assert_eq!(
            after_queue,
            before_queue - i64::try_from(amount.0).expect("fits"),
            "queuing must immediately exclude `amount` (not max_fee) from net assets"
        );

        // Signing/Submitted must not move net assets further.
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(
            &WithdrawalStateKey(out_point),
            &WithdrawalState::Signing(op_hash),
        )
        .await;
        dbtx.commit_tx().await;
        assert_eq!(
            net_assets(&module, db).await,
            after_queue,
            "Signing must not change net assets"
        );

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_entry(
            &WithdrawalStateKey(out_point),
            &WithdrawalState::Submitted(op_hash),
        )
        .await;
        dbtx.commit_tx().await;
        assert_eq!(
            net_assets(&module, db).await,
            after_queue,
            "Submitted must not change net assets"
        );

        // Confirm: pool debited by `amount`, UnclaimedWithdrawal removed --
        // net assets must be UNCHANGED from the queued figure (the
        // subtraction and the debit are exactly offsetting).
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &SubmittedUserOpKey(op_hash),
            &SubmittedUserOp {
                signed: fedimint_usdt_common::user_op::SignedUserOp {
                    // Real, decodable calldata (Phase 9 hardening, sec-21):
                    // `apply_user_op_confirmed` re-derives `swept` from
                    // this and rejects a mismatch against the observation
                    // below, which claims `amount`.
                    unsigned: real_withdraw_op_for_test(amount),
                    signature: vec![0x11; 65],
                },
                purpose: UserOpPurpose::Withdraw {
                    outpoints: vec![out_point],
                },
                submitted_block: 1,
                superseded: false,
            },
        )
        .await;
        module
            .apply_user_op_confirmed(
                &mut dbtx.to_ref_nc(),
                op_hash,
                &UserOpConfirmedObservation {
                    success: true,
                    block: 55,
                    block_hash: [0u8; 32],
                    swept: amount,
                    actual_gas_cost_wei: UsdtAmount(0),
                },
            )
            .await;
        dbtx.commit_tx().await;
        assert_eq!(
            net_assets(&module, db).await,
            after_queue,
            "confirming must not move net assets -- it only reconciles which record accounts \
             for the already-excluded amount"
        );
    }

    /// The USDT module's own `audit` net-assets figure (in the custom
    /// `USDT_UNIT`'s smallest unit), a shared helper for the
    /// security-finding-09 refund tests below.
    async fn usdt_net_assets(module: &Usdt, db: &fedimint_core::db::Database) -> i64 {
        let mut dbtx = db.begin_transaction().await;
        let mut audit = fedimint_core::module::audit::Audit::default();
        module.audit(&mut dbtx.to_ref_nc(), &mut audit, 0).await;
        audit.net_assets().expect("no overflow").milli_sat
    }

    /// **Security finding 09, Step 1.** A withdrawal that reverts on-chain in
    /// an isolated (singleton) batch goes terminal-`Failed` AND is refunded:
    /// its `(amount + max_fee)` e-cash is reissued as a `Refund` record MINUS
    /// the gas already incurred (accumulated from the failed batch's
    /// `actual_gas_cost_wei`), the `UnclaimedWithdrawal`/incurred-fee records
    /// are removed, and the module stays solvent.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn terminally_failed_withdrawal_is_refundable_minus_incurred() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        // 1 USDT/ETH exchange rate: makes `wei_gas_cost_to_usdt` a clean
        // divide-by-1e12, so `actual_gas_cost_wei = 1e17` -> 100_000 raw USDT.
        seed_fee_votes(
            db,
            4,
            FeeVote {
                max_fee_per_gas_wei: 1_000_000_000,
                usdt_per_eth_e6: 1_000_000,
            },
        )
        .await;

        let out_point = test_out_point(0);
        let op_hash = [0x91; 32];
        let amount = UsdtAmount(3_000_000);
        let max_fee = UsdtAmount(200_000);
        let refund_pubkey = sample_claim_pk();
        let gas_wei = UsdtAmount(100_000_000_000_000_000); // 1e17 wei
        let expected_incurred = 100_000u64; // 1e17 * 1e6 / 1e18
        let expected_refund = amount.0 + max_fee.0 - expected_incurred;

        let mut dbtx = db.begin_transaction().await;
        // A fully-swept deposit's worth of pool balance backs the withdrawal.
        dbtx.insert_new_entry(
            &PoolStateKey,
            &PoolState {
                account: module.pool_account(),
                balance: UsdtAmount(10_000_000),
                nonce: 0,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &UnclaimedWithdrawalKey(out_point),
            &UsdtWithdrawalV0 {
                recipient: EvmAddress([0x55; 20]),
                amount,
                max_fee,
                requested_block: 0,
                refund_pubkey,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &WithdrawalStateKey(out_point),
            &WithdrawalState::Submitted(op_hash),
        )
        .await;
        dbtx.insert_new_entry(
            &SubmittedUserOpKey(op_hash),
            &SubmittedUserOp {
                signed: fedimint_usdt_common::user_op::SignedUserOp {
                    unsigned: real_withdraw_op_for_test(amount),
                    signature: vec![0x11; 65],
                },
                purpose: UserOpPurpose::Withdraw {
                    outpoints: vec![out_point],
                },
                submitted_block: 1,
                superseded: false,
            },
        )
        .await;
        dbtx.commit_tx().await;

        let before_fail = usdt_net_assets(&module, db).await;

        // The batch's UserOp reverted on-chain (success = false), consuming
        // `gas_wei` of gas.
        let mut dbtx = db.begin_transaction().await;
        module
            .apply_user_op_confirmed(
                &mut dbtx.to_ref_nc(),
                op_hash,
                &UserOpConfirmedObservation {
                    success: false,
                    block: 55,
                    block_hash: [0u8; 32],
                    swept: UsdtAmount(0),
                    actual_gas_cost_wei: gas_wei,
                },
            )
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        // The refund is present, claimable only by the original withdrawer's
        // refund key, and reduced by the incurred gas.
        let refund = dbtx
            .get_value(&RefundKey(out_point))
            .await
            .expect("a refund must exist after a terminal failure");
        assert_eq!(refund.amount, UsdtAmount(expected_refund));
        assert_eq!(refund.refund_pubkey, refund_pubkey);
        // UnclaimedWithdrawal + incurred-fee records are cleared; the state is
        // terminal Failed.
        assert!(
            dbtx.get_value(&UnclaimedWithdrawalKey(out_point))
                .await
                .is_none(),
            "UnclaimedWithdrawal must be removed once refunded"
        );
        assert!(
            dbtx.get_value(&WithdrawalIncurredFeeKey(out_point))
                .await
                .is_none(),
            "the incurred-fee accumulator must be removed once refunded"
        );
        assert!(matches!(
            dbtx.get_value(&WithdrawalStateKey(out_point)).await,
            Some(WithdrawalState::Failed { .. })
        ));
        drop(dbtx);

        let after_refund = usdt_net_assets(&module, db).await;
        // Net assets stay solvent, and drop by exactly the fee the federation
        // now owes back (max_fee) net of the gas it actually kept (incurred) --
        // never a spurious increase.
        assert!(after_refund >= 0, "module must stay solvent after refund");
        assert_eq!(
            after_refund,
            before_fail - i64::try_from(max_fee.0 - expected_incurred).expect("fits"),
            "refund liability = amount + max_fee - incurred (only `amount` was excluded while \
             queued)"
        );
        assert_eq!(
            after_refund,
            10_000_000 - i64::try_from(expected_refund).expect("fits")
        );
    }

    /// **Security finding 09, Step 2.** The 5.2 over-ceiling reprice-abort path
    /// (a withdrawal whose repriced batch would exceed its committed `max_fee`)
    /// terminal-fails with NO confirmed on-chain attempt, so its incurred gas
    /// is `0` and the refund is the FULL `(amount + max_fee)`.
    #[tokio::test]
    async fn over_ceiling_refund_has_zero_incurred_full_refund() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let out_point = test_out_point(0);
        let amount = UsdtAmount(2_000_000);
        let max_fee = UsdtAmount(150_000);
        let refund_pubkey = sample_claim_pk();

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &UnclaimedWithdrawalKey(out_point),
            &UsdtWithdrawalV0 {
                recipient: EvmAddress([0x66; 20]),
                amount,
                max_fee,
                requested_block: 0,
                refund_pubkey,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &WithdrawalStateKey(out_point),
            &WithdrawalState::Submitted([0x077; 32]),
        )
        .await;
        // No WithdrawalIncurredFeeKey -> the withdrawal never confirmed-failed.
        module
            .create_withdrawal_refund(
                &mut dbtx.to_ref_nc(),
                out_point,
                "gas exceeds committed max_fee".to_string(),
            )
            .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        let refund = dbtx
            .get_value(&RefundKey(out_point))
            .await
            .expect("refund present");
        assert_eq!(
            refund.amount,
            UsdtAmount(amount.0 + max_fee.0),
            "zero incurred gas -> full amount + max_fee refunded"
        );
        assert_eq!(refund.reason, "gas exceeds committed max_fee");
    }

    /// **Security finding 09, Step 3.** A `RefundV0` input claims a refund
    /// EXACTLY ONCE: `process_input` returns the reissued amount + the refund
    /// pubkey and removes the `RefundKey`; a second claim finds it absent and
    /// errors `UnknownRefund`.
    #[tokio::test]
    async fn refund_claim_mints_once_and_rejects_replay() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let out_point = test_out_point(0);
        let refund_pubkey = sample_claim_pk();

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &RefundKey(out_point),
            &Refund {
                amount: UsdtAmount(3_100_000),
                refund_pubkey,
                reason: "transfer reverts".to_string(),
            },
        )
        .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        let meta = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::RefundV0 { out_point },
                test_in_point(),
            )
            .await
            .expect("first refund claim succeeds");
        // The reissued e-cash equals the refund amount, no fee, and is
        // authorized by the refund pubkey (so only the original withdrawer can
        // claim).
        assert_eq!(
            meta.amount.amounts,
            Amounts::new_custom(USDT_UNIT, usdt_amount(UsdtAmount(3_100_000)))
        );
        assert_eq!(meta.amount.fees, Amounts::ZERO);
        assert_eq!(meta.pub_key, refund_pubkey);
        // The record is gone -> claimed exactly once.
        assert!(
            dbtx.get_value(&RefundKey(out_point)).await.is_none(),
            "the RefundKey must be removed on claim"
        );

        // A replay finds nothing and errors.
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::RefundV0 { out_point },
                test_in_point(),
            )
            .await
            .expect_err("a second claim must be rejected");
        assert_eq!(err, UsdtInputError::UnknownRefund);
    }

    /// **Security finding 09, Step 4.** The claim is authorized ONLY by the
    /// refund pubkey: `process_input` returns exactly that pubkey as
    /// `InputMeta.pub_key`, which the fedimint transaction framework verifies
    /// the input signature against -- so a wrong signer's transaction cannot
    /// balance/settle.
    #[tokio::test]
    async fn refund_claim_requires_correct_key() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let out_point = test_out_point(1);
        // A DISTINCT refund pubkey (not `sample_claim_pk`).
        let refund_pubkey = secp256k1::SecretKey::from_slice(&[0x7c; 32])
            .expect("valid scalar")
            .public_key(secp256k1::SECP256K1);

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &RefundKey(out_point),
            &Refund {
                amount: UsdtAmount(500_000),
                refund_pubkey,
                reason: "gas exceeds committed max_fee".to_string(),
            },
        )
        .await;
        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction().await;
        let meta = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::RefundV0 { out_point },
                test_in_point(),
            )
            .await
            .expect("claim resolves");
        assert_eq!(
            meta.pub_key, refund_pubkey,
            "process_input must return the withdrawal's own refund_pubkey so only that key can \
             sign the claim"
        );
        assert_ne!(meta.pub_key, sample_claim_pk());
    }

    /// **Security finding 09, Step 5 (SOLVENCY-CRITICAL).** Net assets are
    /// invariant across the FULL `withdraw -> fail -> refund -> claim`
    /// lifecycle: the round trip returns the module to its pre-withdrawal
    /// figure, and at no intermediate stage is more than one of
    /// `UnclaimedWithdrawal`/`Refund` subtracted for the same withdrawal.
    #[tokio::test]
    async fn audit_net_assets_invariant_across_withdraw_fail_refund_claim() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let out_point = test_out_point(0);
        let amount = UsdtAmount(3_000_000);
        let max_fee = UsdtAmount(200_000);
        let refund_pubkey = sample_claim_pk();

        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &PoolStateKey,
            &PoolState {
                account: module.pool_account(),
                balance: UsdtAmount(10_000_000),
                nonce: 0,
            },
        )
        .await;
        dbtx.commit_tx().await;
        let baseline = usdt_net_assets(&module, db).await;

        // Queue: only `amount` is excluded (max_fee is federation revenue).
        let mut dbtx = db.begin_transaction().await;
        dbtx.insert_new_entry(
            &UnclaimedWithdrawalKey(out_point),
            &UsdtWithdrawalV0 {
                recipient: EvmAddress([0x55; 20]),
                amount,
                max_fee,
                requested_block: 0,
                refund_pubkey,
            },
        )
        .await;
        dbtx.insert_new_entry(&WithdrawalStateKey(out_point), &WithdrawalState::Queued)
            .await;
        dbtx.commit_tx().await;
        assert_eq!(
            usdt_net_assets(&module, db).await,
            baseline - i64::try_from(amount.0).expect("fits")
        );

        // Fail + refund (no incurred gas): UnclaimedWithdrawal -> Refund, and
        // exactly ONE of the two is subtracted (not both).
        let mut dbtx = db.begin_transaction().await;
        module
            .create_withdrawal_refund(&mut dbtx.to_ref_nc(), out_point, "boom".to_string())
            .await;
        dbtx.commit_tx().await;
        assert_eq!(
            usdt_net_assets(&module, db).await,
            baseline - i64::try_from(amount.0 + max_fee.0).expect("fits"),
            "the Refund (amount + max_fee) replaces the UnclaimedWithdrawal (amount); no \
             double-subtraction"
        );

        // Claim: process_input removes the RefundKey, minting the e-cash via
        // the mint module -> the USDT module's net assets return to baseline.
        let mut dbtx = db.begin_transaction().await;
        module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::RefundV0 { out_point },
                test_in_point(),
            )
            .await
            .expect("refund claim succeeds");
        dbtx.commit_tx().await;
        assert_eq!(
            usdt_net_assets(&module, db).await,
            baseline,
            "claiming the refund restores the pre-withdrawal net-assets figure (full round-trip \
             invariant)"
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // one insert per DbKeyPrefix variant is inherently long
    async fn dump_database_covers_every_key_prefix() {
        // Phase 9, Task 1 hardening: `dump_database`'s match over
        // `DbKeyPrefix` is exhaustive (no `_` arm), so the compiler already
        // guarantees every variant has an arm -- but this additionally
        // proves each arm actually surfaces real inserted data end to end
        // (not just that it compiles), and pins the exact set of
        // human-readable table labels `dump_database` reports, so an
        // accidentally-dropped arm (which would need a matching enum
        // variant removal to even compile) or a silently-empty/no-op arm
        // gets caught by a regular `cargo test` run.
        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );

        let claim_pk = test_pubkey(0x21);
        let account = EvmAddress([0x31; 20]);
        let op_hash = [0x41; 32];
        let out_point = test_out_point(9);
        let session_id = signing_session_id(&[0x51; 32], 0);

        let mut dbtx = db.begin_transaction().await;

        dbtx.insert_new_entry(&BlockCountVoteKey(PeerId::from(0)), &42u64)
            .await;
        dbtx.insert_new_entry(
            &FeeVoteKey(PeerId::from(0)),
            &StoredFeeVote {
                vote: sample_fee_vote(),
                recorded_block: 42,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &DepositRecordKey(account),
            &DepositRecord {
                claim_pk,
                credited: UsdtAmount(1_000_000),
                claimed: UsdtAmount(0),
                last_observed_block: 1,
                swept: UsdtAmount(0),
                nonce: 0,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &DepositObservationVoteKey(account, PeerId::from(0)),
            &DepositObservation {
                account,
                balance: UsdtAmount(1_000_000),
                block: 1,
                block_hash: [0u8; 32],
                claim_pk,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &SigningSessionKey(session_id),
            &SigningSession {
                purpose: SigningPurpose::UserOp(op_hash),
                digest: [0x61; 32],
                signers: vec![PeerId::from(0)],
                round: 0,
                state: SessionState::InProgress,
                attempt: 0,
                last_progress_block: 1,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &MpcRoundChunkKey(session_id, 0, PeerId::from(0), 0),
            &MpcRoundChunk {
                count: 1,
                bytes: vec![0x01],
            },
        )
        .await;
        dbtx.insert_new_entry(
            &PendingUserOpKey(op_hash),
            &PendingUserOp {
                op: sample_unsigned_user_op_for_test(),
                purpose: UserOpPurpose::DeployAndSweep { source: account },
                created_block: 1,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &SubmittedUserOpKey(op_hash),
            &SubmittedUserOp {
                signed: fedimint_usdt_common::user_op::SignedUserOp {
                    unsigned: sample_unsigned_user_op_for_test(),
                    signature: vec![0x71; 65],
                },
                purpose: UserOpPurpose::DeployAndSweep { source: account },
                submitted_block: 1,
                superseded: false,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &PoolStateKey,
            &PoolState {
                account,
                balance: UsdtAmount(1_000_000),
                nonce: 0,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &UserOpConfirmedVoteKey(op_hash, PeerId::from(0)),
            &UserOpConfirmedObservation {
                success: true,
                block: 1,
                block_hash: [0u8; 32],
                swept: UsdtAmount(1_000_000),
                actual_gas_cost_wei: UsdtAmount(0),
            },
        )
        .await;
        dbtx.insert_new_entry(
            &UnclaimedWithdrawalKey(out_point),
            &UsdtWithdrawalV0 {
                recipient: account,
                amount: UsdtAmount(1_000_000),
                max_fee: UsdtAmount(20_000),
                requested_block: 1,
                refund_pubkey: sample_claim_pk(),
            },
        )
        .await;
        dbtx.insert_new_entry(&WithdrawalStateKey(out_point), &WithdrawalState::Queued)
            .await;
        dbtx.insert_new_entry(
            &BootstrapVoteKey(PeerId::from(0)),
            &BootstrapObservation {
                entry_point_ok: true,
                factory_ok: true,
                impl_ok: true,
                broadcaster_funded: true,
                rpc_healthy: true,
            },
        )
        .await;
        dbtx.insert_new_entry(&HasEverBeenReadyKey, &()).await;
        dbtx.insert_new_entry(&WithdrawalBatchCapKey(out_point), &2u32)
            .await;
        dbtx.insert_new_entry(
            &RefundKey(out_point),
            &Refund {
                amount: UsdtAmount(1_020_000),
                refund_pubkey: sample_claim_pk(),
                reason: "transfer reverts".to_string(),
            },
        )
        .await;
        dbtx.insert_new_entry(&WithdrawalIncurredFeeKey(out_point), &UsdtAmount(12_345))
            .await;
        dbtx.insert_new_entry(&BlockHashRingKey(1), &[0x61; 32])
            .await;
        dbtx.insert_new_entry(
            &BlockHashVoteKey(PeerId::from(0)),
            &BlockHashObservation {
                height: 1,
                block_hash: [0x62; 32],
            },
        )
        .await;

        dbtx.commit_tx().await;

        let mut dbtx = db.begin_transaction_nc().await;
        let dumped: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = UsdtInit::default()
            .dump_database(&mut dbtx.to_ref_nc(), Vec::new())
            .await
            .collect();

        let expected_labels = [
            "Block Count Votes",
            "Fee Votes",
            "Deposit Records",
            "Deposit Observation Votes",
            "Signing Sessions",
            "MPC Round Chunks",
            "Pending UserOps",
            "Submitted UserOps",
            "Pool State",
            "UserOp Confirmed Votes",
            "Unclaimed Withdrawals",
            "Withdrawal States",
            "Bootstrap Votes",
            "Has Ever Been Ready",
            "Withdrawal Batch Caps",
            "Withdrawal Refunds",
            "Withdrawal Incurred Fees",
            "Block Hash Ring",
            "Block Hash Votes",
        ];
        assert_eq!(
            dumped.len(),
            expected_labels.len(),
            "dump_database must produce exactly one entry per DbKeyPrefix variant"
        );
        for label in expected_labels {
            assert!(
                dumped.contains_key(label),
                "dump_database is missing the {label:?} table"
            );
        }
    }

    /// Shared sample [`UnsignedUserOp`] for tests that need a
    /// `SubmittedUserOp` fixture but never actually decode its `call_data`
    /// (e.g. a `success: false` `UserOpConfirmed` observation, or a
    /// signing-session fixture). Deliberately NOT a valid `execute()`/
    /// `executeBatch()` encoding (`call_data: [0xde, 0xad]`) -- since
    /// [`Usdt::apply_user_op_confirmed`] now re-derives `swept` from this
    /// calldata on any `success: true` observation (Phase 9 hardening,
    /// sec-21) and rejects a decode failure, a test whose confirm path must
    /// actually settle needs [`real_deploy_and_sweep_op_for_test`]/
    /// [`real_withdraw_op_for_test`] instead.
    fn sample_unsigned_user_op_for_test() -> fedimint_usdt_common::user_op::UnsignedUserOp {
        fedimint_usdt_common::user_op::UnsignedUserOp {
            sender: EvmAddress([0; 20]),
            nonce: alloy::primitives::U256::ZERO,
            init_code: vec![],
            call_data: vec![0xde, 0xad],
            verification_gas_limit: 500_000,
            call_gas_limit: 200_000,
            pre_verification_gas: alloy::primitives::U256::from(100_000u64),
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 30_000_000_000,
            paymaster_and_data: vec![],
        }
    }

    /// A real, decodable `DeployAndSweep` [`UnsignedUserOp`] whose
    /// [`crate::user_op::decode_transfer_amount`] equals `amount`, sender
    /// `source` (Phase 9 hardening, sec-21) -- for fixtures whose
    /// `UserOpConfirmed { success: true, .. }` confirm path must actually
    /// re-derive and settle (see [`sample_unsigned_user_op_for_test`]'s doc
    /// comment for why the old undecodable sample no longer suffices
    /// there). The `account_factory`/`usdt_contract`/`owner`/`pool`
    /// addresses and `claim_pk` are arbitrary test fixtures -- only the
    /// decoded transfer amount is load-bearing for these tests.
    fn real_deploy_and_sweep_op_for_test(
        source: EvmAddress,
        amount: UsdtAmount,
    ) -> fedimint_usdt_common::user_op::UnsignedUserOp {
        crate::user_op::build_deploy_and_sweep_userop(DeployAndSweepParams {
            account_factory: EvmAddress([0x01; 20]),
            usdt_contract: EvmAddress([0x02; 20]),
            deposit_account: source,
            owner: EvmAddress([0x03; 20]),
            claim_pk: test_pubkey(0xf0),
            amount,
            pool: EvmAddress([0x04; 20]),
            nonce: alloy::primitives::U256::ZERO,
            needs_deploy: false,
            paymaster_and_data: Vec::new(),
            gas_bounds: GasBounds::DEPLOY_AND_SWEEP_DEVNET,
        })
    }

    /// Mirrors [`real_deploy_and_sweep_op_for_test`] for the `Withdraw`
    /// purpose: a real, decodable single-item batch [`UnsignedUserOp`]
    /// whose [`crate::user_op::decode_batch_transfer_total`] equals
    /// `amount`, paid to one arbitrary recipient. The specific recipient
    /// and the number of transfer items in the batch are irrelevant to
    /// these tests -- `UserOpPurpose::Withdraw { outpoints }`'s own
    /// `outpoints` (not this calldata) is what determines which
    /// `WithdrawalState`s a confirm settles; this calldata only needs to
    /// decode to the right TOTAL.
    fn real_withdraw_op_for_test(
        amount: UsdtAmount,
    ) -> fedimint_usdt_common::user_op::UnsignedUserOp {
        crate::user_op::build_withdrawal_batch_userop(WithdrawalBatchParams {
            account_factory: EvmAddress([0x01; 20]),
            usdt_contract: EvmAddress([0x02; 20]),
            pool: EvmAddress([0x04; 20]),
            owner: EvmAddress([0x03; 20]),
            withdrawals: vec![(EvmAddress([0x05; 20]), amount)],
            nonce: alloy::primitives::U256::ZERO,
            needs_deploy: false,
            paymaster_and_data: Vec::new(),
            gas_bounds: GasBounds::withdrawal_batch(1, false),
        })
    }

    /// **Security finding 21, fix (a).** The guardian-local `UserOp`
    /// confirmation task (`Usdt::spawn_user_op_submitter`) must fail
    /// CLOSED, not open, when a successful op's own committed calldata
    /// fails to decode: it must skip proposing a `UserOpConfirmed` for that
    /// op entirely, never propose one with a fabricated `swept =
    /// UsdtAmount(0)` (the old `.unwrap_or(UsdtAmount(0))` behavior, which
    /// would let a real on-chain transfer settle without moving the pool
    /// accounting). Exercised for BOTH purposes (`DeployAndSweep` via
    /// `decode_transfer_amount`, `Withdraw` via
    /// `decode_batch_transfer_total`), each with undecodable calldata
    /// (`sample_unsigned_user_op_for_test`'s `[0xde, 0xad]`). A THIRD,
    /// well-formed `DeployAndSweep` op is the positive control: it must
    /// still produce a proposal with the correctly-decoded `swept`, proving
    /// the malformed ops' absence is really the fail-closed skip and not
    /// just the background task never having run.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn swept_decode_failure_does_not_propose_zero() {
        let evm_rpc = MockEvmRpc::default();

        let malformed_sweep_hash = [0xf1; 32];
        let malformed_sweep_source = EvmAddress([0xf2; 20]);
        let malformed_withdraw_hash = [0xf3; 32];
        let malformed_withdraw_out = test_out_point(0xf4);
        let good_hash = [0xf5; 32];
        let good_source = EvmAddress([0xf6; 20]);
        let good_amount = UsdtAmount(7_000_000);

        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );
        {
            let mut dbtx = db.begin_transaction().await;
            let mut malformed_sweep = sample_unsigned_user_op_for_test();
            malformed_sweep.sender = malformed_sweep_source;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(malformed_sweep_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: malformed_sweep,
                        signature: vec![0xaa; 65],
                    },
                    purpose: UserOpPurpose::DeployAndSweep {
                        source: malformed_sweep_source,
                    },
                    submitted_block: 1,
                    superseded: false,
                },
            )
            .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(malformed_withdraw_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: sample_unsigned_user_op_for_test(),
                        signature: vec![0xbb; 65],
                    },
                    purpose: UserOpPurpose::Withdraw {
                        outpoints: vec![malformed_withdraw_out],
                    },
                    submitted_block: 1,
                    superseded: false,
                },
            )
            .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(good_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: real_deploy_and_sweep_op_for_test(good_source, good_amount),
                        signature: vec![0xcc; 65],
                    },
                    purpose: UserOpPurpose::DeployAndSweep {
                        source: good_source,
                    },
                    submitted_block: 1,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        for hash in [malformed_sweep_hash, malformed_withdraw_hash, good_hash] {
            evm_rpc.set_user_op_receipt(
                hash,
                fedimint_usdt_common::user_op::UserOpReceipt {
                    success: true,
                    block: 42,
                    block_hash: [0u8; 32],
                    actual_gas_cost_wei: UsdtAmount(0),
                },
            );
        }

        // Security finding 04: the confirmation-depth gate needs a consensus
        // block count comfortably past `receipt.block (42) + confirmation_depth`
        // so this test (which predates the gate) still sees its proposals.
        let num_peers = (0..4u16)
            .map(PeerId::from)
            .collect::<Vec<_>>()
            .to_num_peers();
        seed_block_count_votes(&db, 4, 100).await;

        let user_op_confirmed_proposals = Arc::new(Mutex::new(Vec::new()));
        let task_group = TaskGroup::new();
        Usdt::spawn_user_op_submitter(
            &task_group,
            UserOpSubmitterHandles {
                db: db.clone(),
                evm_rpc: evm_rpc.into_dyn(),
                user_op_confirmed_proposals: user_op_confirmed_proposals.clone(),
                confirmation_depth: 6,
                num_peers,
            },
        );

        // Poll (rather than a fixed sleep) for the positive control to
        // appear, bounded well above the 1s test-env tick interval so this
        // is not flaky under load; failure to appear at all fails the test
        // below via the final assertion, not a timeout panic.
        let deadline = fedimint_core::time::now() + Duration::from_secs(10);
        loop {
            if user_op_confirmed_proposals
                .lock()
                .expect("not poisoned")
                .iter()
                .any(|p| p.op_hash == good_hash)
                || fedimint_core::time::now() >= deadline
            {
                break;
            }
            fedimint_core::runtime::sleep(Duration::from_millis(50)).await;
        }

        let proposals = user_op_confirmed_proposals.lock().expect("not poisoned");
        assert!(
            !proposals.iter().any(|p| p.op_hash == malformed_sweep_hash),
            "a DeployAndSweep op whose calldata fails to decode must never propose a \
             confirmation (found: {proposals:?})"
        );
        assert!(
            !proposals
                .iter()
                .any(|p| p.op_hash == malformed_withdraw_hash),
            "a Withdraw op whose calldata fails to decode must never propose a confirmation \
             (found: {proposals:?})"
        );
        let good = proposals
            .iter()
            .find(|p| p.op_hash == good_hash)
            .expect("positive control: a well-formed op must still propose a confirmation");
        assert_eq!(
            good.swept, good_amount,
            "positive control's proposed swept must match the op's real decoded amount"
        );
    }

    /// **Security finding 19.** [`rpc_deadline_with`] (the parameterized
    /// implementation behind [`rpc_deadline`]) must turn a never-resolving
    /// future into a bounded `Err` rather than hanging forever, so a
    /// stalled RPC call lands in the same retry/sleep branch as an ordinary
    /// RPC error. Uses a short (50ms) deadline directly rather than the
    /// production `RPC_REQUEST_TIMEOUT_SECS` so this test is fast and
    /// deterministic regardless of whether it runs under plain `cargo test`
    /// or `cargo nextest run`.
    #[tokio::test]
    async fn rpc_deadline_times_out() {
        let result = fedimint_core::runtime::timeout(Duration::from_secs(10), async {
            rpc_deadline_with::<()>(Duration::from_millis(50), std::future::pending()).await
        })
        .await
        .expect("rpc_deadline_with itself must return well within the outer 10s test bound");

        let err = result.expect_err("a never-resolving future must map to Err, not hang");
        assert!(
            err.to_string().contains("timed out"),
            "rpc_deadline's error should explain it was a timeout, got: {err}"
        );
    }

    /// **Security finding 19.** `Usdt::spawn_user_op_submitter` must not let
    /// one op whose `get_user_op_receipt` never resolves block progress on
    /// other submitted ops: with the old fully-serial `for` loop, the hung
    /// op's await would wedge the whole task and the prompt op's receipt
    /// would never be observed. With bounded-concurrency processing (each
    /// op's RPC awaits wrapped in `rpc_deadline`), the prompt op's
    /// `UserOpConfirmed` proposal must still appear within a bounded wait.
    #[tokio::test]
    async fn hung_rpc_does_not_block_other_submitted_ops() {
        let evm_rpc = MockEvmRpc::default();

        let hung_hash = [0xa1; 32];
        let hung_source = EvmAddress([0xa2; 20]);
        let prompt_hash = [0xa3; 32];
        let prompt_source = EvmAddress([0xa4; 20]);
        let prompt_amount = UsdtAmount(1_500_000);

        evm_rpc.set_receipt_hangs(hung_hash);
        evm_rpc.set_user_op_receipt(
            prompt_hash,
            fedimint_usdt_common::user_op::UserOpReceipt {
                success: true,
                block: 7,
                block_hash: [0u8; 32],
                actual_gas_cost_wei: UsdtAmount(0),
            },
        );

        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(hung_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: sample_unsigned_user_op_for_test(),
                        signature: vec![0xaa; 65],
                    },
                    purpose: UserOpPurpose::DeployAndSweep {
                        source: hung_source,
                    },
                    submitted_block: 1,
                    superseded: false,
                },
            )
            .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(prompt_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: real_deploy_and_sweep_op_for_test(prompt_source, prompt_amount),
                        signature: vec![0xcc; 65],
                    },
                    purpose: UserOpPurpose::DeployAndSweep {
                        source: prompt_source,
                    },
                    submitted_block: 1,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        // Security finding 04: seed a consensus block count past
        // `receipt.block (7) + confirmation_depth` so the confirmation-depth
        // gate does not suppress the prompt op's proposal this test asserts on.
        let num_peers = (0..4u16)
            .map(PeerId::from)
            .collect::<Vec<_>>()
            .to_num_peers();
        seed_block_count_votes(&db, 4, 100).await;

        let user_op_confirmed_proposals = Arc::new(Mutex::new(Vec::new()));
        let task_group = TaskGroup::new();
        Usdt::spawn_user_op_submitter(
            &task_group,
            UserOpSubmitterHandles {
                db: db.clone(),
                evm_rpc: evm_rpc.into_dyn(),
                user_op_confirmed_proposals: user_op_confirmed_proposals.clone(),
                confirmation_depth: 6,
                num_peers,
            },
        );

        // Poll (rather than a fixed sleep) for the prompt op's proposal,
        // bounded well above both `rpc_deadline`'s own test-env deadline and
        // the 1s test-env tick interval, so the test is not flaky under
        // load; the hung op being present forever alongside it (or absent
        // entirely, since it never produces a proposal) is asserted below.
        let deadline = fedimint_core::time::now() + Duration::from_secs(10);
        loop {
            if user_op_confirmed_proposals
                .lock()
                .expect("not poisoned")
                .iter()
                .any(|p| p.op_hash == prompt_hash)
                || fedimint_core::time::now() >= deadline
            {
                break;
            }
            fedimint_core::runtime::sleep(Duration::from_millis(50)).await;
        }

        let proposals = user_op_confirmed_proposals.lock().expect("not poisoned");
        let prompt = proposals.iter().find(|p| p.op_hash == prompt_hash).expect(
            "a hung get_user_op_receipt for one op must not block the receipt poll of \
                 another submitted op",
        );
        assert_eq!(
            prompt.swept, prompt_amount,
            "the prompt op's proposal must still carry its correctly-decoded swept amount"
        );
        assert!(
            !proposals.iter().any(|p| p.op_hash == hung_hash),
            "the hung op must never have produced a proposal (found: {proposals:?})"
        );
    }

    /// **Security finding 21, fix (b).** `apply_user_op_confirmed` must
    /// re-derive the expected swept amount from the committed op's own
    /// calldata and reject a `UserOpConfirmed` vote whose `swept` disagrees
    /// with it, rather than trusting the vote outright: on a mismatch, NO
    /// state changes at all (balance, `DepositRecord`/`WithdrawalState`,
    /// AND `SubmittedUserOp` -- see `apply_user_op_confirmed`'s own doc
    /// comment for why the nonce must not advance either) so the op stays
    /// retriable; a SUBSEQUENT matching observation for the exact same
    /// `op_hash` then applies exactly as the honest happy path always has.
    /// Exercised for both purposes.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn apply_rejects_swept_mismatch() {
        // --- DeployAndSweep branch. -----------------------------------
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let source = EvmAddress([0xe1; 20]);
        let claim_pk = test_pubkey(0xe2);
        let op_hash = [0xe3; 32];
        let real_amount = UsdtAmount(2_500_000);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(source),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(2_500_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: real_deploy_and_sweep_op_for_test(source, real_amount),
                        signature: vec![0x22; 65],
                    },
                    purpose: UserOpPurpose::DeployAndSweep { source },
                    submitted_block: 1,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        // A mismatched vote (claims 999_999_999, the op's calldata really
        // decodes to 2_500_000) must be a complete no-op.
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_user_op_confirmed(
                    &mut dbtx.to_ref_nc(),
                    op_hash,
                    &UserOpConfirmedObservation {
                        success: true,
                        block: 10,
                        block_hash: [0u8; 32],
                        swept: UsdtAmount(999_999_999),
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                )
                .await;
            assert!(
                dbtx.to_ref_nc().get_value(&PoolStateKey).await.is_none(),
                "a mismatched vote must not create/credit PoolState"
            );
            let record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(source))
                .await
                .expect("DepositRecord present");
            assert_eq!(record.swept, UsdtAmount(0), "swept must not advance");
            assert_eq!(
                record.nonce, 0,
                "nonce must not advance either -- the whole apply is a no-op on mismatch"
            );
            assert!(
                dbtx.to_ref_nc()
                    .get_value(&SubmittedUserOpKey(op_hash))
                    .await
                    .is_some(),
                "SubmittedUserOp must remain live (retriable) after a mismatched vote"
            );
            dbtx.commit_tx().await;
        }

        // Positive control: a SUBSEQUENT, matching observation for the
        // SAME op_hash applies exactly as the honest happy path always
        // has.
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_user_op_confirmed(
                    &mut dbtx.to_ref_nc(),
                    op_hash,
                    &UserOpConfirmedObservation {
                        success: true,
                        block: 11,
                        block_hash: [0u8; 32],
                        swept: real_amount,
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                )
                .await;
            let pool = dbtx
                .to_ref_nc()
                .get_value(&PoolStateKey)
                .await
                .expect("PoolState created by the matching apply");
            assert_eq!(pool.balance, real_amount);
            let record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(source))
                .await
                .expect("DepositRecord present");
            assert_eq!(record.swept, real_amount);
            assert_eq!(record.nonce, 1);
            assert!(
                dbtx.to_ref_nc()
                    .get_value(&SubmittedUserOpKey(op_hash))
                    .await
                    .is_none(),
                "a matching apply must clear SubmittedUserOp as usual"
            );
            dbtx.commit_tx().await;
        }

        // --- Withdraw branch. -------------------------------------------
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let out_point = test_out_point(0xe4);
        let recipient = EvmAddress([0xe5; 20]);
        let real_total = UsdtAmount(1_800_000);
        let withdraw_op_hash = [0xe6; 32];

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(5_000_000),
                    nonce: 0,
                },
            )
            .await;
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out_point),
                &UsdtWithdrawalV0 {
                    recipient,
                    amount: real_total,
                    max_fee: UsdtAmount(1_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(
                &WithdrawalStateKey(out_point),
                &WithdrawalState::Signing(withdraw_op_hash),
            )
            .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(withdraw_op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: real_withdraw_op_for_test(real_total),
                        signature: vec![0x33; 65],
                    },
                    purpose: UserOpPurpose::Withdraw {
                        outpoints: vec![out_point],
                    },
                    submitted_block: 1,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        // A mismatched vote must not debit the pool, must not touch
        // WithdrawalState/UnclaimedWithdrawal, and must not bump
        // PoolState.nonce.
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_user_op_confirmed(
                    &mut dbtx.to_ref_nc(),
                    withdraw_op_hash,
                    &UserOpConfirmedObservation {
                        success: true,
                        block: 20,
                        block_hash: [0u8; 32],
                        swept: UsdtAmount(1),
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                )
                .await;
            let pool = dbtx
                .to_ref_nc()
                .get_value(&PoolStateKey)
                .await
                .expect("PoolState present");
            assert_eq!(
                pool.balance,
                UsdtAmount(5_000_000),
                "a mismatched vote must not debit the pool"
            );
            assert_eq!(pool.nonce, 0, "nonce must not advance on mismatch");
            let state = dbtx
                .to_ref_nc()
                .get_value(&WithdrawalStateKey(out_point))
                .await
                .expect("WithdrawalState present");
            assert_eq!(
                state,
                WithdrawalState::Signing(withdraw_op_hash),
                "a mismatched vote must not mark Confirmed (or revert to Queued)"
            );
            assert!(
                dbtx.to_ref_nc()
                    .get_value(&UnclaimedWithdrawalKey(out_point))
                    .await
                    .is_some(),
                "UnclaimedWithdrawal must survive a mismatched vote unchanged"
            );
            assert!(
                dbtx.to_ref_nc()
                    .get_value(&SubmittedUserOpKey(withdraw_op_hash))
                    .await
                    .is_some(),
                "SubmittedUserOp must remain live (retriable) after a mismatched vote"
            );
            dbtx.commit_tx().await;
        }

        // Positive control: a SUBSEQUENT, matching observation applies
        // exactly as the honest happy path always has.
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_user_op_confirmed(
                    &mut dbtx.to_ref_nc(),
                    withdraw_op_hash,
                    &UserOpConfirmedObservation {
                        success: true,
                        block: 21,
                        block_hash: [0u8; 32],
                        swept: real_total,
                        actual_gas_cost_wei: UsdtAmount(0),
                    },
                )
                .await;
            let pool = dbtx
                .to_ref_nc()
                .get_value(&PoolStateKey)
                .await
                .expect("PoolState present");
            assert_eq!(pool.balance, UsdtAmount(5_000_000 - real_total.0));
            assert_eq!(pool.nonce, 1);
            let state = dbtx
                .to_ref_nc()
                .get_value(&WithdrawalStateKey(out_point))
                .await
                .expect("WithdrawalState present");
            assert_eq!(state, WithdrawalState::Confirmed { block: 21 });
            assert!(
                dbtx.to_ref_nc()
                    .get_value(&UnclaimedWithdrawalKey(out_point))
                    .await
                    .is_none(),
                "UnclaimedWithdrawal must be removed once confirmed"
            );
            assert!(
                dbtx.to_ref_nc()
                    .get_value(&SubmittedUserOpKey(withdraw_op_hash))
                    .await
                    .is_none()
            );
            dbtx.commit_tx().await;
        }
    }

    /// **Security finding 04 (Task 5.1).** The user-op submitter must NOT
    /// propose a threshold confirmation for a receipt until its block is
    /// `confirmation_depth` consensus blocks deep -- so a reorg shallower than
    /// the depth cannot make the federation apply an irreversible sweep/
    /// withdrawal settlement against a block that later disappears.
    #[tokio::test(flavor = "multi_thread")]
    async fn userop_confirm_waits_for_confirmation_depth() {
        let source = EvmAddress([0x51; 20]);
        let op_hash = [0x52u8; 32];
        let receipt_block = 10u64;
        let confirmation_depth = 6u64;

        let evm_rpc = MockEvmRpc::default();
        evm_rpc.set_user_op_receipt(
            op_hash,
            fedimint_usdt_common::user_op::UserOpReceipt {
                success: true,
                block: receipt_block,
                block_hash: [0x77; 32],
                actual_gas_cost_wei: UsdtAmount(0),
            },
        );

        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: real_deploy_and_sweep_op_for_test(source, UsdtAmount(1_000_000)),
                        signature: vec![0xcc; 65],
                    },
                    purpose: UserOpPurpose::DeployAndSweep { source },
                    submitted_block: 1,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let num_peers = (0..4u16)
            .map(PeerId::from)
            .collect::<Vec<_>>()
            .to_num_peers();
        // Consensus block count 12 < receipt_block(10) + confirmation_depth(6)
        // = 16, so the gate must suppress the proposal.
        seed_block_count_votes(&db, 4, 12).await;

        let proposals = Arc::new(Mutex::new(Vec::new()));
        let task_group = TaskGroup::new();
        Usdt::spawn_user_op_submitter(
            &task_group,
            UserOpSubmitterHandles {
                db: db.clone(),
                evm_rpc: evm_rpc.into_dyn(),
                user_op_confirmed_proposals: proposals.clone(),
                confirmation_depth,
                num_peers,
            },
        );

        // Below depth: give the task several 1s test-env ticks; NO proposal
        // may appear.
        fedimint_core::runtime::sleep(Duration::from_secs(3)).await;
        assert!(
            proposals.lock().expect("not poisoned").is_empty(),
            "a receipt shallower than confirmation_depth must not be proposed"
        );

        // Advance the consensus block count to exactly confirmation-deep.
        seed_block_count_votes(&db, 4, receipt_block + confirmation_depth).await;

        let deadline = fedimint_core::time::now() + Duration::from_secs(10);
        loop {
            if let Some(p) = proposals.lock().expect("not poisoned").first().cloned() {
                assert_eq!(p.op_hash, op_hash);
                assert_eq!(p.block, receipt_block);
                assert_eq!(
                    p.block_hash, [0x77; 32],
                    "the proposal must carry the receipt's canonical block hash"
                );
                break;
            }
            assert!(
                fedimint_core::time::now() < deadline,
                "receipt must be proposed once it becomes confirmation-deep"
            );
            fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
        }
    }

    /// **Security findings 04/15 (Task 5.1).** `UserOpConfirmed` votes that
    /// agree on `{success, block, swept}` but carry DIFFERENT `block_hash`es
    /// (two forks at the same height) must NOT aggregate toward the
    /// confirmation threshold; only a matching-hash quorum applies the
    /// settlement.
    #[tokio::test]
    async fn userop_votes_on_different_block_hashes_do_not_aggregate() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();
        let source = EvmAddress([0x61; 20]);
        let op_hash = [0x62u8; 32];
        let amount = UsdtAmount(1_000_000);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(op_hash),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: real_deploy_and_sweep_op_for_test(source, amount),
                        signature: vec![0xcc; 65],
                    },
                    purpose: UserOpPurpose::DeployAndSweep { source },
                    submitted_block: 1,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let hash_fork_a = [0xA1u8; 32];
        let hash_fork_b = [0xB2u8; 32];
        let vote = |block_hash: [u8; 32]| UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: true,
            block: 10,
            block_hash,
            swept: amount,
            actual_gas_cost_wei: UsdtAmount(0),
        };

        let mut dbtx = db.begin_transaction().await;
        // 2 votes on fork A + 1 vote on fork B at the SAME height: no full-field
        // quorum of 3, so the op must NOT be applied.
        for p in [0u16, 1] {
            module
                .process_consensus_item(&mut dbtx.to_ref_nc(), vote(hash_fork_a), PeerId::from(p))
                .await
                .unwrap();
        }
        module
            .process_consensus_item(&mut dbtx.to_ref_nc(), vote(hash_fork_b), PeerId::from(2))
            .await
            .unwrap();
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(op_hash))
                .await
                .is_some(),
            "split-fork votes must not reach threshold, so the op stays submitted"
        );
        assert!(
            dbtx.to_ref_nc().get_value(&PoolStateKey).await.is_none(),
            "no settlement may occur without a matching-hash quorum"
        );

        // Peer 2 switches to fork A: now three votes fully agree -> applied.
        module
            .process_consensus_item(&mut dbtx.to_ref_nc(), vote(hash_fork_a), PeerId::from(2))
            .await
            .unwrap();
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(op_hash))
                .await
                .is_none(),
            "a matching-hash quorum must apply and clear the submitted op"
        );
        assert_eq!(
            dbtx.to_ref_nc()
                .get_value(&PoolStateKey)
                .await
                .expect("pool credited on successful sweep")
                .balance,
            amount
        );
    }

    /// **Security finding 15 op facet (Task 5.1).** When the bundler claims an
    /// op succeeded but the authoritative `EntryPoint` `UserOperationEvent`
    /// log is absent, `get_user_op_receipt` returns `None` and the submitter
    /// must propose NOTHING for it -- while a genuinely log-confirmed op
    /// alongside it is still proposed (proving the task is live).
    #[tokio::test(flavor = "multi_thread")]
    async fn entrypoint_log_mismatch_rejects_receipt() {
        let good_source = EvmAddress([0x71; 20]);
        let good_hash = [0x72u8; 32];
        let mismatch_source = EvmAddress([0x73; 20]);
        let mismatch_hash = [0x74u8; 32];

        let evm_rpc = MockEvmRpc::default();
        // Positive control: a genuinely EntryPoint-log-confirmed receipt.
        evm_rpc.set_user_op_receipt(
            good_hash,
            fedimint_usdt_common::user_op::UserOpReceipt {
                success: true,
                block: 10,
                block_hash: [0x88; 32],
                actual_gas_cost_wei: UsdtAmount(0),
            },
        );
        // Bundler claims success, but no confirming EntryPoint log -> None.
        evm_rpc.set_bundler_success_without_entrypoint_log(mismatch_hash);

        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );
        {
            let mut dbtx = db.begin_transaction().await;
            for (hash, source) in [(good_hash, good_source), (mismatch_hash, mismatch_source)] {
                dbtx.insert_new_entry(
                    &SubmittedUserOpKey(hash),
                    &SubmittedUserOp {
                        signed: fedimint_usdt_common::user_op::SignedUserOp {
                            unsigned: real_deploy_and_sweep_op_for_test(
                                source,
                                UsdtAmount(500_000),
                            ),
                            signature: vec![0xcc; 65],
                        },
                        purpose: UserOpPurpose::DeployAndSweep { source },
                        submitted_block: 1,
                        superseded: false,
                    },
                )
                .await;
            }
            dbtx.commit_tx().await;
        }

        let num_peers = (0..4u16)
            .map(PeerId::from)
            .collect::<Vec<_>>()
            .to_num_peers();
        seed_block_count_votes(&db, 4, 100).await; // well past any depth gate

        let proposals = Arc::new(Mutex::new(Vec::new()));
        let task_group = TaskGroup::new();
        Usdt::spawn_user_op_submitter(
            &task_group,
            UserOpSubmitterHandles {
                db: db.clone(),
                evm_rpc: evm_rpc.into_dyn(),
                user_op_confirmed_proposals: proposals.clone(),
                confirmation_depth: 6,
                num_peers,
            },
        );

        // Wait for the positive control to be proposed (proves the task ran).
        let deadline = fedimint_core::time::now() + Duration::from_secs(10);
        loop {
            let has_good = proposals
                .lock()
                .expect("not poisoned")
                .iter()
                .any(|p: &UserOpConfirmedProposal| p.op_hash == good_hash);
            if has_good {
                break;
            }
            assert!(
                fedimint_core::time::now() < deadline,
                "the log-confirmed positive-control op must be proposed"
            );
            fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
        }

        // The mismatch op (bundler-only, no EntryPoint log) must never be
        // proposed.
        assert!(
            proposals
                .lock()
                .expect("not poisoned")
                .iter()
                .all(|p: &UserOpConfirmedProposal| p.op_hash != mismatch_hash),
            "an op whose EntryPoint log is absent must not be confirmed on the bundler's word"
        );
    }

    /// **Security finding 12 (Task 5.1).** A sub-threshold set of deposit
    /// observation votes that ages out of the freshness window can no longer
    /// be completed to a threshold credit by a late (Byzantine or delayed)
    /// duplicate -- the deep-reorg stale-vote scenario.
    #[tokio::test]
    async fn stale_deposit_vote_past_max_age_cannot_complete() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();
        let depth = module.cfg.consensus.confirmation_depth;
        let claim_pk = test_pubkey(0x88);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );
        let obs = DepositObservation {
            account,
            balance: UsdtAmount(2_000_000),
            block: 50,
            block_hash: [0x9A; 32],
            claim_pk,
        };

        // In-window: two honest votes stored, below the 3-of-4 threshold.
        seed_block_count_votes(db, 4, 50 + depth).await;
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1] {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::Deposit(obs.clone()),
                    PeerId::from(p),
                )
                .await
                .unwrap();
        }
        dbtx.commit_tx().await;
        assert!(
            db.begin_transaction_nc()
                .await
                .get_value(&DepositRecordKey(account))
                .await
                .is_none(),
            "two of three votes must not credit"
        );

        // A deep reorg's worth of blocks pass: advance consensus far past the
        // freshness window (age = depth + 200 > depth + DEPOSIT_VOTE_MAX_AGE_BLOCKS).
        seed_block_count_votes(db, 4, 50 + depth + DEPOSIT_VOTE_MAX_AGE_BLOCKS + 100).await;

        // The late (would-be threshold-completing) third vote must be rejected
        // as too old and credit nothing.
        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::Deposit(obs.clone()),
                PeerId::from(2),
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("too old"),
            "unexpected error: {err}"
        );
        assert!(
            dbtx.to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .is_none(),
            "a vote aged out of the freshness window must never complete a threshold credit"
        );
    }

    /// **Security finding 12 (Task 5.1).** Deposit observations that agree on
    /// account/balance/height but carry different `block_hash`es (two forks)
    /// must not aggregate; only a matching-hash quorum credits.
    #[tokio::test]
    async fn deposit_observation_carries_and_requires_block_hash() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();
        let depth = module.cfg.consensus.confirmation_depth;
        let claim_pk = test_pubkey(0x99);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );
        seed_block_count_votes(db, 4, 50 + depth).await;

        let obs = |block_hash: [u8; 32]| DepositObservation {
            account,
            balance: UsdtAmount(2_000_000),
            block: 50,
            block_hash,
            claim_pk,
        };
        let fork_a = [0xAAu8; 32];
        let fork_b = [0xBBu8; 32];

        let mut dbtx = db.begin_transaction().await;
        // 2 votes on fork A + 1 on fork B at the same height: no full-field
        // quorum, so no credit.
        for p in [0u16, 1] {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::Deposit(obs(fork_a)),
                    PeerId::from(p),
                )
                .await
                .unwrap();
        }
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::Deposit(obs(fork_b)),
                PeerId::from(2),
            )
            .await
            .unwrap();
        assert!(
            dbtx.to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .is_none(),
            "different-fork observations must not aggregate to a credit"
        );

        // Peer 2 switches to fork A: three matching-hash votes -> credited.
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::Deposit(obs(fork_a)),
                PeerId::from(2),
            )
            .await
            .unwrap();
        assert_eq!(
            dbtx.to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("matching-hash quorum credits")
                .credited,
            UsdtAmount(2_000_000)
        );
    }

    // ---------------------------------------------------------------------
    // Phase 5 Task 5.2 (security finding 03): submitted-UserOp timeout +
    // reprice/replacement, RBF-nonce-safe.
    // ---------------------------------------------------------------------

    /// A `Withdraw`-purpose `SubmittedUserOp` covering `outpoints`, whose op
    /// decodes to `total`, with explicitly-set fee fields (so the reprice
    /// bump/ceiling can be exercised precisely) and `submitted_block`.
    fn submitted_withdraw_op(
        outpoints: Vec<OutPoint>,
        total: UsdtAmount,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        submitted_block: u64,
        superseded: bool,
    ) -> SubmittedUserOp {
        let mut op = real_withdraw_op_for_test(total);
        op.max_fee_per_gas = max_fee_per_gas;
        op.max_priority_fee_per_gas = max_priority_fee_per_gas;
        SubmittedUserOp {
            signed: fedimint_usdt_common::user_op::SignedUserOp {
                unsigned: op,
                signature: vec![0xdd; 65],
            },
            purpose: UserOpPurpose::Withdraw { outpoints },
            submitted_block,
            superseded,
        }
    }

    /// Collects every `Withdraw`-purpose `PendingUserOp` and its record.
    async fn pending_withdraw_ops(
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<([u8; 32], PendingUserOp)> {
        let pending: Vec<(PendingUserOpKey, PendingUserOp)> = dbtx
            .find_by_prefix(&PendingUserOpPrefix)
            .await
            .collect()
            .await;
        pending
            .into_iter()
            .filter(|(_, p)| matches!(p.purpose, UserOpPurpose::Withdraw { .. }))
            .map(|(PendingUserOpKey(h), p)| (h, p))
            .collect()
    }

    /// **Task 5.2, step 1.** A stuck (non-superseded) `SubmittedUserOp` past
    /// `submitted_op_timeout_blocks()` is proposed for replacement and, on
    /// apply, is REPLACED by a fresh `PendingUserOp` + signing session at the
    /// SAME `(sender, nonce)` with a fee >= 10% higher; the old op is marked
    /// `superseded` and KEPT (RBF-nonce safety).
    #[tokio::test]
    async fn underpriced_submitted_op_is_replaced_after_timeout() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let ha = [0xa1; 32];
        let out1 = test_out_point(1);
        let total = UsdtAmount(1_000_000);
        // Old op priced HIGH (100 gwei) so the >=10% bump path dominates the
        // fresh-median price and the assertion isolates the RBF rule.
        let old_fee = 100_000_000_000u128;

        // ccount strictly past the timeout (read the fn directly rather than
        // assuming the test-env value; plain `cargo test` does not set NEXTEST).
        seed_block_count_votes(db, 4, submitted_op_timeout_blocks() + 1).await;
        seed_fee_votes(db, 4, sample_fee_vote()).await; // fresh median at block 10

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out1),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([0xc1; 20]),
                    amount: total,
                    // Generous ceiling: comfortably above the repriced op's
                    // ~118.8M-unit USDT gas cost, so this replaces (not fails).
                    max_fee: UsdtAmount(300_000_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out1), &WithdrawalState::Submitted(ha))
                .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(ha),
                &submitted_withdraw_op(vec![out1], total, old_fee, 2_000_000_000, 0, false),
            )
            .await;
            dbtx.commit_tx().await;
        }

        // The timed-out op is proposed for replacement.
        let mut dbtx = db.begin_transaction().await;
        let proposal = module.consensus_proposal(&mut dbtx.to_ref_nc()).await;
        assert!(
            proposal.contains(&UsdtConsensusItem::ReplaceUserOp { op_hash: ha }),
            "consensus_proposal must propose ReplaceUserOp for the timed-out op: {proposal:?}"
        );

        // Applying it replaces the op.
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::ReplaceUserOp { op_hash: ha },
                PeerId::from(0),
            )
            .await
            .expect("ReplaceUserOp for a timed-out op must process cleanly");

        // Old op kept, now superseded.
        let old = dbtx
            .to_ref_nc()
            .get_value(&SubmittedUserOpKey(ha))
            .await
            .expect("superseded old op is KEPT for RBF-nonce safety");
        assert!(old.superseded, "old op must be marked superseded");

        // Exactly one fresh replacement PendingUserOp at the SAME (sender,
        // nonce), fee >= 10% higher.
        let mut new_ops = pending_withdraw_ops(&mut dbtx.to_ref_nc()).await;
        assert_eq!(new_ops.len(), 1, "exactly one replacement must be enqueued");
        let (new_hash, new_pending) = new_ops.pop().expect("len == 1");
        assert_ne!(new_hash, ha, "the replacement has a fresh op_hash");
        assert_eq!(new_pending.op.sender, old.signed.unsigned.sender);
        assert_eq!(new_pending.op.nonce, old.signed.unsigned.nonce);
        assert_eq!(
            new_pending.op.max_fee_per_gas, 110_000_000_000,
            "replacement fee is exactly the 10% bump over the old 100 gwei"
        );
        assert!(
            new_pending.op.max_fee_per_gas * 10 >= old_fee * 11,
            "replacement fee must be at least 10% above the old op's fee"
        );
        // Identical calldata: settlement is a pure function of purpose +
        // calldata, so either op settles identically (RBF-nonce safety).
        assert_eq!(new_pending.op.call_data, old.signed.unsigned.call_data);

        // A signing session was started for the replacement, and the covered
        // withdrawal was re-tagged to it.
        let session_id = signing_session_id(&eth_signed_message_hash(new_hash), 0);
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SigningSessionKey(session_id))
                .await
                .is_some(),
            "a signing session must be started for the replacement"
        );
        assert_eq!(
            dbtx.to_ref_nc().get_value(&WithdrawalStateKey(out1)).await,
            Some(WithdrawalState::Signing(new_hash))
        );
    }

    /// **Task 5.2, step 2.** A stuck+replaced withdrawal batch no longer
    /// wedges ALL withdrawals: once the batch confirms (via EITHER hash in the
    /// chain), its covered withdrawals settle and a later-queued withdrawal
    /// can be batched again (the global-wedge regression is gone).
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn withdrawal_batch_no_longer_wedges_all_withdrawals() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let ha = [0xa1; 32]; // old (superseded)
        let hb = [0xb2; 32]; // live replacement
        let out1 = test_out_point(1);
        let out2 = test_out_point(2); // later, still Queued
        let total = UsdtAmount(1_000_000);

        seed_fee_votes(db, 4, sample_fee_vote()).await;

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(10_000_000),
                    nonce: 5,
                },
            )
            .await;
            // The in-flight batch (chain A superseded + B live) covering out1.
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out1),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([0xc1; 20]),
                    amount: total,
                    max_fee: UsdtAmount(300_000_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out1), &WithdrawalState::Signing(hb))
                .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(ha),
                &submitted_withdraw_op(vec![out1], total, 100_000_000_000, 2_000_000_000, 0, true),
            )
            .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(hb),
                &submitted_withdraw_op(vec![out1], total, 110_000_000_000, 2_200_000_000, 8, false),
            )
            .await;
            // A later withdrawal that has been stuck in Queued behind the batch.
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out2),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([0xc2; 20]),
                    amount: UsdtAmount(500_000),
                    max_fee: UsdtAmount(300_000_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out2), &WithdrawalState::Queued)
                .await;
            dbtx.commit_tx().await;
        }

        // The replacement (B) confirms.
        let mut dbtx = db.begin_transaction().await;
        module
            .apply_user_op_confirmed(
                &mut dbtx.to_ref_nc(),
                hb,
                &UserOpConfirmedObservation {
                    success: true,
                    block: 99,
                    block_hash: [0u8; 32],
                    swept: total,
                    actual_gas_cost_wei: UsdtAmount(0),
                },
            )
            .await;

        // out1 settled; the whole chain (A too) is gone; no Withdraw op is
        // in flight any more.
        assert_eq!(
            dbtx.to_ref_nc().get_value(&WithdrawalStateKey(out1)).await,
            Some(WithdrawalState::Confirmed { block: 99 })
        );
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(ha))
                .await
                .is_none(),
            "the superseded predecessor must be purged with the chain"
        );
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(hb))
                .await
                .is_none()
        );

        // Now a later batch can be built for out2 (wedge gone). Commit the
        // confirmation, advance past the interval, and trigger.
        dbtx.commit_tx().await;
        seed_block_count_votes(db, 4, batch_interval_blocks() + 1).await;
        let mut dbtx = db.begin_transaction().await;
        module
            .maybe_trigger_withdrawal_batch(&mut dbtx.to_ref_nc())
            .await;
        let new_ops = pending_withdraw_ops(&mut dbtx.to_ref_nc()).await;
        assert_eq!(
            new_ops.len(),
            1,
            "the previously-wedged out2 must now batch: {new_ops:?}"
        );
        let UserOpPurpose::Withdraw { outpoints } = &new_ops[0].1.purpose else {
            panic!("must be a Withdraw op");
        };
        assert_eq!(outpoints, &vec![out2]);
    }

    /// **Task 5.2, step 3.** When the repriced batch's gas would exceed the
    /// covered withdrawals' committed `max_fee` ceiling, the op is NOT
    /// replaced: every covered withdrawal becomes terminal `Failed`, its
    /// `UnclaimedWithdrawal` is KEPT (for the Phase 6.1 refund), and the stuck
    /// `SubmittedUserOp` is removed.
    #[tokio::test]
    async fn reprice_over_user_max_fee_marks_withdrawals_failed() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let ha = [0xa1; 32];
        let out1 = test_out_point(1);
        let total = UsdtAmount(1_000_000);

        seed_block_count_votes(db, 4, submitted_op_timeout_blocks() + 1).await;
        seed_fee_votes(db, 4, sample_fee_vote()).await;

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out1),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([0xc1; 20]),
                    amount: total,
                    // LOW ceiling: below the repriced op's ~118.8M-unit gas
                    // cost, so the reprice cannot proceed.
                    max_fee: UsdtAmount(50_000_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out1), &WithdrawalState::Submitted(ha))
                .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(ha),
                &submitted_withdraw_op(vec![out1], total, 100_000_000_000, 2_000_000_000, 0, false),
            )
            .await;
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::ReplaceUserOp { op_hash: ha },
                PeerId::from(0),
            )
            .await
            .expect("over-ceiling reprice is a state change (Failed), returns Ok");

        assert_eq!(
            dbtx.to_ref_nc().get_value(&WithdrawalStateKey(out1)).await,
            Some(WithdrawalState::Failed {
                reason: "gas exceeds committed max_fee".to_string()
            })
        );
        // Security finding 09: the over-ceiling terminal failure replaces the
        // UnclaimedWithdrawal with a reissued-e-cash Refund.
        assert!(
            dbtx.to_ref_nc()
                .get_value(&UnclaimedWithdrawalKey(out1))
                .await
                .is_none(),
            "UnclaimedWithdrawal must be replaced by a Refund"
        );
        assert!(
            dbtx.to_ref_nc().get_value(&RefundKey(out1)).await.is_some(),
            "the terminally-failed withdrawal must have a reissued-e-cash Refund"
        );
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(ha))
                .await
                .is_none(),
            "the stuck op must be removed"
        );
        assert!(
            pending_withdraw_ops(&mut dbtx.to_ref_nc()).await.is_empty(),
            "no replacement is enqueued when over the ceiling"
        );
    }

    /// **Task 5.2, step 3 (regression, security finding 03).** When the op that
    /// goes over the ceiling is ITSELF a replacement (a superseded predecessor
    /// `A` shares its `(sender, nonce)`), the over-ceiling handling must tear
    /// down the WHOLE chain -- not just the current op. Otherwise the orphaned
    /// `A` (which `withdraw_batch_in_flight` counts, ignoring `superseded`)
    /// wedges every future withdrawal batch permanently. Asserts: after the
    /// over-ceiling apply NO Submitted `Withdraw` op remains at that nonce,
    /// `withdraw_batch_in_flight` is `false`, and a later `Queued` withdrawal
    /// can batch again. This is the exact gap the plain over-ceiling test
    /// (`reprice_over_user_max_fee_marks_withdrawals_failed`) does not cover.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn over_ceiling_reprice_of_a_replacement_purges_the_whole_chain() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let ha = [0xa1; 32]; // superseded predecessor (orphan risk)
        let hb = [0xb2; 32]; // current op, over-ceiling on reprice
        let out1 = test_out_point(1); // covered by the (A->B) batch
        let out2 = test_out_point(2); // later, still Queued behind the wedge
        let total = UsdtAmount(1_000_000);

        // High enough for BOTH the ReplaceUserOp timeout gate and the later
        // withdrawal-batch interval, regardless of their relative sizes.
        seed_block_count_votes(
            db,
            4,
            batch_interval_blocks() + submitted_op_timeout_blocks() + 1,
        )
        .await;
        seed_fee_votes(db, 4, sample_fee_vote()).await;

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(10_000_000),
                    nonce: 5,
                },
            )
            .await;
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out1),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([0xc1; 20]),
                    amount: total,
                    // LOW ceiling: below the repriced op's gas cost, so B goes
                    // over the ceiling.
                    max_fee: UsdtAmount(50_000_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out1), &WithdrawalState::Signing(hb))
                .await;
            // A (superseded) and B (live, the current op) share the SAME
            // (sender, nonce) -- a real replacement chain.
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(ha),
                &submitted_withdraw_op(vec![out1], total, 100_000_000_000, 2_000_000_000, 0, true),
            )
            .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(hb),
                &submitted_withdraw_op(vec![out1], total, 110_000_000_000, 2_200_000_000, 0, false),
            )
            .await;
            // A later withdrawal stuck Queued behind the batch.
            dbtx.insert_new_entry(
                &UnclaimedWithdrawalKey(out2),
                &UsdtWithdrawalV0 {
                    recipient: EvmAddress([0xc2; 20]),
                    amount: UsdtAmount(500_000),
                    max_fee: UsdtAmount(300_000_000),
                    requested_block: 0,
                    refund_pubkey: sample_claim_pk(),
                },
            )
            .await;
            dbtx.insert_new_entry(&WithdrawalStateKey(out2), &WithdrawalState::Queued)
                .await;
            dbtx.commit_tx().await;
        }

        // Reprice the current op B -- goes over the ceiling.
        let mut dbtx = db.begin_transaction().await;
        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::ReplaceUserOp { op_hash: hb },
                PeerId::from(0),
            )
            .await
            .expect("over-ceiling reprice is a state change (Failed), returns Ok");

        // out1 is terminal-Failed; its UnclaimedWithdrawal is replaced by a
        // reissued-e-cash Refund (security finding 09).
        assert_eq!(
            dbtx.to_ref_nc().get_value(&WithdrawalStateKey(out1)).await,
            Some(WithdrawalState::Failed {
                reason: "gas exceeds committed max_fee".to_string()
            })
        );
        assert!(
            dbtx.to_ref_nc()
                .get_value(&UnclaimedWithdrawalKey(out1))
                .await
                .is_none(),
            "UnclaimedWithdrawal must be replaced by a Refund"
        );
        assert!(
            dbtx.to_ref_nc().get_value(&RefundKey(out1)).await.is_some(),
            "the terminally-failed withdrawal must have a reissued-e-cash Refund"
        );

        // The WHOLE chain is gone -- both B (current) AND the superseded
        // predecessor A. This is the fix: without the chain purge, A would
        // linger and wedge every future batch.
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(hb))
                .await
                .is_none(),
            "the current op B must be removed"
        );
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(ha))
                .await
                .is_none(),
            "the superseded predecessor A must be purged with the whole chain"
        );
        assert!(
            !module.withdraw_batch_in_flight(&mut dbtx.to_ref_nc()).await,
            "no Withdraw op is in flight once the chain is purged"
        );

        // The previously-wedged out2 can now batch again.
        dbtx.commit_tx().await;
        let mut dbtx = db.begin_transaction().await;
        module
            .maybe_trigger_withdrawal_batch(&mut dbtx.to_ref_nc())
            .await;
        let new_ops = pending_withdraw_ops(&mut dbtx.to_ref_nc()).await;
        assert_eq!(
            new_ops.len(),
            1,
            "the previously-wedged out2 must now batch: {new_ops:?}"
        );
        let UserOpPurpose::Withdraw { outpoints } = &new_ops[0].1.purpose else {
            panic!("must be a Withdraw op");
        };
        assert_eq!(
            outpoints,
            &vec![out2],
            "only the still-Queued out2 batches; the Failed out1 does not"
        );
    }

    /// **Task 5.2, step 4 (the crux).** A late confirmation of the OLD op (A)
    /// after it was replaced by B: A settles the withdrawals EXACTLY ONCE and
    /// B's `SubmittedUserOp` (same nonce) is removed with the chain; a
    /// subsequent confirmation vote for B is rejected (its `SubmittedUserOp`
    /// is gone), so there is no double-settle.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn late_old_op_confirmation_settles_and_cleans_replacement() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        let ha = [0xa1; 32]; // old, superseded, but it is the one that landed
        let hb = [0xb2; 32]; // replacement, never lands (nonce consumed by A)
        let out1 = test_out_point(1);
        let out2 = test_out_point(2);
        let outpoints = vec![out1, out2];
        let total = UsdtAmount(3_000_000);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &PoolStateKey,
                &PoolState {
                    account: module.pool_account(),
                    balance: UsdtAmount(5_000_000),
                    nonce: 7,
                },
            )
            .await;
            for &o in &outpoints {
                dbtx.insert_new_entry(
                    &UnclaimedWithdrawalKey(o),
                    &UsdtWithdrawalV0 {
                        recipient: EvmAddress([0xc1; 20]),
                        amount: UsdtAmount(1_500_000),
                        max_fee: UsdtAmount(300_000_000),
                        requested_block: 0,
                        refund_pubkey: sample_claim_pk(),
                    },
                )
                .await;
                dbtx.insert_new_entry(&WithdrawalStateKey(o), &WithdrawalState::Signing(hb))
                    .await;
            }
            // A (superseded) and B (live) share the SAME (sender, nonce) and
            // identical calldata (both decode to `total`).
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(ha),
                &submitted_withdraw_op(
                    outpoints.clone(),
                    total,
                    100_000_000_000,
                    2_000_000_000,
                    0,
                    true,
                ),
            )
            .await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(hb),
                &submitted_withdraw_op(
                    outpoints.clone(),
                    total,
                    110_000_000_000,
                    2_200_000_000,
                    8,
                    false,
                ),
            )
            .await;
            dbtx.commit_tx().await;
        }

        // A late UserOpConfirmed for the OLD op A reaches threshold.
        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash: ha,
            success: true,
            block: 99,
            block_hash: [0u8; 32],
            swept: total,
            actual_gas_cost_wei: UsdtAmount(0),
        };
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(&mut dbtx.to_ref_nc(), obs.clone(), PeerId::from(p))
                .await
                .expect("a UserOpConfirmed vote for the (existing) old op A processes cleanly");
        }

        // Withdrawals settled exactly once; pool debited once.
        for &o in &outpoints {
            assert_eq!(
                dbtx.to_ref_nc().get_value(&WithdrawalStateKey(o)).await,
                Some(WithdrawalState::Confirmed { block: 99 })
            );
            assert!(
                dbtx.to_ref_nc()
                    .get_value(&UnclaimedWithdrawalKey(o))
                    .await
                    .is_none()
            );
        }
        let pool = dbtx
            .to_ref_nc()
            .get_value(&PoolStateKey)
            .await
            .expect("PoolState present");
        assert_eq!(pool.balance, UsdtAmount(5_000_000 - total.0));
        assert_eq!(pool.nonce, 8);

        // Both A and B are gone -- the whole (sender, nonce) chain was purged.
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(ha))
                .await
                .is_none()
        );
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(hb))
                .await
                .is_none(),
            "the replacement B must be purged with the confirmed chain"
        );

        // A subsequent confirmation vote for B is rejected (no SubmittedUserOp
        // backs it), so there is NO double-settle.
        let err = module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::UserOpConfirmed {
                    op_hash: hb,
                    success: true,
                    block: 99,
                    block_hash: [0u8; 32],
                    swept: total,
                    actual_gas_cost_wei: UsdtAmount(0),
                },
                PeerId::from(0),
            )
            .await
            .expect_err("a confirm vote for the purged replacement B must be rejected");
        assert!(
            err.to_string().contains("never submitted"),
            "rejection must be the Task 2.2 existence check: {err}"
        );
        let pool_after = dbtx
            .to_ref_nc()
            .get_value(&PoolStateKey)
            .await
            .expect("PoolState present");
        assert_eq!(
            pool_after.balance,
            UsdtAmount(5_000_000 - total.0),
            "the pool must not be double-debited"
        );
    }

    /// **Task 5.2, step 5.** A `DeployAndSweep` reprice whose bumped fee would
    /// exceed the config gas ceiling is NOT replaced: the op is left as-is
    /// (funds are safe on-chain in the deposit account -- no refund concept),
    /// and the item is non-state-changing (`Err`).
    #[tokio::test]
    async fn sweep_reprice_over_ceiling_leaves_op_stuck_no_refund() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();

        let ha = [0xa1; 32];
        let source = EvmAddress([0x51; 20]);
        // 199 gwei bumps to 218.9 gwei > the 200 gwei ceiling.
        let old_fee = 199_000_000_000u128;

        seed_block_count_votes(db, 4, submitted_op_timeout_blocks() + 1).await;
        seed_fee_votes(db, 4, sample_fee_vote()).await;

        {
            let mut op = real_deploy_and_sweep_op_for_test(source, UsdtAmount(1_000_000));
            op.max_fee_per_gas = old_fee;
            op.max_priority_fee_per_gas = 5_000_000_000;
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &SubmittedUserOpKey(ha),
                &SubmittedUserOp {
                    signed: fedimint_usdt_common::user_op::SignedUserOp {
                        unsigned: op,
                        signature: vec![0xcc; 65],
                    },
                    purpose: UserOpPurpose::DeployAndSweep { source },
                    submitted_block: 0,
                    superseded: false,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::ReplaceUserOp { op_hash: ha },
                PeerId::from(0),
            )
            .await
            .expect_err("an over-ceiling sweep reprice is non-state-changing (Err)");
        assert!(
            err.to_string().contains("gas ceiling"),
            "rejection must be the sweep gas-ceiling guard: {err}"
        );

        // Op left as-is: still present, still NOT superseded, no replacement.
        let still = dbtx
            .to_ref_nc()
            .get_value(&SubmittedUserOpKey(ha))
            .await
            .expect("the stuck sweep op is left in place");
        assert!(!still.superseded, "the op must not be marked superseded");
        assert_eq!(
            dbtx.to_ref_nc()
                .find_by_prefix(&PendingUserOpPrefix)
                .await
                .count()
                .await,
            0,
            "no replacement is enqueued"
        );
    }

    /// **Task 5.2, migration.** `migrate_db_v2` REWRITES (does not drop) each
    /// pre-0.6 `SubmittedUserOp` row by appending the default `superseded:
    /// false`, so an in-flight signed op survives the upgrade and decodes with
    /// the field defaulted. Verifies the byte-append the migration performs at
    /// the encoding level (the migration itself is a `raw_insert_bytes` of
    /// exactly this transform).
    #[tokio::test]
    async fn migrate_v2_appends_superseded_false_and_round_trips() {
        use fedimint_core::encoding::{Decodable, Encodable};

        // The pre-0.6 row shape: the same struct MINUS the trailing
        // `superseded` field. Encoding a struct is its fields concatenated in
        // order, so the old bytes are exactly the new encoding without the
        // final bool.
        #[derive(Encodable)]
        struct OldSubmittedUserOp {
            signed: fedimint_usdt_common::user_op::SignedUserOp,
            purpose: UserOpPurpose,
            submitted_block: u64,
        }

        let signed = fedimint_usdt_common::user_op::SignedUserOp {
            unsigned: real_withdraw_op_for_test(UsdtAmount(1_234_567)),
            signature: vec![0x7a; 65],
        };
        let old = OldSubmittedUserOp {
            signed: signed.clone(),
            purpose: UserOpPurpose::Withdraw {
                outpoints: vec![test_out_point(3)],
            },
            submitted_block: 42,
        };

        let mut old_bytes = old.consensus_encode_to_vec();
        // The exact transform `migrate_db_v2` applies to each raw value.
        old_bytes.push(0u8);

        let decoded = SubmittedUserOp::consensus_decode_whole(
            &old_bytes,
            &fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        )
        .expect("a migrated (byte-appended) row must decode as a 0.6 SubmittedUserOp");

        assert_eq!(decoded.signed, signed);
        assert_eq!(decoded.submitted_block, 42);
        assert!(
            !decoded.superseded,
            "a migrated pre-0.6 row must default superseded to false"
        );
    }
}

/// Acceptance test for real distributed key generation (`distributed_gen`):
/// runs the actual N-party cggmp21 keygen + aux-info-gen over a hermetic
/// fake config-gen peer channel, then proves the resulting key shares are
/// genuinely usable by running one 3-of-4 threshold signature and verifying
/// it against the group key with the independent `secp256k1` crate.
#[cfg(test)]
mod distributed_gen_tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use cggmp21::ExecutionId;
    use fedimint_core::bitcoin::Network;
    use fedimint_core::{NumPeers, NumPeersExt as _, PeerId};
    use fedimint_threshold_ecdsa::Curve;
    use fedimint_threshold_ecdsa::transport::{
        EncryptedRoundCodec, drive_over_exchange, in_memory_mesh,
    };
    use rand::rngs::OsRng;
    use tokio::sync::Notify;

    use super::*;

    const N: u16 = 4;
    const T: u16 = 3;

    /// Shared state for [`FakeDkgNetwork`]: one entry per logical round
    /// (keyed by a per-peer, monotonically increasing round counter), each
    /// holding the payload every peer has submitted so far for that round.
    /// A round is complete once all `total` peers have submitted.
    struct DkgCoordinator {
        rounds: std::sync::Mutex<HashMap<u64, BTreeMap<PeerId, Vec<u8>>>>,
        notify: Notify,
        total: usize,
    }

    /// A hermetic, in-memory [`PeerHandleOps`] impl for N peers sharing one
    /// [`DkgCoordinator`]: `exchange_bytes` is an all-to-all round barrier —
    /// it submits this peer's payload for "its next round" and blocks until
    /// every peer has submitted for that same round, then returns all of
    /// them. Each `FakeDkgNetwork` tracks its own round counter, so
    /// `distributed_gen`'s sequential keygen-then-aux-gen round series (each
    /// itself many rounds) is serviced correctly without any explicit round
    /// numbering in the `exchange_bytes` API itself.
    struct FakeDkgNetwork {
        coordinator: Arc<DkgCoordinator>,
        my_peer: PeerId,
        num_peers: NumPeers,
        next_round: AtomicU64,
    }

    #[async_trait::async_trait]
    impl PeerHandleOps for FakeDkgNetwork {
        fn num_peers(&self) -> NumPeers {
            self.num_peers
        }

        async fn run_dkg_g1(
            &self,
        ) -> anyhow::Result<(Vec<bls12_381::G1Projective>, bls12_381::Scalar)> {
            unimplemented!("usdt DKG does not use run_dkg_g1")
        }

        async fn run_dkg_g2(
            &self,
        ) -> anyhow::Result<(Vec<bls12_381::G2Projective>, bls12_381::Scalar)> {
            unimplemented!("usdt DKG does not use run_dkg_g2")
        }

        async fn exchange_bytes(&self, data: Vec<u8>) -> anyhow::Result<BTreeMap<PeerId, Vec<u8>>> {
            let round = self.next_round.fetch_add(1, Ordering::SeqCst);

            {
                let mut rounds = self
                    .coordinator
                    .rounds
                    .lock()
                    .expect("coordinator mutex poisoned");
                let entry = rounds.entry(round).or_default();
                entry.insert(self.my_peer, data);
                if entry.len() == self.coordinator.total {
                    // Every peer has submitted for this round: wake everyone
                    // (including peers that haven't called `notified()` yet;
                    // see the loop below for why that is still race-free).
                    self.coordinator.notify.notify_waiters();
                }
            }

            loop {
                // Register as a waiter *before* checking the round's
                // completion, using `enable()` so a `notify_waiters()` that
                // races with our check (fired by another peer between our
                // check and our `.await` below) is not missed. Without this,
                // a peer could check the map (not yet complete), then miss
                // the one-shot `notify_waiters()` fired immediately after by
                // the peer that completes the round, and hang forever.
                let notified = self.coordinator.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();

                {
                    let rounds = self
                        .coordinator
                        .rounds
                        .lock()
                        .expect("coordinator mutex poisoned");
                    if let Some(entry) = rounds.get(&round)
                        && entry.len() == self.coordinator.total
                    {
                        return Ok(entry.clone());
                    }
                }

                notified.await;
            }
        }
    }

    /// Runs `UsdtInit::distributed_gen` concurrently for all of `peer_ids`
    /// over a shared, hermetic [`FakeDkgNetwork`] coordinator, returning
    /// every guardian's typed config.
    async fn run_distributed_gen_for_all_peers(peer_ids: &[PeerId]) -> Vec<UsdtConfig> {
        let coordinator = Arc::new(DkgCoordinator {
            rounds: std::sync::Mutex::new(HashMap::new()),
            notify: Notify::new(),
            total: peer_ids.len(),
        });
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };

        let mut tasks = Vec::with_capacity(peer_ids.len());
        for &peer in peer_ids {
            let net = FakeDkgNetwork {
                coordinator: coordinator.clone(),
                my_peer: peer,
                num_peers: peer_ids.to_num_peers(),
                next_round: AtomicU64::new(0),
            };
            // This module has no other way to obtain N concurrent, `Send`
            // `distributed_gen` futures than spawning them onto the
            // multi-thread runtime: each one blocks (via `PeerHandleOps`)
            // on the others' progress, so they cannot be `.await`ed
            // sequentially on one task.
            // nosemgrep: ban-tokio-spawn
            tasks.push(tokio::spawn(async move {
                UsdtInit::default()
                    .distributed_gen(&net, &args, &fedimint_usdt_common::UsdtGenParams::default())
                    .await
            }));
        }

        let mut configs = Vec::with_capacity(peer_ids.len());
        for t in tasks {
            configs.push(
                t.await
                    .expect("distributed_gen task must not panic")
                    .expect("distributed_gen must succeed")
                    .to_typed::<UsdtConfig>()
                    .expect("config was just generated by the same distributed_gen"),
            );
        }
        configs
    }

    /// Asserts every guardian's config agrees on the group key/threshold,
    /// each guardian's own key share aggregates to that group key, and each
    /// config passes `validate_config` under its own `PeerId`.
    fn assert_configs_consistent_and_valid(peer_ids: &[PeerId], configs: &[UsdtConfig]) {
        let group_public_key = configs[0].consensus.group_public_key;
        for cfg in configs {
            assert_eq!(
                cfg.consensus.group_public_key, group_public_key,
                "all guardians must agree on the DKG group public key"
            );
            assert_eq!(cfg.consensus.threshold, T);
            assert_eq!(
                fedimint_threshold_ecdsa::group_public_key(&cfg.private.key_share)
                    .expect("valid key share"),
                group_public_key,
                "each guardian's own key share must aggregate to the group key"
            );
        }

        for peer in peer_ids {
            UsdtInit::default()
                .validate_config(peer, configs[peer.to_usize()].clone().to_erased())
                .expect("distributed_gen output must validate for every guardian");
        }
    }

    /// Runs a real `T`-of-`N` threshold signature over `shares` (a fresh
    /// mesh + fresh MPC-transport encryption keys for the signing
    /// sub-protocol, independent of the DKG's), returning the raw cggmp21
    /// signatures.
    ///
    /// cggmp21's synchronous signing state machine is `!Send` (like
    /// keygen/aux-gen; see `threshold-ecdsa`'s
    /// `keygen_and_signing_over_exchange_transport` test), so the signer
    /// tasks are scheduled cooperatively on one thread via `LocalSet`
    /// instead of `tokio::spawn`.
    async fn run_threshold_signing(
        shares: &[fedimint_threshold_ecdsa::KeyShare],
        signers: [u16; T as usize],
        digest: [u8; 32],
    ) -> Vec<cggmp21::Signature<Curve>> {
        let secp = secp256k1::Secp256k1::new();
        let signer_secret_keys: Vec<secp256k1::SecretKey> = (0..signers.len())
            .map(|i| {
                let mut bytes = [7u8; 32];
                bytes[31] = u8::try_from(i + 1).expect("fewer than 256 signers in this test");
                secp256k1::SecretKey::from_slice(&bytes).expect("valid scalar")
            })
            .collect();
        let signer_public_keys: Vec<secp256k1::PublicKey> = signer_secret_keys
            .iter()
            .map(|sk| sk.public_key(&secp))
            .collect();

        let data = cggmp21::DataToSign::from_scalar(
            cggmp21::generic_ec::Scalar::from_be_bytes_mod_order(digest),
        );
        let eid_signing = ExecutionId::new(b"usdt-server-distributed-gen-test-signing");

        let local = tokio::task::LocalSet::new();
        local
            .run_until(async {
                let meshes = in_memory_mesh(T);
                let mut handles = Vec::with_capacity(usize::from(T));
                for (pos, mut mesh) in meshes.into_iter().enumerate() {
                    let pos = u16::try_from(pos).expect("T fits in u16");
                    let keygen_index = signers[usize::from(pos)];
                    let codec = EncryptedRoundCodec::new(
                        pos,
                        signer_secret_keys[usize::from(pos)],
                        signer_public_keys.clone(),
                        eid_signing.as_bytes().to_vec(),
                    );
                    let share = shares[usize::from(keygen_index)].clone();
                    handles.push(tokio::task::spawn_local(async move {
                        let mut rng = OsRng;
                        let sm = cggmp21::signing(eid_signing, pos, &signers, &share)
                            .sign_sync(&mut rng, data);
                        drive_over_exchange(sm, &codec, &mut mesh).await
                    }));
                }
                let mut signatures = Vec::with_capacity(usize::from(T));
                for h in handles {
                    signatures.push(
                        h.await
                            .expect("signer task must not panic")
                            .expect("driving signing over the mesh")
                            .expect("cggmp21 signing"),
                    );
                }
                signatures
            })
            .await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn distributed_gen_produces_working_threshold_signing_key() {
        let peer_ids: Vec<PeerId> = (0..N).map(PeerId::from).collect();

        let configs = run_distributed_gen_for_all_peers(&peer_ids).await;
        assert_configs_consistent_and_valid(&peer_ids, &configs);
        let group_public_key = configs[0].consensus.group_public_key;

        // Strongest possible acceptance: prove the DKG output is genuine
        // signing material by running a real 3-of-4 threshold signature over
        // the shares and verifying it against the group key.
        let shares: Vec<fedimint_threshold_ecdsa::KeyShare> = configs
            .iter()
            .map(|cfg| cfg.private.key_share.clone())
            .collect();
        let digest: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"usdt distributed_gen acceptance test").into()
        };
        let signatures = run_threshold_signing(&shares, [0, 1, 3], digest).await;

        // Independent verification: convert the raw (r, s) scalars to the
        // workspace's canonical secp256k1 signature type (same compact +
        // normalize_s conversion `fedimint_threshold_ecdsa::run_signing`
        // uses internally) and check against the group key.
        let msg = secp256k1::Message::from_digest(digest);
        let verifier = secp256k1::Secp256k1::verification_only();
        for sig in &signatures {
            let mut compact = [0u8; 64];
            compact[..32].copy_from_slice(&sig.r.to_be_bytes());
            compact[32..].copy_from_slice(&sig.s.to_be_bytes());
            let mut ecdsa_sig = secp256k1::ecdsa::Signature::from_compact(&compact)
                .expect("cggmp21 produced a valid compact signature");
            ecdsa_sig.normalize_s();
            verifier
                .verify_ecdsa(&msg, &ecdsa_sig, &group_public_key)
                .expect(
                    "signature produced from the DKG-generated shares must verify against the DKG group key",
                );
        }
    }
}
