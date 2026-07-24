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
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::envs::{
    FM_ENABLE_MODULE_USDT_ENV, FM_USDT_ACCOUNT_FACTORY_ENV,
    FM_USDT_BROADCASTER_MIN_BALANCE_WEI_ENV, FM_USDT_BROADCASTER_PRIVATE_KEY_ENV,
    FM_USDT_CHAIN_ID_ENV, FM_USDT_CONFIRMATION_DEPTH_ENV, FM_USDT_CONTRACT_ENV,
    FM_USDT_ENTRY_POINT_ENV, FM_USDT_ETH_USD_PRICE_FEED_ENV, FM_USDT_EVM_RPC_API_KEY_ENV,
    FM_USDT_EVM_RPC_URL_ENV, FM_USDT_SIMPLE_ACCOUNT_IMPL_ENV,
    FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV, is_env_var_set_opt, is_running_in_test_env,
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
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use fedimint_threshold_ecdsa::{convert_signature, group_public_key};
pub use fedimint_usdt_common as common;
use fedimint_usdt_common::config::UsdtClientConfig;
use fedimint_usdt_common::endpoint_constants::{
    CHECK_DEPOSIT_ENDPOINT, DEPOSIT_FEE_QUOTE_ENDPOINT, DEPOSIT_STATUS_ENDPOINT,
    GROUP_PUBLIC_KEY_ENDPOINT, POOL_STATE_ENDPOINT, USDT_STATUS_ENDPOINT, USEROP_STATUS_ENDPOINT,
    WITHDRAW_FEE_QUOTE_ENDPOINT, WITHDRAWAL_STATUS_ENDPOINT,
};
use fedimint_usdt_common::user_op::{SignedUserOp, eth_signed_message_hash, user_op_hash};
use fedimint_usdt_common::{
    BootstrapObservation, BootstrapState, CheckDepositRequest, CheckDepositResponse,
    DepositFeeQuoteRequest, DepositFeeQuoteResponse, DepositObservation, DepositStatusRequest,
    DepositStatusResponse, FeeVote, MAX_MPC_CHUNKS, MAX_MPC_ROUND_BYTES, MAX_PENDING_CHECKS,
    MODULE_CONSENSUS_VERSION, MPC_ROUND_CHUNK_SIZE, MpcRoundItem, PoolStateResponse,
    SigningSessionId, StatusResponse, USDT_UNIT, UsdtAmount, UsdtCommonInit, UsdtConsensusItem,
    UsdtGenParams, UsdtInput, UsdtInputError, UsdtModuleTypes, UsdtOutput, UsdtOutputError,
    UsdtOutputOutcome, UserOpStatus, UserOpStatusRequest, UserOpStatusResponse,
    WithdrawFeeQuoteRequest, WithdrawFeeQuoteResponse, WithdrawalStatus, WithdrawalStatusRequest,
    WithdrawalStatusResponse, deposit_fee_quote, deposit_salt, derive_deposit_account,
    derive_pool_account, evm_address, pool_salt, signing_session_id, usdt_amount,
    validate_usdt_params, withdrawal_fee_quote,
};
use futures::StreamExt as _;
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use tracing::{debug, info, warn};

use crate::config::{UsdtConfig, UsdtConfigConsensus, UsdtConfigLocal, UsdtConfigPrivate};
use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, BootstrapVoteKey, BootstrapVotePrefix, DbKeyPrefix,
    DepositObservationVoteAccountPrefix, DepositObservationVoteKey, DepositObservationVotePrefix,
    DepositRecord, DepositRecordKey, DepositRecordPrefix, FeeVoteKey, FeeVotePrefix,
    HasEverBeenReadyKey, HasEverBeenReadyPrefix, LastSweepBlockKey, LastSweepBlockPrefix,
    MpcRoundChunk, MpcRoundChunkKey, MpcRoundChunkPrefix, MpcRoundChunkSessionPrefix,
    MpcRoundChunkSessionRoundPeerPrefix, MpcRoundChunkSessionRoundPrefix, PendingCheck,
    PendingCheckKey, PendingCheckPrefix, PendingUserOp, PendingUserOpKey, PendingUserOpPrefix,
    PoolState, PoolStateKey, PoolStatePrefix, SessionState, SigningPurpose, SigningSession,
    SigningSessionKey, SigningSessionPrefix, SubmittedUserOp, SubmittedUserOpKey,
    SubmittedUserOpPrefix, UnclaimedWithdrawalKey, UnclaimedWithdrawalPrefix, UsdtWithdrawalV0,
    UserOpConfirmedObservation, UserOpConfirmedVoteKey, UserOpConfirmedVoteOpPrefix,
    UserOpConfirmedVotePrefix, UserOpPurpose, WithdrawalState, WithdrawalStateKey,
    WithdrawalStatePrefix,
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
                        fedimint_usdt_common::FeeVote,
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
                DbKeyPrefix::PendingCheck => {
                    push_db_pair_items!(
                        dbtx,
                        PendingCheckPrefix,
                        crate::db::PendingCheckKey,
                        PendingCheck,
                        items,
                        "Pending Checks"
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
                DbKeyPrefix::LastSweepBlock => {
                    push_db_pair_items!(
                        dbtx,
                        LastSweepBlockPrefix,
                        LastSweepBlockKey,
                        u64,
                        items,
                        "Last Sweep Blocks"
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
            let evm_rpc_url = match std::env::var(FM_USDT_EVM_RPC_API_KEY_ENV)
                .ok()
                .filter(|s| !s.is_empty())
            {
                Some(key) => format!("{}/{key}", evm_rpc_url.trim_end_matches('/')),
                None => evm_rpc_url,
            };
            let mut rpc = AlloyEvmRpc::new(&evm_rpc_url)?
                .with_entry_point(cfg.consensus.entry_point)
                .with_price_feed(
                    cfg.consensus.eth_usd_price_feed,
                    cfg.consensus.price_feed_max_staleness_secs,
                );
            let broadcaster_private_key = std::env::var(FM_USDT_BROADCASTER_PRIVATE_KEY_ENV)
                .ok()
                .filter(|s| !s.is_empty())
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
    /// Empty today: the `usdt` module is greenfield/unreleased (this is its
    /// first, still-`MODULE_CONSENSUS_VERSION`-0 shape), so there is no
    /// prior on-disk layout to migrate FROM yet. This doc comment exists to
    /// establish the pattern this module MUST follow the first time a DB
    /// schema change actually ships (Phase 9, Task 1 hardening scaffold),
    /// mirroring e.g. `fedimint-mint-server`'s
    /// `ServerModuleInit::get_database_migrations`/
    /// `fedimint-wallet-server`'s equivalent:
    ///
    /// 1. Bump [`MODULE_CONSENSUS_VERSION`]'s DB-relevant component and add a
    ///    `migrate_db_v<N>(ctx: ServerModuleDbMigrationFnContext<'_, Usdt>) ->
    ///    anyhow::Result<()>` free function next to this `impl` that reads the
    ///    OLD key/value shape and rewrites it into the NEW one (typically via
    ///    `ctx.get_typed_module_history_stream()` + `dbtx.insert_entry`,
    ///    removing/replacing stale keys as needed).
    /// 2. Register it here: `migrations.insert(DatabaseVersion(N),
    ///    Box::new(|ctx| migrate_db_v<N>(ctx).boxed()))`.
    /// 3. Add a `fedimint_migration_tests` module in
    ///    `fedimint-usdt-tests/tests/tests.rs` (mirroring
    ///    `fedimint-mint-tests`' module of the same name) with:
    ///    - `create_server_db_with_v<N-1>_data` -- builds a `Database`
    ///      populated with the OLD shape's records (one of every affected
    ///      `DbKeyPrefix`, matching this module's own `dump_database` coverage
    ///      test).
    ///    - `snapshot_server_db_migrations` -- calls
    ///      `fedimint_testing::db::snapshot_db_migrations::<_, UsdtCommonInit>`
    ///      to freeze that pre-migration DB as a checked-in snapshot
    ///      (regenerated via `just snapshot-server-db-migrations
    ///      fedimint-usdt-tests`).
    ///    - `test_server_db_migrations` -- calls
    ///      `fedimint_testing::db::validate_migrations_server`, runs
    ///      `get_database_migrations` against the frozen snapshot, and asserts
    ///      every `DbKeyPrefix` reads back in the NEW shape.
    ///
    /// See `fedimint-mint-server/src/lib.rs`'s `get_database_migrations` +
    /// `fedimint-mint-tests/tests/tests.rs`'s `fedimint_migration_tests`
    /// module for a complete worked example of this exact pattern.
    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Usdt>> {
        BTreeMap::new()
    }
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
    /// Deposit observations gathered by the background deposit-checker task
    /// (spawned in [`Usdt::new`]; see [`scan_pending_deposits`]), drained
    /// into `UsdtConsensusItem::Deposit` proposals in `consensus_proposal`.
    deposit_proposals: Arc<Mutex<Vec<DepositObservation>>>,
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
    /// Mirrors `deposit_proposals`'s drain pattern.
    #[allow(clippy::type_complexity)]
    pending_signature_proposals: Arc<Mutex<Vec<(SigningSessionId, Vec<u8>)>>>,
    /// `UserOp` on-chain outcomes gathered by the background
    /// `usdt-user-op-submitter` task (spawned in [`Usdt::new`]; see
    /// [`Usdt::spawn_user_op_submitter`]), drained into
    /// `UsdtConsensusItem::UserOpConfirmed` proposals in
    /// `consensus_proposal`. Mirrors `deposit_proposals`'s drain pattern
    /// exactly (Phase 7, Task 5).
    user_op_confirmed_proposals: Arc<Mutex<Vec<UserOpConfirmedProposal>>>,
    /// This guardian's most recently polled [`FeeVote`] (current EVM fee
    /// market / USDT-per-ETH exchange rate), refreshed in the background by
    /// [`Usdt::spawn_fee_estimate_poller`] (Phase 8, Task 1) -- mirrors
    /// `block_count`'s push-updated cache pattern exactly, except `Option`
    /// (rather than an `AtomicU64` defaulting to `0`) since a `FeeVote` of
    /// all-zero fields would be a meaningfully wrong value to ever propose,
    /// unlike block count `0`, which is a legitimate (if unlikely)
    /// "chain not observed yet" state already handled elsewhere. `None`
    /// until the poller's first successful read.
    fee_estimate: Arc<Mutex<Option<FeeVote>>>,
    /// Readiness observations gathered by the background bootstrap-observer
    /// task (Part C; spawned in [`Usdt::new`], see
    /// [`Usdt::spawn_bootstrap_observer`]), drained into
    /// `UsdtConsensusItem::BootstrapObservation` proposals in
    /// `consensus_proposal`. Mirrors `deposit_proposals`'s drain pattern;
    /// each observation is this guardian's own guardian-LOCAL read of the
    /// on-chain readiness conditions, never itself a consensus decision.
    bootstrap_proposals: Arc<Mutex<Vec<BootstrapObservation>>>,
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
    swept: UsdtAmount,
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

/// Grouped handles/config for [`Usdt::spawn_deposit_checker`], bundling its
/// many related parameters into one utility struct (per this workspace's
/// convention for functions that would otherwise take too many individual
/// parameters) instead of listing them all out.
struct DepositCheckerHandles {
    db: Database,
    evm_rpc: DynServerEvmRpc,
    block_count: Arc<AtomicU64>,
    deposit_proposals: Arc<Mutex<Vec<DepositObservation>>>,
    usdt_contract: fedimint_usdt_common::EvmAddress,
    confirmation_depth: u64,
    check_ttl_blocks: u64,
    num_peers: NumPeers,
}

/// Grouped handles for [`Usdt::spawn_user_op_submitter`], mirroring
/// [`DepositCheckerHandles`]'s convention.
struct UserOpSubmitterHandles {
    db: Database,
    evm_rpc: DynServerEvmRpc,
    user_op_confirmed_proposals: Arc<Mutex<Vec<UserOpConfirmedProposal>>>,
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
        let fee_vote = *self.fee_estimate.lock().expect("not poisoned");
        if let Some(vote) = fee_vote {
            let current_vote = dbtx.get_value(&FeeVoteKey(self.our_peer_id)).await;
            if current_vote != Some(vote) {
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

        // Drain observations gathered by the background deposit-checker task
        // (see `scan_pending_deposits`), proposing only those that differ
        // from what this peer has already voted for the account (avoiding
        // redundant proposals that `process_consensus_item` would reject).
        let pending = std::mem::take(&mut *self.deposit_proposals.lock().expect("not poisoned"));
        for obs in pending {
            let current_vote = dbtx
                .get_value(&DepositObservationVoteKey(obs.account, self.our_peer_id))
                .await;
            if current_vote != Some(obs.clone()) {
                items.push(UsdtConsensusItem::Deposit(obs));
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
                swept: proposal.swept,
            };
            let current_vote = dbtx
                .get_value(&UserOpConfirmedVoteKey(proposal.op_hash, self.our_peer_id))
                .await;
            if current_vote != Some(obs) {
                items.push(UsdtConsensusItem::UserOpConfirmed {
                    op_hash: proposal.op_hash,
                    success: proposal.success,
                    block: proposal.block,
                    swept: proposal.swept,
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

                // Store this peer's vote; redundancy guard (unbounded-history rule).
                let key = DepositObservationVoteKey(obs.account, peer_id);
                if dbtx.insert_entry(&key, &obs).await.as_ref() == Some(&obs) {
                    bail!("Deposit observation vote is redundant");
                }

                // Count identical observations for this account.
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
                swept,
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
                    swept,
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
                // DETERMINISTIC, mirrors the `BlockCount` arm's discipline:
                // store this peer's vote with a redundancy guard. Unlike
                // `BlockCount` (monotonic, so the guard is `vote >
                // current_vote`), the EVM fee market moves in both
                // directions, so the guard here is equality-based (reject
                // only an EXACT repeat). No threshold-triggered "apply"
                // step: the federation's fee quote is always read on
                // demand as the median over whatever votes are currently
                // stored (see `Usdt::fee_vote_median`), never derived from
                // any single peer's vote or written to a separate
                // consensus-agreed record here.
                let current_vote = dbtx.get_value(&FeeVoteKey(peer_id)).await;
                ensure!(current_vote != Some(vote), "FeeVote is redundant");

                dbtx.insert_entry(&FeeVoteKey(peer_id), &vote).await;

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
        let UsdtInput::V0(input) = input else {
            return Err(UsdtInputError::UnknownDepositAccount); // unknown/default variant
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
                CHECK_DEPOSIT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, context, req: CheckDepositRequest| -> CheckDepositResponse {
                    // Writes a `PendingCheck`, so this needs a committable
                    // transaction (mirroring lnv2's `add_gateway`), unlike
                    // the read-only `deposit_status` endpoint below.
                    let db = context.db();
                    let mut dbtx = db.begin_transaction().await;
                    let response = module
                        .handle_check_deposit(&mut dbtx.to_ref_nc(), req.claim_pk)
                        .await;
                    dbtx.commit_tx().await;

                    Ok(response)
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
    /// poller task (see [`Usdt::spawn_block_count_poller`]) and the
    /// deposit-checker task (see [`Usdt::spawn_deposit_checker`]).
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

        let deposit_proposals = Arc::new(Mutex::new(Vec::new()));
        Self::spawn_deposit_checker(
            &task_group,
            DepositCheckerHandles {
                db: db.clone(),
                evm_rpc: evm_rpc.clone(),
                block_count: block_count.clone(),
                deposit_proposals: deposit_proposals.clone(),
                usdt_contract: cfg.consensus.usdt_contract,
                confirmation_depth: cfg.consensus.confirmation_depth,
                check_ttl_blocks: cfg.consensus.check_ttl_blocks,
                num_peers,
            },
        );

        let user_op_confirmed_proposals = Arc::new(Mutex::new(Vec::new()));
        Self::spawn_user_op_submitter(
            &task_group,
            UserOpSubmitterHandles {
                db: db.clone(),
                evm_rpc: evm_rpc.clone(),
                user_op_confirmed_proposals: user_op_confirmed_proposals.clone(),
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

        Usdt {
            cfg,
            evm_rpc,
            db,
            our_peer_id,
            num_peers,
            block_count,
            task_group,
            deposit_proposals,
            signing_sessions: Arc::new(Mutex::new(BTreeMap::new())),
            completed_signatures: Arc::new(Mutex::new(BTreeMap::new())),
            pending_signature_proposals: Arc::new(Mutex::new(Vec::new())),
            user_op_confirmed_proposals,
            fee_estimate,
            bootstrap_proposals,
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
            deposit_proposals: Arc::new(Mutex::new(Vec::new())),
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

                fedimint_core::runtime::sleep(Duration::from_secs(if is_running_in_test_env() {
                    1
                } else {
                    10
                }))
                .await;
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
                        warn!(
                            target: "usdt",
                            err = %err.fmt_compact_anyhow(),
                            "fee estimate poll failed; keeping last vote (abstaining this cycle)"
                        );
                    }
                }

                fedimint_core::runtime::sleep(Duration::from_secs(if is_running_in_test_env() {
                    1
                } else {
                    10
                }))
                .await;
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
            loop {
                // Part A deploy tick (guardian-local side effect, writes NO
                // consensus): self-deploy the SimpleAccountFactory if it is not
                // yet on-chain and this guardian's broadcaster is funded. Runs
                // before observing so a just-deployed factory can be voted ready
                // on the same tick. Best-effort: any error is logged and the
                // observation still proceeds (a wrong/absent factory simply
                // keeps the federation not-`Ready` via Part C's gate).
                if let Err(err) = Self::ensure_factory_deployed(
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
                )
                .await;

                bootstrap_proposals
                    .lock()
                    .expect("not poisoned")
                    .push(observation);

                fedimint_core::runtime::sleep(Duration::from_secs(if is_running_in_test_env() {
                    1
                } else {
                    10
                }))
                .await;
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
    ) -> BootstrapObservation {
        let observe = || async {
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

            // Broadcaster funding: `None` (no broadcaster configured) counts
            // as not funded.
            let broadcaster_funded = rpc_deadline(evm_rpc.broadcaster_eth_balance())
                .await?
                .is_some_and(|balance| balance >= u128::from(broadcaster_min_balance_wei));

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

    /// Spawns a background task that periodically scans this guardian's
    /// [`PendingCheck`]s (see [`scan_pending_deposits`]) and extends
    /// `deposit_proposals` with any newly observed deposits, for
    /// `consensus_proposal` to drain into `UsdtConsensusItem::Deposit`
    /// proposals.
    ///
    /// The scan itself only *reads* the module DB (via
    /// `db.begin_transaction_nc()`), mirroring
    /// [`Usdt::spawn_block_count_poller`]: no consensus-relevant write may
    /// happen outside the consensus flow. `PendingCheck` inserts still only
    /// ever happen in the check-deposit API handler; `PendingCheck` removal
    /// on a credited deposit still only happens in [`Usdt::credit_deposit`]
    /// (via `process_consensus_item`).
    ///
    /// After the read-only scan, this task additionally opens a SEPARATE,
    /// committable local transaction and runs [`gc_expired_pending_checks`]
    /// on it (security finding 13). This is safe despite the "no writes
    /// outside consensus" rule above because `PendingCheck` is guardian-local,
    /// non-consensus state -- see that function's doc comment for the full
    /// argument -- so this is the one guardian-local write this task
    /// performs, deliberately kept out of the read-only scan itself.
    fn spawn_deposit_checker(task_group: &TaskGroup, handles: DepositCheckerHandles) {
        let DepositCheckerHandles {
            db,
            evm_rpc,
            block_count,
            deposit_proposals,
            usdt_contract,
            confirmation_depth,
            check_ttl_blocks,
            num_peers,
        } = handles;

        task_group.spawn_cancellable("usdt-deposit-checker", async move {
            loop {
                let mut dbtx = db.begin_transaction_nc().await;
                let observations = scan_pending_deposits(
                    &mut dbtx.to_ref_nc(),
                    &evm_rpc,
                    block_count.load(Ordering::Relaxed),
                    usdt_contract,
                    confirmation_depth,
                    check_ttl_blocks,
                    num_peers,
                )
                .await;
                drop(dbtx);

                deposit_proposals
                    .lock()
                    .expect("not poisoned")
                    .extend(observations);

                // GC (security finding 13): a separate, committable local
                // transaction -- deliberately not part of the read-only scan
                // above. See `gc_expired_pending_checks`'s doc comment for why
                // this guardian-local write needs no consensus agreement.
                let mut gc_dbtx = db.begin_transaction().await;
                let removed = gc_expired_pending_checks(
                    &mut gc_dbtx.to_ref_nc(),
                    check_ttl_blocks,
                    num_peers,
                )
                .await;
                gc_dbtx.commit_tx().await;
                if removed > 0 {
                    debug!(
                        target: "usdt",
                        removed,
                        "garbage-collected expired PendingChecks"
                    );
                }

                fedimint_core::runtime::sleep(Duration::from_secs(if is_running_in_test_env() {
                    1
                } else {
                    10
                }))
                .await;
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
    /// Mirrors [`Usdt::spawn_deposit_checker`]'s discipline EXACTLY: reads
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
        } = handles;

        task_group.spawn_cancellable("usdt-user-op-submitter", async move {
            loop {
                let mut dbtx = db.begin_transaction_nc().await;
                let submitted: Vec<(SubmittedUserOpKey, SubmittedUserOp)> = dbtx
                    .find_by_prefix(&SubmittedUserOpPrefix)
                    .await
                    .collect()
                    .await;
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
                                            swept,
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

                fedimint_core::runtime::sleep(Duration::from_secs(if is_running_in_test_env() {
                    1
                } else {
                    10
                }))
                .await;
            }
        });
    }

    /// Median (over all peers, unresponsive peers counted as `0`) of the
    /// most recent `BlockCount` votes, mirroring
    /// `Wallet::consensus_block_count` (but `u64`-valued since EVM block
    /// numbers do not fit the wallet's `u32` bitcoin block heights).
    ///
    /// Delegates to the free [`consensus_block_count`] function so
    /// [`scan_pending_deposits`] (which has no `Usdt` to call this method
    /// on — it must run from a `'static` spawned task) can compute the same
    /// value without duplicating the median logic.
    pub async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        consensus_block_count(dbtx, self.num_peers).await
    }

    /// The federation's current withdrawal fee quote: the per-field MEDIAN
    /// (over every peer's stored [`FeeVote`]) of `max_fee_per_gas_wei` and
    /// `usdt_per_eth_e6` independently, `None` if not a single peer has
    /// voted yet (Phase 8, Task 1).
    ///
    /// Delegates to the free [`fee_vote_median`] function, mirroring
    /// [`Self::consensus_block_count`]'s delegation to the free
    /// [`consensus_block_count`] -- kept as a free function so any future
    /// `'static`-spawned background task could compute the same value
    /// without a `&Usdt` (today, nothing needs to; `process_output` and the
    /// `withdraw_fee_quote` endpoint both hold `&self`).
    ///
    /// Deliberately does NOT zero-pad missing votes out to `num_peers` the
    /// way [`consensus_block_count`] does: block count is monotonic (a
    /// missing/lagging peer's vote is always "behind", so padding with `0`
    /// is a safe, conservative default), but the EVM fee market moves in
    /// both directions, so padding an absent guardian's vote with `0` would
    /// let a Byzantine guardian bias the fee quote DOWN merely by
    /// withholding a vote (undercharging users, at the federation's
    /// expense) — the opposite of what padding protects against for block
    /// count. The median is instead taken over whatever votes are actually
    /// present, which — combined with `process_consensus_item`'s
    /// per-vote redundancy guard — still bounds any single Byzantine
    /// guardian's influence on the result to one vote out of however many
    /// have been cast.
    pub async fn fee_vote_median(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<FeeVote> {
        fee_vote_median(dbtx).await
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

    /// Credits a deposit observation that has reached threshold agreement:
    /// creates the account's [`DepositRecord`] (using `obs.claim_pk`) if it
    /// does not exist yet, advances `credited` monotonically forward (see
    /// "Credit rule" below), updates `last_observed_block`, and clears the
    /// round's votes and the account's `PendingCheck`.
    ///
    /// # Credit rule (sweep-aware, monotone)
    ///
    /// Which floor `credited` is advanced to depends on where `obs.block`
    /// falls relative to the account's consensus-agreed last sweep block
    /// ([`LastSweepBlockKey`], written by [`Usdt::apply_user_op_confirmed`]
    /// from the threshold-agreed [`UserOpConfirmedObservation::block`]):
    ///
    /// - `obs.block > last_sweep_block`: the observation provably saw the
    ///   POST-sweep balance (every confirmed sweep already left the account by
    ///   `obs.block`), so the account's true all-time deposit total is
    ///   `record.swept + obs.balance` and `credited` advances to `max(credited,
    ///   swept + balance)`. This is what lets a brand-new deposit to an
    ///   already-swept address credit FULLY (previously a documented
    ///   limitation: the raw balance of such a deposit never exceeded the
    ///   historic `credited`, so it was never -- or only partially --
    ///   credited).
    /// - `obs.block <= last_sweep_block` (or no sweep has ever confirmed): the
    ///   conservative raw-balance rule, `max(credited, balance)`. An
    ///   observation taken before a sweep but processed after its confirm lands
    ///   here, so the funds that sweep moved are never counted twice.
    ///
    /// No double credit either way: `swept` only covers sweeps confirmed at
    /// blocks `<= last_sweep_block`, whose funds are absent from any balance
    /// observed at `obs.block > last_sweep_block` -- so `swept + balance`
    /// never exceeds the true deposit total. A sweep that has executed
    /// on-chain but not yet reached its `UserOpConfirmed` threshold merely
    /// leaves `swept`/`last_sweep_block` un-advanced, which can only
    /// UNDER-credit temporarily (both rules are monotone `max`es), and the
    /// next observation after the confirm catches up.
    ///
    /// # Determinism (consensus-critical)
    ///
    /// `process_consensus_item` must be a pure function of `(ordered
    /// consensus items, prior consensus DB state)` — byte-identical on every
    /// honest guardian. The claim key therefore MUST come from `obs` itself,
    /// never from this guardian's local [`PendingCheck`] (or an existing
    /// [`DepositRecord`]): `PendingCheck` is guardian-local, non-consensus
    /// state written only by the `check_deposit` API handler, which a
    /// client's request reaches via a *threshold* of guardians, not all of
    /// them. A guardian that never received the `check_deposit` call would
    /// have no `PendingCheck` for this account, yet must still process the
    /// same ordered `Deposit` item identically to every other guardian.
    /// Reading local state here previously caused exactly that: guardians
    /// with the `PendingCheck` credited the deposit while a guardian without
    /// it hit a `bail!` and diverged permanently.
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
        // Sweep-aware credit rule (see this method's doc comment). Every
        // input is consensus state or the ordered item itself:
        // `last_sweep_block` is written only by `apply_user_op_confirmed`
        // from the threshold-agreed observation, `record.swept` is consensus
        // DB, and `obs` is the ordered consensus item -- no guardian-local
        // reads, so every guardian computes the identical floor.
        let last_sweep_block = dbtx.get_value(&LastSweepBlockKey(obs.account)).await;
        let floor = match last_sweep_block {
            // Observation provably post-sweep: the swept total has already
            // left the balance, so the all-time deposit total is their sum.
            Some(sweep_block) if obs.block > sweep_block => {
                record.swept.0.saturating_add(obs.balance.0)
            }
            // Never swept, or the observation may straddle the sweep: the
            // conservative raw-balance rule.
            _ => obs.balance.0,
        };
        // Only credit forward; both floors are monotone in practice (balance
        // is monotonic between sweeps since only the federation moves funds
        // out), and the `max` keeps a late/stale floor from ever regressing
        // `credited`.
        if floor > record.credited.0 {
            record.credited = UsdtAmount(floor);
        }
        record.last_observed_block = obs.block;
        dbtx.insert_entry(&DepositRecordKey(obs.account), &record)
            .await;
        // Clear the round's votes. The `PendingCheck` removal below is local
        // cleanup only (a guardian lacking one just no-ops the remove) — it
        // is not read to obtain `claim_pk` above, so its absence cannot
        // cause divergence.
        dbtx.remove_by_prefix(&DepositObservationVoteAccountPrefix(obs.account))
            .await;
        dbtx.remove_entry(&PendingCheckKey(obs.account)).await;

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
    /// # Deposits after a completed sweep
    ///
    /// A brand-new deposit paid to an address whose balance was already
    /// fully swept back to `0` is credited FULLY by `Usdt::credit_deposit`'s
    /// sweep-aware credit rule (an observation at a block later than the
    /// account's [`LastSweepBlockKey`] credits `swept + balance` -- see that
    /// method's "Credit rule" doc for why this cannot double-credit an
    /// observation straddling the sweep), growing `credited` past the
    /// already-swept total; this method then re-sweeps exactly that
    /// `credited - swept` remainder. So the whole re-arm loop is: client
    /// re-runs `check_deposit` -> observation reaches threshold ->
    /// `credit_deposit` credits the new deposit -> this method sweeps it.
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
        let median = self.fee_vote_median(dbtx).await;
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
                .with_median_fees(median.map(|m| m.max_fee_per_gas_wei)),
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

                    // Record the consensus-agreed block this sweep confirmed
                    // at (monotone max, so a late-applied confirm can never
                    // regress it), which `credit_deposit` compares deposit
                    // observations against: an observation at a LATER block
                    // provably saw the post-sweep balance and is credited as
                    // `swept + balance` (see `credit_deposit`'s "Credit
                    // rule"). `obs.block` is threshold-agreed data (the
                    // full-field `PartialEq` vote tally in the caller), not
                    // any single guardian's RPC read, so this write is
                    // byte-identical on every guardian.
                    let last_sweep_block = dbtx
                        .get_value(&LastSweepBlockKey(source))
                        .await
                        .unwrap_or(0);
                    dbtx.insert_entry(&LastSweepBlockKey(source), &last_sweep_block.max(obs.block))
                        .await;

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
    /// On `!success`: the DELIBERATE, solvent choice (documented per this
    /// task's spec) is to revert every `outpoints` withdrawal back to
    /// `WithdrawalState::Queued` -- NOT `Failed` -- so
    /// `Usdt::maybe_trigger_withdrawal_batch` retries it in a later batch
    /// (under a fresh, now-correct `PoolState.nonce`). `PoolState.balance`
    /// is left untouched (nothing left the pool on-chain) and
    /// `UnclaimedWithdrawal` is left in place (still a real, still-funded
    /// obligation) -- a permanent `Failed` terminal state would need a
    /// refund path this phase does not build, and would otherwise either
    /// strand the user's already-burned e-cash unpaid (an actual loss to
    /// them) or require re-issuing e-cash (a much larger, out-of-scope
    /// change); retrying is simple, keeps the pool's on-chain and
    /// consensus-DB `nonce` in lockstep, and never loses funds.
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

        for &out_point in outpoints {
            if obs.success {
                dbtx.insert_entry(
                    &WithdrawalStateKey(out_point),
                    &WithdrawalState::Confirmed { block: obs.block },
                )
                .await;
                dbtx.remove_entry(&UnclaimedWithdrawalKey(out_point)).await;
            } else {
                dbtx.insert_entry(&WithdrawalStateKey(out_point), &WithdrawalState::Queued)
                    .await;
            }
        }

        if obs.success {
            info!(
                target: "usdt",
                count = outpoints.len(),
                paid_out = swept.0,
                block = obs.block,
                pool_balance_after = pool.balance.0,
                new_pool_nonce = pool.nonce,
                "withdrawal batch CONFIRMED on-chain; withdrawals settled"
            );
        } else {
            warn!(
                target: "usdt",
                count = outpoints.len(),
                block = obs.block,
                new_pool_nonce = pool.nonce,
                "withdrawal batch REVERTED on-chain; withdrawals returned to Queued for retry (pool balance untouched)"
            );
        }
    }

    /// Derives `claim_pk`'s deposit account and enqueues a guardian-local
    /// [`PendingCheck`] for it, so this guardian's deposit-checker task (see
    /// [`scan_pending_deposits`]) starts watching that address. Idempotent:
    /// if a `PendingCheck` already exists for the account, it is left
    /// untouched.
    ///
    /// The response only ever carries `account` (deterministic from
    /// `claim_pk`) and `ready` (deterministic from consensus DB via
    /// [`Usdt::bootstrap_state`]), never whether this call is what enqueued
    /// the `PendingCheck` or whether a cap suppressed the insert: that is
    /// guardian-local state and would let honest guardians return different
    /// responses to the same request, breaking the threshold-identical
    /// response requirement of `request_current_consensus`.
    ///
    /// # Readiness gate (security finding 13, r2 facet)
    ///
    /// If the federation is not yet [`BootstrapState::Ready`], no
    /// `PendingCheck` is stored at all: funding a deposit account before the
    /// federation's infra (EntryPoint/factory/impl) is confirmed ready would
    /// let a caller strand funds in an account the federation cannot yet
    /// sweep. `bootstrap_state` is a pure function of consensus DB, so this
    /// gate is identical on every guardian at the same consensus position.
    ///
    /// # Cap (security finding 13)
    ///
    /// Before inserting a NEW `PendingCheck`, this counts the existing
    /// `PendingCheck` table and, at [`MAX_PENDING_CHECKS`], skips the insert
    /// (logging a warning) rather than growing the table further --
    /// `check_deposit` is unauthenticated and each distinct `claim_pk` derives
    /// a distinct account, so without a cap this table could grow without
    /// bound. The cap is enforced purely guardian-locally and, per the
    /// determinism note above, never changes the response shape.
    async fn handle_check_deposit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        claim_pk: secp256k1::PublicKey,
    ) -> CheckDepositResponse {
        let account = derive_deposit_account(
            &self.cfg.consensus.group_public_key,
            self.cfg.consensus.account_factory,
            self.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        let ready = self.bootstrap_state(dbtx).await == BootstrapState::Ready;
        if !ready {
            return CheckDepositResponse {
                account,
                ready: false,
            };
        }

        if dbtx.get_value(&PendingCheckKey(account)).await.is_some() {
            return CheckDepositResponse { account, ready };
        }

        let pending_count: u64 = dbtx
            .find_by_prefix(&PendingCheckPrefix)
            .await
            .count()
            .await
            .try_into()
            .unwrap_or(u64::MAX);
        if pending_count >= MAX_PENDING_CHECKS {
            warn!(
                target: "usdt",
                count = pending_count,
                "PendingCheck cap reached; not storing new check"
            );
            return CheckDepositResponse { account, ready };
        }

        let requested_at_block = self.consensus_block_count(dbtx).await;
        dbtx.insert_entry(
            &PendingCheckKey(account),
            &PendingCheck {
                claim_pk,
                requested_at_block,
            },
        )
        .await;

        CheckDepositResponse { account, ready }
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

    /// The deterministic signer subset for a session's `attempt`: a rotated
    /// window of size `t = threshold` over the sorted peer ring of size `n`,
    /// starting at offset `attempt % n` and wrapping. Returned in the same
    /// canonical sorted order [`spawn_signing_session`]/[`process_mpc_round`]
    /// use everywhere else, so every guardian independently agrees on both the
    /// membership and the party ordering of each attempt's subset.
    ///
    /// A pure function of `num_peers` and `attempt`: peer ids are exactly
    /// `0..n` and [`NumPeers::peer_ids`] yields them in order, so attempt 0 is
    /// the lowest-`t` subset and each subsequent attempt rotates the window
    /// one peer forward. Rotating on retry keeps a single persistently-faulty
    /// signer from stalling every attempt.
    fn signer_subset(&self, attempt: u32) -> Vec<PeerId> {
        let ids: Vec<PeerId> = self.num_peers.peer_ids().collect();
        let n = ids.len();
        let t = self.num_peers.threshold();
        let offset = (attempt as usize) % n;
        let mut subset: Vec<PeerId> = (0..t).map(|i| ids[(offset + i) % n]).collect();
        subset.sort_unstable();
        subset
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

    /// Starts (idempotently) a threshold-ECDSA signing session over `digest`
    /// on its `attempt`'th try.
    ///
    /// Writes the consensus [`SigningSession`] — id
    /// [`signing_session_id(&digest, attempt)`][signing_session_id], signer
    /// subset [`signer_subset(attempt)`][Self::signer_subset], `round: 0`,
    /// [`SessionState::InProgress`] — and no-ops if a session for this
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

        let signers = self.signer_subset(attempt);
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
/// from that method and from [`scan_pending_deposits`] (which, running from a
/// `'static` spawned task, cannot hold a `&Usdt` reference).
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
/// [`consensus_block_count`], this does NOT zero-pad missing votes out to a
/// peer count).
async fn fee_vote_median(dbtx: &mut DatabaseTransaction<'_>) -> Option<FeeVote> {
    let votes: Vec<FeeVote> = dbtx
        .find_by_prefix(&FeeVotePrefix)
        .await
        .map(|entry| entry.1)
        .collect()
        .await;

    if votes.is_empty() {
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

/// Scans every guardian-local [`PendingCheck`] and returns the
/// [`DepositObservation`]s this guardian is ready to propose for, without
/// making any writes to `dbtx`.
///
/// This is a **pure reader**: fedimint server-module background tasks read
/// the module DB via `db.begin_transaction_nc()` (non-committable) and must
/// not commit writes to the module DB outside the consensus flow (mirroring
/// e.g. the wallet module's read-only `run_broadcast_pending_tx`). All
/// `PendingCheck` writes therefore live in the check-deposit API handler and
/// in [`Usdt::credit_deposit`] (via `process_consensus_item`), never here.
///
/// The read block (`consensus_block_count(..) - confirmation_depth`) is
/// derived from federation-wide consensus state, not this guardian's local
/// EVM head, so that every honest guardian computes an identical observation
/// for the same deposit and can reach agreement on it.
///
/// TTL-expired `PendingCheck`s are skipped (not deleted): deleting them here
/// would violate the pure-reader constraint above. Garbage collection of
/// expired checks instead happens in a separate, committable local
/// transaction opened by the deposit-checker task right after it calls this
/// function (see [`Usdt::spawn_deposit_checker`] and
/// [`gc_expired_pending_checks`]; security finding 13).
async fn scan_pending_deposits(
    dbtx: &mut DatabaseTransaction<'_>,
    evm_rpc: &DynServerEvmRpc,
    cached_head: u64,
    usdt_contract: fedimint_usdt_common::EvmAddress,
    confirmation_depth: u64,
    check_ttl_blocks: u64,
    num_peers: NumPeers,
) -> Vec<DepositObservation> {
    let ccount = consensus_block_count(dbtx, num_peers).await;
    let at = ccount.saturating_sub(confirmation_depth);

    let pending: Vec<(PendingCheckKey, PendingCheck)> = dbtx
        .find_by_prefix(&PendingCheckPrefix)
        .await
        .collect()
        .await;

    let mut observations = Vec::new();
    for (PendingCheckKey(account), check) in pending {
        // Skipped (not deleted) here -- see this function's doc comment for
        // why, and `gc_expired_pending_checks` for where the deletion
        // actually happens.
        if check.requested_at_block + check_ttl_blocks < ccount {
            continue;
        }

        if at > cached_head {
            // This guardian's own EVM node hasn't confirmed that block yet;
            // retry next tick.
            continue;
        }

        let balance =
            match rpc_deadline(evm_rpc.get_erc20_balance(usdt_contract, account, at)).await {
                Ok(balance) => balance,
                Err(err) => {
                    debug!(
                        target: "usdt",
                        err = %err.fmt_compact_anyhow(),
                        ?account,
                        at_block = at,
                        "deposit balance check failed, retrying next tick"
                    );
                    continue;
                }
            };

        let credited = dbtx
            .get_value(&DepositRecordKey(account))
            .await
            .map_or(UsdtAmount(0), |record| record.credited);

        if balance.0 > credited.0 {
            observations.push(DepositObservation {
                account,
                balance,
                block: at,
                claim_pk: check.claim_pk,
            });
        }
    }

    observations
}

/// Deletes every guardian-local [`PendingCheck`] whose TTL has elapsed
/// (security finding 13), using the exact same expiry predicate
/// [`scan_pending_deposits`] uses to *skip* (but not delete) expired checks,
/// so the two stay consistent.
///
/// Guardian-local, non-consensus cleanup: `PendingCheck` is guardian-local
/// state -- see [`Usdt::credit_deposit`]'s own local `remove_entry` for the
/// same key, whose doc comment notes a guardian lacking a `PendingCheck`
/// simply no-ops the removal and is not read to derive anything
/// consensus-relevant. Deleting expired entries here therefore needs no
/// federation agreement and cannot cause divergence: an honest guardian that
/// GC'd (or never had) a `PendingCheck` for an account still correctly
/// applies a threshold-agreed deposit credit for it.
///
/// Takes a **committable** `dbtx`, unlike [`scan_pending_deposits`]'s
/// read-only one -- callers must commit a dedicated transaction for this
/// call, kept separate from the read-only scan (see
/// [`Usdt::spawn_deposit_checker`]). Returns the number of entries removed,
/// for logging/tests.
async fn gc_expired_pending_checks(
    dbtx: &mut DatabaseTransaction<'_>,
    check_ttl_blocks: u64,
    num_peers: NumPeers,
) -> usize {
    let ccount = consensus_block_count(dbtx, num_peers).await;

    let pending: Vec<(PendingCheckKey, PendingCheck)> = dbtx
        .find_by_prefix(&PendingCheckPrefix)
        .await
        .collect()
        .await;

    let mut removed = 0usize;
    for (key, check) in pending {
        if check.requested_at_block + check_ttl_blocks < ccount {
            dbtx.remove_entry(&key).await;
            removed += 1;
        }
    }

    removed
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
    /// median/redundancy) rather than EVM-RPC-driven behavior, plus minimal
    /// scripting of `get_erc20_balance` (via `set_erc20_balance_at`) for the
    /// deposit-checker tests. This is deliberately separate from
    /// `fedimint-usdt-tests`' fuller scriptable `MockEvmRpc`:
    /// `fedimint-usdt-server` cannot depend on `fedimint-usdt-tests` (which
    /// itself depends on this crate) without a dependency cycle.
    #[derive(Debug, Default)]
    struct MockEvmRpc {
        #[allow(clippy::type_complexity)]
        balances: Mutex<
            std::collections::HashMap<
                (
                    fedimint_usdt_common::EvmAddress,
                    fedimint_usdt_common::EvmAddress,
                ),
                BTreeMap<u64, fedimint_usdt_common::UsdtAmount>,
            >,
        >,
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
    }

    impl MockEvmRpc {
        /// Scripts `get_erc20_balance(token, holder, at_block)` to return
        /// `balance` for any `at_block >= block` (until a later, higher
        /// scripted block for the same `(token, holder)` supersedes it),
        /// mirroring `fedimint-usdt-tests`' `MockEvmRpc::set_erc20_balance_at`.
        fn set_erc20_balance_at(
            &self,
            token: fedimint_usdt_common::EvmAddress,
            holder: fedimint_usdt_common::EvmAddress,
            block: u64,
            balance: fedimint_usdt_common::UsdtAmount,
        ) {
            self.balances
                .lock()
                .expect("not poisoned")
                .entry((token, holder))
                .or_default()
                .insert(block, balance);
        }

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

        async fn get_erc20_balance(
            &self,
            token: fedimint_usdt_common::EvmAddress,
            holder: fedimint_usdt_common::EvmAddress,
            at_block: u64,
        ) -> anyhow::Result<fedimint_usdt_common::UsdtAmount> {
            Ok(self
                .balances
                .lock()
                .expect("not poisoned")
                .get(&(token, holder))
                .and_then(|by_block| by_block.range(..=at_block).next_back())
                .map_or(fedimint_usdt_common::UsdtAmount(0), |(_, balance)| *balance))
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
        )
        .await;

        assert!(observation.rpc_healthy);
        assert!(!observation.factory_ok);
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
        let claim_pk = test_pubkey(0xaa);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        // A PendingCheck is not required for crediting (that is the whole
        // point of this fix — see `credit_deposit`'s doc comment), but a
        // real guardian that itself handled the `check_deposit` call would
        // have one, and this test also exercises that it gets cleared on
        // credit.
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(
                &PendingCheckKey(account),
                &PendingCheck {
                    claim_pk,
                    requested_at_block: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = DepositObservation {
            account,
            balance: UsdtAmount(2_000_000),
            block: 50,
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

        // Third identical 2M vote reaches threshold → credited, votes + pending
        // cleared.
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
        assert!(
            dbtx.to_ref_nc()
                .get_value(&PendingCheckKey(account))
                .await
                .is_none()
        );
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
        let claim_pk = test_pubkey(0xbb);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(
                &PendingCheckKey(account),
                &PendingCheck {
                    claim_pk,
                    requested_at_block: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = DepositObservation {
            account,
            balance: UsdtAmount(1_000_000),
            block: 10,
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

    /// Regression test for the consensus-safety fix: a guardian that never
    /// saw the `check_deposit` API call (so has NO local [`PendingCheck`]
    /// for this account — e.g. a momentarily-slow guardian that a client's
    /// `check_deposit` did not happen to reach, since
    /// `request_current_consensus` only hits a threshold of peers, not all
    /// of them) must still credit the deposit identically to every other
    /// guardian once threshold-identical `Deposit` votes are ordered,
    /// because `claim_pk` now comes from the observation itself rather than
    /// from local state.
    ///
    /// Before the fix, `credit_deposit` recovered the claim key by reading
    /// `PendingCheckKey(obs.account)` and `bail!`ed with "no pending check or
    /// record" when it was absent — so this exact scenario (no `PendingCheck`
    /// ever inserted) would return `Err` while guardians that did have the
    /// `PendingCheck` returned `Ok` for the same ordered consensus item: a
    /// permanent consensus DB divergence.
    #[tokio::test]
    async fn credit_deposit_succeeds_without_any_local_pending_check() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x42);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        // Deliberately do NOT insert a `PendingCheck` for `account` —
        // simulating the guardian that `check_deposit` never reached.
        assert!(
            db.begin_transaction_nc()
                .await
                .get_value(&PendingCheckKey(account))
                .await
                .is_none(),
            "test setup: this guardian must have no PendingCheck for the account"
        );

        let obs = DepositObservation {
            account,
            balance: UsdtAmount(2_000_000),
            block: 50,
            claim_pk,
        };
        let mut dbtx = db.begin_transaction().await;

        // Three (threshold) identical votes, exactly as the ordered
        // consensus items would arrive on any guardian, PendingCheck or not.
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::Deposit(obs.clone()),
                    PeerId::from(p),
                )
                .await
                .expect("crediting must not depend on a local PendingCheck");
        }

        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("DepositRecord must be created purely from the observation");
        assert_eq!(record.credited, UsdtAmount(2_000_000));
        assert_eq!(record.claimed, UsdtAmount(0));
        assert_eq!(record.claim_pk, claim_pk);
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
    /// num_peers)` (and therefore `scan_pending_deposits`) computes exactly
    /// `ccount`.
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

    /// `signer_subset` is a deterministic rotated window of size `t` over the
    /// sorted peer ring, offset by `attempt % n` and wrapping — the same
    /// canonical sorted order every guardian independently agrees on. For
    /// n=4, t=3: attempt 0 → {0,1,2}; attempt 1 → {1,2,3}; attempt 2 wraps to
    /// sorted {0,2,3}; attempt 3 wraps to sorted {0,1,3}; attempt 4 wraps back
    /// to attempt 0's subset.
    #[tokio::test]
    async fn signer_subset_rotates_and_wraps_deterministically() {
        let module = test_module_with_block_count(4, 0).await;
        let p = |i: u16| PeerId::from(i);

        assert_eq!(module.signer_subset(0), vec![p(0), p(1), p(2)]);
        assert_eq!(module.signer_subset(1), vec![p(1), p(2), p(3)]);
        assert_eq!(module.signer_subset(2), vec![p(0), p(2), p(3)]);
        assert_eq!(module.signer_subset(3), vec![p(0), p(1), p(3)]);
        // Wraps: attempt 4 == attempt 0 (offset 4 % 4 == 0).
        assert_eq!(module.signer_subset(4), module.signer_subset(0));
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

        // Attempt 0: every guardian starts the identical session over the
        // lowest-`t` subset {0,1,2}. `consensus_block_count` is 0 here (no
        // votes yet), so each session's `last_progress_block` is 0.
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
            assert_eq!(
                session.signers,
                vec![PeerId::from(0), PeerId::from(1), PeerId::from(2)]
            );
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
        // attempt-1 session InProgress at round 0 under the rotated subset
        // {1,2,3}.
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
                retry.signers,
                vec![PeerId::from(1), PeerId::from(2), PeerId::from(3)],
                "the retry must run under the rotated (offset-1) signer subset"
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

        // Attempt 0: every guardian starts the identical session over the
        // lowest-`t` subset {0,1,2}.
        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
            module
                .start_session(&mut dbtx.to_ref_nc(), purpose.clone(), digest, 0)
                .await;
            dbtx.commit_tx().await;
        }

        // Round 0: two HONEST signers (peers 0, 1) each send a single,
        // self-consistent chunk (chunk_count=1, chunk=0). The consensus-level
        // payload bytes are opaque to `process_mpc_round` (see its own doc
        // comment: reassembly/off-thread interpretation is guardian-local),
        // so arbitrary content is fine here.
        let honest_items = [
            (
                PeerId::from(0),
                MpcRoundItem {
                    session_id: attempt0_id,
                    round: 0,
                    chunk: 0,
                    chunk_count: 1,
                    payload: vec![0xAA],
                },
            ),
            (
                PeerId::from(1),
                MpcRoundItem {
                    session_id: attempt0_id,
                    round: 0,
                    chunk: 0,
                    chunk_count: 1,
                    payload: vec![0xBB],
                },
            ),
        ];
        // The BYZANTINE signer (peer 2, a genuine member of attempt 0's
        // subset) sends exactly one chunk claiming an inconsistent
        // `chunk_count` of 5, then withholds the rest -- this is a
        // self-inflicted stall (`0..5` can never all be present), not a
        // crash or a consensus-divergence: `process_mpc_round`'s explicit
        // range check (`chunk_count >= 1 && chunk < chunk_count`) and sec-11's
        // `chunk_count <= MAX_MPC_CHUNKS` cap both accept this item as
        // well-formed (0 < 5 <= MAX_MPC_CHUNKS), exactly as they must accept
        // any syntactically valid but semantically hostile chunk count that
        // stays within the federation-wide cap.
        let byzantine_item = (
            PeerId::from(2),
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
            for honest_peer in [PeerId::from(0), PeerId::from(1)] {
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
        // {1,2,3} (which excludes the Byzantine peer 2's OWN chunk-count
        // shenanigans from repeating, since peer 2's position/role in the
        // new subset restarts cleanly -- though even if it stayed a signer,
        // a fresh attempt starts its `MpcRoundChunk` table empty).
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
                retry.signers,
                vec![PeerId::from(1), PeerId::from(2), PeerId::from(3)],
                "the retry must run under the rotated (offset-1) signer subset"
            );
        }
    }

    #[tokio::test]
    async fn scan_pending_deposits_finds_confirmed_balance_above_credited() {
        let num_peers = 4u16;
        let confirmation_depth = 6u64;
        let check_ttl_blocks = 500u64;
        let ccount = 100u64;
        let usdt_contract = EvmAddress([0x11; 20]);
        let account = EvmAddress([0x22; 20]);
        let claim_pk = test_pubkey(0xcc);

        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );
        seed_block_count_votes(&db, num_peers, ccount).await;
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(
                &PendingCheckKey(account),
                &PendingCheck {
                    claim_pk,
                    requested_at_block: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let at = ccount - confirmation_depth;
        let evm_rpc = MockEvmRpc::default();
        evm_rpc.set_erc20_balance_at(usdt_contract, account, at, UsdtAmount(3_000_000));
        let evm_rpc: DynServerEvmRpc = std::sync::Arc::new(evm_rpc);

        let mut dbtx = db.begin_transaction_nc().await;
        let observations = scan_pending_deposits(
            &mut dbtx.to_ref_nc(),
            &evm_rpc,
            ccount, // cached head is at least as fresh as `at`
            usdt_contract,
            confirmation_depth,
            check_ttl_blocks,
            (0..num_peers)
                .map(PeerId::from)
                .collect::<Vec<_>>()
                .to_num_peers(),
        )
        .await;

        assert_eq!(
            observations,
            vec![DepositObservation {
                account,
                balance: UsdtAmount(3_000_000),
                block: at,
                claim_pk,
            }]
        );
    }

    #[tokio::test]
    async fn scan_pending_deposits_skips_expired_pending_check_without_deleting() {
        let num_peers = 4u16;
        let confirmation_depth = 6u64;
        let check_ttl_blocks = 10u64;
        let ccount = 1_000u64; // far past requested_at_block(0) + ttl(10)
        let usdt_contract = EvmAddress([0x33; 20]);
        let account = EvmAddress([0x44; 20]);
        let claim_pk = test_pubkey(0xdd);

        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );
        seed_block_count_votes(&db, num_peers, ccount).await;
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(
                &PendingCheckKey(account),
                &PendingCheck {
                    claim_pk,
                    requested_at_block: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let evm_rpc: DynServerEvmRpc = std::sync::Arc::new(MockEvmRpc::default());

        let mut dbtx = db.begin_transaction_nc().await;
        let observations = scan_pending_deposits(
            &mut dbtx.to_ref_nc(),
            &evm_rpc,
            ccount,
            usdt_contract,
            confirmation_depth,
            check_ttl_blocks,
            (0..num_peers)
                .map(PeerId::from)
                .collect::<Vec<_>>()
                .to_num_peers(),
        )
        .await;

        assert!(
            observations.is_empty(),
            "expired pending check must not be proposed"
        );

        // The expired PendingCheck must NOT have been deleted by the scan
        // itself: removal of stale expired entries happens in the SEPARATE
        // `gc_expired_pending_checks` (see `scan_pending_deposits`'s doc
        // comment, and `expired_pending_checks_are_deleted` below for that
        // function's own coverage).
        let mut dbtx = db.begin_transaction_nc().await;
        assert!(
            dbtx.get_value(&PendingCheckKey(account)).await.is_some(),
            "the read-only scan must not delete the PendingCheck"
        );
    }

    /// Security finding 13: `gc_expired_pending_checks` deletes exactly the
    /// `PendingCheck`s whose TTL has elapsed (the same predicate
    /// `scan_pending_deposits` uses to skip them), leaving non-expired ones
    /// untouched.
    #[tokio::test]
    async fn expired_pending_checks_are_deleted() {
        let num_peers = 4u16;
        let check_ttl_blocks = 10u64;
        let ccount = 1_000u64;
        let expired_account = EvmAddress([0x55; 20]);
        let live_account = EvmAddress([0x66; 20]);
        let claim_pk = test_pubkey(0xee);

        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );
        seed_block_count_votes(&db, num_peers, ccount).await;
        {
            let mut dbtx = db.begin_transaction().await;
            // Expired: requested_at_block(0) + ttl(10) = 10 < ccount(1000).
            dbtx.insert_entry(
                &PendingCheckKey(expired_account),
                &PendingCheck {
                    claim_pk,
                    requested_at_block: 0,
                },
            )
            .await;
            // Not expired: requested_at_block(995) + ttl(10) = 1005 >= ccount(1000).
            dbtx.insert_entry(
                &PendingCheckKey(live_account),
                &PendingCheck {
                    claim_pk,
                    requested_at_block: 995,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let num_peers = (0..num_peers)
            .map(PeerId::from)
            .collect::<Vec<_>>()
            .to_num_peers();

        let mut dbtx = db.begin_transaction().await;
        let removed =
            gc_expired_pending_checks(&mut dbtx.to_ref_nc(), check_ttl_blocks, num_peers).await;
        dbtx.commit_tx().await;

        assert_eq!(removed, 1);

        let mut dbtx = db.begin_transaction_nc().await;
        assert!(
            dbtx.get_value(&PendingCheckKey(expired_account))
                .await
                .is_none(),
            "the expired PendingCheck must be removed"
        );
        assert!(
            dbtx.get_value(&PendingCheckKey(live_account))
                .await
                .is_some(),
            "the non-expired PendingCheck must survive"
        );
    }

    // --- Phase 9, Drill A: deposit reorg safety -----------------------------
    //
    // Hardening-acceptance-audit plan (`docs/superpowers/plans/
    // 2026-07-21-hardening-acceptance-audit.md`), Task 1. These three tests
    // prove, against the hermetic (block-aware) `MockEvmRpc` above, that a
    // reorg shallower than `confirmation_depth` cannot cause a
    // spurious/rolled-back credit, and document the guarantee's boundary.
    //
    // The formal guarantee: once a deposit has been credited, the block it
    // was credited from was already `confirmation_depth` deep at the time of
    // crediting (that's what makes `scan_pending_deposits` propose it in the
    // first place -- see that function's own doc comment). A SUBSEQUENT
    // reorg of depth `d < confirmation_depth` can only rewrite blocks within
    // `d` of the (same-or-taller) new head, and can therefore never reach a
    // block that was already `confirmation_depth`-deep: `d <
    // confirmation_depth` implies the credited block lies outside the
    // reorg's reach. So a shallow reorg cannot un-happen an already-credited
    // deposit by construction -- there is nothing for consensus logic to
    // defend against there. What consensus logic DOES defend (and what
    // `drill_a_deposit_within_confirmation_depth_is_not_credited` and
    // `drill_a_deposit_reorged_out_before_confirmation_depth_is_never_credited`
    // below prove) is the OTHER half: a deposit that has NOT yet reached
    // `confirmation_depth` must never be credited off an unconfirmed read,
    // precisely because a shallow reorg CAN still rewrite it.
    //
    // What this does NOT prove (a documented boundary, not a gap): a reorg
    // DEEPER than `confirmation_depth` -- i.e. one that manages to
    // reorganize a block that was already credited against -- is out of
    // scope by construction. `credit_deposit`'s `credited` write is
    // monotonic-forward-only (see its "Credit rule (sweep-aware, monotone)"
    // doc comment: both floors only ever advance `credited` via a `max`)
    // and there is no consensus arm that un-credits it.
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
    async fn drill_a_deposit_within_confirmation_depth_is_not_credited() {
        // The "intended-safe case": a deposit that has NOT yet accumulated
        // `confirmation_depth` confirmations must never be proposed as an
        // observation (and therefore never credited), even though the funds
        // already exist on-chain at the current, unconfirmed head.
        let num_peers = 4u16;
        let confirmation_depth = 6u64;
        let check_ttl_blocks = 500u64;
        let usdt_contract = EvmAddress([0x71; 20]);
        let account = EvmAddress([0x72; 20]);
        let claim_pk = test_pubkey(0x71);

        let deposit_block = 50u64;
        // Head is only `confirmation_depth - 1` past the deposit block: NOT
        // yet confirmed (`at = ccount - confirmation_depth` lands strictly
        // before `deposit_block`, where the pre-deposit balance is 0).
        let ccount = deposit_block + confirmation_depth - 1;

        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );
        seed_block_count_votes(&db, num_peers, ccount).await;
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(
                &PendingCheckKey(account),
                &PendingCheck {
                    claim_pk,
                    requested_at_block: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let evm_rpc = MockEvmRpc::default();
        evm_rpc.set_erc20_balance_at(usdt_contract, account, deposit_block, UsdtAmount(2_000_000));
        let evm_rpc: DynServerEvmRpc = std::sync::Arc::new(evm_rpc);

        let mut dbtx = db.begin_transaction_nc().await;
        let observations = scan_pending_deposits(
            &mut dbtx.to_ref_nc(),
            &evm_rpc,
            ccount,
            usdt_contract,
            confirmation_depth,
            check_ttl_blocks,
            (0..num_peers)
                .map(PeerId::from)
                .collect::<Vec<_>>()
                .to_num_peers(),
        )
        .await;

        assert!(
            observations.is_empty(),
            "a deposit that has not yet reached confirmation_depth confirmations must never \
             be proposed for crediting"
        );
    }

    #[tokio::test]
    async fn drill_a_deposit_reorged_out_before_confirmation_depth_is_never_credited() {
        // A reorg that removes a deposit BEFORE it accumulates
        // `confirmation_depth` confirmations is fully invisible to the
        // deposit-checker: the checker only ever reads a block once it is
        // `confirmation_depth` deep, and by the time it reads, it sees
        // whatever the (now-canonical, post-reorg) chain actually has at
        // that block. No special reorg-handling logic is needed for this
        // case -- it falls straight out of confirmation-depth gating.
        //
        // This mock keys scripted balances by block number (see
        // `MockEvmRpc::set_erc20_balance_at`'s doc comment), mirroring how a
        // reorged chain has exactly one canonical value per block: a reorg
        // is modeled here by re-scripting the SAME block key to its
        // post-reorg value.
        let num_peers = 4u16;
        let confirmation_depth = 6u64;
        let check_ttl_blocks = 500u64;
        let usdt_contract = EvmAddress([0x73; 20]);
        let account = EvmAddress([0x74; 20]);
        let claim_pk = test_pubkey(0x73);

        let deposit_block = 50u64;

        let db = fedimint_core::db::Database::new(
            fedimint_core::db::mem_impl::MemDatabase::new(),
            fedimint_core::module::registry::ModuleDecoderRegistry::default(),
        );
        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_entry(
                &PendingCheckKey(account),
                &PendingCheck {
                    claim_pk,
                    requested_at_block: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let evm_rpc = MockEvmRpc::default();
        // The deposit lands at block 50 with a 2,000,000 balance...
        evm_rpc.set_erc20_balance_at(usdt_contract, account, deposit_block, UsdtAmount(2_000_000));
        // ...but is reorged out before it ever reaches confirmation depth:
        // the canonical balance AT BLOCK 50 is rewritten back to 0.
        evm_rpc.set_erc20_balance_at(usdt_contract, account, deposit_block, UsdtAmount(0));
        let evm_rpc: DynServerEvmRpc = std::sync::Arc::new(evm_rpc);

        // The chain head later advances well past confirmation_depth...
        let ccount = deposit_block + confirmation_depth + 100;
        seed_block_count_votes(&db, num_peers, ccount).await;

        let mut dbtx = db.begin_transaction_nc().await;
        let observations = scan_pending_deposits(
            &mut dbtx.to_ref_nc(),
            &evm_rpc,
            ccount,
            usdt_contract,
            confirmation_depth,
            check_ttl_blocks,
            (0..num_peers)
                .map(PeerId::from)
                .collect::<Vec<_>>()
                .to_num_peers(),
        )
        .await;

        assert!(
            observations.is_empty(),
            "a deposit reorged out before it reached confirmation_depth confirmations must \
             never be credited"
        );
    }

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

    #[tokio::test]
    async fn fee_vote_median_none_until_first_vote_and_is_per_field() {
        let module = test_module_with_block_count(4, 0).await;
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
        for (i, vote) in votes.iter().enumerate() {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::FeeVote(*vote),
                    PeerId::from(u16::try_from(i).expect("small")),
                )
                .await
                .expect("first vote from each peer must succeed");
        }

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
        let module = test_module_with_block_count(4, 0).await;
        let mut dbtx = module.db_for_test().begin_transaction().await;
        let vote = sample_fee_vote();

        module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::FeeVote(vote),
                PeerId::from(0u16),
            )
            .await
            .expect("first vote must succeed");

        let median = module
            .fee_vote_median(&mut dbtx.to_ref_nc())
            .await
            .expect("a single stored vote is its own median");
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

    /// Seeds every peer's `FeeVoteKey` with `vote`, so
    /// `Usdt::fee_vote_median` resolves to exactly `vote` (all fields
    /// identical across peers -> trivially their own median).
    async fn seed_fee_votes(db: &fedimint_core::db::Database, num_peers: u16, vote: FeeVote) {
        let mut dbtx = db.begin_transaction().await;
        for p in 0..num_peers {
            dbtx.insert_new_entry(&FeeVoteKey(PeerId::from(p)), &vote)
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
    async fn check_deposit_enqueues_pending_check_and_is_idempotent() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x01);
        let expected_account = fedimint_usdt_common::derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        // Reach BootstrapState::Ready first (security finding 13's readiness
        // gate): otherwise handle_check_deposit refuses to enqueue anything.
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1, 2] {
            vote_bootstrap(&module, &mut dbtx.to_ref_nc(), p, ready_observation()).await;
        }
        dbtx.commit_tx().await;

        // First call: derives the account and enqueues a PendingCheck.
        let mut dbtx = db.begin_transaction().await;
        let response = module
            .handle_check_deposit(&mut dbtx.to_ref_nc(), claim_pk)
            .await;
        dbtx.commit_tx().await;

        assert_eq!(response.account, expected_account);
        assert!(response.ready, "federation was voted to Ready above");

        let pending = db
            .begin_transaction_nc()
            .await
            .get_value(&PendingCheckKey(expected_account))
            .await
            .expect("PendingCheck must have been inserted");
        assert_eq!(pending.claim_pk, claim_pk);
        assert_eq!(pending.requested_at_block, 0);

        // Advance the consensus block count so a bug that re-derives
        // requested_at_block on every call (instead of leaving an existing
        // PendingCheck untouched) would be caught below.
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::BlockCount(100),
                    PeerId::from(p),
                )
                .await
                .expect("valid consensus item");
        }
        dbtx.commit_tx().await;
        let mut dbtx = db.begin_transaction().await;
        assert_eq!(
            module.consensus_block_count(&mut dbtx.to_ref_nc()).await,
            100
        );
        dbtx.commit_tx().await;

        // Second call for the same claim_pk: idempotent, must not overwrite the
        // existing PendingCheck (in particular, requested_at_block must stay 0,
        // not be bumped to the now-advanced block count of 100).
        let mut dbtx = db.begin_transaction().await;
        let response2 = module
            .handle_check_deposit(&mut dbtx.to_ref_nc(), claim_pk)
            .await;
        dbtx.commit_tx().await;

        assert_eq!(response2.account, expected_account);
        assert!(response2.ready);

        let pending_after_second_call = db
            .begin_transaction_nc()
            .await
            .get_value(&PendingCheckKey(expected_account))
            .await
            .expect("PendingCheck must still be present");
        assert_eq!(pending_after_second_call, pending);
    }

    /// Security finding 13 (r2 facet): before the federation reaches
    /// `BootstrapState::Ready`, `handle_check_deposit` must refuse to enqueue
    /// a `PendingCheck` -- funding an account before the federation can sweep
    /// it would strand funds -- and must report `ready: false` so the caller
    /// knows nothing was enqueued.
    #[tokio::test]
    async fn check_deposit_rejected_before_ready() {
        let module = test_module_with_block_count(4, 0).await; // no bootstrap votes cast
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x10);
        let expected_account = fedimint_usdt_common::derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        let mut dbtx = db.begin_transaction().await;
        let response = module
            .handle_check_deposit(&mut dbtx.to_ref_nc(), claim_pk)
            .await;
        dbtx.commit_tx().await;

        assert_eq!(
            response.account, expected_account,
            "account is a pure function of claim_pk + config, unaffected by readiness"
        );
        assert!(!response.ready);

        let mut dbtx = db.begin_transaction_nc().await;
        assert!(
            dbtx.get_value(&PendingCheckKey(expected_account))
                .await
                .is_none(),
            "no PendingCheck may be stored before the federation is Ready"
        );
    }

    /// Security finding 13: once `PendingCheckPrefix` holds
    /// `MAX_PENDING_CHECKS` entries, `handle_check_deposit` must not insert
    /// another one for a brand-new distinct account -- but must still return
    /// a normal, well-formed (deterministic) response rather than encoding
    /// the cap into it.
    #[tokio::test]
    async fn check_deposit_capped_at_max() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        // Reach BootstrapState::Ready: the cap only matters on the insert
        // path, which is only reached once ready.
        let mut dbtx = db.begin_transaction().await;
        for p in [0u16, 1, 2] {
            vote_bootstrap(&module, &mut dbtx.to_ref_nc(), p, ready_observation()).await;
        }
        dbtx.commit_tx().await;

        // Seed the table up to the cap with distinct accounts.
        let filler_claim_pk = test_pubkey(0x11);
        let mut dbtx = db.begin_transaction().await;
        for i in 0..MAX_PENDING_CHECKS {
            let mut bytes = [0u8; 20];
            bytes[12..20].copy_from_slice(&i.to_be_bytes());
            dbtx.insert_new_entry(
                &PendingCheckKey(EvmAddress(bytes)),
                &PendingCheck {
                    claim_pk: filler_claim_pk,
                    requested_at_block: 0,
                },
            )
            .await;
        }
        dbtx.commit_tx().await;

        let claim_pk = test_pubkey(0x12);
        let expected_account = fedimint_usdt_common::derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        let mut dbtx = db.begin_transaction().await;
        let response = module
            .handle_check_deposit(&mut dbtx.to_ref_nc(), claim_pk)
            .await;
        dbtx.commit_tx().await;

        assert_eq!(response.account, expected_account);
        assert!(response.ready, "cap must not affect the ready computation");

        let mut dbtx = db.begin_transaction_nc().await;
        assert!(
            dbtx.get_value(&PendingCheckKey(expected_account))
                .await
                .is_none(),
            "at the cap, a new distinct account's PendingCheck must not be stored"
        );

        let count: u64 = dbtx
            .find_by_prefix(&PendingCheckPrefix)
            .await
            .count()
            .await
            .try_into()
            .unwrap_or(u64::MAX);
        assert_eq!(
            count, MAX_PENDING_CHECKS,
            "the table must stay exactly at the cap, not grow past it"
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
        // signing-session store. Peer 3 is outside the lowest-3 signer subset.
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
        for &peer in &peers[..3] {
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
            modules[&peers[3]]
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
            claim_pk,
        };

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
            // Gas-pricing regression guard (the mainnet on-chain wedge): with
            // no `FeeVote` in this federation the median is absent, so the op
            // must be priced at the median-fee FLOOR (1 gwei) via
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
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: true,
            block: 20,
            swept: UsdtAmount(4_000_000),
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
                    swept: UsdtAmount(1),
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
                    swept: UsdtAmount(4_000_000),
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
            swept: UsdtAmount(1_000_000),
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
                    swept: UsdtAmount(1_000_000),
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
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: false,
            block: 21,
            swept: UsdtAmount(0),
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
                },
            )
            .await;
        dbtx.to_ref_nc()
            .remove_entry(&PendingUserOpKey(op_hash))
            .await;
        dbtx.commit_tx().await;
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
        let account = EvmAddress([0xc1; 20]);
        let claim_pk = test_pubkey(0xc2);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(10),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                    nonce: 0,
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        // First sweep: full credited (10), nonce 0, deploying (initCode set).
        let op_hash_1 = {
            let mut dbtx = db.begin_transaction().await;
            module
                .maybe_trigger_sweep(&mut dbtx.to_ref_nc(), account)
                .await;
            let (hash, op) = single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
            assert_eq!(op.nonce, alloy::primitives::U256::ZERO);
            assert_eq!(
                crate::user_op::decode_transfer_amount(&op).expect("op call_data decodes"),
                UsdtAmount(10)
            );
            assert!(
                !op.init_code.is_empty(),
                "first sweep must deploy the account"
            );
            dbtx.commit_tx().await;
            hash
        };

        // Confirm the first sweep (swept 10).
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
                        swept: UsdtAmount(10),
                    },
                )
                .await;
            let record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("record present");
            assert_eq!(record.swept, UsdtAmount(10));
            assert_eq!(record.nonce, 1, "nonce advances on the confirmed sweep");
            let pool = dbtx
                .to_ref_nc()
                .get_value(&PoolStateKey)
                .await
                .expect("pool credited");
            assert_eq!(pool.balance, UsdtAmount(10));
            // Remainder is now 0, so the success auto-retrigger enqueued nothing.
            assert!(
                pending_deploy_and_sweeps(&mut dbtx.to_ref_nc(), account)
                    .await
                    .is_empty(),
                "no re-sweep while credited == swept"
            );
            dbtx.commit_tx().await;
        }

        // A second deposit bumps credited to 20.
        {
            let mut dbtx = db.begin_transaction().await;
            let mut record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("record present");
            record.credited = UsdtAmount(20);
            dbtx.to_ref_nc()
                .insert_entry(&DepositRecordKey(account), &record)
                .await;
            dbtx.commit_tx().await;
        }

        // Re-sweep: only the remainder (10), at nonce 1, WITHOUT redeploying.
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
                UsdtAmount(10),
                "re-sweep moves only the remainder, not the full credited"
            );
            assert!(
                op.init_code.is_empty(),
                "an already-deployed account must not redeploy"
            );
            dbtx.commit_tx().await;
            hash
        };

        // Confirm the re-sweep (swept another 10).
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
                        swept: UsdtAmount(10),
                    },
                )
                .await;
            let record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("record present");
            assert_eq!(record.swept, UsdtAmount(20));
            assert_eq!(record.nonce, 2);
            let pool = dbtx
                .to_ref_nc()
                .get_value(&PoolStateKey)
                .await
                .expect("pool present");
            assert_eq!(pool.balance, UsdtAmount(20));
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

    /// Feeds threshold-many (3-of-4) identical `Deposit` votes for `obs`
    /// through `process_consensus_item`, exactly as the ordered consensus
    /// items would arrive, so the third vote runs `credit_deposit`'s
    /// sweep-aware credit rule.
    async fn vote_deposit(
        module: &Usdt,
        dbtx: &mut DatabaseTransaction<'_>,
        obs: &DepositObservation,
    ) {
        for p in [0u16, 1, 2] {
            module
                .process_consensus_item(
                    &mut dbtx.to_ref_nc(),
                    UsdtConsensusItem::Deposit(obs.clone()),
                    PeerId::from(p),
                )
                .await
                .expect("vote is not redundant");
        }
    }

    /// Shared setup for the sweep-aware credit-rule tests: drives a first
    /// deposit of 100 (observed at block 10) through the consensus vote path
    /// (which auto-enqueues its sweep), then confirms that sweep at
    /// `sweep_block` -- leaving `credited == swept == 100`, `nonce == 1`,
    /// `LastSweepBlockKey(account) == sweep_block`, and no in-flight op.
    /// Returns the swept account.
    async fn credit_100_and_confirm_sweep(
        module: &Usdt,
        sweep_block: u64,
        claim_pk_byte: u8,
    ) -> EvmAddress {
        let db = module.db_for_test();
        let claim_pk = test_pubkey(claim_pk_byte);
        let account = derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        // First deposit: 100 observed at block 10 -> credited 100, sweep of
        // the full 100 auto-enqueued at nonce 0.
        let op_hash = {
            let mut dbtx = db.begin_transaction().await;
            vote_deposit(
                module,
                &mut dbtx.to_ref_nc(),
                &DepositObservation {
                    account,
                    balance: UsdtAmount(100),
                    block: 10,
                    claim_pk,
                },
            )
            .await;
            let record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("record created by the threshold-reaching vote");
            assert_eq!(record.credited, UsdtAmount(100));
            let (hash, op) = single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
            assert_eq!(
                crate::user_op::decode_transfer_amount(&op).expect("op call_data decodes"),
                UsdtAmount(100)
            );
            dbtx.commit_tx().await;
            hash
        };

        // Confirm the sweep at `sweep_block` (swept = 100).
        promote_pending_to_submitted(db, op_hash).await;
        {
            let mut dbtx = db.begin_transaction().await;
            module
                .apply_user_op_confirmed(
                    &mut dbtx.to_ref_nc(),
                    op_hash,
                    &UserOpConfirmedObservation {
                        success: true,
                        block: sweep_block,
                        swept: UsdtAmount(100),
                    },
                )
                .await;
            let record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("record present");
            assert_eq!(record.swept, UsdtAmount(100));
            assert_eq!(
                dbtx.to_ref_nc()
                    .get_value(&LastSweepBlockKey(account))
                    .await,
                Some(sweep_block),
                "the confirmed sweep must record its consensus-agreed block"
            );
            assert!(
                pending_deploy_and_sweeps(&mut dbtx.to_ref_nc(), account)
                    .await
                    .is_empty(),
                "no re-sweep while credited == swept"
            );
            dbtx.commit_tx().await;
        }

        account
    }

    /// **Sweep-aware credit rule (deposits after a completed sweep).** A NEW
    /// deposit paid to an address whose balance was already fully swept back
    /// to `0` must credit FULLY -- under the pre-fix raw-balance rule its
    /// post-sweep balance (50) never exceeded the historic `credited` (100),
    /// so it was never credited at all and the funds were effectively lost
    /// to the depositor. Drives the whole re-arm loop end to end:
    /// deposit 100 -> credit -> sweep confirms at block 20 (swept 100) ->
    /// second deposit of 50 observed at block 25 (> 20) -> `credited`
    /// becomes `swept + balance = 150`, `claimable` reflects it, and
    /// `maybe_trigger_sweep` (auto-run by `credit_deposit`) sweeps the 50
    /// remainder at the advanced nonce.
    #[tokio::test]
    async fn post_sweep_deposit_credits_fully_and_re_arms_the_sweep() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0xe1);
        let account = credit_100_and_confirm_sweep(&module, 20, 0xe1).await;

        // Second deposit: 50 observed at block 25 > sweep block 20, so the
        // observation provably saw the post-sweep balance.
        let mut dbtx = db.begin_transaction().await;
        vote_deposit(
            &module,
            &mut dbtx.to_ref_nc(),
            &DepositObservation {
                account,
                balance: UsdtAmount(50),
                block: 25,
                claim_pk,
            },
        )
        .await;

        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record present");
        assert_eq!(
            record.credited,
            UsdtAmount(150),
            "post-sweep deposit must credit fully: swept (100) + balance (50)"
        );

        let status = module
            .handle_deposit_status(&mut dbtx.to_ref_nc(), claim_pk)
            .await;
        assert_eq!(status.credited, UsdtAmount(150));
        assert_eq!(status.claimable, UsdtAmount(150));

        // The credit auto-re-armed the sweep: the 50 remainder is enqueued
        // at the advanced nonce, without redeploying.
        let (_, op) = single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
        assert_eq!(
            crate::user_op::decode_transfer_amount(&op).expect("op call_data decodes"),
            UsdtAmount(50),
            "the re-armed sweep moves exactly the new deposit"
        );
        assert_eq!(op.nonce, alloy::primitives::U256::from(1u64));
        assert!(
            op.init_code.is_empty(),
            "an already-deployed account must not redeploy"
        );
        dbtx.commit_tx().await;
    }

    /// **Sweep-aware credit rule (straddle safety).** An observation taken
    /// BEFORE a sweep executed (its pre-sweep balance of 100 at block 15)
    /// but processed AFTER the sweep's confirm (at block 20) must NOT
    /// double-credit: `obs.block <= last_sweep_block` keeps the conservative
    /// raw-balance rule, so `credited` stays 100 and nothing is re-swept.
    #[tokio::test]
    async fn observation_straddling_a_sweep_does_not_double_credit() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0xe2);
        let account = credit_100_and_confirm_sweep(&module, 20, 0xe2).await;

        // A straggler observation of the PRE-sweep balance (100 at block
        // 15 <= sweep block 20) reaches threshold only now.
        let mut dbtx = db.begin_transaction().await;
        vote_deposit(
            &module,
            &mut dbtx.to_ref_nc(),
            &DepositObservation {
                account,
                balance: UsdtAmount(100),
                block: 15,
                claim_pk,
            },
        )
        .await;

        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record present");
        assert_eq!(
            record.credited,
            UsdtAmount(100),
            "a pre-sweep observation processed post-confirm must not credit the swept funds twice"
        );
        assert!(
            pending_deploy_and_sweeps(&mut dbtx.to_ref_nc(), account)
                .await
                .is_empty(),
            "nothing new was credited, so nothing must be re-swept"
        );
        dbtx.commit_tx().await;
    }

    /// **Sweep-aware credit rule (large post-sweep deposit).** A post-sweep
    /// deposit LARGER than the historic `credited` high-water mark must
    /// credit fully as `swept + balance`, not merely the raw-balance delta
    /// above the historic high (the pre-fix rule would have credited only
    /// `120 - 100 = 20` of the new 120).
    #[tokio::test]
    async fn post_sweep_deposit_larger_than_historic_credited_credits_fully() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0xe3);
        let account = credit_100_and_confirm_sweep(&module, 20, 0xe3).await;

        // Second deposit: 120 (> the historic credited of 100) observed at
        // block 25 > sweep block 20.
        let mut dbtx = db.begin_transaction().await;
        vote_deposit(
            &module,
            &mut dbtx.to_ref_nc(),
            &DepositObservation {
                account,
                balance: UsdtAmount(120),
                block: 25,
                claim_pk,
            },
        )
        .await;

        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record present");
        assert_eq!(
            record.credited,
            UsdtAmount(220),
            "the full 120 must credit on top of the 100 already swept, not just the 20 delta"
        );
        dbtx.commit_tx().await;
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
        let account = EvmAddress([0xd1; 20]);
        let claim_pk = test_pubkey(0xd2);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(10),
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

        // credited grows to 20 while A is still in flight; re-triggering must
        // NOT create a second op -- the per-account guard holds.
        {
            let mut dbtx = db.begin_transaction().await;
            let mut record = dbtx
                .to_ref_nc()
                .get_value(&DepositRecordKey(account))
                .await
                .expect("record present");
            record.credited = UsdtAmount(20);
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

        // Confirm A (swept 10). The success auto-retrigger now sweeps the
        // remainder as op B: nonce 1, amount 10 -- exactly one in flight.
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
                        swept: UsdtAmount(10),
                    },
                )
                .await;
            let (hash_b, op_b) =
                single_pending_deploy_and_sweep(&mut dbtx.to_ref_nc(), account).await;
            assert_ne!(hash_b, op_a, "the auto-retrigger enqueued a fresh op");
            assert_eq!(op_b.nonce, alloy::primitives::U256::from(1u64));
            assert_eq!(
                crate::user_op::decode_transfer_amount(&op_b).expect("decodes"),
                UsdtAmount(10),
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
        let account = EvmAddress([0xe1; 20]);
        let claim_pk = test_pubkey(0xe2);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(10),
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
                        swept: UsdtAmount(0),
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
                UsdtAmount(10)
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
        };
        let withdrawal_b = UsdtWithdrawalV0 {
            recipient: EvmAddress([0xb1; 20]),
            amount: UsdtAmount(2_000_000),
            max_fee: UsdtAmount(2_000),
            requested_block: 0,
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
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: true,
            block: 99,
            swept: total,
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
                    swept: total,
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

    /// **Phase 8, Task 2.** A `!success` `Withdraw`-purpose confirmation
    /// reverts its withdrawals back to `Queued` (for a later batch to
    /// retry) rather than crediting/debiting anything -- but the pool's
    /// `nonce` is STILL bumped, since a `UserOpConfirmed` observation only
    /// ever exists for an op the `EntryPoint` actually validated/included
    /// (see `Usdt::apply_withdraw_confirmed`'s doc comment).
    #[tokio::test]
    async fn user_op_confirmed_withdraw_purpose_failure_reverts_to_queued_but_still_bumps_nonce() {
        let module = test_module_with_block_count(4, 0).await; // threshold = 3
        let db = module.db_for_test();

        let op_hash = [0xb2; 32];
        let out_point = test_out_point(9);
        let withdrawal = UsdtWithdrawalV0 {
            recipient: EvmAddress([0xd1; 20]),
            amount: UsdtAmount(1_500_000),
            max_fee: UsdtAmount(500),
            requested_block: 0,
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
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let obs = UsdtConsensusItem::UserOpConfirmed {
            op_hash,
            success: false,
            block: 101,
            swept: UsdtAmount(0),
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

        let state = dbtx
            .to_ref_nc()
            .get_value(&WithdrawalStateKey(out_point))
            .await
            .expect("WithdrawalState present");
        assert_eq!(
            state,
            WithdrawalState::Queued,
            "a failed batch must revert its withdrawals to Queued for retry"
        );
        assert_eq!(
            dbtx.to_ref_nc()
                .get_value(&UnclaimedWithdrawalKey(out_point))
                .await,
            Some(withdrawal),
            "UnclaimedWithdrawal must survive a failed batch unchanged, for retry"
        );
        assert!(
            dbtx.to_ref_nc()
                .get_value(&SubmittedUserOpKey(op_hash))
                .await
                .is_none()
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
                    swept: amount,
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
        dbtx.insert_new_entry(&FeeVoteKey(PeerId::from(0)), &sample_fee_vote())
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
                claim_pk,
            },
        )
        .await;
        dbtx.insert_new_entry(
            &PendingCheckKey(account),
            &PendingCheck {
                claim_pk,
                requested_at_block: 1,
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
                swept: UsdtAmount(1_000_000),
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
            },
        )
        .await;
        dbtx.insert_new_entry(&WithdrawalStateKey(out_point), &WithdrawalState::Queued)
            .await;
        dbtx.insert_new_entry(&BootstrapVoteKey(PeerId::from(0)), &ready_observation())
            .await;
        dbtx.insert_new_entry(&HasEverBeenReadyKey, &()).await;
        dbtx.insert_new_entry(&LastSweepBlockKey(account), &7u64)
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
            "Pending Checks",
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
            "Last Sweep Blocks",
        ];
        assert_eq!(
            dumped.len(),
            expected_labels.len(),
            "dump_database must produce exactly one entry per DbKeyPrefix variant (0x01..=0x10)"
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
                    actual_gas_cost_wei: UsdtAmount(0),
                },
            );
        }

        let user_op_confirmed_proposals = Arc::new(Mutex::new(Vec::new()));
        let task_group = TaskGroup::new();
        Usdt::spawn_user_op_submitter(
            &task_group,
            UserOpSubmitterHandles {
                db: db.clone(),
                evm_rpc: evm_rpc.into_dyn(),
                user_op_confirmed_proposals: user_op_confirmed_proposals.clone(),
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
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        let user_op_confirmed_proposals = Arc::new(Mutex::new(Vec::new()));
        let task_group = TaskGroup::new();
        Usdt::spawn_user_op_submitter(
            &task_group,
            UserOpSubmitterHandles {
                db: db.clone(),
                evm_rpc: evm_rpc.into_dyn(),
                user_op_confirmed_proposals: user_op_confirmed_proposals.clone(),
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
                        swept: UsdtAmount(999_999_999),
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
                        swept: real_amount,
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
                        swept: UsdtAmount(1),
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
                        swept: real_total,
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
