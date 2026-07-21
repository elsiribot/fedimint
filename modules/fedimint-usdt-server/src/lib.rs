#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, ensure};
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
    FM_ENABLE_MODULE_USDT_ENV, FM_USDT_CONTRACT_ENV, FM_USDT_EVM_RPC_URL_ENV, is_env_var_set_opt,
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
use fedimint_core::{Amount, InPoint, NumPeers, NumPeersExt, OutPoint, PeerId, push_db_pair_items};
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, EnvVarDoc, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use fedimint_threshold_ecdsa::{convert_signature, group_public_key};
pub use fedimint_usdt_common as common;
use fedimint_usdt_common::config::UsdtClientConfig;
use fedimint_usdt_common::endpoint_constants::{
    CHECK_DEPOSIT_ENDPOINT, DEBUG_START_SIGNING_ENDPOINT, DEBUG_SUPPRESS_ATTEMPT0_ROUND_ENDPOINT,
    DEPOSIT_STATUS_ENDPOINT, GROUP_PUBLIC_KEY_ENDPOINT, POOL_STATE_ENDPOINT,
    SIGNING_SESSION_STATUS_ENDPOINT, USEROP_STATUS_ENDPOINT, WITHDRAW_FEE_QUOTE_ENDPOINT,
    WITHDRAWAL_STATUS_ENDPOINT,
};
use fedimint_usdt_common::user_op::{SignedUserOp, eth_signed_message_hash, user_op_hash};
use fedimint_usdt_common::{
    CheckDepositRequest, CheckDepositResponse, DepositObservation, DepositStatusRequest,
    DepositStatusResponse, FeeVote, MODULE_CONSENSUS_VERSION, MPC_ROUND_CHUNK_SIZE, MpcRoundItem,
    PoolStateResponse, SigningSessionId, USDT_UNIT, UsdtAmount, UsdtCommonInit, UsdtConsensusItem,
    UsdtInput, UsdtInputError, UsdtModuleTypes, UsdtOutput, UsdtOutputError, UsdtOutputOutcome,
    UserOpStatus, UserOpStatusRequest, UserOpStatusResponse, WithdrawFeeQuoteRequest,
    WithdrawFeeQuoteResponse, WithdrawalStatus, WithdrawalStatusRequest, WithdrawalStatusResponse,
    derive_deposit_account, derive_pool_account, evm_address, signing_session_id,
    withdrawal_fee_quote,
};
use futures::StreamExt as _;
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use tracing::{debug, warn};

use crate::config::{UsdtConfig, UsdtConfigConsensus, UsdtConfigLocal, UsdtConfigPrivate};
use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, DbKeyPrefix, DepositObservationVoteAccountPrefix,
    DepositObservationVoteKey, DepositObservationVotePrefix, DepositRecord, DepositRecordKey,
    DepositRecordPrefix, FeeVoteKey, FeeVotePrefix, MpcRoundChunk, MpcRoundChunkKey,
    MpcRoundChunkPrefix, MpcRoundChunkSessionRoundPrefix, PendingCheck, PendingCheckKey,
    PendingCheckPrefix, PendingUserOp, PendingUserOpKey, PendingUserOpPrefix, PoolState,
    PoolStateKey, PoolStatePrefix, SessionState, SigningPurpose, SigningSession, SigningSessionKey,
    SigningSessionPrefix, SubmittedUserOp, SubmittedUserOpKey, SubmittedUserOpPrefix,
    UnclaimedWithdrawalKey, UnclaimedWithdrawalPrefix, UsdtWithdrawalV0,
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

pub mod config;
pub mod db;
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
            }
        }

        Box::new(items.into_iter())
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

        let mut params = fedimint_usdt_common::UsdtGenParams::default();

        if let Ok(contract) = std::env::var(FM_USDT_CONTRACT_ENV)
            && !contract.is_empty()
        {
            params.usdt_contract = contract.parse().unwrap_or_else(|err| {
                panic!("{FM_USDT_CONTRACT_ENV} must be a valid EvmAddress: {err}")
            });
        }

        params
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
                name: FM_USDT_CONTRACT_ENV,
                description: "Overrides the default instance's `usdt_contract` config-gen param (a 0x-prefixed 20-byte hex EVM address) for the config-gen leader.",
            },
        ]
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        let cfg: UsdtConfig = args.cfg().to_typed()?;

        // Factory-config setup-validation guard (Phase 9, Task 1 hardening;
        // deferred from Phase 7/9). We cannot RPC the configured
        // `account_factory.getAddress` here to fully cross-check it against
        // `derive_deposit_account` without complicating module startup
        // (ordering a live EVM RPC call before the module -- which owns the
        // RPC client -- is even constructed), so this is deliberately a
        // pragmatic, LOCAL-only check: warn if `account_factory` or
        // `simple_account_impl` is still the compiled-in all-zero
        // placeholder (`EvmAddress([0u8; 20])`, see
        // `fedimint_usdt_common::UsdtGenParams::default`).
        //
        // The real hazard this guards against: a real deployment's
        // `account_factory`/`simple_account_impl` MUST point at a deployed
        // `SimpleAccountFactory`/`SimpleAccount` whose on-chain CREATE2
        // `initCodeHash` matches this build's vendored
        // `ERC1967_PROXY_CREATION_CODE` (see
        // `fedimint_usdt_common::derive_deposit_account`'s doc comment). If
        // it doesn't -- e.g. a mis-compiled or wrong-version factory -- every
        // off-chain-derived deposit address disagrees with the real
        // on-chain `account_factory.getAddress`, and any USDT sent to the
        // (wrong) derived address becomes UNSPENDABLE. A guardian operator
        // MUST independently verify this off-chain before going live (see
        // the ops runbook); this check can only catch the placeholder case.
        //
        // Deliberately non-fatal (`warn!`, never `Err`): hermetic tests
        // routinely construct modules with the placeholder (no real EVM
        // stack deployed), and erroring here would break them.
        if cfg.consensus.account_factory.0 == [0u8; 20]
            || cfg.consensus.simple_account_impl.0 == [0u8; 20]
        {
            warn!(
                account_factory = %cfg.consensus.account_factory,
                simple_account_impl = %cfg.consensus.simple_account_impl,
                "USDT module configured with a placeholder account_factory/simple_account_impl \
                 (all-zero address). Deposit-account derivation will not match any real \
                 on-chain factory. This is expected for hermetic tests, but a real deployment \
                 MUST configure both to a deployed SimpleAccountFactory/SimpleAccount whose \
                 CREATE2 initCodeHash matches this build's vendored ERC1967_PROXY_CREATION_CODE, \
                 or deposits sent to derived addresses will be unspendable."
            );
        }

        let evm_rpc = if let Some(evm_rpc) = &self.evm_rpc_override {
            evm_rpc.clone()
        } else {
            let evm_rpc_url = std::env::var(FM_USDT_EVM_RPC_URL_ENV)
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| cfg.private.local.evm_rpc_url.clone());
            let mut rpc =
                AlloyEvmRpc::new(&evm_rpc_url)?.with_entry_point(cfg.consensus.entry_point);
            if let Some(broadcaster_private_key) = &cfg.private.local.broadcaster_private_key {
                rpc = rpc.with_broadcaster(broadcaster_private_key)?;
            }
            rpc.into_dyn()
        };
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
        let num_peers = peers.to_num_peers();
        let n = u16::try_from(num_peers.total())
            .expect("federation sizes fit in u16 in every supported deployment");
        let threshold = u16::try_from(num_peers.threshold())
            .expect("federation sizes fit in u16 in every supported deployment");

        let shares = cggmp21::trusted_dealer::builder::<fedimint_threshold_ecdsa::Curve, _>(n)
            .set_threshold(Some(threshold))
            .hd_wallet(true)
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
    /// Digests queued by the test-only `debug_start_signing` API endpoint
    /// (Phase-6a scaffolding; not access-gated — see the endpoint), drained
    /// into
    /// `UsdtConsensusItem::StartSigning` proposals in `consensus_proposal`.
    /// Mirrors `deposit_proposals`'s drain pattern. A test needs only to
    /// call `debug_start_signing` on ONE guardian: the resulting consensus
    /// item starts the session identically on every guardian (see
    /// `UsdtConsensusItem::StartSigning`'s doc comment for why this must go
    /// through consensus rather than being called per-guardian directly).
    pending_signing_starts: Arc<Mutex<Vec<[u8; 32]>>>,
    /// Signatures this guardian's off-thread signers have assembled and are
    /// awaiting federation-wide agreement (Phase 6b): pushed by
    /// [`Usdt::advance_local_signer`] alongside (not instead of) its
    /// `completed_signatures` write, drained into
    /// `UsdtConsensusItem::MpcSignature` proposals in `consensus_proposal`.
    /// Mirrors `pending_signing_starts`'s drain pattern.
    #[allow(clippy::type_complexity)]
    pending_signature_proposals: Arc<Mutex<Vec<(SigningSessionId, Vec<u8>)>>>,
    /// Test-only (Phase 6b Task 4 harness): when set, this guardian skips
    /// proposing `MpcRound` items for attempt-0 signing sessions in
    /// `consensus_proposal`, letting a test force attempt 0 to stall (and
    /// eventually time out) without a real killed guardian. Toggled by the
    /// `debug_suppress_attempt0_round` API endpoint; see
    /// `DEBUG_SUPPRESS_ATTEMPT0_ROUND_ENDPOINT`'s doc comment for why the
    /// `fedimint-testing` degraded-federation fixture can't be used here
    /// instead. Purely guardian-local — never read by `process_consensus_item`
    /// or folded into any consensus-DB write or `Ok`/`Err` decision.
    suppress_attempt0_round: Arc<AtomicBool>,
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

            // Test-only (Phase 6b Task 4 harness): a guardian with
            // suppression toggled on never proposes `MpcRound` items for
            // attempt-0 sessions, so the round can never reach 3-of-3 and
            // the session stalls until it times out. Scoped to attempt 0
            // only, so a rotated later attempt is unaffected. See
            // `suppress_attempt0_round`'s doc comment.
            if session.attempt == 0 && self.suppress_attempt0_round.load(Ordering::Relaxed) {
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

        // Drain digests queued by the test-only `debug_start_signing` API
        // endpoint, proposing a `StartSigning` consensus item for each so
        // every guardian starts the session atomically in consensus order
        // (see `UsdtConsensusItem::StartSigning`'s doc comment).
        let pending_starts =
            std::mem::take(&mut *self.pending_signing_starts.lock().expect("not poisoned"));
        for digest in pending_starts {
            items.push(UsdtConsensusItem::StartSigning { digest });
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
            UsdtConsensusItem::StartSigning { digest } => {
                // DETERMINISTIC (mirrors the `MpcRound` arm's discipline): a
                // pure function of the item, prior consensus-DB state, and
                // config. `start_session` is idempotent (it no-ops if the
                // session already exists), so the redundancy guard here must
                // check FIRST and reject a repeat proposal rather than
                // silently no-op-`Ok`ing it (the unbounded-history rule).
                // `our_peer_id` never influences this `Ok`/`Err` or the
                // consensus-DB write below -- only whether `start_session`
                // additionally spawns this guardian's in-memory off-thread
                // state machine, a guardian-local side effect.
                let session_id = signing_session_id(&digest, 0);
                if dbtx
                    .get_value(&SigningSessionKey(session_id))
                    .await
                    .is_some()
                {
                    bail!("redundant StartSigning");
                }

                self.start_session(dbtx, SigningPurpose::Test(digest), digest, 0)
                    .await;

                Ok(())
            }
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
            UsdtConsensusItem::Default { .. } => {
                bail!("The usdt module does not support this consensus item yet")
            }
        }
    }

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
        // `saturating_add` (Phase 9, Task 1 hardening, N1): `claimed` is
        // already bounded above by `credited` (a real, finite on-chain
        // balance) via the `available` check just above, so this can never
        // actually saturate -- but a deterministic saturate is strictly
        // safer than a deterministic panic on the (unreachable in practice)
        // chance of a `u64` overflow, and saturation is exactly as
        // reproducible across guardians as a raw `+` would be (still a pure
        // function of the two operands).
        record.claimed = UsdtAmount(record.claimed.0.saturating_add(input.amount.0));
        dbtx.insert_entry(&DepositRecordKey(input.account), &record)
            .await;

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_custom(USDT_UNIT, Amount::from_msats(input.amount.0)),
                fees: Amounts::ZERO,
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

        Ok(TransactionItemAmounts {
            amounts: Amounts::new_custom(USDT_UNIT, Amount::from_msats(withdrawal.amount.0)),
            fees: Amounts::new_custom(USDT_UNIT, Amount::from_msats(withdrawal.max_fee.0)),
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
                DEBUG_START_SIGNING_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, _context, digest: [u8; 32]| -> () {
                    // Phase-6a debug/scaffolding trigger: queues `digest` so
                    // this guardian proposes a `StartSigning` consensus item,
                    // which deterministically starts the session on every
                    // guardian (see `DEBUG_START_SIGNING_ENDPOINT`'s doc
                    // comment for why session start must go through consensus).
                    // Phase 7 replaces this with deterministic session creation
                    // from pending sign-request records and removes this
                    // endpoint. It is intentionally not access-gated here: the
                    // usdt module is experimental and opt-in
                    // (`FM_ENABLE_MODULE_USDT`), so the endpoint only exists on
                    // federations that deliberately enabled it, and in Phase 6a
                    // a triggered signing session has no on-chain effect.
                    module
                        .pending_signing_starts
                        .lock()
                        .expect("not poisoned")
                        .push(digest);

                    Ok(())
                }
            },
            api_endpoint! {
                SIGNING_SESSION_STATUS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Usdt, context, session_id: SigningSessionId| -> Option<Vec<u8>> {
                    // Read-only: reads the federation-agreed consensus state
                    // (Phase 6b), so any guardian -- not just a signer -- can
                    // answer authoritatively (see
                    // `SIGNING_SESSION_STATUS_ENDPOINT`'s doc comment).
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    let session = dbtx.get_value(&SigningSessionKey(session_id)).await;

                    Ok(match session.map(|s| s.state) {
                        Some(SessionState::Completed(sig)) => Some(sig),
                        _ => None,
                    })
                }
            },
            api_endpoint! {
                DEBUG_SUPPRESS_ATTEMPT0_ROUND_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Usdt, _context, suppress: bool| -> () {
                    // Test-only (Phase 6b Task 4 harness); see
                    // `DEBUG_SUPPRESS_ATTEMPT0_ROUND_ENDPOINT`'s doc comment.
                    // Purely guardian-local: never touches the consensus DB.
                    module
                        .suppress_attempt0_round
                        .store(suppress, Ordering::Relaxed);

                    Ok(())
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
                    // mirroring `deposit_status`). Before any `FeeVote` has
                    // landed, `max_fee` reports `0` (a sentinel meaning "no
                    // quote yet", mirroring `deposit_status`'s
                    // pre-credit-zeros shape) rather than erroring --
                    // `process_output` is what actually enforces
                    // `NoFeeQuoteAvailable`; a `0` quote here can never be
                    // used to withdraw for free, since any `max_fee` (even
                    // `0`) still needs `process_output`'s own median lookup
                    // to succeed at the point the transaction lands.
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    let median = module.fee_vote_median(&mut dbtx.to_ref_nc()).await;
                    let max_fee = median
                        .and_then(|median| withdrawal_fee_quote(&median))
                        .unwrap_or(UsdtAmount(0));

                    Ok(WithdrawFeeQuoteResponse {
                        max_fee,
                        valid_blocks: WITHDRAW_QUOTE_VALID_BLOCKS,
                    })
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
        ]
    }
}

/// Advisory (non-enforced) number of further guardian-observed EVM blocks a
/// `withdraw_fee_quote` response should be treated as valid for before
/// re-querying, since the fee-vote-median-derived quote can move as
/// guardians' individual `FeeVote`s change. Not read by any consensus
/// decision -- `process_output` always re-derives the quote fresh from the
/// median at the block it processes the output, regardless of how stale a
/// client's cached quote is.
const WITHDRAW_QUOTE_VALID_BLOCKS: u64 = 50;

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
            pending_signing_starts: Arc::new(Mutex::new(Vec::new())),
            pending_signature_proposals: Arc::new(Mutex::new(Vec::new())),
            suppress_attempt0_round: Arc::new(AtomicBool::new(false)),
            user_op_confirmed_proposals,
            fee_estimate,
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
            pending_signing_starts: Arc::new(Mutex::new(Vec::new())),
            pending_signature_proposals: Arc::new(Mutex::new(Vec::new())),
            suppress_attempt0_round: Arc::new(AtomicBool::new(false)),
            user_op_confirmed_proposals: Arc::new(Mutex::new(Vec::new())),
            fee_estimate: Arc::new(Mutex::new(None)),
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
                match evm_rpc.get_block_number().await {
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
                match evm_rpc.get_fee_estimate().await {
                    Ok(vote) => {
                        *fee_estimate.lock().expect("not poisoned") = Some(vote);
                    }
                    Err(err) => {
                        warn!(
                            target: "usdt",
                            err = %err.fmt_compact_anyhow(),
                            "fee estimate poll failed"
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

    /// Spawns a background task that periodically scans this guardian's
    /// [`PendingCheck`]s (see [`scan_pending_deposits`]) and extends
    /// `deposit_proposals` with any newly observed deposits, for
    /// `consensus_proposal` to drain into `UsdtConsensusItem::Deposit`
    /// proposals.
    ///
    /// Like [`Usdt::spawn_block_count_poller`], this task only *reads* the
    /// module DB (via `db.begin_transaction_nc()`) and never commits writes
    /// to it: fedimint server-module background tasks must not commit
    /// writes to the module DB outside the consensus flow. All
    /// `PendingCheck` writes happen in the check-deposit API handler and in
    /// [`Usdt::credit_deposit`] (via `process_consensus_item`), never from a
    /// background task.
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

                for (SubmittedUserOpKey(op_hash), record) in submitted {
                    // Idempotent, guardian-local: errors (including "already
                    // included") are swallowed and simply retried next tick.
                    if let Err(err) = evm_rpc.submit_user_ops(vec![record.signed.clone()]).await {
                        debug!(
                            target: "usdt",
                            err = %err.fmt_compact_anyhow(),
                            ?op_hash,
                            "UserOp submission failed, retrying next tick"
                        );
                    }

                    match evm_rpc.get_user_op_receipt(op_hash).await {
                        Ok(Some(receipt)) => {
                            // `swept` doubles as "amount moved by this op":
                            // swept-TO-the-pool for `DeployAndSweep`,
                            // paid-OUT-of-the-pool for `Withdraw` (Phase 8,
                            // Task 2) -- both decoded from the already
                            // federation-agreed `op`'s own calldata, never
                            // from the RPC response, per this fn's own doc
                            // comment.
                            let swept = if receipt.success {
                                match &record.purpose {
                                    UserOpPurpose::DeployAndSweep { .. } => {
                                        crate::user_op::decode_transfer_amount(
                                            &record.signed.unsigned,
                                        )
                                        .unwrap_or(UsdtAmount(0))
                                    }
                                    UserOpPurpose::Withdraw { .. } => {
                                        crate::user_op::decode_batch_transfer_total(
                                            &record.signed.unsigned,
                                        )
                                        .unwrap_or(UsdtAmount(0))
                                    }
                                }
                            } else {
                                UsdtAmount(0)
                            };
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
    /// does not exist yet, advances `credited` monotonically forward to
    /// `obs.balance` (balance is monotonic between sweeps since only the
    /// federation moves funds out), updates `last_observed_block`, and
    /// clears the round's votes and the account's `PendingCheck`.
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
            });
        // Only credit forward; balance is monotonic between sweeps.
        if obs.balance.0 > record.credited.0 {
            record.credited = obs.balance;
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
    /// `account`'s [`DepositRecord`] has credit that has never been swept
    /// (`record.swept.0 == 0`) -- i.e. this account has not yet completed
    /// its (Phase-7-scoped, first-and-only) sweep. Called from
    /// [`Usdt::credit_deposit`], right after the credit write, so it always
    /// observes the freshest `DepositRecord`.
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
    /// # Scope (Phase 7)
    ///
    /// `nonce` is always `0` and `needs_deploy` is always `true`: this phase
    /// only handles a counterfactual account's FIRST sweep. The
    /// `record.swept.0 == 0` guard prevents ever building a second,
    /// nonce-colliding op for an account that has already completed one
    /// (which would revert on-chain with an invalid-nonce error); a second
    /// deposit arriving before the first sweep confirms instead
    /// transparently supersedes the still-`Pending`/`Submitted` op with a
    /// fresh, higher-`amount` one (same nonce 0, since the account is still
    /// undeployed) -- the stale op's `PendingUserOp`/`SubmittedUserOp`
    /// record, if any, is simply left orphaned in the DB (harmless: it can
    /// never be confirmed for a different amount than what's actually on
    /// the sender's balance, and Task 5's acceptance only exercises the
    /// single-deposit case). Consolidating multiple sweeps into one
    /// account's lifetime, or handling withdrawals, is Phase 8's `Withdraw`
    /// `UserOpPurpose`.
    async fn maybe_trigger_sweep(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        account: fedimint_usdt_common::EvmAddress,
    ) {
        let Some(record) = dbtx.get_value(&DepositRecordKey(account)).await else {
            return;
        };
        if record.swept.0 != 0 || record.credited.0 == 0 {
            return;
        }

        let owner = evm_address(&self.cfg.consensus.group_public_key);
        let params = DeployAndSweepParams {
            account_factory: self.cfg.consensus.account_factory,
            usdt_contract: self.cfg.consensus.usdt_contract,
            deposit_account: account,
            owner,
            claim_pk: record.claim_pk,
            amount: record.credited,
            pool: self.pool_account(),
            nonce: alloy::primitives::U256::ZERO,
            needs_deploy: true,
            paymaster_and_data: Vec::new(),
            gas_bounds: GasBounds::DEPLOY_AND_SWEEP_DEVNET,
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

        // Same consensus-ordered `start_session` path Phase 6a's
        // `debug_start_signing` uses -- every guardian processes this
        // identical `Deposit` item, so every guardian starts the identical
        // session deterministically (no separate `StartSigning` consensus
        // item needed: unlike the debug endpoint, which fans a single
        // guardian's local trigger out through consensus, this trigger is
        // ALREADY inside `process_consensus_item`, so it runs on every
        // guardian directly).
        let digest = eth_signed_message_hash(op_hash);
        self.start_session(dbtx, SigningPurpose::UserOp(op_hash), digest, 0)
            .await;
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
        if pending
            .iter()
            .any(|(_, p)| matches!(p.purpose, UserOpPurpose::Withdraw { .. }))
        {
            return true;
        }

        let submitted: Vec<(SubmittedUserOpKey, SubmittedUserOp)> = dbtx
            .find_by_prefix(&SubmittedUserOpPrefix)
            .await
            .collect()
            .await;
        submitted
            .iter()
            .any(|(_, s)| matches!(s.purpose, UserOpPurpose::Withdraw { .. }))
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

        let outpoints: Vec<OutPoint> = queued.iter().map(|(o, _)| *o).collect();
        let withdrawals: Vec<(fedimint_usdt_common::EvmAddress, UsdtAmount)> = queued
            .iter()
            .map(|(_, w)| (w.recipient, w.amount))
            .collect();

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
            gas_bounds: GasBounds::withdrawal_batch(withdrawals.len(), needs_deploy),
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
    /// `PoolState.balance` by `obs.swept` and marks the corresponding
    /// [`DepositRecord`] (recovered from the op's own `sender`, i.e. the
    /// swept deposit account) as swept forward (Phase 7 behavior,
    /// unchanged); a `Withdraw` op settles the covered withdrawals -- see
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

        match &submitted.purpose {
            UserOpPurpose::DeployAndSweep { .. } => {
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
                    pool.balance = UsdtAmount(pool.balance.0.saturating_add(obs.swept.0));
                    dbtx.insert_entry(&PoolStateKey, &pool).await;

                    let source = submitted.signed.unsigned.sender;
                    if let Some(mut record) = dbtx.get_value(&DepositRecordKey(source)).await {
                        record.swept = UsdtAmount(
                            record
                                .swept
                                .0
                                .saturating_add(obs.swept.0)
                                .min(record.credited.0),
                        );
                        dbtx.insert_entry(&DepositRecordKey(source), &record).await;
                    }
                }
            }
            UserOpPurpose::Withdraw { outpoints } => {
                self.apply_withdraw_confirmed(dbtx, outpoints, obs).await;
            }
        }

        dbtx.remove_entry(&SubmittedUserOpKey(op_hash)).await;
        dbtx.remove_by_prefix(&UserOpConfirmedVoteOpPrefix(op_hash))
            .await;
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
    /// On `success`: debits `PoolState.balance` by `obs.swept` (the total
    /// actually paid out, decoded from the agreed op's own calldata --
    /// see [`crate::user_op::decode_batch_transfer_total`]), marks every
    /// `outpoints` withdrawal `WithdrawalState::Confirmed { block: obs.block
    /// }`, and removes its now-settled `UnclaimedWithdrawal` (so `Usdt::audit`
    /// stops subtracting it -- see that method's doc comment for the
    /// solvency argument).
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
    async fn apply_withdraw_confirmed(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        outpoints: &[OutPoint],
        obs: &UserOpConfirmedObservation,
    ) {
        let mut pool = dbtx.get_value(&PoolStateKey).await.unwrap_or(PoolState {
            account: self.pool_account(),
            balance: UsdtAmount(0),
            nonce: 0,
        });
        pool.nonce += 1;

        if obs.success {
            pool.balance = UsdtAmount(pool.balance.0.saturating_sub(obs.swept.0));
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
    }

    /// Derives `claim_pk`'s deposit account and enqueues a guardian-local
    /// [`PendingCheck`] for it, so this guardian's deposit-checker task (see
    /// [`scan_pending_deposits`]) starts watching that address. Idempotent:
    /// if a `PendingCheck` already exists for the account, it is left
    /// untouched.
    ///
    /// The response only ever carries `account` (deterministic from
    /// `claim_pk`), never whether this call is what enqueued the
    /// `PendingCheck`: that is guardian-local state and would let honest
    /// guardians return different responses to the same request, breaking
    /// the threshold-identical response requirement of
    /// `request_current_consensus`.
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

        if dbtx.get_value(&PendingCheckKey(account)).await.is_some() {
            return CheckDepositResponse { account };
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

        CheckDepositResponse { account }
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
            // the consensus DB or the `Ok`/`Err` decision.
            if session.signers.contains(&self.our_peer_id) {
                let mut payloads = Vec::with_capacity(signers.len());
                for peer in &signers {
                    let peer_chunks = chunks_by_peer
                        .get(peer)
                        .expect("every signer was just confirmed complete");
                    let mut reassembled = Vec::new();
                    for idx in 0..u16::try_from(peer_chunks.len()).expect("chunk count fits in u16")
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
    /// **`UserOp` finalization (Phase 7, Task 5).** If `session.purpose` is
    /// `SigningPurpose::UserOp(op_hash)`, this ALSO assembles the 65-byte
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
    /// either everything here commits or (only in the unreachable case
    /// `assemble_eth_signature` fails, which the verified-signature
    /// precondition rules out) nothing does.
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

        // Prepare the UserOp-finalization write (if any) BEFORE any write
        // happens below -- see this method's doc comment.
        let finalized_user_op = if let SigningPurpose::UserOp(op_hash) = session.purpose {
            match dbtx.get_value(&PendingUserOpKey(op_hash)).await {
                Some(pending) => {
                    let compact: [u8; 64] = signature.as_slice().try_into().map_err(|_| {
                        anyhow::anyhow!("MPC signature is not the expected 64-byte compact length")
                    })?;
                    let owner = evm_address(&self.cfg.consensus.group_public_key);
                    let eth_sig =
                        assemble_eth_signature(compact, session.digest, owner).map_err(|err| {
                            anyhow::anyhow!(
                                "failed to assemble the Ethereum signature for completed \
                                 UserOp session {session_id:?} (op_hash {op_hash:?}): {err}"
                            )
                        })?;
                    Some((op_hash, pending, eth_sig))
                }
                // Already finalized by a racing attempt of the same digest
                // that reached `Completed` first; nothing left to do.
                None => None,
            }
        } else {
            None
        };

        let mut completed = session;
        completed.state = SessionState::Completed(signature);
        dbtx.insert_entry(&SigningSessionKey(session_id), &completed)
            .await;

        if let Some((op_hash, pending, eth_sig)) = finalized_user_op {
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
        }

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
/// few withdrawals are queued (Phase 8, Task 2). Small under
/// `is_running_in_test_env()`, mirroring [`timeout_blocks`] -- both values
/// are otherwise arbitrary policy knobs (bounding worst-case withdrawal
/// latency vs. batching efficiency) with no consensus-correctness
/// requirement beyond "every guardian computes the same one" (which
/// `is_running_in_test_env()` does, being a pure function of the process
/// environment, identical across a test federation's guardians).
fn batch_interval_blocks() -> u64 {
    if is_running_in_test_env() { 3 } else { 200 }
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
/// TTL-expired `PendingCheck`s are skipped (not deleted): garbage-collecting
/// them is deferred, since deleting from a read-only scan would violate the
/// pure-reader constraint above.
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
        // Phase 9: stale expired PendingChecks are skipped here but not yet
        // garbage-collected.
        if check.requested_at_block + check_ttl_blocks < ccount {
            continue;
        }

        if at > cached_head {
            // This guardian's own EVM node hasn't confirmed that block yet;
            // retry next tick.
            continue;
        }

        let balance = match evm_rpc.get_erc20_balance(usdt_contract, account, at).await {
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

#[cfg(test)]
mod tests {
    use fedimint_core::bitcoin::Network;
    use fedimint_core::{BitcoinHash, PeerId, TransactionId};
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

        /// Every `SignedUserOp` batch previously passed to
        /// `submit_user_ops`, in call order.
        #[allow(dead_code)]
        fn submitted_user_ops(&self) -> Vec<Vec<fedimint_usdt_common::user_op::SignedUserOp>> {
            self.submitted_user_ops
                .lock()
                .expect("not poisoned")
                .clone()
        }
    }

    #[async_trait::async_trait]
    impl crate::rpc::IServerEvmRpc for MockEvmRpc {
        async fn get_chain_id(&self) -> anyhow::Result<u64> {
            Ok(0)
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

        async fn get_fee_estimate(&self) -> anyhow::Result<fedimint_usdt_common::FeeVote> {
            Ok(fedimint_usdt_common::FeeVote {
                max_fee_per_gas_wei: 0,
                usdt_per_eth_e6: 0,
            })
        }

        async fn get_code_len(
            &self,
            _addr: fedimint_usdt_common::EvmAddress,
        ) -> anyhow::Result<usize> {
            Ok(0)
        }

        async fn send_raw_transaction(&self, _signed_tx: Vec<u8>) -> anyhow::Result<[u8; 32]> {
            Ok([0u8; 32])
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
            Ok(self
                .user_op_receipts
                .lock()
                .expect("not poisoned")
                .get(&user_op_hash)
                .copied())
        }
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
        let mut dbtx = db.begin_transaction().await;

        // First two votes just accumulate below threshold, no error yet.
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

        // Third vote reaches threshold and triggers `credit_deposit`, which
        // must reject the mismatched claim_pk/account pairing.
        let err = module
            .process_consensus_item(
                &mut dbtx.to_ref_nc(),
                UsdtConsensusItem::Deposit(obs.clone()),
                PeerId::from(2),
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("does not derive its account"));

        assert!(
            dbtx.to_ref_nc()
                .get_value(&DepositRecordKey(wrong_account))
                .await
                .is_none(),
            "no DepositRecord must be created for a self-authentication failure"
        );
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
            purpose: SigningPurpose::Test([7; 32]),
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
        let purpose = SigningPurpose::Test(digest);

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

        // The expired PendingCheck must NOT have been deleted: removal of
        // stale expired entries is deferred to Phase 9 (see
        // `scan_pending_deposits`'s doc comment).
        let mut dbtx = db.begin_transaction_nc().await;
        assert!(
            dbtx.get_value(&PendingCheckKey(account)).await.is_some(),
            "the read-only scan must not delete the PendingCheck"
        );
    }

    #[tokio::test]
    async fn process_input_claims_credited_deposit_and_guards_against_double_claim() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let account = EvmAddress([0x55; 20]);
        let claim_pk = test_pubkey(0xee);

        {
            let mut dbtx = db.begin_transaction().await;
            dbtx.insert_new_entry(
                &DepositRecordKey(account),
                &DepositRecord {
                    claim_pk,
                    credited: UsdtAmount(5_000_000),
                    claimed: UsdtAmount(0),
                    last_observed_block: 0,
                    swept: UsdtAmount(0),
                },
            )
            .await;
            dbtx.commit_tx().await;
        }

        // First claim of 2M succeeds, funding USDT_UNIT and bumping `claimed`.
        let mut dbtx = db.begin_transaction().await;
        let meta = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: UsdtAmount(2_000_000),
                }),
                test_in_point(),
            )
            .await
            .expect("first claim within credited balance must succeed");
        assert_eq!(
            meta.amount.amounts,
            Amounts::new_custom(USDT_UNIT, Amount::from_msats(2_000_000))
        );
        assert_eq!(meta.amount.fees, Amounts::ZERO);
        assert_eq!(meta.pub_key, claim_pk);
        dbtx.commit_tx().await;

        let record = db
            .begin_transaction_nc()
            .await
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record still exists");
        assert_eq!(record.claimed, UsdtAmount(2_000_000));

        // Second claim of 2M succeeds (4M of 5M now claimed).
        let mut dbtx = db.begin_transaction().await;
        module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: UsdtAmount(2_000_000),
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
        assert_eq!(record.claimed, UsdtAmount(4_000_000));

        // Third claim of 2M exceeds the remaining 1M: double-claim/over-claim guard.
        let mut dbtx = db.begin_transaction().await;
        let err = module
            .process_input(
                &mut dbtx.to_ref_nc(),
                &UsdtInput::V0(UsdtInputV0 {
                    account,
                    amount: UsdtAmount(2_000_000),
                }),
                test_in_point(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            err,
            UsdtInputError::InsufficientCredit {
                available: UsdtAmount(1_000_000),
                requested: UsdtAmount(2_000_000),
            }
        );

        // `claimed` must not have been bumped by the rejected claim.
        let record = dbtx
            .to_ref_nc()
            .get_value(&DepositRecordKey(account))
            .await
            .expect("record still exists");
        assert_eq!(record.claimed, UsdtAmount(4_000_000));
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
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x01);
        let expected_account = fedimint_usdt_common::derive_deposit_account(
            &module.cfg.consensus.group_public_key,
            module.cfg.consensus.account_factory,
            module.cfg.consensus.simple_account_impl,
            &claim_pk,
        );

        // First call: derives the account and enqueues a PendingCheck.
        let mut dbtx = db.begin_transaction().await;
        let response = module
            .handle_check_deposit(&mut dbtx.to_ref_nc(), claim_pk)
            .await;
        dbtx.commit_tx().await;

        assert_eq!(response.account, expected_account);

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

        let pending_after_second_call = db
            .begin_transaction_nc()
            .await
            .get_value(&PendingCheckKey(expected_account))
            .await
            .expect("PendingCheck must still be present");
        assert_eq!(pending_after_second_call, pending);
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
        let purpose = SigningPurpose::Test(digest);

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
        let session_id = fedimint_usdt_common::signing_session_id(&digest, 0);
        let purpose = SigningPurpose::Test(digest);

        for module in modules.values() {
            let mut dbtx = module.db_for_test().begin_transaction().await;
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
            actual_cost_usdt: fedimint_usdt_common::UsdtAmount(1_000),
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

        // `apply_user_op_confirmed` clears the ENTIRE vote prefix once
        // threshold is reached (mirroring `credit_deposit`'s
        // `DepositObservationVoteAccountPrefix` clear), so re-delivering a
        // vote a peer already cast is no longer rejected as "redundant" --
        // the stored entry is gone, so it is processed as a fresh vote
        // towards a new round. It must NOT, on its own, re-trigger
        // `apply_user_op_confirmed` (only 1 of the 3 needed votes is now
        // present).
        module
            .process_consensus_item(&mut dbtx.to_ref_nc(), obs.clone(), PeerId::from(0))
            .await
            .expect("a vote cast after the prefix was cleared is a fresh vote, not redundant");
        let pool_still_single_credit = dbtx
            .to_ref_nc()
            .get_value(&PoolStateKey)
            .await
            .expect("PoolState still present");
        assert_eq!(
            pool_still_single_credit.balance,
            UsdtAmount(4_000_000),
            "a single fresh vote below threshold must not re-credit the pool"
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
                        unsigned: sample_unsigned_user_op_for_test(),
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
                    unsigned: sample_unsigned_user_op_for_test(),
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
                purpose: SigningPurpose::Test([0x61; 32]),
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
        ];
        assert_eq!(
            dumped.len(),
            expected_labels.len(),
            "dump_database must produce exactly one entry per DbKeyPrefix variant (0x01..=0x0D)"
        );
        for label in expected_labels {
            assert!(
                dumped.contains_key(label),
                "dump_database is missing the {label:?} table"
            );
        }
    }

    /// Shared sample [`UnsignedUserOp`] for the `UserOpConfirmed` tests
    /// above, whose `call_data` decodes to a `transfer(pool, 4_000_000)`
    /// call via `crate::user_op::decode_transfer_amount` (exercised by
    /// `spawn_user_op_submitter`, not directly by these consensus-level
    /// tests, but kept realistic).
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
