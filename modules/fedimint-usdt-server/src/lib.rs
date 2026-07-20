#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
    CHECK_DEPOSIT_ENDPOINT, DEBUG_START_SIGNING_ENDPOINT, DEPOSIT_STATUS_ENDPOINT,
    GROUP_PUBLIC_KEY_ENDPOINT, SIGNING_SESSION_STATUS_ENDPOINT,
};
use fedimint_usdt_common::{
    CheckDepositRequest, CheckDepositResponse, DepositObservation, DepositStatusRequest,
    DepositStatusResponse, MODULE_CONSENSUS_VERSION, MPC_ROUND_CHUNK_SIZE, MpcRoundItem,
    SigningSessionId, USDT_UNIT, UsdtAmount, UsdtCommonInit, UsdtConsensusItem, UsdtInput,
    UsdtInputError, UsdtModuleTypes, UsdtOutput, UsdtOutputError, UsdtOutputOutcome,
    derive_deposit_account, signing_session_id,
};
use futures::StreamExt as _;
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use tracing::{debug, warn};

use crate::config::{UsdtConfig, UsdtConfigConsensus, UsdtConfigLocal, UsdtConfigPrivate};
use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, DbKeyPrefix, DepositObservationVoteAccountPrefix,
    DepositObservationVoteKey, DepositObservationVotePrefix, DepositRecord, DepositRecordKey,
    DepositRecordPrefix, MpcRoundChunk, MpcRoundChunkKey, MpcRoundChunkPrefix,
    MpcRoundChunkSessionRoundPrefix, PendingCheck, PendingCheckKey, PendingCheckPrefix,
    SessionState, SigningPurpose, SigningSession, SigningSessionKey, SigningSessionPrefix,
};
use crate::rpc::{AlloyEvmRpc, DynServerEvmRpc, IServerEvmRpc as _};
use crate::signing::{SessionSlot, SessionStore, pump_slot_outgoing, spawn_signing_session};

mod dkg;

pub mod config;
pub mod db;
pub mod rpc;
pub mod signing;

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
}

impl UsdtInit {
    /// Builds a `UsdtInit` that hands every guardian the same injected
    /// `evm_rpc` instead of building an `AlloyEvmRpc`, for hermetic tests.
    #[must_use]
    pub fn with_evm_rpc(evm_rpc: crate::rpc::DynServerEvmRpc) -> Self {
        Self {
            evm_rpc_override: Some(evm_rpc),
        }
    }
}

impl ModuleInit for UsdtInit {
    type Common = UsdtCommonInit;

    /// Dumps all database items for debugging
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
    fn default_config_gen_params(&self) -> Self::Params {
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
        let evm_rpc = if let Some(evm_rpc) = &self.evm_rpc_override {
            evm_rpc.clone()
        } else {
            let evm_rpc_url = std::env::var(FM_USDT_EVM_RPC_URL_ENV)
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| cfg.private.local.evm_rpc_url.clone());
            AlloyEvmRpc::new(&evm_rpc_url)?.into_dyn()
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

    /// DB migrations to move from old to newer versions
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

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Usdt {
    /// Define the consensus types
    type Common = UsdtModuleTypes;
    type Init = UsdtInit;

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

        // Drain digests queued by the test-only `debug_start_signing` API
        // endpoint, proposing a `StartSigning` consensus item for each so
        // every guardian starts the session atomically in consensus order
        // (see `UsdtConsensusItem::StartSigning`'s doc comment).
        let pending_starts =
            std::mem::take(&mut *self.pending_signing_starts.lock().expect("not poisoned"));
        for digest in pending_starts {
            items.push(UsdtConsensusItem::StartSigning { digest });
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

                self.start_session(dbtx, SigningPurpose::Test(digest), digest)
                    .await;

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
        record.claimed = UsdtAmount(record.claimed.0 + input.amount.0);
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

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a UsdtOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, UsdtOutputError> {
        Err(UsdtOutputError::NotSupported)
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<UsdtOutputOutcome> {
        None
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
        // `credited` amount here -- not `credited - claimed` -- can only
        // create a surplus (deposits credited but not yet claimed into
        // e-cash), never a deficit, keeping the federation's global balance
        // sheet (`fedimint_core::module::audit::Audit::net_assets`) solvent.
        //
        // PROVISIONAL (Phase 5, mirrors `deposit_address`'s doc comment):
        // the on-chain deposit account is derived from the group public key
        // (`derive_deposit_account`), so once the federation has reached
        // consensus that it holds `credited` USDT there, it is already
        // vouching for that balance the same way the wallet module vouches
        // for UTXOs it controls, even though the withdrawal/sweep signing
        // path is reconciled later.
        audit
            .add_items(dbtx, module_instance_id, &DepositRecordPrefix, |_k, v| {
                i64::try_from(v.credited.0).unwrap_or(i64::MAX)
            })
            .await;
    }

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
                async |module: &Usdt, _context, session_id: SigningSessionId| -> Option<Vec<u8>> {
                    // Read-only, guardian-LOCAL: see
                    // `SIGNING_SESSION_STATUS_ENDPOINT`'s doc comment for why
                    // this is never read from the consensus DB.
                    Ok(module
                        .completed_signatures
                        .lock()
                        .expect("not poisoned")
                        .get(&session_id)
                        .cloned())
                }
            },
        ]
    }
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
        Ok(())
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
        let account = derive_deposit_account(&self.cfg.consensus.group_public_key, &claim_pk);

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
        let account = derive_deposit_account(&self.cfg.consensus.group_public_key, &claim_pk);

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

    /// Starts (idempotently) a threshold-ECDSA signing session over `digest`.
    ///
    /// Writes the consensus [`SigningSession`] — signer subset = the lowest-`t`
    /// peer ids, `round: 0`, [`SessionState::InProgress`] — and no-ops if a
    /// session for this digest already exists. If this guardian is in the
    /// subset it also spawns the off-thread signing state machine into
    /// `signing_sessions` and pre-pumps round 0's payload, so the next
    /// `consensus_proposal` can propose it immediately.
    ///
    /// The signer subset is a pure function of `num_peers`: peer ids are
    /// exactly `0..n` and [`NumPeers::peer_ids`] yields them in order, so
    /// `take(t)` is the lowest-`t` subset every guardian independently agrees
    /// on.
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
    ) {
        let session_id = signing_session_id(&digest, 0);
        if dbtx
            .get_value(&SigningSessionKey(session_id))
            .await
            .is_some()
        {
            return;
        }

        let threshold = self.num_peers.threshold();
        let signers: Vec<PeerId> = self.num_peers.peer_ids().take(threshold).collect();

        dbtx.insert_new_entry(
            &SigningSessionKey(session_id),
            &SigningSession {
                purpose,
                digest,
                signers: signers.clone(),
                round: 0,
                state: SessionState::InProgress,
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
                    self.completed_signatures
                        .lock()
                        .expect("not poisoned")
                        .insert(session_id, sig.serialize_compact().to_vec());
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
            check_ttl_blocks: 500,
        };

        let server_cfgs = UsdtInit::default().trusted_dealer_gen(&peers, &args, &params);
        let cfg0 = server_cfgs[&peers[0]]
            .clone()
            .to_typed::<UsdtConfig>()
            .unwrap();
        assert_eq!(cfg0.consensus.usdt_contract, params.usdt_contract);
        assert_eq!(cfg0.consensus.confirmation_depth, 6);
        assert_eq!(cfg0.consensus.check_ttl_blocks, 500);

        let client_cfg = UsdtInit::default()
            .get_client_config(&cfg0.clone().to_erased().consensus)
            .unwrap();
        assert_eq!(client_cfg.usdt_contract, params.usdt_contract);
        assert_eq!(client_cfg.confirmation_depth, 6);
        assert_eq!(client_cfg.chain_id, 1);
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
        let account = derive_deposit_account(&module.cfg.consensus.group_public_key, &claim_pk);

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
        let account = derive_deposit_account(&module.cfg.consensus.group_public_key, &claim_pk);

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
        let account = derive_deposit_account(&module.cfg.consensus.group_public_key, &claim_pk);

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

    #[tokio::test]
    async fn check_deposit_enqueues_pending_check_and_is_idempotent() {
        let module = test_module_with_block_count(4, 0).await;
        let db = module.db_for_test();
        let claim_pk = test_pubkey(0x01);
        let expected_account = fedimint_usdt_common::derive_deposit_account(
            &module.cfg.consensus.group_public_key,
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
                .start_session(&mut dbtx.to_ref_nc(), purpose.clone(), digest)
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
