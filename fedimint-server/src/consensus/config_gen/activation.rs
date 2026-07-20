//! Shared initialization of dynamically generated modules.
//!
//! Used by the startup path to load previously activated modules from the
//! generation log and by the consensus engine to hot activate a module at
//! its activation session. Both paths have to produce identical state, so
//! all module initialization for dynamic modules lives here.

use std::sync::Arc;

use async_channel::Sender;
use fedimint_api_client::api::DynGlobalApi;
use fedimint_core::NumPeers;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped, apply_migrations_dbtx};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::task::TaskGroup;
use fedimint_logging::LOG_CORE;
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_server_core::{DynServerModule, ServerModuleInitRegistry};
use tracing::info;

use crate::config::ServerConfig;
use crate::consensus::config_gen::ActiveModule;
use crate::consensus::db::ServerDbMigrationContext;
use crate::consensus::submit_module_ci_proposals;
use crate::db::LocalGenerationOutcomeKey;

/// The current module set of the server, published by the consensus engine
/// whenever a module is hot activated so the api surface can be rebuilt to
/// include it.
#[derive(Clone)]
pub struct ModuleSetSnapshot {
    pub modules: fedimint_server_core::ServerModuleRegistry,
    /// Database handle whose decoders cover all modules in the snapshot
    pub db: Database,
}

/// Initializes dynamically generated modules and spawns their consensus
/// item proposal submitters.
#[derive(Clone)]
pub struct DynModuleActivator {
    cfg: ServerConfig,
    module_inits: ServerModuleInitRegistry,
    task_group: TaskGroup,
    submission_sender: Sender<ConsensusItem>,
    global_api: DynGlobalApi,
    bitcoin_rpc_connection: ServerBitcoinRpcMonitor,
}

impl DynModuleActivator {
    pub fn new(
        cfg: ServerConfig,
        module_inits: ServerModuleInitRegistry,
        task_group: TaskGroup,
        submission_sender: Sender<ConsensusItem>,
        global_api: DynGlobalApi,
        bitcoin_rpc_connection: ServerBitcoinRpcMonitor,
    ) -> Self {
        Self {
            cfg,
            module_inits,
            task_group,
            submission_sender,
            global_api,
            bitcoin_rpc_connection,
        }
    }

    /// Runs the database migrations for and initializes a single dynamically
    /// generated module from its generation log entry and our locally stored
    /// private config.
    pub async fn init_module(
        &self,
        db: &Database,
        active_module: &ActiveModule,
    ) -> anyhow::Result<(ModuleKind, DynServerModule)> {
        let kind = active_module.consensus_config.kind.clone();

        let module_init = self.module_inits.get(&kind).ok_or_else(|| {
            anyhow::anyhow!("Activated dynamic module of unsupported kind {kind}")
        })?;

        let outcome = db
            .begin_transaction_nc()
            .await
            .get_value(&LocalGenerationOutcomeKey(active_module.generation_id))
            .await
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Missing local outcome for activated {}",
                    active_module.generation_id
                )
            })?;

        info!(
            target: LOG_CORE,
            instance_id = active_module.instance_id,
            %kind,
            active_from_session = active_module.active_from_session,
            "Initialise dynamic module..."
        );

        let mut dbtx = db.begin_transaction().await;
        apply_migrations_dbtx(
            &mut dbtx.to_ref_nc(),
            Arc::new(ServerDbMigrationContext) as Arc<_>,
            module_init.module_kind().to_string(),
            module_init.get_database_migrations(),
            Some(active_module.instance_id),
            None,
        )
        .await?;
        dbtx.commit_tx_result().await?;

        let module_cfg = fedimint_core::config::ServerModuleConfig::from(
            serde_json::from_str(&outcome.private_json)?,
            active_module.consensus_config.clone(),
        );

        let module = module_init
            .init(
                NumPeers::from(self.cfg.consensus.api_endpoints().len()),
                module_cfg,
                db.with_prefix_module_id(active_module.instance_id).0,
                &self.task_group,
                self.cfg.local.identity,
                self.global_api.with_module(active_module.instance_id),
                self.bitcoin_rpc_connection.clone(),
            )
            .await?;

        Ok((kind, module))
    }

    /// Spawns the consensus item proposal submitter for a module instance.
    pub fn spawn_ci_submitter(
        &self,
        db: Database,
        instance_id: ModuleInstanceId,
        kind: ModuleKind,
        module: DynServerModule,
    ) {
        submit_module_ci_proposals(
            &self.task_group,
            db,
            instance_id,
            kind,
            module,
            self.submission_sender.clone(),
        );
    }
}
