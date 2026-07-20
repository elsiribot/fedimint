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
use fedimint_core::config::JsonWithKind;
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

/// Parses the private module config json stored by the generation manager.
///
/// Applies the same [`JsonWithKind::with_fixed_empty_value`] workaround as
/// `ServerConfig::get_module_config`: unit struct private configs serialize
/// to a bare `{"kind": ...}` object and would otherwise deserialize with an
/// empty map value that fails to parse back into the unit struct.
fn parse_private_config(private_json: &str) -> anyhow::Result<JsonWithKind> {
    Ok(serde_json::from_str::<JsonWithKind>(private_json)?.with_fixed_empty_value())
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
            parse_private_config(&outcome.private_json)?,
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

#[cfg(test)]
mod tests {
    use fedimint_core::config::JsonWithKind;
    use fedimint_core::core::ModuleKind;
    use serde::{Deserialize, Serialize};

    use super::parse_private_config;

    /// Private configs without fields, like the meta module's
    /// `MetaConfigPrivate`, are unit structs that serialize to json `null`.
    #[derive(Serialize, Deserialize)]
    struct UnitConfigPrivate;

    #[test]
    fn parses_unit_struct_private_config() {
        // The generation manager stores the private config by serializing the
        // JsonWithKind returned from the module's distributed_gen, which
        // flattens a null value into a bare `{"kind": ...}` object
        let stored = serde_json::to_string(&JsonWithKind::new(
            ModuleKind::from_static_str("meta"),
            serde_json::to_value(UnitConfigPrivate).expect("serializable"),
        ))
        .expect("serializable");

        let parsed = parse_private_config(&stored).expect("stored private config parses");

        serde_json::from_value::<UnitConfigPrivate>(parsed.value().clone())
            .expect("private config deserializes into the unit struct");
    }
}
