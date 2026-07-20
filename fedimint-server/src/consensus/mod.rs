pub mod aleph_bft;
pub mod api;
pub mod config_gen;
pub mod db;
pub mod debug;
pub mod engine;
pub mod transaction;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use async_channel::Sender;
use db::{ServerDbMigrationContext, get_global_database_migrations};
use fedimint_api_client::api::DynGlobalApi;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::NumPeers;
use fedimint_core::config::P2PMessage;
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{
    Database, IDatabaseTransactionOpsCoreTyped, apply_migrations_dbtx,
    verify_module_db_integrity_dbtx,
};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{
    ApiAuth, ApiEndpoint, ApiError, ApiMethod, FEDIMINT_API_ALPN, IrohApiRequest,
};
use fedimint_core::net::iroh::build_iroh_endpoint;
use fedimint_core::net::peers::DynP2PConnections;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl};
use fedimint_logging::{LOG_CONSENSUS, LOG_CORE, LOG_NET_API};
use fedimint_server_core::bitcoin_rpc::{DynServerBitcoinRpc, ServerBitcoinRpcMonitor};
use fedimint_server_core::dashboard_ui::IDashboardApi;
use fedimint_server_core::migration::apply_migrations_server_dbtx;
use fedimint_server_core::{DynServerModule, ServerModuleInitRegistry};
use futures::FutureExt;
use iroh::Endpoint;
use iroh::endpoint::{Incoming, RecvStream, SendStream, VarInt};
use jsonrpsee::RpcModule;
use jsonrpsee::server::ServerHandle;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tracing::{info, warn};

use crate::config::{ServerConfig, ServerConfigLocal};
use crate::connection_limits::ConnectionLimits;
use crate::consensus::api::{ConsensusApi, server_endpoints};
use crate::consensus::config_gen::activation::{DynModuleActivator, ModuleSetSnapshot};
use crate::consensus::config_gen::manager::GenerationManager;
use crate::consensus::engine::ConsensusEngine;
use crate::db::verify_server_db_integrity_dbtx;
use crate::metrics::{
    IROH_API_CONNECTION_DURATION_SECONDS, IROH_API_CONNECTION_IDLE_TIMEOUT_TOTAL,
    IROH_API_CONNECTIONS_ACTIVE, IROH_API_REQUEST_DURATION_SECONDS, IROH_API_REQUEST_RESPONSE_CODE,
};
use crate::net::api::announcement::get_api_urls;
use crate::net::api::{ApiSecrets, HasApiContext};
use crate::net::p2p::P2PStatusReceivers;
use crate::{DashboardUiRouter, net, update_server_info_version_dbtx};

/// How many txs can be stored in memory before blocking the API
const TRANSACTION_BUFFER: usize = 1000;

/// How long an iroh API connection may stay idle before the server closes it.
const IROH_API_CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Application-level QUIC error code for expected idle iroh API connection
/// reaping.
const IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_CODE: u32 = 0;

/// Application-level QUIC close reason for idle iroh API connection reaping.
const IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_REASON: &[u8] = b"idle timeout";

#[allow(clippy::too_many_arguments)]
pub async fn run(
    connectors: ConnectorRegistry,
    auth_ui: Option<ApiAuth>,
    auth_api: Option<ApiAuth>,
    connections: DynP2PConnections<P2PMessage>,
    p2p_status_receivers: P2PStatusReceivers,
    api_bind: SocketAddr,
    iroh_dns: Option<SafeUrl>,
    iroh_relays: Vec<SafeUrl>,
    cfg: ServerConfig,
    db: Database,
    module_init_registry: ServerModuleInitRegistry,
    task_group: &TaskGroup,
    force_api_secrets: ApiSecrets,
    data_dir: PathBuf,
    code_version_str: String,
    code_version_hash: String,
    dyn_server_bitcoin_rpc: DynServerBitcoinRpc,
    ui_bind: SocketAddr,
    dashboard_ui_router: DashboardUiRouter,
    db_checkpoint_retention: u64,
    session_timeout: Duration,
    iroh_api_limits: ConnectionLimits,
) -> anyhow::Result<()> {
    cfg.validate_config(&cfg.local.identity, &module_init_registry)?;

    let mut global_dbtx = db.begin_transaction().await;
    apply_migrations_server_dbtx(
        &mut global_dbtx.to_ref_nc(),
        Arc::new(ServerDbMigrationContext),
        "fedimint-server".to_string(),
        get_global_database_migrations(),
    )
    .await?;

    update_server_info_version_dbtx(&mut global_dbtx.to_ref_nc(), &code_version_str).await;

    if is_running_in_test_env() {
        verify_server_db_integrity_dbtx(&mut global_dbtx.to_ref_nc()).await;
    }
    global_dbtx.commit_tx_result().await?;

    let mut modules = BTreeMap::new();

    // TODO: make it work with all transports and federation secrets
    let global_api = DynGlobalApi::new(
        connectors.clone(),
        cfg.consensus
            .api_endpoints()
            .iter()
            .map(|(&peer_id, url)| (peer_id, url.url.clone()))
            .collect(),
        None,
    )?;

    let bitcoin_rpc_connection = ServerBitcoinRpcMonitor::new(
        dyn_server_bitcoin_rpc,
        if is_running_in_test_env() {
            Duration::from_millis(100)
        } else {
            Duration::from_mins(1)
        },
        task_group,
    );

    for (module_id, module_cfg) in &cfg.consensus.modules {
        match module_init_registry.get(&module_cfg.kind) {
            Some(module_init) => {
                info!(target: LOG_CORE, "Initialise module {module_id}...");

                let mut dbtx = db.begin_transaction().await;
                apply_migrations_dbtx(
                    &mut dbtx.to_ref_nc(),
                    Arc::new(ServerDbMigrationContext) as Arc<_>,
                    module_init.module_kind().to_string(),
                    module_init.get_database_migrations(),
                    Some(*module_id),
                    None,
                )
                .await?;

                if let Some(used_db_prefixes) = module_init.used_db_prefixes()
                    && is_running_in_test_env()
                {
                    verify_module_db_integrity_dbtx(
                        &mut dbtx.to_ref_nc(),
                        *module_id,
                        module_init.module_kind(),
                        &used_db_prefixes,
                    )
                    .await;
                }
                dbtx.commit_tx_result().await?;

                let module = module_init
                    .init(
                        NumPeers::from(cfg.consensus.api_endpoints().len()),
                        cfg.get_module_config(*module_id)?,
                        db.with_prefix_module_id(*module_id).0,
                        task_group,
                        cfg.local.identity,
                        global_api.with_module(*module_id),
                        bitcoin_rpc_connection.clone(),
                    )
                    .await?;

                modules.insert(*module_id, (module_cfg.kind.clone(), module));
            }
            None => bail!("Detected configuration for unsupported module id: {module_id}"),
        }
    }

    // Load dynamically generated modules that were activated via consensus;
    // see [`crate::consensus::config_gen`].
    let generation_log = db
        .begin_transaction_nc()
        .await
        .get_value(&crate::db::ConfigGenerationLogKey)
        .await
        .unwrap_or_default();

    let dynamic_modules = generation_log.active_modules();

    let db = if dynamic_modules.is_empty() {
        db
    } else {
        // The database decoders have to know all dynamic modules, e.g. to
        // decode module items in accepted consensus items on replay
        db.with_decoders(
            module_init_registry.available_decoders(
                cfg.consensus.iter_module_instances().chain(
                    dynamic_modules
                        .iter()
                        .map(|module| (module.instance_id, &module.consensus_config.kind)),
                ),
            )?,
        )
    };

    let (submission_sender, submission_receiver) = async_channel::bounded(TRANSACTION_BUFFER);

    let module_activator = DynModuleActivator::new(
        cfg.clone(),
        module_init_registry.clone(),
        task_group.clone(),
        submission_sender.clone(),
        global_api.clone(),
        bitcoin_rpc_connection.clone(),
    );

    let mut dynamic_module_activation = BTreeMap::new();

    for dynamic_module in &dynamic_modules {
        let (kind, module) = module_activator.init_module(&db, dynamic_module).await?;

        modules.insert(dynamic_module.instance_id, (kind, module));

        dynamic_module_activation.insert(
            dynamic_module.instance_id,
            dynamic_module.active_from_session,
        );
    }

    let module_registry = ModuleRegistry::from(modules);

    // The engine publishes the extended module set on hot activation; the
    // api surface is rebuilt from it. Initial value covers startup modules.
    let (snapshot_sender, api_snapshot_receiver) = watch::channel(ModuleSetSnapshot {
        modules: module_registry.clone(),
        db: db.clone(),
    });

    let (shutdown_sender, shutdown_receiver) = watch::channel(None);
    let (ord_latency_sender, ord_latency_receiver) = watch::channel(None);
    // Carries runtime DKG messages from the p2p receive loop to the config
    // generation manager.
    let (config_gen_sender, config_gen_receiver) =
        async_channel::bounded::<(fedimint_core::PeerId, fedimint_core::config::P2PMessage)>(1024);

    GenerationManager::new(
        db.clone(),
        NumPeers::from(cfg.consensus.api_endpoints().len()),
        cfg.local.identity,
        module_init_registry.clone(),
        connections.clone(),
        config_gen_receiver,
        submission_sender.clone(),
        crate::consensus::config_gen::secrets::config_gen_root(&cfg.private.broadcast_secret_key),
    )
    .spawn(task_group);

    let mut ci_status_senders = BTreeMap::new();
    let mut ci_status_receivers = BTreeMap::new();

    for peer in cfg.consensus.broadcast_public_keys.keys().copied() {
        let (ci_sender, ci_receiver) = watch::channel(None);

        ci_status_senders.insert(peer, ci_sender);
        ci_status_receivers.insert(peer, ci_receiver);
    }

    let api_ctx = ApiSurfaceContext {
        cfg: cfg.clone(),
        module_init_registry: module_init_registry.clone(),
        submission_sender: submission_sender.clone(),
        shutdown_sender,
        shutdown_receiver: shutdown_receiver.clone(),
        auth_ui,
        auth_api,
        p2p_status_receivers,
        ci_status_receivers,
        ord_latency_receiver,
        bitcoin_rpc_connection: bitcoin_rpc_connection.clone(),
        force_api_secrets: force_api_secrets.clone(),
        code_version_str,
        code_version_hash,
        task_group: task_group.clone(),
        api_bind,
        ui_bind,
        dashboard_ui_router,
    };

    info!(target: LOG_CONSENSUS, "Starting Consensus Api...");

    let initial_snapshot = api_snapshot_receiver.borrow().clone();

    let consensus_api = api_ctx.build_consensus_api(&initial_snapshot).await?;

    let api_handler = start_consensus_api(
        &cfg.local,
        consensus_api.clone(),
        force_api_secrets.clone(),
        api_bind,
    )
    .await;

    let (iroh_handlers_sender, iroh_handlers_receiver) =
        watch::channel(IrohApiHandlers::new(consensus_api.clone()));

    if let Some(iroh_api_sk) = cfg.private.iroh_api_sk.clone()
        && let Err(e) = Box::pin(start_iroh_api(
            iroh_api_sk,
            api_bind,
            iroh_dns,
            iroh_relays,
            iroh_handlers_receiver,
            task_group,
            iroh_api_limits,
        ))
        .await
    {
        // clean up ws api before propagating error
        api_handler.stop().expect("Just started");
        api_handler.stopped().await;
        return Err(e);
    }

    info!(target: LOG_CONSENSUS, "Starting Submission of Module CI proposals...");

    for (module_id, kind, module) in module_registry.iter_modules() {
        submit_module_ci_proposals(
            task_group,
            db.clone(),
            module_id,
            kind.clone(),
            module.clone(),
            submission_sender.clone(),
        );
    }

    let dashboard_handle = api_ctx.spawn_dashboard_ui(&consensus_api).await?;

    info!(target: LOG_CONSENSUS, "Dashboard UI running at http://{ui_bind} 🚀");

    // Rebuilds the api surface whenever the engine hot activates a module
    task_group.spawn_cancellable(
        "api-refresher",
        run_api_refresher(
            api_ctx,
            api_snapshot_receiver,
            api_handler,
            dashboard_handle,
            iroh_handlers_sender,
        ),
    );

    loop {
        match bitcoin_rpc_connection.status() {
            Some(status) => {
                if let Some(progress) = status.sync_progress {
                    if progress >= 0.999 {
                        break;
                    }

                    info!(target: LOG_CONSENSUS, "Waiting for bitcoin backend to sync... {progress:.1}%");
                } else {
                    break;
                }
            }
            None => {
                info!(target: LOG_CONSENSUS, "Waiting to connect to bitcoin backend...");
            }
        }

        sleep(Duration::from_secs(1)).await;
    }

    info!(target: LOG_CONSENSUS, "Starting Consensus Engine...");

    let api_urls = get_api_urls(&db, &cfg.consensus).await;

    // FIXME: (@leonardo) How should this be handled ?
    // Using the `Connector::default()` for now!
    ConsensusEngine {
        db,
        federation_api: DynGlobalApi::new(
            connectors,
            api_urls,
            force_api_secrets.get_active().as_deref(),
        )?,
        cfg: cfg.clone(),
        connections,
        ord_latency_sender,
        ci_status_senders,
        submission_receiver,
        shutdown_receiver,
        module_activator,
        snapshot_sender,
        config_gen_sender,
        dynamic_module_activation,
        modules: module_registry,
        task_group: task_group.clone(),
        data_dir,
        db_checkpoint_retention,
        session_timeout,
    }
    .run()
    .await?;

    // Dropping the engine closes the snapshot channel, which makes the api
    // refresher stop the api servers it owns.

    Ok(())
}

/// Everything needed to build the api surface for a module set snapshot,
/// both at startup and after a hot activation extended the module set.
struct ApiSurfaceContext {
    cfg: ServerConfig,
    module_init_registry: ServerModuleInitRegistry,
    submission_sender: Sender<ConsensusItem>,
    shutdown_sender: watch::Sender<Option<u64>>,
    shutdown_receiver: watch::Receiver<Option<u64>>,
    auth_ui: Option<ApiAuth>,
    auth_api: Option<ApiAuth>,
    p2p_status_receivers: P2PStatusReceivers,
    ci_status_receivers: BTreeMap<fedimint_core::PeerId, watch::Receiver<Option<u64>>>,
    ord_latency_receiver: watch::Receiver<Option<Duration>>,
    bitcoin_rpc_connection: ServerBitcoinRpcMonitor,
    force_api_secrets: ApiSecrets,
    code_version_str: String,
    code_version_hash: String,
    task_group: TaskGroup,
    api_bind: SocketAddr,
    ui_bind: SocketAddr,
    dashboard_ui_router: DashboardUiRouter,
}

impl ApiSurfaceContext {
    /// Builds the consensus api for a module set snapshot. The client config
    /// and advertised api versions cover dynamic modules as well, so clients
    /// pick them up via their additive config refresh.
    async fn build_consensus_api(
        &self,
        snapshot: &ModuleSetSnapshot,
    ) -> anyhow::Result<ConsensusApi> {
        let dynamic_modules = snapshot
            .db
            .begin_transaction_nc()
            .await
            .get_value(&crate::db::ConfigGenerationLogKey)
            .await
            .unwrap_or_default()
            .active_modules();

        let mut client_cfg = self
            .cfg
            .consensus
            .to_client_config(&self.module_init_registry)?;

        let mut all_module_configs = self.cfg.consensus.modules.clone();

        for dynamic_module in &dynamic_modules {
            let module_init = self
                .module_init_registry
                .get(&dynamic_module.consensus_config.kind)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Active dynamic module of unsupported kind {}",
                        dynamic_module.consensus_config.kind
                    )
                })?;

            client_cfg.modules.insert(
                dynamic_module.instance_id,
                module_init.get_client_config(
                    dynamic_module.instance_id,
                    &dynamic_module.consensus_config,
                )?,
            );

            all_module_configs.insert(
                dynamic_module.instance_id,
                dynamic_module.consensus_config.clone(),
            );
        }

        Ok(ConsensusApi {
            cfg: self.cfg.clone(),
            db: snapshot.db.clone(),
            modules: snapshot.modules.clone(),
            module_inits: self.module_init_registry.clone(),
            client_cfg,
            submission_sender: self.submission_sender.clone(),
            shutdown_sender: self.shutdown_sender.clone(),
            shutdown_receiver: self.shutdown_receiver.clone(),
            supported_api_versions: ServerConfig::supported_api_versions_summary(
                &all_module_configs,
                &self.module_init_registry,
            ),
            auth_ui: self.auth_ui.clone(),
            auth_api: self.auth_api.clone(),
            p2p_status_receivers: self.p2p_status_receivers.clone(),
            ci_status_receivers: self.ci_status_receivers.clone(),
            ord_latency_receiver: self.ord_latency_receiver.clone(),
            bitcoin_rpc_connection: self.bitcoin_rpc_connection.clone(),
            force_api_secret: self.force_api_secrets.get_active(),
            code_version_str: self.code_version_str.clone(),
            code_version_hash: self.code_version_hash.clone(),
            task_group: self.task_group.clone(),
        })
    }

    async fn spawn_dashboard_ui(
        &self,
        consensus_api: &ConsensusApi,
    ) -> anyhow::Result<DashboardUiHandle> {
        let ui_service =
            (self.dashboard_ui_router)(consensus_api.clone().into_dyn()).into_make_service();

        let ui_listener = TcpListener::bind(self.ui_bind).await?;

        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();

        let join_handle = fedimint_core::runtime::spawn("dashboard-ui", async move {
            axum::serve(ui_listener, ui_service)
                .with_graceful_shutdown(async {
                    let _ = shutdown_receiver.await;
                })
                .await
                .expect("Failed to serve dashboard UI");
        });

        Ok(DashboardUiHandle {
            shutdown_sender,
            join_handle,
        })
    }
}

/// Handle to a running dashboard ui server; dropping the shutdown sender
/// stops the server gracefully.
struct DashboardUiHandle {
    shutdown_sender: tokio::sync::oneshot::Sender<()>,
    join_handle: fedimint_core::runtime::JoinHandle<()>,
}

impl DashboardUiHandle {
    async fn stop(self) {
        drop(self.shutdown_sender);
        let _ = self.join_handle.await;
    }
}

/// Rebuilds the api surface from the module set snapshot published by the
/// consensus engine whenever a module is hot activated: the websocket api
/// server is respawned with the extended endpoint set, the iroh api handlers
/// are swapped in place and the dashboard ui is respawned. Stops the api
/// servers once the engine drops the snapshot channel on shutdown.
async fn run_api_refresher(
    ctx: ApiSurfaceContext,
    mut snapshot_receiver: watch::Receiver<ModuleSetSnapshot>,
    mut api_handler: ServerHandle,
    mut dashboard_handle: DashboardUiHandle,
    iroh_handlers_sender: watch::Sender<Arc<IrohApiHandlers>>,
) {
    while snapshot_receiver.changed().await.is_ok() {
        let snapshot = snapshot_receiver.borrow_and_update().clone();

        let consensus_api = match ctx.build_consensus_api(&snapshot).await {
            Ok(consensus_api) => consensus_api,
            Err(err) => {
                warn!(
                    target: LOG_CONSENSUS,
                    err = %err.fmt_compact_anyhow(),
                    "Failed to rebuild consensus api for extended module set"
                );
                continue;
            }
        };

        if api_handler.stop().is_ok() {
            api_handler.stopped().await;
        }

        api_handler = start_consensus_api(
            &ctx.cfg.local,
            consensus_api.clone(),
            ctx.force_api_secrets.clone(),
            ctx.api_bind,
        )
        .await;

        iroh_handlers_sender.send_replace(IrohApiHandlers::new(consensus_api.clone()));

        dashboard_handle.stop().await;

        dashboard_handle = loop {
            match ctx.spawn_dashboard_ui(&consensus_api).await {
                Ok(handle) => break handle,
                Err(err) => {
                    warn!(
                        target: LOG_CONSENSUS,
                        err = %err.fmt_compact_anyhow(),
                        "Failed to respawn dashboard ui, retrying..."
                    );
                    sleep(Duration::from_millis(500)).await;
                }
            }
        };

        info!(
            target: LOG_CONSENSUS,
            "Rebuilt api surface for hot activated modules"
        );
    }

    if api_handler.stop().is_ok() {
        api_handler.stopped().await;
    }

    dashboard_handle.stop().await;
}

async fn start_consensus_api(
    cfg: &ServerConfigLocal,
    api: ConsensusApi,
    force_api_secrets: ApiSecrets,
    api_bind: SocketAddr,
) -> ServerHandle {
    let mut rpc_module = RpcModule::new(api.clone());

    net::api::attach_endpoints(&mut rpc_module, api::server_endpoints(), None);

    for (id, _, module) in api.modules.iter_modules() {
        net::api::attach_endpoints(&mut rpc_module, module.api_endpoints(), Some(id));
    }

    net::api::spawn(
        "consensus",
        api_bind,
        rpc_module,
        cfg.max_connections,
        force_api_secrets,
    )
    .await
}

const CONSENSUS_PROPOSAL_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn submit_module_ci_proposals(
    task_group: &TaskGroup,
    db: Database,
    module_id: ModuleInstanceId,
    kind: ModuleKind,
    module: DynServerModule,
    submission_sender: Sender<ConsensusItem>,
) {
    let mut interval = tokio::time::interval(if is_running_in_test_env() {
        Duration::from_millis(100)
    } else {
        Duration::from_secs(1)
    });

    task_group.spawn(
        format!("citem_proposals_{module_id}"),
        move |task_handle| async move {
            while !task_handle.is_shutting_down() {
                let module_consensus_items = tokio::time::timeout(
                    CONSENSUS_PROPOSAL_TIMEOUT,
                    module.consensus_proposal(
                        &mut db
                            .begin_transaction_nc()
                            .await
                            .to_ref_with_prefix_module_id(module_id)
                            .0
                            .into_nc(),
                        module_id,
                    ),
                )
                .await;

                match module_consensus_items {
                    Ok(items) => {
                        for item in items {
                            if submission_sender
                                .send(ConsensusItem::Module(item))
                                .await
                                .is_err()
                            {
                                warn!(
                                    target: LOG_CONSENSUS,
                                    module_id,
                                    "Unable to submit module consensus item proposal via channel"
                                );
                            }
                        }
                    }
                    Err(..) => {
                        warn!(
                            target: LOG_CONSENSUS,
                            module_id,
                            %kind,
                            "Module failed to propose consensus items on time"
                        );
                    }
                }

                interval.tick().await;
            }
        },
    );
}

/// Api handlers the iroh api dispatches requests to. Swapped out as a whole
/// whenever a hot activation extends the module set, so requests always see
/// the current module set without interrupting the iroh endpoint.
struct IrohApiHandlers {
    consensus_api: ConsensusApi,
    core_api: BTreeMap<String, ApiEndpoint<ConsensusApi>>,
    module_api: BTreeMap<ModuleInstanceId, BTreeMap<String, ApiEndpoint<DynServerModule>>>,
}

impl IrohApiHandlers {
    fn new(consensus_api: ConsensusApi) -> Arc<Self> {
        let core_api = server_endpoints()
            .into_iter()
            .map(|endpoint| (endpoint.path.to_string(), endpoint))
            .collect::<BTreeMap<String, ApiEndpoint<ConsensusApi>>>();

        let module_api = consensus_api
            .modules
            .iter_modules()
            .map(|(id, _, module)| {
                let api_endpoints = module
                    .api_endpoints()
                    .into_iter()
                    .map(|endpoint| (endpoint.path.to_string(), endpoint))
                    .collect::<BTreeMap<String, ApiEndpoint<DynServerModule>>>();

                (id, api_endpoints)
            })
            .collect();

        Arc::new(IrohApiHandlers {
            consensus_api,
            core_api,
            module_api,
        })
    }
}

async fn start_iroh_api(
    secret_key: iroh::SecretKey,
    api_bind: SocketAddr,
    iroh_dns: Option<SafeUrl>,
    iroh_relays: Vec<SafeUrl>,
    handlers: watch::Receiver<Arc<IrohApiHandlers>>,
    task_group: &TaskGroup,
    iroh_api_limits: ConnectionLimits,
) -> anyhow::Result<()> {
    let endpoint = build_iroh_endpoint(
        secret_key,
        api_bind,
        iroh_dns,
        iroh_relays,
        FEDIMINT_API_ALPN,
    )
    .await?;
    task_group.spawn_cancellable(
        "iroh-api",
        run_iroh_api(handlers, endpoint, task_group.clone(), iroh_api_limits),
    );

    Ok(())
}

async fn run_iroh_api(
    handlers: watch::Receiver<Arc<IrohApiHandlers>>,
    endpoint: Endpoint,
    task_group: TaskGroup,
    iroh_api_limits: ConnectionLimits,
) {
    let parallel_connections_limit = Arc::new(Semaphore::new(iroh_api_limits.max_connections));

    loop {
        match endpoint.accept().await {
            Some(incoming) => {
                if parallel_connections_limit.available_permits() == 0 {
                    warn!(
                        target: LOG_NET_API,
                        limit = iroh_api_limits.max_connections,
                        "Iroh API connection limit reached, blocking new connections"
                    );
                }
                let permit = parallel_connections_limit
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("semaphore should not be closed");
                task_group.spawn_cancellable_silent(
                    "handle-iroh-connection",
                    handle_incoming(
                        handlers.clone(),
                        task_group.clone(),
                        incoming,
                        permit,
                        iroh_api_limits.max_requests_per_connection,
                    )
                    .then(|result| async {
                        if let Err(err) = result {
                            warn!(target: LOG_NET_API, err = %err.fmt_compact_anyhow(), "Failed to handle iroh connection");
                        }
                    }),
                );
            }
            None => return,
        }
    }
}

async fn handle_incoming(
    handlers: watch::Receiver<Arc<IrohApiHandlers>>,
    task_group: TaskGroup,
    incoming: Incoming,
    _connection_permit: tokio::sync::OwnedSemaphorePermit,
    iroh_api_max_requests_per_connection: usize,
) -> anyhow::Result<()> {
    let connection = incoming.accept()?.await?;
    let parallel_requests_limit = Arc::new(Semaphore::new(iroh_api_max_requests_per_connection));

    IROH_API_CONNECTIONS_ACTIVE.inc();
    let connection_timer = IROH_API_CONNECTION_DURATION_SECONDS.start_timer();
    scopeguard::defer! {
        IROH_API_CONNECTIONS_ACTIVE.dec();
        connection_timer.observe_duration();
    }

    loop {
        let accept_result = fedimint_core::runtime::timeout(
            IROH_API_CONNECTION_IDLE_TIMEOUT,
            connection.accept_bi(),
        )
        .await;

        let (send_stream, recv_stream) = match accept_result {
            Ok(streams) => streams?,
            Err(_)
                if parallel_requests_limit.available_permits()
                    < iroh_api_max_requests_per_connection =>
            {
                continue;
            }
            Err(_) => {
                IROH_API_CONNECTION_IDLE_TIMEOUT_TOTAL.inc();
                tracing::debug!(
                    target: LOG_NET_API,
                    idle_timeout_secs = IROH_API_CONNECTION_IDLE_TIMEOUT.as_secs(),
                    "Closing idle iroh API connection"
                );
                connection.close(
                    VarInt::from_u32(IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_CODE),
                    IROH_API_CONNECTION_IDLE_TIMEOUT_ERROR_REASON,
                );
                return Ok(());
            }
        };

        if parallel_requests_limit.available_permits() == 0 {
            warn!(
                target: LOG_NET_API,
                limit = iroh_api_max_requests_per_connection,
                "Iroh API request limit reached for connection, blocking new requests"
            );
        }
        let permit = parallel_requests_limit
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore should not be closed");
        task_group.spawn_cancellable_silent(
            "handle-iroh-request",
            handle_request(
                handlers.borrow().clone(),
                send_stream,
                recv_stream,
                permit,
            )
            .then(|result| async {
                if let Err(err) = result {
                    warn!(target: LOG_NET_API, err = %err.fmt_compact_anyhow(), "Failed to handle iroh request");
                }
            }),
        );
    }
}

async fn handle_request(
    handlers: Arc<IrohApiHandlers>,
    mut send_stream: SendStream,
    mut recv_stream: RecvStream,
    _request_permit: tokio::sync::OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    let request = recv_stream.read_to_end(100_000).await?;

    let request = serde_json::from_slice::<IrohApiRequest>(&request)?;

    let method = request.method.to_string();
    let timer = IROH_API_REQUEST_DURATION_SECONDS
        .with_label_values(&[&method])
        .start_timer();

    let response = await_response(&handlers, request).await;

    timer.observe_duration();

    let response_code = response
        .as_ref()
        .map_or_else(|err| err.code.to_string(), |_| "0".to_string());
    IROH_API_REQUEST_RESPONSE_CODE
        .with_label_values(&[method.as_str(), response_code.as_str(), "default"])
        .inc();

    let response = serde_json::to_vec(&response)?;

    send_stream.write_all(&response).await?;

    send_stream.finish()?;

    Ok(())
}

async fn await_response(
    handlers: &IrohApiHandlers,
    request: IrohApiRequest,
) -> Result<Value, ApiError> {
    match request.method {
        ApiMethod::Core(method) => {
            let endpoint = handlers
                .core_api
                .get(&method)
                .ok_or(ApiError::not_found(method))?;

            let (state, context) = handlers.consensus_api.context(&request.request, None).await;

            (endpoint.handler)(state, context, request.request).await
        }
        ApiMethod::Module(module_id, method) => {
            let endpoint = handlers
                .module_api
                .get(&module_id)
                .ok_or(ApiError::not_found(module_id.to_string()))?
                .get(&method)
                .ok_or(ApiError::not_found(method))?;

            let (state, context) = handlers
                .consensus_api
                .context(&request.request, Some(module_id))
                .await;

            (endpoint.handler)(state, context, request.request).await
        }
    }
}
