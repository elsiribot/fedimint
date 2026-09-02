#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::ref_option)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::trivially_copy_pass_by_ref)]

//! Server side fedimint module traits

extern crate fedimint_core;
pub mod connection_limits;
pub mod db;

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use anyhow::Context;
use config::ServerConfig;
use config::io::{PLAINTEXT_PASSWORD, read_server_config};
pub use connection_limits::ConnectionLimits;
use fedimint_aead::random_salt;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::P2PMessage;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::net::peers::DynP2PConnections;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::write_new;
use fedimint_logging::LOG_CONSENSUS;
pub use fedimint_server_core as core;
use fedimint_server_core::ServerModuleInitRegistry;
use fedimint_server_core::bitcoin_rpc::DynServerBitcoinRpc;
use fedimint_server_core::dashboard_ui::DynDashboardApi;
use fedimint_server_core::setup_ui::{DynSetupApi, ISetupApi};
use jsonrpsee::RpcModule;
use net::api::ApiSecrets;
use net::p2p::P2PStatusReceivers;
use net::p2p_connector::IrohConnector;
#[cfg(unix)]
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::config::ConfigGenSettings;
#[cfg(unix)]
use crate::config::driven::{
    ChildMessage, ChildState, FM_DKG_CTRL_ENV, PROTOCOL_VERSION, ParentMessage,
    ensure_no_config_artifacts, install_staging, prepare_staging, read_frame, validate_run_dkg,
    write_frame,
};
use crate::config::io::{
    SALT_FILE, finalize_password_change, recover_interrupted_password_change, trim_password,
    write_server_config,
};
use crate::config::setup::SetupApi;
use crate::db::{ServerInfo, ServerInfoKey};
use crate::fedimint_core::net::peers::IP2PConnections;
use crate::metrics::initialize_gauge_metrics;
use crate::net::api::announcement::start_api_announcement_service;
use crate::net::api::guardian_metadata::start_guardian_metadata_service;
use crate::net::api::pkarr_publish::start_pkarr_publish_service;
use crate::net::p2p::{ReconnectP2PConnections, p2p_status_channels};
use crate::net::p2p_connector::{IP2PConnector, TlsTcpConnector};

pub mod metrics;

/// The actual implementation of consensus
pub mod consensus;

/// Networking for mint-to-mint and client-to-mint communiccation
pub mod net;

/// Fedimint toplevel config
pub mod config;

/// A function/closure type for handling dashboard UI
pub type DashboardUiRouter = Box<dyn Fn(DynDashboardApi) -> axum::Router + Send>;

/// A function/closure type for handling setup UI
pub type SetupUiRouter = Box<dyn Fn(DynSetupApi) -> axum::Router + Send>;

/// Deferred database opener used to keep driven DKG path-independent.
pub type DatabaseOpener = Box<
    dyn FnOnce(PathBuf) -> Pin<Box<dyn Future<Output = anyhow::Result<Database>> + Send>> + Send,
>;

fn config_gen_failure(
    stage: &'static str,
    failure_kind: &'static str,
    error: impl Into<anyhow::Error>,
) -> anyhow::Error {
    let error = error.into();
    tracing::error!(
        error = format_args!("{error:#}"),
        "configuration generation stage failed"
    );
    tracing::warn!(
        safe_to_share = true,
        stage,
        failure_kind,
        "Configuration generation failed"
    );
    error
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    data_dir: PathBuf,
    force_api_secrets: ApiSecrets,
    settings: ConfigGenSettings,
    db: Database,
    code_version_str: String,
    module_init_registry: ServerModuleInitRegistry,
    task_group: TaskGroup,
    bitcoin_rpc: DynServerBitcoinRpc,
    setup_ui_router: SetupUiRouter,
    dashboard_ui_router: DashboardUiRouter,
    db_checkpoint_retention: u64,
    iroh_api_limits: ConnectionLimits,
) -> anyhow::Result<()> {
    let (cfg, connections, p2p_status_receivers) = match get_config(&data_dir)? {
        Some(cfg) => {
            let connector = if cfg.consensus.iroh_endpoints.is_empty() {
                TlsTcpConnector::new(
                    cfg.tls_config(),
                    settings.p2p_bind,
                    cfg.local.p2p_endpoints.clone(),
                    cfg.local.identity,
                )
                .await
                .into_dyn()
            } else {
                IrohConnector::new(
                    cfg.private.iroh_p2p_sk.clone().unwrap(),
                    settings.p2p_bind,
                    settings.iroh_dns.clone(),
                    settings.iroh_relays.clone(),
                    cfg.consensus
                        .iroh_endpoints
                        .iter()
                        .map(|(peer, endpoints)| (*peer, endpoints.p2p_pk))
                        .collect(),
                )
                .await?
                .into_dyn()
            };

            let (p2p_status_senders, p2p_status_receivers) = p2p_status_channels(connector.peers());

            let connections = ReconnectP2PConnections::new(
                cfg.local.identity,
                connector,
                &task_group,
                p2p_status_senders,
            )
            .into_dyn();

            (cfg, connections, p2p_status_receivers)
        }
        None => Box::pin(run_config_gen(
            data_dir.clone(),
            settings.clone(),
            db.clone(),
            &task_group,
            code_version_str.clone(),
            force_api_secrets.clone(),
            setup_ui_router,
            module_init_registry.clone(),
        ))
        .await
        .map_err(|err| {
            error!(
                target: LOG_CONSENSUS,
                error = format_args!("{err:#}"),
                "configuration generation failed"
            );
            warn!(
                target: LOG_CONSENSUS,
                safe_to_share = true,
                stage = "configuration_generation",
                failure_kind = "fatal",
                "Configuration generation failed"
            );
            err
        })?,
    };

    run_consensus(
        data_dir,
        force_api_secrets,
        settings,
        db,
        code_version_str,
        module_init_registry,
        task_group,
        bitcoin_rpc,
        dashboard_ui_router,
        db_checkpoint_retention,
        iroh_api_limits,
        cfg,
        connections,
        p2p_status_receivers,
        async { Ok(()) },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_consensus(
    data_dir: PathBuf,
    force_api_secrets: ApiSecrets,
    settings: ConfigGenSettings,
    db: Database,
    code_version_str: String,
    module_init_registry: ServerModuleInitRegistry,
    task_group: TaskGroup,
    bitcoin_rpc: DynServerBitcoinRpc,
    dashboard_ui_router: DashboardUiRouter,
    db_checkpoint_retention: u64,
    iroh_api_limits: ConnectionLimits,
    cfg: ServerConfig,
    connections: DynP2PConnections<P2PMessage>,
    p2p_status_receivers: P2PStatusReceivers,
    consensus_started: impl Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let decoders = module_init_registry.decoders_strict(
        cfg.consensus
            .modules
            .iter()
            .map(|(id, config)| (*id, &config.kind)),
    )?;

    let db = db.with_decoders(decoders);

    initialize_gauge_metrics(&task_group, &db).await;

    start_api_announcement_service(&db, &task_group, &cfg, force_api_secrets.get_active()).await?;
    start_guardian_metadata_service(&db, &task_group, &cfg, force_api_secrets.get_active()).await?;
    start_pkarr_publish_service(&db, &task_group, &cfg).await?;

    info!(target: LOG_CONSENSUS, safe_to_share = true, "Starting consensus...");

    let connectors = ConnectorRegistry::build_from_server_defaults()
        .bind()
        .await?;

    consensus_started.await?;

    Box::pin(consensus::run(
        connectors,
        connections,
        p2p_status_receivers,
        settings.api_bind,
        settings.iroh_dns,
        settings.iroh_relays,
        cfg,
        db,
        module_init_registry.clone(),
        &task_group,
        force_api_secrets,
        data_dir,
        code_version_str,
        bitcoin_rpc,
        settings.ui_bind,
        dashboard_ui_router,
        db_checkpoint_retention,
        iroh_api_limits,
    ))
    .await?;

    info!(target: LOG_CONSENSUS, safe_to_share = true, "Shutting down tasks...");

    task_group.shutdown();

    Ok(())
}

/// Run setup exclusively over the inherited driven-DKG control socket.
///
/// No setup API, UI, authentication endpoint, or database is opened until a
/// complete configuration has been atomically installed in `data_dir`.
#[allow(clippy::too_many_arguments)]
#[cfg(unix)]
pub async fn run_driven(
    data_dir: PathBuf,
    force_api_secrets: ApiSecrets,
    settings: ConfigGenSettings,
    open_database: DatabaseOpener,
    code_version_str: String,
    module_init_registry: ServerModuleInitRegistry,
    task_group: TaskGroup,
    bitcoin_rpc: DynServerBitcoinRpc,
    dashboard_ui_router: DashboardUiRouter,
    db_checkpoint_retention: u64,
    iroh_api_limits: ConnectionLimits,
) -> anyhow::Result<()> {
    let mut control = inherited_control_socket()?;

    let existing_config = if data_dir.exists() {
        match get_config_if_present_strict(&data_dir) {
            Ok(config) => config,
            Err(error) => {
                error!(
                    target: LOG_CONSENSUS,
                    error = format_args!("{error:#}"),
                    "Existing driven-DKG configuration is unreadable"
                );
                return Err(error);
            }
        }
    } else {
        None
    };

    let (cfg, connections, p2p_status_receivers) = if let Some(cfg) = existing_config {
        write_frame(
            &mut control,
            &ChildMessage::Hello {
                proto: PROTOCOL_VERSION,
                code_version: code_version_str.clone(),
                state: ChildState::AlreadyConfigured {
                    invite_code: cfg
                        .get_invite_code(force_api_secrets.get_active())
                        .to_string(),
                },
            },
        )
        .await?;

        let connector = if cfg.consensus.iroh_endpoints.is_empty() {
            TlsTcpConnector::try_new(
                cfg.tls_config(),
                settings.p2p_bind,
                cfg.local.p2p_endpoints.clone(),
                cfg.local.identity,
            )
            .await?
            .into_dyn()
        } else {
            IrohConnector::new(
                cfg.private
                    .iroh_p2p_sk
                    .clone()
                    .expect("Iroh config contains a P2P secret key"),
                settings.p2p_bind,
                settings.iroh_dns.clone(),
                settings.iroh_relays.clone(),
                cfg.consensus
                    .iroh_endpoints
                    .iter()
                    .map(|(peer, endpoints)| (*peer, endpoints.p2p_pk))
                    .collect(),
            )
            .await?
            .into_dyn()
        };
        let (status_senders, status_receivers) = p2p_status_channels(connector.peers());
        let connections = ReconnectP2PConnections::new(
            cfg.local.identity,
            connector,
            &task_group,
            status_senders,
        )
        .into_dyn();
        (cfg, connections, status_receivers)
    } else {
        let staging = prepare_staging(&data_dir)?;
        write_frame(
            &mut control,
            &ChildMessage::Hello {
                proto: PROTOCOL_VERSION,
                code_version: code_version_str.clone(),
                state: ChildState::NeedsParams,
            },
        )
        .await?;

        let parent_message: ParentMessage = read_frame(&mut control).await?;
        let params = match validate_run_dkg(parent_message, &settings) {
            Ok(params) => params,
            Err(error) => {
                let reason = bounded_reason(&format!("{error:#}"));
                write_frame(&mut control, &ChildMessage::ParamsRejected { reason }).await?;
                return Err(error);
            }
        };
        write_frame(&mut control, &ChildMessage::DkgStarted {}).await?;

        let generated = async {
            let connector = if params.iroh_endpoints().is_empty() {
                TlsTcpConnector::try_new(
                    params.tls_config(),
                    settings.p2p_bind,
                    params.p2p_urls(),
                    params.identity,
                )
                .await?
                .into_dyn()
            } else {
                IrohConnector::new(
                    params
                        .iroh_p2p_sk
                        .clone()
                        .expect("validated Iroh params contain a P2P secret key"),
                    settings.p2p_bind,
                    settings.iroh_dns.clone(),
                    settings.iroh_relays.clone(),
                    params
                        .iroh_endpoints()
                        .iter()
                        .map(|(peer, endpoints)| (*peer, endpoints.p2p_pk))
                        .collect(),
                )
                .await?
                .into_dyn()
            };
            let (status_senders, status_receivers) = p2p_status_channels(connector.peers());
            let connections = ReconnectP2PConnections::new(
                params.identity,
                connector,
                &task_group,
                status_senders,
            )
            .into_dyn();

            let cfg = ServerConfig::distributed_gen(
                &params,
                module_init_registry.clone(),
                code_version_str.clone(),
                connections.clone(),
                status_receivers.clone(),
            )
            .await?;
            cfg.validate_config(&cfg.local.identity, &module_init_registry)?;
            Ok::<_, anyhow::Error>((cfg, connections, status_receivers))
        }
        .await;

        let (cfg, connections, status_receivers) = match generated {
            Ok(generated) => generated,
            Err(error) => {
                error!(
                    target: LOG_CONSENSUS,
                    error = format_args!("{error:#}"),
                    "driven DKG failed"
                );
                write_frame(
                    &mut control,
                    &ChildMessage::DkgFailed {
                        reason: "distributed key generation failed; see server logs".to_string(),
                    },
                )
                .await?;
                return Err(error);
            }
        };

        let persist_result = (|| {
            write_new(
                staging.join(PLAINTEXT_PASSWORD),
                cfg.private.api_auth.as_str(),
            )?;
            write_new(staging.join(SALT_FILE), random_salt())?;
            write_server_config(
                &cfg,
                &staging,
                cfg.private.api_auth.as_str(),
                &module_init_registry,
                force_api_secrets.get_active(),
            )?;
            install_staging(&staging, &data_dir)
        })();
        if let Err(error) = persist_result {
            error!(
                target: LOG_CONSENSUS,
                error = format_args!("{error:#}"),
                "driven-DKG configuration persistence failed"
            );
            write_frame(
                &mut control,
                &ChildMessage::DkgFailed {
                    reason: "configuration persistence failed; see server logs".to_string(),
                },
            )
            .await?;
            return Err(error);
        }

        write_frame(
            &mut control,
            &ChildMessage::ConfigPersisted {
                invite_code: cfg
                    .get_invite_code(force_api_secrets.get_active())
                    .to_string(),
                api_url: cfg.consensus.api_endpoints()[&cfg.local.identity]
                    .url
                    .to_string(),
            },
        )
        .await?;
        (cfg, connections, status_receivers)
    };

    let db = open_database(data_dir.clone()).await?;
    run_consensus(
        data_dir,
        force_api_secrets,
        settings,
        db,
        code_version_str,
        module_init_registry,
        task_group,
        bitcoin_rpc,
        dashboard_ui_router,
        db_checkpoint_retention,
        iroh_api_limits,
        cfg,
        connections,
        p2p_status_receivers,
        async move {
            write_frame(&mut control, &ChildMessage::ConsensusStarted {}).await?;
            control.shutdown().await?;
            Ok(())
        },
    )
    .await
}

/// Driven DKG is unavailable without AF_UNIX socket support.
#[allow(clippy::too_many_arguments)]
#[cfg(not(unix))]
pub async fn run_driven(
    _data_dir: PathBuf,
    _force_api_secrets: ApiSecrets,
    _settings: ConfigGenSettings,
    _open_database: DatabaseOpener,
    _code_version_str: String,
    _module_init_registry: ServerModuleInitRegistry,
    _task_group: TaskGroup,
    _bitcoin_rpc: DynServerBitcoinRpc,
    _dashboard_ui_router: DashboardUiRouter,
    _db_checkpoint_retention: u64,
    _iroh_api_limits: ConnectionLimits,
) -> anyhow::Result<()> {
    anyhow::bail!("Driven DKG requires an AF_UNIX control socket")
}

#[cfg(unix)]
fn bounded_reason(reason: &str) -> String {
    reason.chars().take(512).collect()
}

#[cfg(unix)]
fn inherited_control_socket() -> anyhow::Result<tokio::net::UnixStream> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    anyhow::ensure!(
        fedimint_core::envs::is_env_var_set(FM_DKG_CTRL_ENV),
        "Driven DKG requires FM_DKG_CTRL=1"
    );
    // SAFETY: driven mode takes exclusive ownership of stdin, which the parent
    // contract requires to be its end of the control socketpair.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(std::io::stdin().as_raw_fd()) };
    let stream = std::os::unix::net::UnixStream::from(owned_fd);
    stream
        .peer_addr()
        .context("Driven-DKG stdin must be a connected AF_UNIX socket")?;
    let socket_type = nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::SockType)
        .context("Reading driven-DKG stdin socket type")?;
    anyhow::ensure!(
        socket_type == nix::sys::socket::SockType::Stream,
        "Driven-DKG stdin must use SOCK_STREAM semantics"
    );
    stream.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(stream).context("Opening driven-DKG control socket")
}

async fn update_server_info_version_dbtx(
    dbtx: &mut DatabaseTransaction<'_>,
    code_version_str: &str,
) {
    let mut server_info = dbtx.get_value(&ServerInfoKey).await.unwrap_or(ServerInfo {
        init_version: code_version_str.to_string(),
        last_version: code_version_str.to_string(),
    });
    server_info.last_version = code_version_str.to_string();
    dbtx.insert_entry(&ServerInfoKey, &server_info).await;
}

pub fn get_config(data_dir: &Path) -> anyhow::Result<Option<ServerConfig>> {
    recover_interrupted_password_change(data_dir)?;

    // Attempt get the config with local password, otherwise start config gen
    let path = data_dir.join(PLAINTEXT_PASSWORD);
    if let Ok(password_untrimmed) = fs::read_to_string(&path) {
        let password = trim_password(&password_untrimmed);
        let cfg = read_server_config(password, data_dir)?;
        finalize_password_change(data_dir)?;
        return Ok(Some(cfg));
    }

    Ok(None)
}

fn get_config_if_present_strict(data_dir: &Path) -> anyhow::Result<Option<ServerConfig>> {
    recover_interrupted_password_change(data_dir)?;

    let path = data_dir.join(PLAINTEXT_PASSWORD);
    let password_untrimmed = match fs::read_to_string(&path) {
        Ok(password) => password,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure_no_config_artifacts(data_dir)?;
            return Ok(None);
        }
        Err(error) => return Err(error).context("Reading existing driven-DKG password file"),
    };
    let password = trim_password(&password_untrimmed);
    let cfg = read_server_config(password, data_dir)?;
    finalize_password_change(data_dir)?;
    Ok(Some(cfg))
}

#[allow(clippy::too_many_arguments)]
pub async fn run_config_gen(
    data_dir: PathBuf,
    settings: ConfigGenSettings,
    db: Database,
    task_group: &TaskGroup,
    code_version_str: String,
    api_secrets: ApiSecrets,
    setup_ui_handler: SetupUiRouter,
    module_init_registry: ServerModuleInitRegistry,
) -> anyhow::Result<(
    ServerConfig,
    DynP2PConnections<P2PMessage>,
    P2PStatusReceivers,
)> {
    info!(target: LOG_CONSENSUS, safe_to_share = true, "Starting config gen");

    initialize_gauge_metrics(task_group, &db).await;

    let (cgp_sender, mut cgp_receiver) = tokio::sync::mpsc::channel(1);

    let setup_api = SetupApi::new(settings.clone(), db.clone(), cgp_sender);

    let mut rpc_module = RpcModule::new(setup_api.clone());

    net::api::attach_endpoints(&mut rpc_module, config::setup::server_endpoints(), None);

    let api_handler = net::api::spawn(
        "setup",
        // config gen always uses ws api
        settings.api_bind,
        rpc_module,
        10,
        api_secrets.clone(),
    )
    .await;

    let ui_task_group = TaskGroup::new();

    let ui_service = setup_ui_handler(setup_api.clone().into_dyn()).into_make_service();

    let ui_listener = TcpListener::bind(settings.ui_bind)
        .await
        .context("Failed to bind setup UI")
        .map_err(|error| config_gen_failure("setup_ui_bind", "bind_failed", error))?;

    ui_task_group.spawn("setup-ui", move |handle| async move {
        if let Err(err) = axum::serve(ui_listener, ui_service)
            .with_graceful_shutdown(handle.make_shutdown_rx())
            .await
        {
            error!(error = %err, "setup UI server failed");
            warn!(
                safe_to_share = true,
                stage = "setup_ui",
                failure_kind = "server_failed",
                "Configuration generation failed"
            );
            panic!("Failed to serve setup UI");
        }
    });

    info!(target: LOG_CONSENSUS, "Setup UI running at http://{} 🚀", settings.ui_bind);
    info!(
        target: LOG_CONSENSUS,
        safe_to_share = true,
        stage = "setup_services",
        "Configuration setup services are ready"
    );

    let cg_params = cgp_receiver.recv().await.ok_or_else(|| {
        config_gen_failure(
            "setup_parameters",
            "channel_closed",
            anyhow::anyhow!("Config gen params receiver closed unexpectedly"),
        )
    })?;

    info!(
        target: LOG_CONSENSUS,
        safe_to_share = true,
        stage = "setup_parameters",
        peer_count = cg_params.peer_ids().len(),
        "Configuration generation parameters accepted"
    );

    // HACK: The `start-dkg` API call needs to have some time to finish
    // before we shut down api handling. There's no easy and good way to do
    // that other than just giving it some grace period.
    sleep(Duration::from_millis(100)).await;

    api_handler
        .stop()
        .map_err(|error| anyhow::anyhow!("Config API stopped before DKG: {error}"))
        .map_err(|error| config_gen_failure("setup_api_shutdown", "stop_failed", error))?;

    api_handler.stopped().await;

    ui_task_group
        .shutdown_join_all(None)
        .await
        .context("Failed to shutdown UI server after config gen")
        .map_err(|error| config_gen_failure("setup_ui_shutdown", "task_join_failed", error))?;

    let connector = if cg_params.iroh_endpoints().is_empty() {
        TlsTcpConnector::new(
            cg_params.tls_config(),
            settings.p2p_bind,
            cg_params.p2p_urls(),
            cg_params.identity,
        )
        .await
        .into_dyn()
    } else {
        IrohConnector::new(
            cg_params.iroh_p2p_sk.clone().unwrap(),
            settings.p2p_bind,
            settings.iroh_dns,
            settings.iroh_relays,
            cg_params
                .iroh_endpoints()
                .iter()
                .map(|(peer, endpoints)| (*peer, endpoints.p2p_pk))
                .collect(),
        )
        .await
        .map_err(|error| config_gen_failure("p2p_connector", "initialization_failed", error))?
        .into_dyn()
    };

    info!(
        target: LOG_CONSENSUS,
        safe_to_share = true,
        stage = "p2p_connector",
        transport = if cg_params.iroh_endpoints().is_empty() { "tcp_tls" } else { "iroh" },
        "Configuration-generation peer connector is ready"
    );

    let (p2p_status_senders, p2p_status_receivers) = p2p_status_channels(connector.peers());

    let connections = ReconnectP2PConnections::new(
        cg_params.identity,
        connector,
        task_group,
        p2p_status_senders,
    )
    .into_dyn();

    let cfg = ServerConfig::distributed_gen(
        &cg_params,
        module_init_registry.clone(),
        code_version_str.clone(),
        connections.clone(),
        p2p_status_receivers.clone(),
    )
    .await?;

    assert_ne!(
        cfg.consensus.iroh_endpoints.is_empty(),
        cfg.consensus.api_endpoints.is_empty(),
    );

    // TODO: Make writing password optional
    write_new(
        data_dir.join(PLAINTEXT_PASSWORD),
        cfg.private.api_auth.as_str(),
    )
    .map_err(|error| {
        config_gen_failure("configuration_persistence", "password_write_failed", error)
    })?;
    write_new(data_dir.join(SALT_FILE), random_salt()).map_err(|error| {
        config_gen_failure("configuration_persistence", "salt_write_failed", error)
    })?;
    write_server_config(
        &cfg,
        &data_dir,
        cfg.private.api_auth.as_str(),
        &module_init_registry,
        api_secrets.get_active(),
    )
    .map_err(|error| {
        config_gen_failure(
            "configuration_persistence",
            "server_config_write_failed",
            error,
        )
    })?;

    info!(
        target: LOG_CONSENSUS,
        safe_to_share = true,
        stage = "configuration_persistence",
        "Generated server configuration was persisted"
    );

    Ok((cfg, connections, p2p_status_receivers))
}
