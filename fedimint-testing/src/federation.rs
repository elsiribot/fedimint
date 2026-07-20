use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use fedimint_api_client::api::{DynGlobalApi, FederationApiExt};
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_client::{Client, ClientHandleArc, RootSecret};
use fedimint_client_module::AdminCreds;
use fedimint_client_module::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::PeerId;
use fedimint_core::config::{ClientConfig, FederationId};
use fedimint_core::core::ModuleKind;
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::endpoint_constants::SESSION_COUNT_ENDPOINT;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::net::peers::IP2PConnections;
use fedimint_core::rustls::install_crypto_provider;
use fedimint_core::task::{TaskGroup, block_in_place, sleep_in_test};
use fedimint_gateway_common::ConnectFedPayload;
use fedimint_gateway_server::{Gateway, IAdminGateway};
use fedimint_logging::LOG_TEST;
use fedimint_rocksdb::RocksDb;
use fedimint_server::config::ServerConfig;
use fedimint_server::core::ServerModuleInitRegistry;
use fedimint_server::net::api::ApiSecrets;
use fedimint_server::net::p2p::{ReconnectP2PConnections, p2p_status_channels};
use fedimint_server::net::p2p_connector::{IP2PConnector, TlsTcpConnector};
use fedimint_server::{ConnectionLimits, consensus};
use fedimint_server_core::bitcoin_rpc::DynServerBitcoinRpc;
use fedimint_testing_core::config::local_config_gen_params;
use tracing::info;

/// Test fixture for a running fedimint federation
#[derive(Clone)]
pub struct FederationTest {
    configs: BTreeMap<PeerId, ServerConfig>,
    databases: BTreeMap<PeerId, Database>,
    server_init: ServerModuleInitRegistry,
    client_init: ClientModuleInitRegistry,
    tasks: BTreeMap<PeerId, TaskGroup>,
    num_peers: u16,
    num_offline: u16,
    base_port: u16,
    bitcoin_rpc: DynServerBitcoinRpc,
    connectors: ConnectorRegistry,
}

impl FederationTest {
    /// Create two clients, useful for send/receive tests
    pub async fn two_clients(&self) -> (ClientHandleArc, ClientHandleArc) {
        (self.new_client().await, self.new_client().await)
    }

    /// Create a client connected to this fed
    pub async fn new_client(&self) -> ClientHandleArc {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap();

        self.new_client_with(client_config, MemDatabase::new().into(), None)
            .await
    }

    /// Create a client connected to this fed using the given database
    pub async fn new_client_with_db(&self, db: Database) -> ClientHandleArc {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap();

        self.new_client_with(client_config, db, None).await
    }

    /// Create a client connected to this fed but using RocksDB instead of MemDB
    pub async fn new_client_rocksdb(&self) -> ClientHandleArc {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap();

        self.new_client_with(
            client_config,
            RocksDb::build(tempfile::tempdir().expect("Couldn't create temp dir"))
                .open()
                .await
                .expect("Couldn't open DB")
                .into(),
            None,
        )
        .await
    }

    /// Returns a peer's full server config, e.g. to derive its secrets in
    /// tests
    pub fn server_config(&self, peer_id: PeerId) -> &ServerConfig {
        self.configs.get(&peer_id).expect("peer to have config")
    }

    /// Waits until every online peer's api answers requests
    pub async fn await_apis_online(&self) {
        for peer_id in self.online_peer_ids() {
            let api = self
                .new_admin_api(peer_id)
                .await
                .expect("Failed to create admin api");

            while let Err(e) = api
                .request_admin_no_auth::<u64>(SESSION_COUNT_ENDPOINT, ApiRequestErased::default())
                .await
            {
                sleep_in_test(
                    format!("Waiting for api of peer {peer_id} to come online: {e}"),
                    Duration::from_millis(500),
                )
                .await;
            }
        }
    }

    /// Stops all peers and starts them again with their existing databases
    /// and configs.
    pub async fn restart_all_peers(&mut self) {
        info!(target: LOG_TEST, "Restarting all federation peers");

        let online: Vec<PeerId> = self.online_peer_ids().collect();

        for peer_id in &online {
            self.stop_peer(*peer_id).await;
        }

        for peer_id in &online {
            self.start_stopped_peer(*peer_id).await;
        }

        self.await_apis_online().await;
    }

    /// Stops a single peer, e.g. to simulate a guardian being offline while
    /// the rest of the federation hot activates a module.
    pub async fn stop_peer(&mut self, peer_id: PeerId) {
        info!(target: LOG_TEST, %peer_id, "Stopping federation peer");

        self.tasks
            .remove(&peer_id)
            .expect("Peer is running")
            .shutdown_join_all(Duration::from_secs(60))
            .await
            .expect("Could not shut down peer cleanly");
    }

    /// Starts a previously stopped peer again with its existing database
    /// and config.
    pub async fn start_stopped_peer(&mut self, peer_id: PeerId) {
        info!(target: LOG_TEST, %peer_id, "Starting federation peer");

        let task_group = TaskGroup::new();

        start_peer(
            self.configs[&peer_id].clone(),
            self.databases[&peer_id].clone(),
            self.server_init.clone(),
            self.base_port,
            &task_group,
            self.bitcoin_rpc.clone(),
        )
        .await;

        self.tasks.insert(peer_id, task_group);
    }

    /// Create a new admin api for the given PeerId
    pub async fn new_admin_api(&self, peer_id: PeerId) -> anyhow::Result<DynGlobalApi> {
        let config = self.configs.get(&peer_id).expect("peer to have config");

        DynGlobalApi::new_admin(
            ConnectorRegistry::build_from_testing_env()?.bind().await?,
            peer_id,
            config.consensus.api_endpoints()[&peer_id].url.clone(),
            None,
        )
    }

    /// Create a new admin client connected to this fed
    pub async fn new_admin_client(&self, peer_id: PeerId, auth: ApiAuth) -> ClientHandleArc {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap();

        let admin_creds = AdminCreds { peer_id, auth };

        self.new_client_with(client_config, MemDatabase::new().into(), Some(admin_creds))
            .await
    }

    pub async fn new_client_with(
        &self,
        client_config: ClientConfig,
        db: Database,
        admin_creds: Option<AdminCreds>,
    ) -> ClientHandleArc {
        info!(target: LOG_TEST, "Setting new client with config");
        let mut client_builder = Client::builder().await.expect("Failed to build client");
        client_builder.with_module_inits(self.client_init.clone());
        if let Some(admin_creds) = admin_creds {
            client_builder.set_admin_creds(admin_creds);
        }
        let client_secret = Client::load_or_generate_client_secret(&db).await.unwrap();
        client_builder
            .preview_with_existing_config(self.connectors.clone(), client_config, None)
            .await
            .expect("Preview failed")
            .join(
                db,
                RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(
                    &client_secret,
                )),
            )
            .await
            .map(Arc::new)
            .expect("Failed to build client")
    }

    /// Join a federation with an existing database and root secret
    pub async fn join_client_with_db(
        &self,
        db: Database,
        root_secret: RootSecret,
    ) -> ClientHandleArc {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap();

        info!(target: LOG_TEST, "Joining client with existing db");
        let mut client_builder = Client::builder().await.expect("Failed to build client");
        client_builder.with_module_inits(self.client_init.clone());
        client_builder
            .preview_with_existing_config(self.connectors.clone(), client_config, None)
            .await
            .expect("Preview failed")
            .join(db, root_secret)
            .await
            .map(Arc::new)
            .expect("Failed to join client")
    }

    /// Create a recovering client with an existing database and root secret.
    /// Returns both the client and the database so a new client can be created
    /// with the same DB after recovery completes.
    pub async fn recover_client_with_db(
        &self,
        db: Database,
        root_secret: RootSecret,
    ) -> ClientHandleArc {
        let client_config = self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap();

        info!(target: LOG_TEST, "Recovering client with existing db");
        let mut client_builder = Client::builder().await.expect("Failed to build client");
        client_builder.with_module_inits(self.client_init.clone());
        client_builder
            .preview_with_existing_config(self.connectors.clone(), client_config, None)
            .await
            .expect("Preview failed")
            .recover(db, root_secret, None)
            .await
            .map(Arc::new)
            .expect("Failed to recover client")
    }

    /// Open an existing client database (e.g., after recovery)
    pub async fn open_client_with_db(
        &self,
        db: Database,
        root_secret: RootSecret,
    ) -> ClientHandleArc {
        info!(target: LOG_TEST, "Opening client with existing db");
        let mut client_builder = Client::builder().await.expect("Failed to build client");
        client_builder.with_module_inits(self.client_init.clone());
        client_builder
            .open(self.connectors.clone(), db, root_secret)
            .await
            .map(Arc::new)
            .expect("Failed to open client")
    }

    /// Return first invite code for gateways
    pub fn invite_code(&self) -> InviteCode {
        let peer_id = PeerId::from(0);
        let cfg = &self.configs[&peer_id];
        InviteCode::new(
            cfg.consensus.api_endpoints()[&peer_id].url.clone(),
            peer_id,
            cfg.calculate_federation_id(),
            None,
        )
    }

    ///  Return the federation id
    pub fn id(&self) -> FederationId {
        self.configs[&PeerId::from(0)]
            .consensus
            .to_client_config(&self.server_init)
            .unwrap()
            .global
            .calculate_federation_id()
    }

    /// Connects a gateway to this `FederationTest`
    pub async fn connect_gateway(&self, gw: &Gateway) {
        gw.handle_connect_federation(ConnectFedPayload {
            invite_code: self.invite_code().to_string(),
            use_tor: Some(false),
            recover: Some(false),
        })
        .await
        .expect("Failed to connect federation");
    }

    /// Return all online PeerIds
    pub fn online_peer_ids(&self) -> impl Iterator<Item = PeerId> + use<> {
        // we can assume this ordering since peers are started in ascending order
        (0..(self.num_peers - self.num_offline)).map(PeerId::from)
    }

    /// Returns true if the federation is running in a degraded state
    pub fn is_degraded(&self) -> bool {
        self.num_offline > 0
    }
}

/// Builder struct for creating a `FederationTest`.
#[derive(Clone, Debug)]
pub struct FederationTestBuilder {
    num_peers: u16,
    num_offline: u16,
    base_port: u16,
    primary_module_kind: ModuleKind,
    version_hash: String,
    server_init: ServerModuleInitRegistry,
    client_init: ClientModuleInitRegistry,
    bitcoin_rpc_connection: DynServerBitcoinRpc,
    enable_mint_fees: bool,
}

impl FederationTestBuilder {
    pub fn new(
        server_init: ServerModuleInitRegistry,
        client_init: ClientModuleInitRegistry,
        primary_module_kind: ModuleKind,
        num_offline: u16,
        bitcoin_rpc_connection: DynServerBitcoinRpc,
    ) -> FederationTestBuilder {
        let num_peers = 4;
        Self {
            num_peers,
            num_offline,
            base_port: block_in_place(|| fedimint_portalloc::port_alloc(num_peers * 3))
                .expect("Failed to allocate a port range"),
            primary_module_kind,
            version_hash: "fedimint-testing-dummy-version-hash".to_owned(),
            server_init,
            client_init,
            bitcoin_rpc_connection,
            enable_mint_fees: true,
        }
    }

    pub fn num_peers(mut self, num_peers: u16) -> FederationTestBuilder {
        self.num_peers = num_peers;
        self
    }

    pub fn num_offline(mut self, num_offline: u16) -> FederationTestBuilder {
        self.num_offline = num_offline;
        self
    }

    pub fn base_port(mut self, base_port: u16) -> FederationTestBuilder {
        self.base_port = base_port;
        self
    }

    pub fn primary_module_kind(mut self, primary_module_kind: ModuleKind) -> FederationTestBuilder {
        self.primary_module_kind = primary_module_kind;
        self
    }

    pub fn version_hash(mut self, version_hash: String) -> FederationTestBuilder {
        self.version_hash = version_hash;
        self
    }

    pub fn disable_mint_fees(mut self) -> FederationTestBuilder {
        self.enable_mint_fees = false;
        self
    }

    #[allow(clippy::too_many_lines)]
    pub async fn build(self) -> FederationTest {
        install_crypto_provider().await;
        let num_offline = self.num_offline;
        assert!(
            self.num_peers > 3 * self.num_offline,
            "too many peers offline ({num_offline}) to reach consensus"
        );
        let peers = (0..self.num_peers).map(PeerId::from).collect::<Vec<_>>();
        let params = local_config_gen_params(
            &peers,
            self.base_port,
            self.enable_mint_fees,
            &self.server_init,
        )
        .expect("Generates local config");

        let configs =
            ServerConfig::trusted_dealer_gen(&params, &self.server_init, &self.version_hash);

        let mut tasks = BTreeMap::new();
        let mut databases = BTreeMap::new();
        for (peer_id, cfg) in configs.clone() {
            if u16::from(peer_id) >= self.num_peers - self.num_offline {
                continue;
            }

            let instances = cfg.consensus.iter_module_instances();
            let decoders = self.server_init.available_decoders(instances).unwrap();
            let db = Database::new(MemDatabase::new(), decoders);
            databases.insert(peer_id, db.clone());

            let task_group = TaskGroup::new();

            start_peer(
                cfg,
                db,
                self.server_init.clone(),
                self.base_port,
                &task_group,
                self.bitcoin_rpc_connection.clone(),
            )
            .await;

            tasks.insert(peer_id, task_group);
        }

        let fed = FederationTest {
            configs,
            databases,
            server_init: self.server_init,
            client_init: self.client_init,
            tasks,
            num_peers: self.num_peers,
            num_offline: self.num_offline,
            base_port: self.base_port,
            bitcoin_rpc: self.bitcoin_rpc_connection,
            connectors: ConnectorRegistry::build_from_testing_env()
                .expect("Failed to initialize endpoints for testing (env)")
                .bind()
                .await
                .expect("Failed to initialize endpoints for testing"),
        };

        fed.await_apis_online().await;

        fed
    }
}

/// Starts one federation peer, used for the initial start and restarts.
async fn start_peer(
    cfg: ServerConfig,
    db: Database,
    server_init: ServerModuleInitRegistry,
    base_port: u16,
    task_group: &TaskGroup,
    bitcoin_rpc: DynServerBitcoinRpc,
) {
    let peer_port = base_port + u16::from(cfg.local.identity) * 3;

    let p2p_bind = format!("127.0.0.1:{peer_port}").parse().unwrap();
    let api_bind = format!("127.0.0.1:{}", peer_port + 1).parse().unwrap();
    let ui_bind = format!("127.0.0.1:{}", peer_port + 2).parse().unwrap();

    let subgroup = task_group.make_subgroup();
    let checkpoint_dir = tempfile::Builder::new().tempdir().unwrap().keep();
    let code_version_str = env!("CARGO_PKG_VERSION");

    let connector = TlsTcpConnector::new(
        cfg.tls_config(),
        p2p_bind,
        cfg.local.p2p_endpoints.clone(),
        cfg.local.identity,
    )
    .await
    .into_dyn();

    let (p2p_status_senders, p2p_status_receivers) = p2p_status_channels(connector.peers());

    let connections = ReconnectP2PConnections::new(
        cfg.local.identity,
        connector,
        task_group,
        p2p_status_senders,
    )
    .into_dyn();

    task_group.spawn("fedimintd", move |_| async move {
        Box::pin(consensus::run(
            ConnectorRegistry::build_from_testing_env()
                .unwrap()
                .bind()
                .await
                .unwrap(),
            Some(ApiAuth::new("pass".to_string())),
            Some(ApiAuth::new("pass".to_string())),
            connections,
            p2p_status_receivers,
            api_bind,
            None,
            vec![],
            cfg.clone(),
            db.clone(),
            server_init,
            &subgroup,
            ApiSecrets::default(),
            checkpoint_dir,
            code_version_str.to_string(),
            String::new(),
            bitcoin_rpc,
            ui_bind,
            Box::new(|_| axum::Router::new()),
            1,
            Duration::from_secs(3600),
            ConnectionLimits {
                max_connections: 1000,
                max_requests_per_connection: 100,
            },
        ))
        .await
        .expect("Could not initialise consensus");
    });
}
