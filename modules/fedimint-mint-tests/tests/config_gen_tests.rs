//! Acceptance test for consensus-coordinated module config generation.
//!
//! Boots a real in-process federation (real AlephBFT consensus, real p2p
//! connections, real api) and drives a full generation lifecycle through
//! the admin api: propose a mint module, approve from every guardian, run
//! the actual mint DKGs over the runtime p2p transport and verify every
//! peer reports an identical generated consensus config.

use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_api_client::api::{DynGlobalApi, FederationApiExt};
use fedimint_client::db::PendingClientConfigKey;
use fedimint_client::{Client, RootSecret};
use fedimint_client_module::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_core::PeerId;
use fedimint_core::config_gen::{
    AbortModuleGenerationRequest, ModuleConfigProposal, ModuleGenerationId, RegisterAssetRequest,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::endpoint_constants::{
    ABORT_MODULE_GENERATION_ENDPOINT, ACTIVATE_MODULE_GENERATION_ENDPOINT,
    APPROVE_MODULE_GENERATION_ENDPOINT, AUDIT_ENDPOINT, MODULE_GENERATIONS_ENDPOINT,
    PROPOSE_MODULE_GENERATION_ENDPOINT, REGISTER_ASSET_ENDPOINT, SESSION_COUNT_ENDPOINT,
};
use fedimint_core::module::{ApiAuth, ApiRequestErased, ModuleConsensusVersion};
use fedimint_core::task::sleep_in_test;
use fedimint_dummy_client::DummyClientInit;
use fedimint_dummy_common::MODULE_CONSENSUS_VERSION as DUMMY_MODULE_CONSENSUS_VERSION;
use fedimint_dummy_server::DummyInit;
use fedimint_logging::LOG_TEST;
use fedimint_mint_client::MintClientInit;
use fedimint_mint_common::MODULE_CONSENSUS_VERSION;
use fedimint_mint_server::MintInit;
use fedimint_testing::fixtures::Fixtures;
use tracing::info;

const NUM_PEERS: u16 = 4;

fn auth() -> ApiAuth {
    ApiAuth::new("pass".to_string())
}

async fn generation_state(
    api: &DynGlobalApi,
    generation_id: ModuleGenerationId,
) -> Option<serde_json::Value> {
    let log: serde_json::Value = api
        .request_admin(
            MODULE_GENERATIONS_ENDPOINT,
            ApiRequestErased::default(),
            auth(),
        )
        .await
        .expect("module_generations request succeeds");

    let state = log["generations"][generation_id.0.to_string()].clone();

    (!state.is_null()).then_some(state)
}

async fn await_state(
    api: &DynGlobalApi,
    generation_id: ModuleGenerationId,
    variant: &str,
) -> serde_json::Value {
    loop {
        if let Some(state) = generation_state(api, generation_id).await {
            assert!(
                state.get("Aborted").is_none() || variant == "Aborted",
                "Generation unexpectedly aborted: {state}"
            );

            if let Some(inner) = state.get(variant) {
                return inner.clone();
            }
        }

        sleep_in_test(
            format!("Waiting for generation state {variant}"),
            Duration::from_millis(200),
        )
        .await;
    }
}

/// Proposes a generation from peer 0 and returns its id.
async fn propose(
    apis: &[DynGlobalApi],
    module_kind: &'static str,
    consensus_version: ModuleConsensusVersion,
) -> ModuleGenerationId {
    propose_with_params(apis, module_kind, consensus_version, BTreeMap::new()).await
}

/// Proposes a generation from peer 0 with the given module params and
/// returns its id.
async fn propose_with_params(
    apis: &[DynGlobalApi],
    module_kind: &'static str,
    consensus_version: ModuleConsensusVersion,
    params: BTreeMap<String, String>,
) -> ModuleGenerationId {
    let proposal = ModuleConfigProposal {
        module_kind: ModuleKind::from_static_str(module_kind),
        consensus_version,
        network: bitcoin::Network::Regtest,
        disable_base_fees: false,
        params,
    };

    let generation_id: ModuleGenerationId = apis[0]
        .request_admin(
            PROPOSE_MODULE_GENERATION_ENDPOINT,
            ApiRequestErased::new(&proposal),
            auth(),
        )
        .await
        .expect("proposal accepted");

    info!(target: LOG_TEST, %generation_id, %module_kind, "Proposed generation");

    generation_id
}

/// Approves the generation from every guardian but the proposer, waiting
/// until the proposal is visible in each guardian's local log first.
async fn approve_all(apis: &[DynGlobalApi], generation_id: ModuleGenerationId) {
    for api in apis.iter().skip(1) {
        while generation_state(api, generation_id).await.is_none() {
            sleep_in_test("Waiting for proposal", Duration::from_millis(200)).await;
        }

        api.request_admin::<()>(
            APPROVE_MODULE_GENERATION_ENDPOINT,
            ApiRequestErased::new(generation_id),
            auth(),
        )
        .await
        .expect("approval accepted");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn generates_mint_config_on_running_federation() -> anyhow::Result<()> {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);
    let fed = fixtures.new_fed_not_degraded().await;

    let mut apis = Vec::new();
    for peer in 0..NUM_PEERS {
        apis.push(fed.new_admin_api(PeerId::from(peer)).await?);
    }

    let generation_id = propose(&apis, "mint", MODULE_CONSENSUS_VERSION).await;

    approve_all(&apis, generation_id).await;

    info!(target: LOG_TEST, "All guardians approved, awaiting DKG results");

    let mut consensus_configs = Vec::new();

    for api in &apis {
        let generated = await_state(api, generation_id, "Generated").await;

        let consensus_config = generated["consensus_config"].clone();

        assert_eq!(consensus_config["kind"], "mint");

        consensus_configs.push(consensus_config);
    }

    assert!(
        consensus_configs
            .iter()
            .all(|config| *config == consensus_configs[0]),
        "Peers reported different consensus configs"
    );

    // The private config committed to consensus is recoverable from the
    // guardian's root secret: fetch peer 1's encrypted blob from peer 0's
    // log and decrypt it with a key derived from peer 1's secret.
    let generated = await_state(&apis[0], generation_id, "Generated").await;

    let mut encrypted_private_config: Vec<u8> =
        serde_json::from_value(generated["encrypted_private_configs"]["1"].clone())?;

    let root = fedimint_server::consensus::config_gen::secrets::config_gen_root(
        &fed.server_config(PeerId::from(1))
            .private
            .broadcast_secret_key,
    );

    let decrypted = fedimint_aead::decrypt(
        &mut encrypted_private_config,
        &fedimint_server::consensus::config_gen::secrets::result_encryption_key(
            &root,
            generation_id,
        ),
    )
    .expect("guardian can decrypt its own committed private config");

    let private_config: serde_json::Value = serde_json::from_slice(decrypted)?;

    assert_eq!(private_config["kind"], "mint");

    info!(
        target: LOG_TEST,
        "All peers generated identical mint consensus config; private config recoverable"
    );

    Ok(())
}

/// Activates a generated module from the given guardian and returns its
/// instance id and activation session.
async fn activate(api: &DynGlobalApi, generation_id: ModuleGenerationId) -> (u64, u64) {
    api.request_admin::<()>(
        ACTIVATE_MODULE_GENERATION_ENDPOINT,
        ApiRequestErased::new(generation_id),
        auth(),
    )
    .await
    .expect("activation accepted");

    let active = await_state(api, generation_id, "Active").await;

    let instance_id = active["instance_id"]
        .as_u64()
        .expect("instance id is a number");
    let active_from_session = active["active_from_session"]
        .as_u64()
        .expect("activation session is a number");

    (instance_id, active_from_session)
}

/// Waits until the guardian's audit covers the module instance. Polled and
/// tolerant of request errors since the guardian's api is respawned with the
/// extended module set shortly after the activation session is reached.
async fn await_module_in_audit(api: &DynGlobalApi, instance_id: u64) {
    loop {
        if let Ok(audit) = api
            .request_admin::<serde_json::Value>(AUDIT_ENDPOINT, ApiRequestErased::default(), auth())
            .await
            && audit["module_summaries"][instance_id.to_string()].is_object()
        {
            return;
        }

        sleep_in_test(
            "Waiting for the guardian to serve the activated module",
            Duration::from_millis(200),
        )
        .await;
    }
}

/// Waits until the guardian's session count has advanced past the session.
async fn await_session_past(api: &DynGlobalApi, session: u64) -> anyhow::Result<()> {
    loop {
        if let Ok(session_count) = api
            .request_admin_no_auth::<u64>(SESSION_COUNT_ENDPOINT, ApiRequestErased::default())
            .await
            && session_count > session
        {
            return Ok(());
        }

        sleep_in_test(
            "Waiting for consensus to advance past the session",
            Duration::from_millis(200),
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn activated_module_runs_without_restart() -> anyhow::Result<()> {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);
    let fed = fixtures.new_fed_not_degraded().await;

    let mut apis = Vec::new();
    for peer in 0..NUM_PEERS {
        apis.push(fed.new_admin_api(PeerId::from(peer)).await?);
    }

    let generation_id = propose(&apis, "mint", MODULE_CONSENSUS_VERSION).await;

    approve_all(&apis, generation_id).await;

    for api in &apis {
        await_state(api, generation_id, "Generated").await;
    }

    let (instance_id, active_from_session) = activate(&apis[0], generation_id).await;

    info!(
        target: LOG_TEST,
        instance_id,
        active_from_session,
        "Module activated, waiting for hot activation"
    );

    // Every guardian hot activates the module at the activation session
    // without restarting: consensus advances past the activation session...
    for api in &apis {
        await_session_past(api, active_from_session).await?;
    }

    // ...and the module shows up in every guardian's audit, polled since
    // each guardian's api is respawned with the extended module set shortly
    // after the activation session is reached
    for api in &apis {
        await_module_in_audit(api, instance_id).await;
    }

    // A client joining with the pre-activation config picks the new module
    // up through its additive config refresh served by the rebuilt api: the
    // refreshed config is stored as pending and promoted on the next start.
    let client_db: Database = MemDatabase::new().into();

    let client = fed.new_client_with_db(client_db.clone()).await;

    while client_db
        .begin_transaction_nc()
        .await
        .get_value(&PendingClientConfigKey)
        .await
        .is_none()
    {
        sleep_in_test(
            "Waiting for client to fetch the refreshed config",
            Duration::from_millis(200),
        )
        .await;
    }

    drop(client);

    let client_secret = Client::load_or_generate_client_secret(&client_db).await?;

    let client = fed
        .open_client_with_db(
            client_db,
            RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(
                &client_secret,
            )),
        )
        .await;

    assert!(
        client
            .config()
            .await
            .modules
            .contains_key(&(instance_id as u16)),
        "Client config is missing the dynamically added module"
    );

    assert!(
        client.has_module(instance_id as u16),
        "Client did not initialize the dynamically added module"
    );

    info!(
        target: LOG_TEST,
        "Dynamically added module is live without any restart"
    );

    Ok(())
}

/// The dummy module's private config is a unit struct, like the production
/// meta module's `MetaConfigPrivate`. Unit structs hit the `JsonWithKind`
/// serde flatten quirk: they serialize to a bare `{"kind": ...}` object and
/// deserialize back with an empty map value, which the activation path has
/// to fix up before initializing the module.
#[tokio::test(flavor = "multi_thread")]
async fn activates_module_with_unit_struct_private_config() -> anyhow::Result<()> {
    let fixtures =
        Fixtures::new_primary(MintClientInit, MintInit).with_module(DummyClientInit, DummyInit);
    let fed = fixtures.new_fed_not_degraded().await;

    let mut apis = Vec::new();
    for peer in 0..NUM_PEERS {
        apis.push(fed.new_admin_api(PeerId::from(peer)).await?);
    }

    let generation_id = propose(&apis, "dummy", DUMMY_MODULE_CONSENSUS_VERSION).await;

    approve_all(&apis, generation_id).await;

    for api in &apis {
        await_state(api, generation_id, "Generated").await;
    }

    let (instance_id, active_from_session) = activate(&apis[0], generation_id).await;

    for api in &apis {
        await_session_past(api, active_from_session).await?;
    }

    for api in &apis {
        await_module_in_audit(api, instance_id).await;
    }

    info!(
        target: LOG_TEST,
        "Module with unit struct private config hot activated on every guardian"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_peer_catches_up_after_activation() -> anyhow::Result<()> {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);
    let mut fed = fixtures.new_fed_not_degraded().await;

    let mut apis = Vec::new();
    for peer in 0..NUM_PEERS {
        apis.push(fed.new_admin_api(PeerId::from(peer)).await?);
    }

    let generation_id = propose(&apis, "mint", MODULE_CONSENSUS_VERSION).await;

    approve_all(&apis, generation_id).await;

    // The offline guardian has to participate in the DKG so it holds its
    // private config before it goes down
    for api in &apis {
        await_state(api, generation_id, "Generated").await;
    }

    let offline_peer = PeerId::from(NUM_PEERS - 1);

    fed.stop_peer(offline_peer).await;

    info!(target: LOG_TEST, %offline_peer, "Stopped guardian, activating without it");

    let (instance_id, active_from_session) = activate(&apis[0], generation_id).await;

    // The remaining quorum hot activates the module and keeps running
    await_session_past(&apis[0], active_from_session).await?;

    fed.start_stopped_peer(offline_peer).await;

    info!(target: LOG_TEST, %offline_peer, "Restarted guardian, waiting for catch up");

    // The restarted guardian replays the missed sessions including the
    // activation and initializes the module during catch up
    let offline_api = fed.new_admin_api(offline_peer).await?;

    await_session_past(&offline_api, active_from_session).await?;

    await_module_in_audit(&offline_api, instance_id).await;

    info!(
        target: LOG_TEST,
        "Offline guardian caught up with the hot activated module"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn aborted_generation_can_be_retried_under_fresh_id() -> anyhow::Result<()> {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);
    let fed = fixtures.new_fed_not_degraded().await;

    let mut apis = Vec::new();
    for peer in 0..NUM_PEERS {
        apis.push(fed.new_admin_api(PeerId::from(peer)).await?);
    }

    let generation_id = propose(&apis, "mint", MODULE_CONSENSUS_VERSION).await;

    // Any single guardian can abort a pending generation
    while generation_state(&apis[1], generation_id).await.is_none() {
        sleep_in_test("Waiting for proposal", Duration::from_millis(200)).await;
    }

    apis[1]
        .request_admin::<()>(
            ABORT_MODULE_GENERATION_ENDPOINT,
            ApiRequestErased::new(AbortModuleGenerationRequest {
                generation_id,
                reason: "test abort".to_string(),
            }),
            auth(),
        )
        .await?;

    for api in &apis {
        await_state(api, generation_id, "Aborted").await;
    }

    // A fresh proposal under the next id completes normally
    let retry_id = propose(&apis, "mint", MODULE_CONSENSUS_VERSION).await;
    assert_eq!(retry_id.0, generation_id.0 + 1);

    approve_all(&apis, retry_id).await;

    for api in &apis {
        await_state(api, retry_id, "Generated").await;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_module_kind_is_rejected() -> anyhow::Result<()> {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);
    let fed = fixtures.new_fed_not_degraded().await;

    let mut apis = Vec::new();
    for peer in 0..NUM_PEERS {
        apis.push(fed.new_admin_api(PeerId::from(peer)).await?);
    }

    // The propose endpoint validates the module kind upfront (see
    // `try_propose_module_generation`) and rejects unsupported kinds
    // synchronously, before ever submitting a consensus item -- so there is
    // no pending generation to approve or await an abort for.
    let proposal = ModuleConfigProposal {
        module_kind: ModuleKind::from_static_str("no-such-module"),
        consensus_version: MODULE_CONSENSUS_VERSION,
        network: bitcoin::Network::Regtest,
        disable_base_fees: false,
        params: BTreeMap::new(),
    };

    let err = apis[0]
        .request_admin::<ModuleGenerationId>(
            PROPOSE_MODULE_GENERATION_ENDPOINT,
            ApiRequestErased::new(&proposal),
            auth(),
        )
        .await
        .expect_err("proposal for an unsupported module kind is rejected");

    assert!(
        err.to_string().contains("Unsupported module kind"),
        "Unexpected propose error: {err}"
    );

    Ok(())
}

/// Registers an asset and proposes a mint module parameterized by it: the
/// activated instance's client config should carry the registered asset's
/// custom `AmountUnit`.
#[tokio::test(flavor = "multi_thread")]
async fn mint_with_custom_asset_unit() -> anyhow::Result<()> {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);
    let fed = fixtures.new_fed_not_degraded().await;

    let mut apis = Vec::new();
    for peer in 0..NUM_PEERS {
        apis.push(fed.new_admin_api(PeerId::from(peer)).await?);
    }

    // Register an asset on peer 0; every peer sees it in its log
    apis[0]
        .request_admin::<()>(
            REGISTER_ASSET_ENDPOINT,
            ApiRequestErased::new(RegisterAssetRequest {
                name: "US Dollar".to_string(),
                ticker: "USD".to_string(),
            }),
            auth(),
        )
        .await?;

    for api in &apis {
        loop {
            let log: serde_json::Value = api
                .request_admin(
                    MODULE_GENERATIONS_ENDPOINT,
                    ApiRequestErased::default(),
                    auth(),
                )
                .await?;
            if log["assets"]["1"]["ticker"] == "USD" {
                break;
            }
            sleep_in_test("Waiting for asset registration", Duration::from_millis(200)).await;
        }
    }

    // Propose a mint denominated in the registered asset and activate it
    let generation_id = propose_with_params(
        &apis,
        "mint",
        MODULE_CONSENSUS_VERSION,
        BTreeMap::from([("amount_unit".to_string(), "1".to_string())]),
    )
    .await;

    approve_all(&apis, generation_id).await;

    for api in &apis {
        await_state(api, generation_id, "Generated").await;
    }

    let (instance_id, active_from_session) = activate(&apis[0], generation_id).await;

    await_session_past(&apis[0], active_from_session).await?;
    await_module_in_audit(&apis[0], instance_id).await;

    // A client joining with the pre-activation config picks the new module up
    // through its additive config refresh, promoted on reopen (same pattern
    // as `activated_module_runs_without_restart`), and its client config
    // should carry the registered asset's custom unit.
    let client_db: Database = MemDatabase::new().into();

    let client = fed.new_client_with_db(client_db.clone()).await;

    while client_db
        .begin_transaction_nc()
        .await
        .get_value(&PendingClientConfigKey)
        .await
        .is_none()
    {
        sleep_in_test(
            "Waiting for client to fetch the refreshed config",
            Duration::from_millis(200),
        )
        .await;
    }

    drop(client);

    let client_secret = Client::load_or_generate_client_secret(&client_db).await?;

    let client = fed
        .open_client_with_db(
            client_db,
            RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(
                &client_secret,
            )),
        )
        .await;

    let config = client.config().await;
    let mint_config = config
        .modules
        .get(&(instance_id as u16))
        .expect("dynamically added mint in client config")
        .cast::<fedimint_mint_common::config::MintClientConfig>()?;

    assert_eq!(
        mint_config.amount_unit,
        fedimint_core::module::AmountUnit::new_custom(1)
    );

    Ok(())
}
