//! Acceptance test for consensus-coordinated module config generation.
//!
//! Boots a real in-process federation (real AlephBFT consensus, real p2p
//! connections, real api) and drives a full generation lifecycle through
//! the admin api: propose a mint module, approve from every guardian, run
//! the actual mint DKGs over the runtime p2p transport and verify every
//! peer reports an identical generated consensus config.

use std::time::Duration;

use fedimint_api_client::api::{DynGlobalApi, FederationApiExt};
use fedimint_client::db::PendingClientConfigKey;
use fedimint_client::{Client, RootSecret};
use fedimint_client_module::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_core::PeerId;
use fedimint_core::config_gen::{
    AbortModuleGenerationRequest, ModuleConfigProposal, ModuleGenerationId,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::endpoint_constants::{
    ABORT_MODULE_GENERATION_ENDPOINT, ACTIVATE_MODULE_GENERATION_ENDPOINT,
    APPROVE_MODULE_GENERATION_ENDPOINT, AUDIT_ENDPOINT, MODULE_GENERATIONS_ENDPOINT,
    PROPOSE_MODULE_GENERATION_ENDPOINT, SESSION_COUNT_ENDPOINT,
};
use fedimint_core::module::{ApiAuth, ApiRequestErased};
use fedimint_core::task::sleep_in_test;
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
async fn propose(apis: &[DynGlobalApi], module_kind: &'static str) -> ModuleGenerationId {
    let proposal = ModuleConfigProposal {
        module_kind: ModuleKind::from_static_str(module_kind),
        consensus_version: MODULE_CONSENSUS_VERSION,
        network: bitcoin::Network::Regtest,
        disable_base_fees: false,
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

    let generation_id = propose(&apis, "mint").await;

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

#[tokio::test(flavor = "multi_thread")]
async fn activated_module_runs_after_restart() -> anyhow::Result<()> {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);
    let mut fed = fixtures.new_fed_not_degraded().await;

    let mut apis = Vec::new();
    for peer in 0..NUM_PEERS {
        apis.push(fed.new_admin_api(PeerId::from(peer)).await?);
    }

    let generation_id = propose(&apis, "mint").await;

    approve_all(&apis, generation_id).await;

    for api in &apis {
        await_state(api, generation_id, "Generated").await;
    }

    // Activation schedules a coordinated restart on every guardian before
    // the activation session
    apis[0]
        .request_admin::<()>(
            ACTIVATE_MODULE_GENERATION_ENDPOINT,
            ApiRequestErased::new(generation_id),
            auth(),
        )
        .await?;

    let active = await_state(&apis[0], generation_id, "Active").await;

    let instance_id = active["instance_id"]
        .as_u64()
        .expect("instance id is a number");
    let active_from_session = active["active_from_session"]
        .as_u64()
        .expect("activation session is a number");

    info!(
        target: LOG_TEST,
        instance_id,
        active_from_session,
        "Module activated, waiting for the scheduled shutdown"
    );

    for api in &apis {
        while api
            .request_admin_no_auth::<u64>(SESSION_COUNT_ENDPOINT, ApiRequestErased::default())
            .await
            .is_ok()
        {
            sleep_in_test(
                "Waiting for peer to shut down for activation",
                Duration::from_millis(200),
            )
            .await;
        }
    }

    fed.restart_all_peers().await;

    // The dynamically added mint instance is now part of the running
    // federation: it shows up in the guardian audit...
    let audit: serde_json::Value = apis[0]
        .request_admin(AUDIT_ENDPOINT, ApiRequestErased::default(), auth())
        .await?;

    let module_summary = audit["module_summaries"][instance_id.to_string()].clone();

    assert!(
        module_summary.is_object(),
        "Audit is missing the activated module: {audit}"
    );

    // ...and consensus keeps advancing past the activation session
    loop {
        let session_count: u64 = apis[0]
            .request_admin_no_auth(SESSION_COUNT_ENDPOINT, ApiRequestErased::default())
            .await?;

        if session_count > active_from_session {
            break;
        }

        sleep_in_test(
            "Waiting for consensus to advance past activation",
            Duration::from_millis(200),
        )
        .await;
    }

    // A client joining with the pre-activation config picks the new module
    // up through its additive config refresh: the refreshed config is
    // stored as pending and promoted on the next client start.
    let client_db: Database = MemDatabase::new().into();

    let client = fed.new_client_with_db(client_db.clone()).await;

    assert!(
        !client
            .config()
            .await
            .modules
            .contains_key(&(instance_id as u16)),
        "Client joined with a config that already contains the dynamic module"
    );

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
        "Dynamically added module is live after restart and visible to clients"
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

    let generation_id = propose(&apis, "mint").await;

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
    let retry_id = propose(&apis, "mint").await;
    assert_eq!(retry_id.0, generation_id.0 + 1);

    approve_all(&apis, retry_id).await;

    for api in &apis {
        await_state(api, retry_id, "Generated").await;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn unsupported_module_kind_is_aborted() -> anyhow::Result<()> {
    let fixtures = Fixtures::new_primary(MintClientInit, MintInit);
    let fed = fixtures.new_fed_not_degraded().await;

    let mut apis = Vec::new();
    for peer in 0..NUM_PEERS {
        apis.push(fed.new_admin_api(PeerId::from(peer)).await?);
    }

    let generation_id = propose(&apis, "no-such-module").await;

    approve_all(&apis, generation_id).await;

    // Every guardian's manager aborts since it cannot run the DKG
    for api in &apis {
        let aborted = await_state(api, generation_id, "Aborted").await;

        assert!(
            aborted["reason"]
                .as_str()
                .expect("reason is a string")
                .contains("not supported"),
            "Unexpected abort reason: {aborted}"
        );
    }

    Ok(())
}
