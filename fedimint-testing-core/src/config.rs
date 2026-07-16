use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

use fedimint_core::PeerId;
use fedimint_core::config::ConfigGenModuleParams;
use fedimint_core::core::ModuleKind;
use fedimint_core::module::ApiAuth;
use fedimint_core::setup_code::{PeerEndpoints, PeerSetupCode};
use fedimint_server::config::{ConfigGenParams, build_module_params_registry};
use fedimint_server::core::ServerModuleInitRegistry;
use fedimint_server::net::p2p_connector::gen_cert_and_key;
use tokio_rustls::rustls;

pub static API_AUTH: LazyLock<ApiAuth> = LazyLock::new(|| ApiAuth::new("pass".to_string()));

/// Creates the config gen params for each peer
///
/// Uses peers * 2 ports offset from `base_port`
///
/// `extra_module_instances` appends additional module instances (of an
/// already-registered kind) beyond the one-instance-per-kind default, each
/// carrying its own config-gen params — e.g. a second `mintv2` instance
/// denominated in a non-Bitcoin `AmountUnit` alongside the default Bitcoin
/// mintv2 instance. Instance ids are assigned by append order, after the
/// default one-per-kind instances.
pub fn local_config_gen_params(
    peers: &[PeerId],
    base_port: u16,
    enable_mint_fees: bool,
    registry: &ServerModuleInitRegistry,
    extra_module_instances: &[(ModuleKind, ConfigGenModuleParams)],
) -> anyhow::Result<BTreeMap<PeerId, ConfigGenParams>> {
    // Enable every registered module. `build_module_params_registry`
    // materializes the module instance list (one instance per kind, carrying
    // each module's default config gen params) in the canonical instance order,
    // which is the single source of truth for config generation.
    let enabled_modules: BTreeSet<ModuleKind> =
        registry.iter().map(|(kind, _)| kind.clone()).collect();
    let mut module_params = build_module_params_registry(registry, &enabled_modules);
    for (kind, params) in extra_module_instances {
        module_params.attach_config_gen_params(kind.clone(), params.clone());
    }

    // Generate TLS cert and private key
    let tls_keys: BTreeMap<
        PeerId,
        (
            rustls::pki_types::CertificateDer<'static>,
            Arc<rustls::pki_types::PrivateKeyDer<'static>>,
        ),
    > = peers
        .iter()
        .map(|peer| {
            (
                *peer,
                gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap(),
            )
        })
        .collect();

    // Generate the P2P and API URL on 2 different ports for each peer
    let connections: BTreeMap<PeerId, PeerSetupCode> = peers
        .iter()
        .map(|peer| {
            let peer_port = base_port + u16::from(*peer) * 3;

            let p2p_url = format!("fedimint://127.0.0.1:{peer_port}");
            let api_url = format!("ws://127.0.0.1:{}", peer_port + 1);

            let params = PeerSetupCode {
                name: format!("peer-{}", peer.to_usize()),
                endpoints: PeerEndpoints::Tcp {
                    api_url: api_url.parse().expect("Should parse"),
                    p2p_url: p2p_url.parse().expect("Should parse"),
                    cert: tls_keys[peer].0.as_ref().to_vec(),
                },
                federation_name: None,
                disable_base_fees: Some(!enable_mint_fees),
                module_params: None,
                federation_size: None,
                network: bitcoin::Network::Regtest,
                fedimint_version: fedimint_core::version::cargo_pkg_release().to_owned(),
            };
            (*peer, params)
        })
        .collect();

    peers
        .iter()
        .map(|peer| {
            let params = ConfigGenParams {
                identity: *peer,
                tls_key: Some(tls_keys[peer].1.clone()),
                iroh_api_sk: None,
                iroh_p2p_sk: None,
                peers: connections.clone(),
                meta: BTreeMap::new(),
                disable_base_fees: !enable_mint_fees,
                module_params: module_params.clone(),
                network: bitcoin::Network::Regtest,
            };
            Ok((*peer, params))
        })
        .collect()
}
