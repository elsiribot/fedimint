use std::collections::BTreeMap;

use fedimint_core::PeerId;
use fedimint_core::config::ServerModuleConfigGenParamsRegistry;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::setup_code::{PeerEndpoints, PeerSetupCode};
use fedimint_mint_common::KIND as MINT_KIND;
use fedimint_mint_common::config::{MintConfig, MintConfigConsensus, MintGenParams};
use fedimint_mint_server::MintInit;
use fedimint_server_core::ServerModuleInitRegistry;

use super::{ConfigGenParams, ServerConfig};
use crate::net::p2p_connector::gen_cert_and_key;

/// Builds local `ConfigGenParams` for `peers`, all sharing `module_params` as
/// the module instance list.
///
/// This mirrors `fedimint_testing_core::config::local_config_gen_params`, but
/// is kept self-contained in this crate: `fedimint-testing-core` depends on
/// `fedimint-server`, so it can't be used from `fedimint-server`'s own tests
/// without an (allowed, but needless) dev-dependency cycle. None of the
/// generated URLs/certs are actually dialed here — `trusted_dealer_gen` never
/// opens a connection.
fn local_config_gen_params(
    peers: &[PeerId],
    module_params: &ServerModuleConfigGenParamsRegistry,
) -> BTreeMap<PeerId, ConfigGenParams> {
    let base_port = 18_000u16;

    let tls_keys: BTreeMap<PeerId, _> = peers
        .iter()
        .map(|peer| {
            (
                *peer,
                gen_cert_and_key(&format!("peer-{}", peer.to_usize()))
                    .expect("Failed to generate cert and key"),
            )
        })
        .collect();

    let connections: BTreeMap<PeerId, PeerSetupCode> = peers
        .iter()
        .map(|peer| {
            let peer_port = base_port + u16::from(*peer) * 2;
            let p2p_url = format!("fedimint://127.0.0.1:{peer_port}");
            let api_url = format!("ws://127.0.0.1:{}", peer_port + 1);

            let setup_code = PeerSetupCode {
                name: format!("peer-{}", peer.to_usize()),
                endpoints: PeerEndpoints::Tcp {
                    api_url: api_url.parse().expect("Valid url"),
                    p2p_url: p2p_url.parse().expect("Valid url"),
                    cert: tls_keys[peer].0.as_ref().to_vec(),
                },
                federation_name: None,
                disable_base_fees: None,
                module_params: None,
                federation_size: None,
                network: bitcoin::Network::Regtest,
                fedimint_version: fedimint_core::version::cargo_pkg_release().to_owned(),
            };
            (*peer, setup_code)
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
                disable_base_fees: false,
                module_params: module_params.clone(),
                network: bitcoin::Network::Regtest,
            };
            (*peer, params)
        })
        .collect()
}

/// Proves the multi-instance capability at the config-gen level: config-genning
/// TWO instances of the SAME module kind (`mint`), with different per-instance
/// params, produces two distinct instance ids whose resulting
/// `ServerModuleConfig`s genuinely differ (different denomination sets).
#[test]
fn trusted_dealer_gen_produces_two_distinct_mint_instances() {
    let peers: Vec<PeerId> = (0..4).map(PeerId::from).collect();

    let mut server_init = ServerModuleInitRegistry::default();
    server_init.attach(MintInit);

    // Two mint instances, same kind, different `denomination_base` (2 vs 4).
    let mut module_params = ServerModuleConfigGenParamsRegistry::default();
    module_params.attach_config_gen_params(MINT_KIND, MintGenParams::new(2, None));
    module_params.attach_config_gen_params(MINT_KIND, MintGenParams::new(4, None));

    let params = local_config_gen_params(&peers, &module_params);

    let configs = ServerConfig::trusted_dealer_gen(&params, &server_init, "test-version-hash");

    let peer0 = &configs[&PeerId::from(0)];

    // (a) two distinct mint instance ids, deterministically 0 and 1 by append
    // order.
    let mint_instance_ids: Vec<_> = peer0
        .iter_module_instances()
        .filter(|(_, kind)| **kind == MINT_KIND)
        .map(|(id, _)| id)
        .collect();
    assert_eq!(
        mint_instance_ids,
        vec![0, 1],
        "expected two mint instances at ids 0 and 1"
    );

    // (b) each instance's config reflects its own params: different
    // `denomination_base` (2 vs 4) must produce different denomination sets.
    let mint_cfg_0: MintConfig = peer0
        .get_module_config_typed(0)
        .expect("instance 0 must be a valid mint config");
    let mint_cfg_1: MintConfig = peer0
        .get_module_config_typed(1)
        .expect("instance 1 must be a valid mint config");

    let denominations_0: Vec<_> = mint_cfg_0.consensus.peer_tbs_pks[&PeerId::from(0)]
        .tiers()
        .copied()
        .collect();
    let denominations_1: Vec<_> = mint_cfg_1.consensus.peer_tbs_pks[&PeerId::from(0)]
        .tiers()
        .copied()
        .collect();

    assert_ne!(
        denominations_0, denominations_1,
        "the two same-kind mint instances must have distinct, params-derived denomination sets"
    );

    // (c) both instances' consensus configs independently round-trip through
    // consensus encoding (the same encoding used to persist/replicate
    // `ServerConfig`), proving each instance is genuinely decodable on its
    // own, not just structurally different in memory.
    for (id, cfg) in [(0u16, &mint_cfg_0), (1u16, &mint_cfg_1)] {
        let bytes = cfg.consensus.consensus_encode_to_vec();
        let decoded =
            MintConfigConsensus::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .unwrap_or_else(|err| panic!("instance {id} consensus config must decode: {err}"));
        // `MintConfigConsensus` doesn't derive `PartialEq`; compare via a
        // second, deterministic consensus-encoding pass instead.
        assert_eq!(decoded.consensus_encode_to_vec(), bytes);
    }
}
