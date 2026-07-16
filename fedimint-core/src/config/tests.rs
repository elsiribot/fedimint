use std::collections::BTreeMap;

use fedimint_core::config::{ClientConfig, GlobalClientConfig};

use crate::config::ServerModuleConfigGenParamsRegistry;
use crate::core::ModuleKind;
use crate::encoding::{Decodable, Encodable};
use crate::module::CoreConsensusVersion;
use crate::module::registry::ModuleDecoderRegistry;

#[test]
fn test_dcode_meta() {
    let config = ClientConfig {
        global: GlobalClientConfig {
            api_endpoints: BTreeMap::new(),
            broadcast_public_keys: None,
            consensus_version: CoreConsensusVersion { major: 0, minor: 0 },
            meta: vec![
                ("foo".to_string(), "bar".to_string()),
                ("baz".to_string(), "\"bam\"".to_string()),
                ("arr".to_string(), "[\"1\", \"2\"]".to_string()),
            ]
            .into_iter()
            .collect(),
        },
        modules: BTreeMap::new(),
    };

    assert_eq!(
        config
            .meta::<String>("foo")
            .expect("parsing legacy string failed"),
        Some("bar".to_string())
    );
    assert_eq!(
        config.meta::<String>("baz").expect("parsing string failed"),
        Some("bam".to_string())
    );
    assert_eq!(
        config
            .meta::<Vec<String>>("arr")
            .expect("parsing array failed"),
        Some(vec!["1".to_string(), "2".to_string()])
    );

    assert!(config.meta::<Vec<String>>("foo").is_err());
    assert!(config.meta::<Vec<String>>("baz").is_err());
    assert_eq!(
        config
            .meta::<String>("arr")
            .expect("parsing via legacy fallback failed"),
        Some("[\"1\", \"2\"]".to_string())
    );
}

/// A module instance list with two instances of the same kind carrying
/// different params must survive both the serde (JSON-RPC) and consensus
/// encoding (setup code) round trips used to carry it across the setup surface.
#[test]
fn module_params_registry_round_trips_with_duplicate_kinds() {
    let mint = ModuleKind::from_static_str("mint");

    let mut registry = ServerModuleConfigGenParamsRegistry::default();
    registry.attach_config_gen_params(mint.clone(), serde_json::json!({ "denomination_base": 2 }));
    registry.attach_config_gen_params(mint.clone(), serde_json::json!({ "denomination_base": 10 }));

    // Two same-kind instances get distinct ids 0 and 1.
    assert_eq!(
        registry
            .iter_modules()
            .map(|(id, kind, _)| (id, kind.clone()))
            .collect::<Vec<_>>(),
        vec![(0, mint.clone()), (1, mint.clone())]
    );

    // serde round trip (JSON-RPC admin surface).
    let json = serde_json::to_string(&registry).expect("serialize");
    let from_json: ServerModuleConfigGenParamsRegistry =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(from_json, registry);

    // consensus encoding round trip (base32 setup code).
    let bytes = registry.consensus_encode_to_vec();
    let from_bytes = ServerModuleConfigGenParamsRegistry::consensus_decode_whole(
        &bytes,
        &ModuleDecoderRegistry::default(),
    )
    .expect("decode");
    assert_eq!(from_bytes, registry);

    // `Ord` is consistent with `Eq`.
    assert_eq!(from_bytes.cmp(&registry), std::cmp::Ordering::Equal);
}
