#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;

use anyhow::{bail, ensure};
use async_trait::async_trait;
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, SupportedModuleApiVersions, TransactionItemAmounts,
};
use fedimint_core::{InPoint, NumPeersExt, OutPoint, PeerId};
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use fedimint_threshold_ecdsa::group_public_key;
pub use fedimint_usdt_common as common;
use fedimint_usdt_common::config::UsdtClientConfig;
use fedimint_usdt_common::{
    MODULE_CONSENSUS_VERSION, UsdtCommonInit, UsdtConsensusItem, UsdtInput, UsdtInputError,
    UsdtModuleTypes, UsdtOutput, UsdtOutputError, UsdtOutputOutcome,
};
use rand::rngs::OsRng;
use strum::IntoEnumIterator;

use crate::config::{UsdtConfig, UsdtConfigConsensus, UsdtConfigPrivate};
use crate::db::DbKeyPrefix;

pub mod config;
pub mod db;

/// Generates the module
#[derive(Debug, Clone)]
pub struct UsdtInit;

impl ModuleInit for UsdtInit {
    type Common = UsdtCommonInit;

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        // No consensus state is persisted yet; nothing to dump for any prefix.
        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::Reserved => {}
            }
        }

        Box::new(items.into_iter())
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for UsdtInit {
    type Module = Usdt;

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 0)],
        )
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Usdt::new(args.cfg().to_typed()?))
    }

    /// Generates configs for all peers in a trusted manner for testing.
    ///
    /// This reconstructs the full threshold-ECDSA secret in one place (the
    /// `cggmp21` "trusted dealer"), which is only appropriate for
    /// development/test federations. Production federations must run
    /// [`ServerModuleInit::distributed_gen`] instead.
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let num_peers = peers.to_num_peers();
        let n = u16::try_from(num_peers.total())
            .expect("federation sizes fit in u16 in every supported deployment");
        let threshold = u16::try_from(num_peers.threshold())
            .expect("federation sizes fit in u16 in every supported deployment");

        let shares = cggmp21::trusted_dealer::builder::<fedimint_threshold_ecdsa::Curve, _>(n)
            .set_threshold(Some(threshold))
            .hd_wallet(true)
            .generate_shares(&mut OsRng)
            .expect("trusted dealer share generation failed");

        let group_public_key =
            group_public_key(&shares[0]).expect("dealer-generated share has a valid group key");

        let secp = secp256k1::Secp256k1::new();
        let mpc_encryption_keys: BTreeMap<PeerId, (secp256k1::SecretKey, secp256k1::PublicKey)> =
            peers
                .iter()
                .map(|&peer| (peer, secp.generate_keypair(&mut OsRng)))
                .collect();
        let mpc_encryption_pks: BTreeMap<PeerId, secp256k1::PublicKey> = mpc_encryption_keys
            .iter()
            .map(|(&peer, (_, pk))| (peer, *pk))
            .collect();

        peers
            .iter()
            .enumerate()
            .map(|(index, &peer)| {
                let cfg = UsdtConfig {
                    private: UsdtConfigPrivate {
                        key_share: shares[index].clone(),
                        mpc_encryption_sk: mpc_encryption_keys[&peer].0,
                    },
                    consensus: UsdtConfigConsensus {
                        group_public_key,
                        mpc_encryption_pks: mpc_encryption_pks.clone(),
                        threshold,
                        network: args.network,
                    },
                };

                (peer, cfg.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        _peers: &(dyn PeerHandleOps + Send + Sync),
        _args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        bail!("usdt distributed_gen implemented in the next task")
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<UsdtClientConfig> {
        let config = UsdtConfigConsensus::from_erased(config)?;
        Ok(UsdtClientConfig {
            group_public_key: config.group_public_key,
            network: config.network,
        })
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<UsdtConfig>()?;

        ensure!(
            group_public_key(&config.private.key_share)? == config.consensus.group_public_key,
            "This guardian's key share does not aggregate to the consensus group public key"
        );

        let secp = secp256k1::Secp256k1::new();
        let our_mpc_pk = config.private.mpc_encryption_sk.public_key(&secp);
        ensure!(
            config.consensus.mpc_encryption_pks.get(identity) == Some(&our_mpc_pk),
            "This guardian's MPC encryption public key does not match the consensus configuration"
        );

        Ok(())
    }

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Usdt>> {
        BTreeMap::new()
    }
}

/// USDT-on-EVM module
#[derive(Debug)]
pub struct Usdt {
    pub cfg: UsdtConfig,
}

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Usdt {
    /// Define the consensus types
    type Common = UsdtModuleTypes;
    type Init = UsdtInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<UsdtConsensusItem> {
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: UsdtConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        // WARNING: `process_consensus_item` should return an `Err` for items that do
        // not change any internal consensus state. Failure to do so, will result in an
        // (potentially significantly) increased consensus history size.
        bail!("The usdt module does not use consensus items yet");
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b UsdtInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, UsdtInputError> {
        Err(UsdtInputError::NotSupported)
    }

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a UsdtOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, UsdtOutputError> {
        Err(UsdtOutputError::NotSupported)
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<UsdtOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _audit: &mut Audit,
        _module_instance_id: ModuleInstanceId,
    ) {
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        Vec::new()
    }
}

impl Usdt {
    /// Create new module instance
    pub fn new(cfg: UsdtConfig) -> Usdt {
        Usdt { cfg }
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::PeerId;
    use fedimint_core::bitcoin::Network;

    use super::*;

    const NUM_PEERS: u16 = 4;

    #[test]
    fn trusted_dealer_gen_produces_consistent_valid_configs() {
        let peers = (0..NUM_PEERS).map(PeerId::from).collect::<Vec<_>>();
        let args = ConfigGenModuleArgs {
            network: Network::Regtest,
            disable_base_fees: false,
        };

        let server_cfgs = UsdtInit.trusted_dealer_gen(&peers, &args);
        assert_eq!(server_cfgs.len(), usize::from(NUM_PEERS));

        let typed_cfgs = server_cfgs
            .iter()
            .map(|(peer, cfg)| {
                (
                    *peer,
                    cfg.clone()
                        .to_typed::<UsdtConfig>()
                        .expect("config was just generated by the same configgen"),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let group_public_key = typed_cfgs[&peers[0]].consensus.group_public_key;
        for cfg in typed_cfgs.values() {
            assert_eq!(cfg.consensus.group_public_key, group_public_key);
            assert_eq!(cfg.consensus.threshold, 3);
            assert_eq!(
                fedimint_threshold_ecdsa::group_public_key(&cfg.private.key_share)
                    .expect("valid key share"),
                group_public_key
            );
        }

        for peer in &peers {
            UsdtInit
                .validate_config(peer, server_cfgs[peer].clone())
                .expect("dealer-generated config must validate for every peer");
        }
    }
}
