#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;

use async_trait::async_trait;
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, SupportedModuleApiVersions, TransactionItemAmounts,
};
use fedimint_core::{InPoint, OutPoint, PeerId, push_db_pair_items};
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
pub use fedimint_swap_common as common;
use fedimint_swap_common::config::{
    SwapClientConfig, SwapConfig, SwapConfigConsensus, SwapConfigPrivate,
};
use fedimint_swap_common::{
    MODULE_CONSENSUS_VERSION, Offer, SwapCommonInit, SwapConsensusItem, SwapInput, SwapInputError,
    SwapModuleTypes, SwapOutput, SwapOutputError, SwapOutputOutcome,
};
use futures::StreamExt;
use strum::IntoEnumIterator;

use crate::db::{ConsensusTsPrefix, DbKeyPrefix, OfferPrefix};

pub mod db;

/// Generates the module
#[derive(Debug, Clone)]
pub struct SwapInit;

impl ModuleInit for SwapInit {
    type Common = SwapCommonInit;

    /// Dumps all database items for debugging
    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::Offer => {
                    push_db_pair_items!(dbtx, OfferPrefix, OfferKey, Offer, items, "Swap Offer");
                }
                DbKeyPrefix::ConsensusTs => {
                    push_db_pair_items!(
                        dbtx,
                        ConsensusTsPrefix,
                        ConsensusTsKey,
                        u64,
                        items,
                        "Swap Consensus Timestamp"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for SwapInit {
    type Module = Swap;
    type Params = ();

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
        Ok(Swap::new(args.cfg().to_typed()?))
    }

    /// Generates configs for all peers in a trusted manner for testing
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        _args: &ConfigGenModuleArgs,
        _params: &Self::Params,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        // Generate a config for each peer
        peers
            .iter()
            .map(|&peer| {
                let config = SwapConfig {
                    private: SwapConfigPrivate,
                    consensus: SwapConfigConsensus,
                };
                (peer, config.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        _peers: &(dyn PeerHandleOps + Send + Sync),
        _args: &ConfigGenModuleArgs,
        _params: &Self::Params,
    ) -> anyhow::Result<ServerModuleConfig> {
        Ok(SwapConfig {
            private: SwapConfigPrivate,
            consensus: SwapConfigConsensus,
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        _config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<SwapClientConfig> {
        Ok(SwapClientConfig)
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Swap>> {
        BTreeMap::new()
    }
}

/// Swap module
#[derive(Debug)]
pub struct Swap {
    pub cfg: SwapConfig,
}

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Swap {
    /// Define the consensus types
    type Common = SwapModuleTypes;
    type Init = SwapInit;

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<SwapConsensusItem> {
        // Phase 4: propose this guardian's current wall-clock time.
        Vec::new()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_item: SwapConsensusItem,
        _peer_id: PeerId,
    ) -> anyhow::Result<()> {
        // WARNING: `process_consensus_item` should return an `Err` for items that do
        // not change any internal consensus state. Failure to do so, will result in an
        // (potentially significantly) increased consensus history size.
        // If you are using this code as a template,
        // make sure to read the [`ServerModule::process_consensus_item`] documentation,
        // Phase 4 implements the timestamp clock; no consensus items yet.
        anyhow::bail!("no consensus items yet");
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b SwapInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, SwapInputError> {
        // Phase 3 implements the offer lifecycle (Claim/Reclaim).
        Err(SwapInputError::UnknownOffer)
    }

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a SwapOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, SwapOutputError> {
        // Phase 3 implements the offer lifecycle (MakeOffer/Fill).
        Err(SwapOutputError::UnknownOffer)
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<SwapOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _audit: &mut Audit,
        _module_instance_id: ModuleInstanceId,
    ) {
        // Phase 3: sum locked offer legs as per-unit liabilities
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        // Phase 5 adds `list_open_offers`/`get_offer`.
        Vec::new()
    }
}

impl Swap {
    /// Create new module instance
    pub fn new(cfg: SwapConfig) -> Swap {
        Swap { cfg }
    }
}
