use fedimint_core::core::DynModuleConsensusItem as ModuleConsensusItem;
use fedimint_core::encoding::{Decodable, Encodable};

use crate::config_gen::ConfigGenItem;
use crate::transaction::Transaction;

/// All the items that may be produced during a consensus epoch
#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub enum ConsensusItem {
    /// Threshold sign the epoch history for verification via the API
    Transaction(Transaction),
    /// Any data that modules require consensus on
    Module(ModuleConsensusItem),
    /// Coordinates runtime module config generation.
    ///
    /// Peers running code without this variant decode it as
    /// [`ConsensusItem::Default`] and panic when processing it, so it must
    /// only be contributed once all peers run a supporting version.
    ConfigGen(ConfigGenItem),
    /// Allows us to add new items in the future without crashing old clients
    /// that try to interpret the session log.
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}
