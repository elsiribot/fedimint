//! Wire types for consensus-coordinated module config generation.
//!
//! These items coordinate the lifecycle of generating a new module's
//! configuration on a running federation. The DKG itself runs over direct
//! P2P connections; consensus only carries proposal, approval, result and
//! activation items. See `docs/superpowers/specs/` for the design.

use std::collections::BTreeMap;

use bitcoin::Network;
use serde::{Deserialize, Serialize};

use crate::config::ServerModuleConsensusConfig;
use crate::core::ModuleKind;
use crate::encoding::{Decodable, Encodable};
use crate::module::ModuleConsensusVersion;

/// Identifies one attempt at generating a module config.
///
/// Generation ids are allocated monotonically by consensus and are
/// single-use: a failed or aborted generation is never retried under the
/// same id since generation randomness is derived from it.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct ModuleGenerationId(pub u64);

impl std::fmt::Display for ModuleGenerationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "generation-{}", self.0)
    }
}

/// Exact parameters of a proposed module generation.
///
/// Every guardian has to approve the exact proposal, which also serves as a
/// check that all guardians run code supporting the module kind and
/// consensus version before any DKG is started.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ModuleConfigProposal {
    pub module_kind: ModuleKind,
    pub consensus_version: ModuleConsensusVersion,
    pub network: Network,
    pub disable_base_fees: bool,
    /// Module-specific generation parameters, e.g. the mint's
    /// `amount_unit`. Stringly typed; each module parses and validates the
    /// keys it understands (see `ServerModuleInit::config_gen_param_docs`).
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

/// Human-readable reason a generation was aborted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ConfigGenAbortReason(pub String);

/// Maximum size of an encrypted private module config committed to
/// consensus, bounded well below the aleph unit byte limit so result items
/// always fit into a unit.
pub const MAX_ENCRYPTED_PRIVATE_CONFIG_BYTES: usize = 40_000;

/// Request body of the abort-module-generation admin endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbortModuleGenerationRequest {
    pub generation_id: ModuleGenerationId,
    pub reason: String,
}

/// Consensus items driving the module config generation lifecycle.
///
/// The item author is the consensus peer that contributed the item; approval
/// and abort authority is derived from authorship, so these items carry no
/// explicit peer id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum ConfigGenItem {
    /// Propose generating a new module config. The proposer implicitly
    /// approves its own proposal.
    Propose {
        generation_id: ModuleGenerationId,
        proposal: ModuleConfigProposal,
    },
    /// Approve the currently proposed generation. A generation only moves
    /// forward once every guardian has approved it.
    Approve { generation_id: ModuleGenerationId },
    /// Report this guardian's completion of the DKG for an approved
    /// generation. A generation completes once every guardian reported an
    /// identical consensus config.
    ///
    /// The private config is committed to consensus history encrypted under
    /// a key only this guardian can derive, so a guardian can recover it
    /// from its root secret and the federation's signed history.
    Result {
        generation_id: ModuleGenerationId,
        consensus_config: ServerModuleConsensusConfig,
        encrypted_private_config: Vec<u8>,
    },
    /// Activate a completed generation as a module instance. On acceptance
    /// the generation is deterministically assigned the next module
    /// instance id and an activation session a safe margin after the item's
    /// own session; every guardian schedules a restart before that session
    /// and loads the module on startup.
    Activate { generation_id: ModuleGenerationId },
    /// Abort the currently proposed generation. Any single guardian may
    /// abort; retrying requires a new proposal under a fresh id.
    Abort {
        generation_id: ModuleGenerationId,
        reason: ConfigGenAbortReason,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::registry::ModuleDecoderRegistry;

    #[test]
    fn config_gen_item_roundtrip() {
        let item = ConfigGenItem::Propose {
            generation_id: ModuleGenerationId(0),
            proposal: ModuleConfigProposal {
                module_kind: ModuleKind::from_static_str("mint"),
                consensus_version: ModuleConsensusVersion::new(2, 0),
                network: Network::Regtest,
                disable_base_fees: false,
                params: BTreeMap::from([("amount_unit".to_string(), "1".to_string())]),
            },
        };

        let bytes = item.consensus_encode_to_vec();
        let decoded =
            ConfigGenItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("roundtrip decodes");

        assert_eq!(item, decoded);
    }
}
