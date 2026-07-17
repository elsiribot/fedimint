//! Deterministic state machine driving runtime module config generation.
//!
//! The lifecycle is carried by [`ConfigGenItem`] consensus items; every
//! guardian applies them to its persisted [`GenerationLog`] in consensus
//! order, so all honest peers agree on the state of every generation.
//!
//! Rejected items simply `bail`, which drops the item without effect for
//! every peer alike, so all acceptance rules in this module must be
//! evaluatable from the log and the item alone.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, bail, ensure};
use fedimint_core::config_gen::{
    ConfigGenAbortReason, ConfigGenItem, ModuleConfigProposal, ModuleGenerationId,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{NumPeers, PeerId};
use serde::Serialize;

/// State of a single module config generation attempt.
#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize)]
pub enum GenerationState {
    /// Proposed by one guardian, awaiting unanimous approval. The proposer
    /// implicitly approves its own proposal.
    Proposed {
        proposal: ModuleConfigProposal,
        proposer: PeerId,
        approvals: BTreeSet<PeerId>,
    },
    /// Unanimously approved. In later phases this state starts the DKG
    /// worker and transitions further; for now it is terminal.
    Approved { proposal: ModuleConfigProposal },
    /// Aborted by a guardian. Terminal; retrying requires a fresh proposal
    /// under a new generation id.
    Aborted { reason: ConfigGenAbortReason },
}

impl GenerationState {
    fn is_pending(&self) -> bool {
        matches!(self, GenerationState::Proposed { .. })
    }
}

/// All module config generations of this federation, in consensus order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Encodable, Decodable, Serialize)]
pub struct GenerationLog {
    generations: BTreeMap<ModuleGenerationId, GenerationState>,
}

impl GenerationLog {
    /// The id the next proposal has to use. Generation ids are allocated
    /// monotonically and never reused.
    pub fn next_id(&self) -> ModuleGenerationId {
        ModuleGenerationId(self.generations.len() as u64)
    }

    pub fn generations(&self) -> &BTreeMap<ModuleGenerationId, GenerationState> {
        &self.generations
    }

    fn pending_generation(&self) -> Option<ModuleGenerationId> {
        self.generations
            .iter()
            .find_map(|(id, state)| state.is_pending().then_some(*id))
    }
}

/// Applies one consensus item contributed by `peer` to the log.
///
/// Returns an error to deterministically reject the item, leaving the log
/// untouched.
pub fn process_item(
    num_peers: NumPeers,
    log: &mut GenerationLog,
    item: ConfigGenItem,
    peer: PeerId,
) -> anyhow::Result<()> {
    match item {
        ConfigGenItem::Propose {
            generation_id,
            proposal,
        } => {
            ensure!(
                generation_id == log.next_id(),
                "Proposal for {generation_id} does not match next id {}",
                log.next_id()
            );

            if let Some(pending) = log.pending_generation() {
                bail!("Cannot propose while {pending} is pending approval");
            }

            log.generations.insert(
                generation_id,
                GenerationState::Proposed {
                    proposal,
                    proposer: peer,
                    approvals: BTreeSet::from([peer]),
                },
            );
        }
        ConfigGenItem::Approve { generation_id } => {
            let state = log
                .generations
                .get_mut(&generation_id)
                .with_context(|| format!("Approval for unknown {generation_id}"))?;

            let GenerationState::Proposed {
                proposal,
                approvals,
                ..
            } = state
            else {
                bail!("Approval for {generation_id} which is not pending");
            };

            ensure!(
                approvals.insert(peer),
                "Duplicate approval for {generation_id} by {peer}"
            );

            if approvals.len() == num_peers.total() {
                *state = GenerationState::Approved {
                    proposal: proposal.clone(),
                };
            }
        }
        ConfigGenItem::Abort {
            generation_id,
            reason,
        } => {
            let state = log
                .generations
                .get_mut(&generation_id)
                .with_context(|| format!("Abort for unknown {generation_id}"))?;

            ensure!(
                state.is_pending(),
                "Abort for {generation_id} which is not pending"
            );

            *state = GenerationState::Aborted { reason };
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use fedimint_core::core::ModuleKind;
    use fedimint_core::module::ModuleConsensusVersion;

    use super::*;

    const NUM_PEERS_TOTAL: usize = 4;

    fn proposal() -> ModuleConfigProposal {
        ModuleConfigProposal {
            module_kind: ModuleKind::from_static_str("mint"),
            consensus_version: ModuleConsensusVersion::new(2, 0),
            network: Network::Regtest,
            disable_base_fees: false,
        }
    }

    fn propose(log: &mut GenerationLog, id: u64, peer: u16) -> anyhow::Result<()> {
        process_item(
            NumPeers::from(NUM_PEERS_TOTAL),
            log,
            ConfigGenItem::Propose {
                generation_id: ModuleGenerationId(id),
                proposal: proposal(),
            },
            PeerId::from(peer),
        )
    }

    fn approve(log: &mut GenerationLog, id: u64, peer: u16) -> anyhow::Result<()> {
        process_item(
            NumPeers::from(NUM_PEERS_TOTAL),
            log,
            ConfigGenItem::Approve {
                generation_id: ModuleGenerationId(id),
            },
            PeerId::from(peer),
        )
    }

    fn abort(log: &mut GenerationLog, id: u64, peer: u16) -> anyhow::Result<()> {
        process_item(
            NumPeers::from(NUM_PEERS_TOTAL),
            log,
            ConfigGenItem::Abort {
                generation_id: ModuleGenerationId(id),
                reason: ConfigGenAbortReason("test".to_string()),
            },
            PeerId::from(peer),
        )
    }

    #[test]
    fn propose_and_unanimous_approval() {
        let mut log = GenerationLog::default();

        propose(&mut log, 0, 0).expect("proposal accepted");
        approve(&mut log, 0, 1).expect("approval accepted");
        approve(&mut log, 0, 2).expect("approval accepted");

        // Not yet unanimous
        assert!(matches!(
            log.generations()[&ModuleGenerationId(0)],
            GenerationState::Proposed { .. }
        ));

        approve(&mut log, 0, 3).expect("approval accepted");

        assert!(matches!(
            log.generations()[&ModuleGenerationId(0)],
            GenerationState::Approved { .. }
        ));
        assert_eq!(log.next_id(), ModuleGenerationId(1));
    }

    #[test]
    fn rejects_duplicate_approval() {
        let mut log = GenerationLog::default();

        propose(&mut log, 0, 0).expect("proposal accepted");
        approve(&mut log, 0, 1).expect("approval accepted");

        assert!(approve(&mut log, 0, 1).is_err());
        // Proposer's approval is implicit, a second one is a duplicate
        assert!(approve(&mut log, 0, 0).is_err());
    }

    #[test]
    fn rejects_approval_for_unknown_generation() {
        let mut log = GenerationLog::default();

        assert!(approve(&mut log, 0, 1).is_err());
    }

    #[test]
    fn rejects_second_proposal_while_pending() {
        let mut log = GenerationLog::default();

        propose(&mut log, 0, 0).expect("proposal accepted");

        assert!(propose(&mut log, 1, 1).is_err());
    }

    #[test]
    fn rejects_proposal_with_stale_id() {
        let mut log = GenerationLog::default();

        propose(&mut log, 0, 0).expect("proposal accepted");
        abort(&mut log, 0, 1).expect("abort accepted");

        assert!(propose(&mut log, 0, 1).is_err());
    }

    #[test]
    fn abort_and_retry_under_fresh_id() {
        let mut log = GenerationLog::default();

        propose(&mut log, 0, 0).expect("proposal accepted");
        abort(&mut log, 0, 3).expect("abort accepted");

        assert!(matches!(
            log.generations()[&ModuleGenerationId(0)],
            GenerationState::Aborted { .. }
        ));

        propose(&mut log, 1, 0).expect("fresh proposal accepted");
        for peer in 1..4 {
            approve(&mut log, 1, peer).expect("approval accepted");
        }

        assert!(matches!(
            log.generations()[&ModuleGenerationId(1)],
            GenerationState::Approved { .. }
        ));
    }

    #[test]
    fn rejects_abort_of_terminal_generation() {
        let mut log = GenerationLog::default();

        propose(&mut log, 0, 0).expect("proposal accepted");
        abort(&mut log, 0, 1).expect("abort accepted");

        assert!(abort(&mut log, 0, 2).is_err());

        for peer in 0..4 {
            let _ = approve(&mut log, 0, peer);
        }
        assert!(matches!(
            log.generations()[&ModuleGenerationId(0)],
            GenerationState::Aborted { .. }
        ));
    }
}
