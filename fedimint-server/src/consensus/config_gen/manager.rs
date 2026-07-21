//! Drives this guardian's side of approved module config generations.
//!
//! The manager watches the consensus-driven [`GenerationLog`] and, once a
//! generation is unanimously approved, runs the module's `distributed_gen`
//! over the runtime p2p transport. The resulting private config is stored
//! locally; only the consensus config is reported back into consensus.
//!
//! Crash handling follows abort-and-retry: a generation that was started
//! but produced no local outcome before a restart cannot be resumed, since
//! its in-memory DKG state is lost, so it is aborted and has to be retried
//! under a fresh generation id.

use std::time::Duration;

use fedimint_core::config::P2PMessage;
use fedimint_core::config_gen::{
    ConfigGenAbortReason, ConfigGenItem, ModuleConfigProposal, ModuleGenerationId,
};
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::epoch::ConsensusItem;
use fedimint_core::net::peers::{DynP2PConnections, IP2PConnections};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::FmtCompactAnyhow;
use fedimint_core::{NumPeers, PeerId};
use fedimint_derive_secret::DerivableSecret;
use fedimint_logging::LOG_CONSENSUS;
use fedimint_server_core::{ConfigGenModuleArgs, ServerModuleInitRegistry};
use tracing::{info, warn};

use super::secrets::result_encryption_key;
use super::transport::GenerationTransport;
use super::{GenerationLog, GenerationState};
use crate::config::peer_handle::PeerHandle;
use crate::db::{
    ConfigGenerationLogKey, LocalGenerationOutcome, LocalGenerationOutcomeKey,
    LocalGenerationStartedKey,
};

/// An approved generation stalls forever if any guardian is offline, so the
/// DKG is bounded and aborted afterwards; guardians retry under a fresh id.
const GENERATION_TIMEOUT: Duration = Duration::from_secs(600);

pub struct GenerationManager {
    db: Database,
    num_peers: NumPeers,
    identity: PeerId,
    module_inits: ServerModuleInitRegistry,
    connections: DynP2PConnections<P2PMessage>,
    incoming: async_channel::Receiver<(PeerId, P2PMessage)>,
    submission_sender: async_channel::Sender<ConsensusItem>,
    config_gen_root: DerivableSecret,
}

impl GenerationManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Database,
        num_peers: NumPeers,
        identity: PeerId,
        module_inits: ServerModuleInitRegistry,
        connections: DynP2PConnections<P2PMessage>,
        incoming: async_channel::Receiver<(PeerId, P2PMessage)>,
        submission_sender: async_channel::Sender<ConsensusItem>,
        config_gen_root: DerivableSecret,
    ) -> Self {
        Self {
            db,
            num_peers,
            identity,
            module_inits,
            connections,
            incoming,
            submission_sender,
            config_gen_root,
        }
    }

    pub fn spawn(self, task_group: &TaskGroup) {
        task_group.spawn_cancellable("config-gen-manager", async move {
            self.run().await;
        });
    }

    async fn run(self) {
        loop {
            let (generation_id, proposal) = self
                .db
                .wait_key_check(&ConfigGenerationLogKey, |log| {
                    log.and_then(|log| self.actionable_generation(&log))
                })
                .await
                .0;

            self.handle_generation(generation_id, proposal).await;
        }
    }

    /// Returns the approved generation awaiting our result, if any.
    fn actionable_generation(
        &self,
        log: &GenerationLog,
    ) -> Option<(ModuleGenerationId, ModuleConfigProposal)> {
        log.generations()
            .iter()
            .find_map(|(generation_id, state)| match state {
                GenerationState::Approved { proposal, results }
                    if !results.contains_key(&self.identity) =>
                {
                    Some((*generation_id, proposal.clone()))
                }
                _ => None,
            })
    }

    async fn handle_generation(
        &self,
        generation_id: ModuleGenerationId,
        proposal: ModuleConfigProposal,
    ) {
        let mut dbtx = self.db.begin_transaction_nc().await;
        let outcome = dbtx
            .get_value(&LocalGenerationOutcomeKey(generation_id))
            .await;
        let started = dbtx
            .get_value(&LocalGenerationStartedKey(generation_id))
            .await
            .is_some();
        drop(dbtx);

        if let Some(outcome) = outcome {
            // Our result item may have been lost before it was ordered;
            // resubmitting is deterministic and duplicates are rejected.
            self.submit(ConfigGenItem::Result {
                generation_id,
                consensus_config: outcome.consensus,
                encrypted_private_config: outcome.encrypted_private_json,
            })
            .await;

            self.await_log_change().await;

            return;
        }

        if started {
            warn!(
                target: LOG_CONSENSUS,
                %generation_id,
                "Aborting generation started before a restart"
            );

            self.submit(ConfigGenItem::Abort {
                generation_id,
                reason: ConfigGenAbortReason("Restarted during generation".to_string()),
            })
            .await;

            self.await_log_change().await;

            return;
        }

        self.run_generation(generation_id, proposal).await;
    }

    async fn run_generation(
        &self,
        generation_id: ModuleGenerationId,
        proposal: ModuleConfigProposal,
    ) {
        let Some(module_init) = self.module_inits.get(&proposal.module_kind) else {
            self.submit(ConfigGenItem::Abort {
                generation_id,
                reason: ConfigGenAbortReason(format!(
                    "Module kind {} is not supported",
                    proposal.module_kind
                )),
            })
            .await;

            self.await_log_change().await;

            return;
        };

        let mut dbtx = self.db.begin_transaction().await;
        dbtx.insert_entry(&LocalGenerationStartedKey(generation_id), &())
            .await;
        dbtx.commit_tx().await;

        info!(
            target: LOG_CONSENSUS,
            %generation_id,
            module_kind = %proposal.module_kind,
            "Running module config generation"
        );

        let transport = GenerationTransport::new(
            generation_id,
            self.connections.clone(),
            self.incoming.clone(),
        )
        .into_dyn();

        let peer_handle = PeerHandle::new(self.num_peers, self.identity, &transport);

        let args = ConfigGenModuleArgs {
            network: proposal.network,
            disable_base_fees: proposal.disable_base_fees,
            params: proposal.params.clone(),
        };

        let result = fedimint_core::runtime::timeout(
            GENERATION_TIMEOUT,
            module_init.distributed_gen(&peer_handle, &args),
        )
        .await
        .map_err(anyhow::Error::from)
        .and_then(|result| result);

        match result {
            Ok(config) => {
                let private_json = serde_json::to_string(&config.private)
                    .expect("Private module config is serializable");

                let encrypted_private_json = fedimint_aead::encrypt(
                    private_json.clone().into_bytes(),
                    &result_encryption_key(&self.config_gen_root, generation_id),
                )
                .expect("Encryption does not fail");

                if encrypted_private_json.len()
                    > fedimint_core::config_gen::MAX_ENCRYPTED_PRIVATE_CONFIG_BYTES
                {
                    self.submit(ConfigGenItem::Abort {
                        generation_id,
                        reason: ConfigGenAbortReason(format!(
                            "Encrypted private config of {} bytes exceeds the size limit",
                            encrypted_private_json.len()
                        )),
                    })
                    .await;

                    self.await_log_change().await;

                    return;
                }

                let mut dbtx = self.db.begin_transaction().await;
                dbtx.insert_entry(
                    &LocalGenerationOutcomeKey(generation_id),
                    &LocalGenerationOutcome {
                        private_json,
                        encrypted_private_json: encrypted_private_json.clone(),
                        consensus: config.consensus.clone(),
                    },
                )
                .await;
                dbtx.commit_tx().await;

                info!(
                    target: LOG_CONSENSUS,
                    %generation_id,
                    "Module config generation completed"
                );

                self.submit(ConfigGenItem::Result {
                    generation_id,
                    consensus_config: config.consensus,
                    encrypted_private_config: encrypted_private_json,
                })
                .await;
            }
            Err(err) => {
                warn!(
                    target: LOG_CONSENSUS,
                    %generation_id,
                    err = %err.fmt_compact_anyhow(),
                    "Module config generation failed"
                );

                self.submit(ConfigGenItem::Abort {
                    generation_id,
                    reason: ConfigGenAbortReason(format!("Generation failed: {err}")),
                })
                .await;
            }
        }

        self.await_log_change().await;
    }

    async fn submit(&self, item: ConfigGenItem) {
        let _ = self
            .submission_sender
            .send(ConsensusItem::ConfigGen(item))
            .await
            .inspect_err(|_| {
                warn!(
                    target: LOG_CONSENSUS,
                    "Unable to submit config gen item into consensus"
                );
            });
    }

    /// Waits for the generation log to change so submissions have a chance
    /// to be processed before re-evaluating, instead of busy-looping.
    async fn await_log_change(&self) {
        let current = self
            .db
            .begin_transaction_nc()
            .await
            .get_value(&ConfigGenerationLogKey)
            .await;

        self.db
            .wait_key_check(&ConfigGenerationLogKey, |log| {
                if log == current { None } else { Some(()) }
            })
            .await;
    }
}
