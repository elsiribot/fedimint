use std::time::Duration;

use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, DynState, State, StateTransition};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::runtime::sleep;
use fedimint_core::secp256k1::Keypair;
use fedimint_core::util::{FmtCompact as _, FmtCompactAnyhow as _};
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_swap_common::{OfferState, Party, SwapInput};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::api::SwapFederationApi as _;
use crate::{LOG_CLIENT_MODULE_SWAP, SwapClientContext};

/// Cap on the exponential backoff the maker state machine waits between
/// `get_offer` polls while waiting for its offer to be filled.
const MAKER_SM_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Client state machine driving the MAKER side of a swap: once the offer is
/// filled by some taker, it automatically claims the taker's leg to the maker's
/// key.
///
/// ```text
/// AwaitingFill -- MakeOffer output rejected --> Failed
/// AwaitingFill -- offer reclaimed before fill --> Failed
/// AwaitingFill -- offer Filled --> (submit Claim{Maker}) --> Claiming --> Claimed
/// ```
///
/// The `Claim` input is signed by [`MakerSMCommon::maker_keypair`] (whose
/// public key the `MakeOffer` output committed as `maker_pk`), so only the
/// maker can claim the taker leg; the server's `maker_claimed` flag makes the
/// claim exactly-once. Voluntary cancellation is the separate
/// [`crate::SwapClientModule::reclaim`] method, not part of this machine.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MakerStateMachine {
    pub common: MakerSMCommon,
    pub state: MakerSMState,
}

/// Immutable identity of a maker-side swap.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct MakerSMCommon {
    pub operation_id: OperationId,
    /// The offer id (the `MakeOffer` output's `OutPoint`); also the key the
    /// `Claim` input targets.
    pub offer_id: OutPoint,
    /// The seed-derived keypair that owns the maker leg; its public key is the
    /// offer's `maker_pk`, so only it can sign the `Claim`.
    pub maker_keypair: Keypair,
    /// The taker leg's unit (specified by the maker at offer-creation time), so
    /// the `Claim` input can declare its `amounts` without re-reading the
    /// offer.
    pub taker_unit: AmountUnit,
    /// The taker leg's amount the maker claims once the offer is filled.
    pub taker_amount: Amount,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum MakerSMState {
    /// Awaiting the `MakeOffer` output's acceptance, then polling `get_offer`
    /// until the offer is `Filled`.
    AwaitingFill,
    /// The offer was filled; a `Claim{Maker}` input (txid `claim_txid`) has
    /// been submitted and is awaiting acceptance.
    Claiming { claim_txid: TransactionId },
    /// The maker leg's counterparty (taker) leg was claimed to the maker's key;
    /// terminal.
    Claimed,
    /// The offer never opened (output rejected) or was reclaimed before any
    /// fill, so nothing was claimed; terminal.
    Failed { error: String },
}

impl MakerStateMachine {
    fn update(&self, state: MakerSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }

    /// Awaits the `MakeOffer` transaction's acceptance, then polls `get_offer`
    /// (with exponential backoff) until the offer is filled (or gone).
    async fn await_fill(
        global_context: DynGlobalClientContext,
        context: SwapClientContext,
        offer_id: OutPoint,
    ) -> MakerOutcome {
        // A rejected `MakeOffer` never opened an offer -- nothing to claim.
        if let Err(error) = global_context.await_tx_accepted(offer_id.txid).await {
            return MakerOutcome::Rejected { error };
        }

        let mut backoff = Duration::from_millis(250);
        loop {
            match context.module_api.get_offer(offer_id).await {
                Ok(Some(offer)) => match offer.state {
                    OfferState::Filled { .. } => return MakerOutcome::Filled,
                    OfferState::Open => {}
                },
                // The offer existed (the `MakeOffer` tx was accepted above) but
                // is now gone: the maker reclaimed it before any fill. Terminal.
                Ok(None) => return MakerOutcome::Gone,
                Err(err) => {
                    debug!(
                        target: LOG_CLIENT_MODULE_SWAP,
                        %offer_id,
                        err = %err.fmt_compact(),
                        "get_offer poll failed, retrying"
                    );
                }
            }

            sleep(backoff).await;
            backoff = (backoff * 2).min(MAKER_SM_MAX_BACKOFF);
        }
    }

    /// Pure mapping of a non-`Filled` outcome to a terminal state. Returns
    /// `None` for `Filled`, which requires submitting a `Claim` input (done in
    /// [`Self::transition_fill`], which needs the dbtx/global context). Split
    /// out so the terminal outcomes are unit-testable without a live context.
    fn terminal_for_outcome(&self, outcome: &MakerOutcome) -> Option<MakerStateMachine> {
        match outcome {
            MakerOutcome::Rejected { error } => Some(self.update(MakerSMState::Failed {
                error: error.clone(),
            })),
            MakerOutcome::Gone => Some(self.update(MakerSMState::Failed {
                error: "offer no longer exists (reclaimed before it was filled)".to_string(),
            })),
            MakerOutcome::Filled => None,
        }
    }

    async fn transition_fill(
        global_context: DynGlobalClientContext,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        outcome: MakerOutcome,
        old_state: MakerStateMachine,
    ) -> MakerStateMachine {
        if let Some(terminal) = old_state.terminal_for_outcome(&outcome) {
            return terminal;
        }
        // The only non-terminal outcome is `Filled`: claim the TAKER leg to the
        // maker's key. The mint (primary for `taker_unit`) mints the reissued
        // e-cash as change.
        let input = ClientInput::<SwapInput> {
            input: SwapInput::Claim {
                offer_id: old_state.common.offer_id,
                party: Party::Maker,
            },
            keys: vec![old_state.common.maker_keypair],
            amounts: Amounts::new_custom(
                old_state.common.taker_unit,
                old_state.common.taker_amount,
            ),
        };

        match global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![input]))
            .await
        {
            Ok(range) => old_state.update(MakerSMState::Claiming {
                claim_txid: range.txid(),
            }),
            Err(err) => {
                warn!(
                    target: LOG_CLIENT_MODULE_SWAP,
                    offer_id = %old_state.common.offer_id,
                    err = %err.fmt_compact_anyhow(),
                    "failed to submit maker claim; re-polling to retry"
                );
                // Stay AwaitingFill: the next `transitions` call re-observes the
                // filled offer and retries the claim.
                old_state.update(MakerSMState::AwaitingFill)
            }
        }
    }

    async fn await_claim_accepted(
        global_context: DynGlobalClientContext,
        claim_txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(claim_txid).await
    }

    fn transition_claim_accepted(
        result: Result<(), String>,
        old_state: &MakerStateMachine,
    ) -> MakerStateMachine {
        match result {
            Ok(()) => old_state.update(MakerSMState::Claimed),
            Err(error) => {
                warn!(
                    target: LOG_CLIENT_MODULE_SWAP,
                    offer_id = %old_state.common.offer_id,
                    error = error.as_str(),
                    "maker claim rejected; re-polling to retry"
                );
                // Re-poll from AwaitingFill; the filled offer is still there and
                // the claim is idempotent server-side (`maker_claimed`).
                old_state.update(MakerSMState::AwaitingFill)
            }
        }
    }
}

impl State for MakerStateMachine {
    type ModuleContext = SwapClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            MakerSMState::AwaitingFill => {
                let gc = global_context.clone();
                let ctx = context.clone();
                let offer_id = self.common.offer_id;
                vec![StateTransition::new(
                    Self::await_fill(gc.clone(), ctx, offer_id),
                    move |dbtx, outcome, old_state| {
                        Box::pin(Self::transition_fill(gc.clone(), dbtx, outcome, old_state))
                    },
                )]
            }
            MakerSMState::Claiming { claim_txid } => {
                let gc = global_context.clone();
                let claim_txid = *claim_txid;
                vec![StateTransition::new(
                    Self::await_claim_accepted(gc, claim_txid),
                    move |_dbtx, result, old_state| {
                        Box::pin(async move { Self::transition_claim_accepted(result, &old_state) })
                    },
                )]
            }
            MakerSMState::Claimed | MakerSMState::Failed { .. } => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

/// The outcome [`MakerStateMachine::await_fill`] resolves an `AwaitingFill`
/// offer to.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum MakerOutcome {
    /// The `MakeOffer` output was rejected by consensus.
    Rejected { error: String },
    /// The offer was reclaimed (deleted) before any fill.
    Gone,
    /// The offer was filled and the taker leg is claimable.
    Filled,
}

impl IntoDynInstance for MakerStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::module::AmountUnit;
    use fedimint_core::secp256k1::SECP256K1;
    use fedimint_core::{Amount, BitcoinHash as _, TransactionId};
    use fedimint_derive_secret::DerivableSecret;

    use super::*;

    fn state(s: MakerSMState) -> MakerStateMachine {
        let keypair =
            DerivableSecret::new_root(b"swap-maker-sm-test-seed", b"salt").to_secp_key(SECP256K1);
        MakerStateMachine {
            common: MakerSMCommon {
                operation_id: OperationId::new_random(),
                offer_id: OutPoint {
                    txid: TransactionId::all_zeros(),
                    out_idx: 0,
                },
                maker_keypair: keypair,
                taker_unit: AmountUnit::new_custom(2),
                taker_amount: Amount::from_msats(2_000_000),
            },
            state: s,
        }
    }

    /// A rejected `MakeOffer` output resolves the machine to the terminal
    /// `Failed` state (no offer ever opened).
    #[test]
    fn rejected_make_offer_becomes_failed() {
        let old = state(MakerSMState::AwaitingFill);
        let next = old
            .terminal_for_outcome(&MakerOutcome::Rejected {
                error: "boom".to_string(),
            })
            .expect("Rejected is terminal");
        assert_eq!(
            next.state,
            MakerSMState::Failed {
                error: "boom".to_string()
            }
        );
    }

    /// An offer that vanished before being filled (reclaimed) resolves to
    /// terminal `Failed`.
    #[test]
    fn gone_offer_becomes_failed() {
        let old = state(MakerSMState::AwaitingFill);
        let next = old
            .terminal_for_outcome(&MakerOutcome::Gone)
            .expect("Gone is terminal");
        assert!(matches!(next.state, MakerSMState::Failed { .. }));
    }

    /// A `Filled` outcome is NOT terminal here (it triggers a claim
    /// submission, handled in `transition_fill`), so the pure mapping returns
    /// `None`.
    #[test]
    fn filled_outcome_is_not_terminal() {
        let old = state(MakerSMState::AwaitingFill);
        assert!(old.terminal_for_outcome(&MakerOutcome::Filled).is_none());
    }

    /// An accepted claim transaction reaches the terminal `Claimed` state; a
    /// rejected one re-polls from `AwaitingFill`.
    #[test]
    fn claim_acceptance_transitions() {
        let old = state(MakerSMState::Claiming {
            claim_txid: TransactionId::all_zeros(),
        });
        assert_eq!(
            MakerStateMachine::transition_claim_accepted(Ok(()), &old).state,
            MakerSMState::Claimed
        );
        assert_eq!(
            MakerStateMachine::transition_claim_accepted(Err("nope".to_string()), &old).state,
            MakerSMState::AwaitingFill
        );
    }
}
