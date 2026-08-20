use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, DynState, State, StateTransition};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_swap_common::{Party, SwapInput};
use tracing::warn;

use crate::{LOG_CLIENT_MODULE_SWAP, SwapClientContext};

/// Client state machine driving the TAKER side of a swap: once the `Fill`
/// output is accepted (which flips the offer to `Filled` server-side), it
/// automatically claims the maker's leg to the taker's key.
///
/// ```text
/// AwaitingAccept -- Fill output rejected --> FillRejected
/// AwaitingAccept -- Fill accepted --> (submit Claim{Taker}) --> Claiming --> Claimed
/// ```
///
/// The `Claim` input is signed by [`TakerSMCommon::taker_keypair`] (whose
/// public key the `Fill` output committed as `taker_pk`), so only the taker can
/// claim the maker leg; the server's `taker_claimed` flag makes the claim
/// exactly-once. A rejected `Fill` moves no funds (its taker leg was never
/// escrowed, the transaction being atomic).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct TakerStateMachine {
    pub common: TakerSMCommon,
    pub state: TakerSMState,
}

/// Immutable identity of a taker-side swap.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct TakerSMCommon {
    pub operation_id: OperationId,
    /// The offer id (the `MakeOffer` output's `OutPoint`); the key the `Claim`
    /// input targets.
    pub offer_id: OutPoint,
    /// The `Fill` transaction's id, awaited for acceptance before claiming.
    pub fill_txid: TransactionId,
    /// The seed-derived keypair that owns the taker leg; its public key is the
    /// offer's `taker_pk`, so only it can sign the `Claim`.
    pub taker_keypair: Keypair,
    /// The maker leg's unit (read from the offer at fill time), so the `Claim`
    /// input can declare its `amounts` without re-reading the offer.
    pub maker_unit: AmountUnit,
    /// The maker leg's amount the taker claims once the fill is accepted.
    pub maker_amount: Amount,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum TakerSMState {
    /// Awaiting the `Fill` output's acceptance.
    AwaitingAccept,
    /// The fill was accepted; a `Claim{Taker}` input (txid `claim_txid`) has
    /// been submitted and is awaiting acceptance.
    Claiming { claim_txid: TransactionId },
    /// The maker leg was claimed to the taker's key; terminal.
    Claimed,
    /// The `Fill` output was rejected by consensus, so no funds moved;
    /// terminal.
    FillRejected { error: String },
}

impl TakerStateMachine {
    fn update(&self, state: TakerSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }

    async fn await_fill_accepted(
        global_context: DynGlobalClientContext,
        fill_txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(fill_txid).await
    }

    /// Pure mapping of a rejected `Fill` to the terminal `FillRejected` state.
    /// Returns `None` on acceptance (which requires submitting a `Claim`, done
    /// in [`Self::transition_fill_accepted`]). Split out so the terminal
    /// outcome is unit-testable without a live context.
    fn terminal_for_fill_result(&self, result: &Result<(), String>) -> Option<TakerStateMachine> {
        match result {
            // A rejected `Fill` never escrowed the taker leg -- nothing to
            // claim, no funds moved.
            Err(error) => Some(self.update(TakerSMState::FillRejected {
                error: error.clone(),
            })),
            Ok(()) => None,
        }
    }

    async fn transition_fill_accepted(
        global_context: DynGlobalClientContext,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        result: Result<(), String>,
        old_state: TakerStateMachine,
    ) -> TakerStateMachine {
        if let Some(terminal) = old_state.terminal_for_fill_result(&result) {
            return terminal;
        }
        // The fill was accepted, so the offer is `Filled` server-side and the
        // MAKER leg is claimable to the taker's key. The mint (primary for
        // `maker_unit`) mints the reissued e-cash as change.
        let input = ClientInput::<SwapInput> {
            input: SwapInput::Claim {
                offer_id: old_state.common.offer_id,
                party: Party::Taker,
            },
            keys: vec![old_state.common.taker_keypair],
            amounts: Amounts::new_custom(
                old_state.common.maker_unit,
                old_state.common.maker_amount,
            ),
        };

        match global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![input]))
            .await
        {
            Ok(range) => old_state.update(TakerSMState::Claiming {
                claim_txid: range.txid(),
            }),
            Err(err) => {
                warn!(
                    target: LOG_CLIENT_MODULE_SWAP,
                    offer_id = %old_state.common.offer_id,
                    err = %err.fmt_compact_anyhow(),
                    "failed to submit taker claim; retrying"
                );
                // Stay AwaitingAccept: the next `transitions` call re-awaits the
                // (already-accepted) fill and retries the claim.
                old_state.update(TakerSMState::AwaitingAccept)
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
        old_state: &TakerStateMachine,
    ) -> TakerStateMachine {
        match result {
            Ok(()) => old_state.update(TakerSMState::Claimed),
            Err(error) => {
                warn!(
                    target: LOG_CLIENT_MODULE_SWAP,
                    offer_id = %old_state.common.offer_id,
                    error = error.as_str(),
                    "taker claim rejected; retrying"
                );
                // Re-await from AwaitingAccept; the claim is idempotent
                // server-side (`taker_claimed`).
                old_state.update(TakerSMState::AwaitingAccept)
            }
        }
    }
}

impl State for TakerStateMachine {
    type ModuleContext = SwapClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            TakerSMState::AwaitingAccept => {
                let gc = global_context.clone();
                let fill_txid = self.common.fill_txid;
                vec![StateTransition::new(
                    Self::await_fill_accepted(gc.clone(), fill_txid),
                    move |dbtx, result, old_state| {
                        Box::pin(Self::transition_fill_accepted(
                            gc.clone(),
                            dbtx,
                            result,
                            old_state,
                        ))
                    },
                )]
            }
            TakerSMState::Claiming { claim_txid } => {
                let gc = global_context.clone();
                let claim_txid = *claim_txid;
                vec![StateTransition::new(
                    Self::await_claim_accepted(gc, claim_txid),
                    move |_dbtx, result, old_state| {
                        Box::pin(async move { Self::transition_claim_accepted(result, &old_state) })
                    },
                )]
            }
            TakerSMState::Claimed | TakerSMState::FillRejected { .. } => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl IntoDynInstance for TakerStateMachine {
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

    fn state(s: TakerSMState) -> TakerStateMachine {
        let keypair =
            DerivableSecret::new_root(b"swap-taker-sm-test-seed", b"salt").to_secp_key(SECP256K1);
        TakerStateMachine {
            common: TakerSMCommon {
                operation_id: OperationId::new_random(),
                offer_id: OutPoint {
                    txid: TransactionId::all_zeros(),
                    out_idx: 0,
                },
                fill_txid: TransactionId::all_zeros(),
                taker_keypair: keypair,
                maker_unit: AmountUnit::new_custom(1),
                maker_amount: Amount::from_msats(1_000_000),
            },
            state: s,
        }
    }

    /// A rejected `Fill` output resolves the machine to the terminal
    /// `FillRejected` state, moving no funds.
    #[test]
    fn rejected_fill_becomes_fill_rejected() {
        let old = state(TakerSMState::AwaitingAccept);
        let next = old
            .terminal_for_fill_result(&Err("boom".to_string()))
            .expect("a rejected fill is terminal");
        assert_eq!(
            next.state,
            TakerSMState::FillRejected {
                error: "boom".to_string()
            }
        );
    }

    /// An accepted `Fill` is NOT terminal here (it triggers a claim
    /// submission, handled in `transition_fill_accepted`), so the pure mapping
    /// returns `None`.
    #[test]
    fn accepted_fill_is_not_terminal() {
        let old = state(TakerSMState::AwaitingAccept);
        assert!(old.terminal_for_fill_result(&Ok(())).is_none());
    }

    /// An accepted claim transaction reaches the terminal `Claimed` state; a
    /// rejected one re-awaits from `AwaitingAccept`.
    #[test]
    fn claim_acceptance_transitions() {
        let old = state(TakerSMState::Claiming {
            claim_txid: TransactionId::all_zeros(),
        });
        assert_eq!(
            TakerStateMachine::transition_claim_accepted(Ok(()), &old).state,
            TakerSMState::Claimed
        );
        assert_eq!(
            TakerStateMachine::transition_claim_accepted(Err("nope".to_string()), &old).state,
            TakerSMState::AwaitingAccept
        );
    }
}
