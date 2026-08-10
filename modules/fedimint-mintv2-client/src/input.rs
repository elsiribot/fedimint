use fedimint_client::DynGlobalClientContext;
use fedimint_client::transaction::{ClientInput, ClientInputBundle};
use fedimint_client_module::module::OutPointRange;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_core::TransactionId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_mintv2_common::MintInput;

use crate::{MintClientContext, SpendableNote};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct InputStateMachine {
    pub common: InputSMCommon,
    pub state: InputSMState,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Decodable, Encodable)]
pub struct InputSMCommon {
    pub operation_id: OperationId,
    pub txid: TransactionId,
    pub spendable_notes: Vec<SpendableNote>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum InputSMState {
    Pending,
    Success,
    Refunding(OutPointRange),
    // Appended after the above variants to preserve wire/DB compatibility of
    // already-persisted states. Terminal state reached when claiming the
    // refund inputs fails (e.g. insufficient funds for the refund's own
    // fees); we cannot recover from this automatically, so we surface it
    // instead of panicking inside the state machine transition.
    RefundFailed(String),
}

impl State for InputStateMachine {
    type ModuleContext = MintClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();
        let amount_unit = context.amount_unit;

        match &self.state {
            InputSMState::Pending => {
                vec![StateTransition::new(
                    Self::await_pending_transaction(gc.clone(), self.common.txid),
                    move |dbtx, result, old_state| {
                        Box::pin(Self::transition_pending_transaction(
                            gc.clone(),
                            dbtx,
                            result,
                            old_state,
                            amount_unit,
                        ))
                    },
                )]
            }
            InputSMState::Success
            | InputSMState::Refunding(..)
            | InputSMState::RefundFailed(..) => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

impl InputStateMachine {
    async fn await_pending_transaction(
        global_context: DynGlobalClientContext,
        txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(txid).await
    }

    async fn transition_pending_transaction(
        global_context: DynGlobalClientContext,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        result: Result<(), String>,
        old_state: InputStateMachine,
        amount_unit: AmountUnit,
    ) -> InputStateMachine {
        if result.is_ok() {
            return InputStateMachine {
                common: old_state.common,
                state: InputSMState::Success,
            };
        }

        let inputs = refund_client_inputs(&old_state.common.spendable_notes, amount_unit);

        let state = match global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(inputs))
            .await
        {
            Ok(change_range) => InputSMState::Refunding(change_range),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "Failed to claim refund inputs after transaction rejection"
                );

                InputSMState::RefundFailed(err.to_string())
            }
        };

        InputStateMachine {
            common: old_state.common,
            state,
        }
    }
}

/// Builds the [`ClientInput`]s that refund `notes` back to the client's own
/// balance, denominated in the federation's configured primary-module
/// `amount_unit`.
///
/// Used on the rejection path of a mintv2 transaction (e.g. "note already
/// spent"): the notes that were about to be spent are re-claimed as inputs of
/// a fresh refund transaction. They must be tagged with the same
/// [`AmountUnit`] the mint module is actually configured for -- in a
/// federation whose primary module uses a non-Bitcoin unit, tagging them as
/// Bitcoin would make `finalize_transaction` unable to find a primary module
/// to balance the transaction.
fn refund_client_inputs(
    notes: &[SpendableNote],
    amount_unit: AmountUnit,
) -> Vec<ClientInput<MintInput>> {
    notes
        .iter()
        .map(|spendable_note| ClientInput::<MintInput> {
            input: MintInput::new_v0(spendable_note.note()),
            keys: vec![spendable_note.keypair],
            amounts: Amounts::new_custom(amount_unit, spendable_note.amount()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use fedimint_core::secp256k1::SECP256K1;
    use fedimint_derive_secret::DerivableSecret;
    use fedimint_mintv2_common::Denomination;

    use super::*;

    fn test_spendable_note(denomination: Denomination) -> SpendableNote {
        let keypair = DerivableSecret::new_root(b"input-rs-test-root", b"input-rs-test-salt")
            .to_secp_key(SECP256K1);

        SpendableNote {
            denomination,
            keypair,
            signature: tbs::Signature(bls12_381::G1Affine::identity()),
        }
    }

    /// The refund path must tag inputs with the federation's actually
    /// configured `amount_unit`, not a hardcoded Bitcoin unit. Otherwise, in
    /// a federation whose primary module uses a custom unit (e.g. USDT),
    /// `finalize_transaction` cannot find a primary module for the Bitcoin
    /// unit and the refund is rejected -- which used to be handled by
    /// `.expect(..)`, panicking inside the state-machine executor.
    #[test]
    fn refund_inputs_use_configured_amount_unit() {
        let custom_unit = AmountUnit::new_custom(1);
        assert_ne!(custom_unit, AmountUnit::BITCOIN);

        let note = test_spendable_note(Denomination(10));

        let inputs = refund_client_inputs(std::slice::from_ref(&note), custom_unit);

        assert_eq!(inputs.len(), 1);

        let amounts = &inputs[0].amounts;

        assert_eq!(amounts.get(&custom_unit), Some(&note.amount()));
        assert_eq!(amounts.get(&AmountUnit::BITCOIN), None);
    }

    #[test]
    fn refund_inputs_use_bitcoin_unit_when_configured() {
        let note = test_spendable_note(Denomination(4));

        let inputs = refund_client_inputs(std::slice::from_ref(&note), AmountUnit::BITCOIN);

        assert_eq!(inputs.len(), 1);

        let amounts = &inputs[0].amounts;

        assert_eq!(amounts.get(&AmountUnit::BITCOIN), Some(&note.amount()));
    }
}
