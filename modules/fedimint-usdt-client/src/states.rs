use std::time::Duration;

use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, DynState, State, StateTransition};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_core::runtime::sleep;
use fedimint_core::secp256k1::Keypair;
use fedimint_core::util::{FmtCompact as _, FmtCompactAnyhow as _};
use fedimint_core::{OutPoint, TransactionId};
use fedimint_logging::LOG_CLIENT_MODULE_USDT;
use fedimint_usdt_common::{USDT_UNIT, UsdtAmount, UsdtInput, WithdrawalStatus, usdt_amount};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

use crate::UsdtClientContext;
use crate::api::UsdtFederationApi as _;

/// Cap on the exponential backoff the withdrawal refund state machine waits
/// between `withdrawal_status`/`refund_status` polls.
const REFUND_SM_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Client state machine for the USDT module (security finding 09): watches a
/// submitted withdrawal to its terminal state and, if it fails, claims the
/// reissued e-cash refund back to the client.
///
/// ```text
/// Pending -- withdrawal Confirmed --> Paid
/// Pending -- withdrawal tx rejected --> Rejected
/// Pending -- withdrawal Failed --> (claim RefundV0) --> Refunding --> Refunded
/// ```
///
/// The refund is claimable ONLY by [`WithdrawalRefundCommon::refund_keypair`]
/// (whose public key the withdrawal output committed as its `refund_pubkey`),
/// so no one but the original withdrawer can claim it; the server clears the
/// refund record the instant this claim is processed, so it mints EXACTLY
/// ONCE.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct UsdtStateMachine {
    pub common: WithdrawalRefundCommon,
    pub state: WithdrawalRefundState,
}

/// Immutable identity of a tracked withdrawal (security finding 09).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct WithdrawalRefundCommon {
    pub operation_id: OperationId,
    /// The `TransactionId` of the withdrawal transaction, awaited for
    /// acceptance before the refund flow begins.
    pub txid: TransactionId,
    /// The `OutPoint` of the withdrawal output (its lifecycle key on the
    /// server and the `RefundV0` claim target).
    pub out_point: OutPoint,
    /// The seed-derived keypair that owns the reissued e-cash refund; its
    /// public key was placed in the withdrawal output's `refund_pubkey`, so
    /// only this key can claim the refund.
    pub refund_keypair: Keypair,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum WithdrawalRefundState {
    /// Awaiting the withdrawal's terminal outcome.
    Pending,
    /// The withdrawal was paid out on-chain at `block`; terminal.
    Paid { block: u64 },
    /// The withdrawal transaction itself was rejected by consensus, so no
    /// e-cash was ever burned (nothing to refund); terminal.
    Rejected { error: String },
    /// The withdrawal failed terminally; a `RefundV0` claim (txid
    /// `refund_txid`) reissuing `amount` e-cash has been submitted and is
    /// awaiting acceptance.
    Refunding {
        refund_txid: TransactionId,
        amount: UsdtAmount,
        reason: String,
    },
    /// The refund's `RefundV0` claim was accepted; `amount` e-cash was
    /// reissued to the client; terminal.
    Refunded { amount: UsdtAmount, reason: String },
}

impl UsdtStateMachine {
    fn update(&self, state: WithdrawalRefundState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }

    /// Awaits the withdrawal transaction's acceptance, then polls
    /// `withdrawal_status` (with exponential backoff) until the withdrawal
    /// reaches a terminal state, returning what happened.
    async fn await_outcome(
        global_context: DynGlobalClientContext,
        context: UsdtClientContext,
        txid: TransactionId,
        out_point: OutPoint,
    ) -> WithdrawalOutcome {
        // If the withdrawal transaction was rejected, the burned e-cash was
        // never actually consumed (the transaction is atomic) -- there is
        // nothing to refund.
        if let Err(error) = global_context.await_tx_accepted(txid).await {
            return WithdrawalOutcome::Rejected { error };
        }

        let mut backoff = Duration::from_millis(250);
        loop {
            match context.module_api.withdrawal_status(out_point).await {
                Ok(resp) => match resp.status {
                    WithdrawalStatus::Confirmed { block } => {
                        return WithdrawalOutcome::Paid { block };
                    }
                    WithdrawalStatus::Failed { reason } => {
                        // The withdrawal is terminal-`Failed`; fetch the refund
                        // amount the server computed so the claim balances.
                        match context.module_api.refund_status(out_point).await {
                            Ok(resp) => match resp.refund {
                                Some(info) => {
                                    return WithdrawalOutcome::Refundable {
                                        amount: info.amount,
                                        reason: info.reason,
                                    };
                                }
                                // No live refund: it was already claimed (e.g.
                                // by a prior run of this machine). Nothing left
                                // to do.
                                None => {
                                    return WithdrawalOutcome::AlreadyRefunded { reason };
                                }
                            },
                            Err(err) => {
                                debug!(
                                    target: LOG_CLIENT_MODULE_USDT,
                                    %out_point,
                                    err = %err.fmt_compact(),
                                    "refund_status poll failed, retrying"
                                );
                            }
                        }
                    }
                    WithdrawalStatus::Unknown
                    | WithdrawalStatus::Queued
                    | WithdrawalStatus::Signing { .. }
                    | WithdrawalStatus::Submitted { .. } => {}
                },
                Err(err) => {
                    debug!(
                        target: LOG_CLIENT_MODULE_USDT,
                        %out_point,
                        err = %err.fmt_compact(),
                        "withdrawal_status poll failed, retrying"
                    );
                }
            }

            sleep(backoff).await;
            backoff = (backoff * 2).min(REFUND_SM_MAX_BACKOFF);
        }
    }

    async fn transition_outcome(
        global_context: DynGlobalClientContext,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        outcome: WithdrawalOutcome,
        old_state: UsdtStateMachine,
    ) -> UsdtStateMachine {
        match outcome {
            WithdrawalOutcome::Paid { block } => {
                old_state.update(WithdrawalRefundState::Paid { block })
            }
            WithdrawalOutcome::Rejected { error } => {
                old_state.update(WithdrawalRefundState::Rejected { error })
            }
            WithdrawalOutcome::AlreadyRefunded { reason } => {
                // The refund was already claimed on a prior run; do not claim
                // again (the server removed the `RefundKey` on that claim),
                // just record it terminally.
                old_state.update(WithdrawalRefundState::Refunded {
                    amount: UsdtAmount(0),
                    reason,
                })
            }
            WithdrawalOutcome::Refundable { amount, reason } => {
                // Build and submit the `RefundV0` claim, signed by the
                // client-controlled refund key. The mint primary module mints
                // `amount` of `USDT_UNIT` e-cash as change, restoring the
                // withdrawer's balance (minus the incurred gas the server
                // already netted out).
                let input = ClientInput::<UsdtInput> {
                    input: UsdtInput::RefundV0 {
                        out_point: old_state.common.out_point,
                    },
                    keys: vec![old_state.common.refund_keypair],
                    amounts: Amounts::new_custom(USDT_UNIT, usdt_amount(amount)),
                };

                match global_context
                    .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![input]))
                    .await
                {
                    Ok(range) => old_state.update(WithdrawalRefundState::Refunding {
                        refund_txid: range.txid(),
                        amount,
                        reason,
                    }),
                    Err(err) => {
                        warn!(
                            target: LOG_CLIENT_MODULE_USDT,
                            out_point = %old_state.common.out_point,
                            err = %err.fmt_compact_anyhow(),
                            "failed to submit withdrawal refund claim; staying Pending to retry"
                        );
                        // Stay Pending: the next `transitions` call re-derives
                        // the outcome and retries the claim.
                        old_state.update(WithdrawalRefundState::Pending)
                    }
                }
            }
        }
    }

    async fn await_refund_accepted(
        global_context: DynGlobalClientContext,
        refund_txid: TransactionId,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(refund_txid).await
    }

    fn transition_refund_accepted(
        result: Result<(), String>,
        old_state: &UsdtStateMachine,
    ) -> UsdtStateMachine {
        let (amount, reason) = match &old_state.state {
            WithdrawalRefundState::Refunding { amount, reason, .. } => (*amount, reason.clone()),
            _ => (UsdtAmount(0), String::new()),
        };
        match result {
            Ok(()) => old_state.update(WithdrawalRefundState::Refunded { amount, reason }),
            Err(error) => {
                // The refund claim was rejected (e.g. the refund was already
                // consumed). Re-poll from Pending; if the refund is gone the
                // machine settles as AlreadyRefunded.
                warn!(
                    target: LOG_CLIENT_MODULE_USDT,
                    out_point = %old_state.common.out_point,
                    error = error.as_str(),
                    "withdrawal refund claim rejected; re-polling"
                );
                old_state.update(WithdrawalRefundState::Pending)
            }
        }
    }
}

impl State for UsdtStateMachine {
    type ModuleContext = UsdtClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            WithdrawalRefundState::Pending => {
                let gc = global_context.clone();
                let ctx = context.clone();
                let common = self.common.clone();
                vec![StateTransition::new(
                    Self::await_outcome(gc.clone(), ctx, common.txid, common.out_point),
                    move |dbtx, outcome, old_state| {
                        Box::pin(Self::transition_outcome(
                            gc.clone(),
                            dbtx,
                            outcome,
                            old_state,
                        ))
                    },
                )]
            }
            WithdrawalRefundState::Refunding { refund_txid, .. } => {
                let gc = global_context.clone();
                let refund_txid = *refund_txid;
                vec![StateTransition::new(
                    Self::await_refund_accepted(gc, refund_txid),
                    move |_dbtx, result, old_state| {
                        Box::pin(
                            async move { Self::transition_refund_accepted(result, &old_state) },
                        )
                    },
                )]
            }
            WithdrawalRefundState::Paid { .. }
            | WithdrawalRefundState::Rejected { .. }
            | WithdrawalRefundState::Refunded { .. } => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

/// The terminal outcome [`UsdtStateMachine::await_outcome`] resolves a
/// `Pending` withdrawal to.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum WithdrawalOutcome {
    Paid { block: u64 },
    Rejected { error: String },
    Refundable { amount: UsdtAmount, reason: String },
    AlreadyRefunded { reason: String },
}

impl IntoDynInstance for UsdtStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

#[derive(Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum UsdtError {
    #[error("Usdt module had an internal error")]
    UsdtInternalError,
}
