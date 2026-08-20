use std::time::Duration;

use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, DynState, State, StateTransition};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, OperationId};
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
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
use crate::db::KeyIndexKey;
use crate::{LOG_CLIENT_MODULE_SWAP, SwapClientContext};

/// Cap on the exponential backoff the maker state machine waits between
/// `get_offer` polls while waiting for its offer to be filled.
const MAKER_SM_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Client state machine driving the MAKER side of a swap: once the offer is
/// filled by some taker, it automatically claims the taker's leg to the maker's
/// key. Its `AwaitingAccept` -> `AwaitingFill` transition is also where
/// `KeyIndexKey(offer_id) -> index` gets persisted crash-safely (see
/// [`MakerSMState::AwaitingAccept`]), which is what lets
/// [`crate::SwapClientModule::reclaim`] always re-derive the maker keypair.
///
/// ```text
/// AwaitingAccept -- MakeOffer accepted --> (persist key index) --> AwaitingFill
/// AwaitingAccept -- MakeOffer output rejected --> Failed
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
    /// The seed-derivation index `maker_keypair` was derived at (see
    /// [`crate::SwapClientModule::offer_keypair_for_index`]). Carried here
    /// purely so `AwaitingAccept`'s transition can persist `KeyIndexKey`
    /// without re-deriving or re-allocating anything.
    pub index: u64,
    /// The taker leg's unit (specified by the maker at offer-creation time), so
    /// the `Claim` input can declare its `amounts` without re-reading the
    /// offer.
    pub taker_unit: AmountUnit,
    /// The taker leg's amount the maker claims once the offer is filled.
    pub taker_amount: Amount,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum MakerSMState {
    /// The SM's initial state: awaiting the `MakeOffer` output's acceptance.
    ///
    /// On acceptance, this transition persists `KeyIndexKey(offer_id) ->
    /// index` -- in the SAME dbtx as the state advance to `AwaitingFill` --
    /// before moving on. This replaces a separate, racy post-submit
    /// `begin_transaction`/`commit_tx` pair that used to live in
    /// [`crate::SwapClientModule::make_offer`]: because this SM's initial
    /// `AwaitingAccept` state is itself persisted atomically with the
    /// submitted `MakeOffer` transaction (both land in the same commit
    /// inside `finalize_and_submit_transaction`), a crash after that commit
    /// but before THIS transition's dbtx commits simply resumes the SM in
    /// `AwaitingAccept` on restart -- the (idempotent) trigger/transition
    /// re-runs and persists the mapping then. `reclaim` can thus always find
    /// the mapping once the `MakeOffer` tx is accepted, across any restart.
    ///
    /// On rejection, moves straight to `Failed` WITHOUT ever persisting the
    /// mapping, so a rejected offer (whose id never became a real offer)
    /// never orphans a `KeyIndexKey` entry.
    AwaitingAccept,
    /// The offer is open (`MakeOffer` accepted, `KeyIndexKey` persisted);
    /// polling `get_offer` until the offer is `Filled`.
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

    /// Awaits the `MakeOffer` transaction's acceptance (the SM's very first
    /// transition, from `AwaitingAccept`).
    async fn await_accepted(
        global_context: DynGlobalClientContext,
        offer_id: OutPoint,
    ) -> Result<(), String> {
        global_context.await_tx_accepted(offer_id.txid).await
    }

    /// On acceptance, persists `KeyIndexKey(offer_id) -> index` (crash-safely
    /// -- see [`MakerSMState::AwaitingAccept`]) and advances to
    /// `AwaitingFill`. On rejection, moves straight to `Failed` without ever
    /// persisting the mapping (a rejected `MakeOffer` never opened an offer,
    /// so there is nothing to reclaim and no mapping should linger).
    async fn transition_accepted(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        result: Result<(), String>,
        old_state: MakerStateMachine,
    ) -> MakerStateMachine {
        match result {
            Ok(()) => {
                dbtx.module_tx()
                    .insert_entry(
                        &KeyIndexKey(old_state.common.offer_id),
                        &old_state.common.index,
                    )
                    .await;
                old_state.update(MakerSMState::AwaitingFill)
            }
            Err(error) => old_state.update(MakerSMState::Failed { error }),
        }
    }

    /// Polls `get_offer` (with exponential backoff) until the offer is filled
    /// (or gone). Assumes the `MakeOffer` tx is already accepted (handled by
    /// `AwaitingAccept`/[`Self::transition_accepted`]).
    async fn await_fill(context: SwapClientContext, offer_id: OutPoint) -> MakerOutcome {
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
            MakerSMState::AwaitingAccept => {
                let gc = global_context.clone();
                let offer_id = self.common.offer_id;
                vec![StateTransition::new(
                    Self::await_accepted(gc, offer_id),
                    move |dbtx, result, old_state| {
                        Box::pin(Self::transition_accepted(dbtx, result, old_state))
                    },
                )]
            }
            MakerSMState::AwaitingFill => {
                let gc = global_context.clone();
                let ctx = context.clone();
                let offer_id = self.common.offer_id;
                vec![StateTransition::new(
                    Self::await_fill(ctx, offer_id),
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
    use fedimint_core::db::Database;
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::module::AmountUnit;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::secp256k1::SECP256K1;
    use fedimint_core::{Amount, BitcoinHash as _, TransactionId};
    use fedimint_derive_secret::DerivableSecret;

    use super::*;

    /// Arbitrary seed-derivation index used by the tests below; distinct from
    /// `0` so a test bug that silently defaults `index` to `0` would still be
    /// caught by asserting the exact stored value.
    const TEST_INDEX: u64 = 7;

    /// A module instance id for constructing an isolated
    /// [`ClientSMDatabaseTransaction`] in tests, mirroring how the real
    /// client scopes each module's database.
    const TEST_MODULE_INSTANCE_ID: ModuleInstanceId = 1;

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
                index: TEST_INDEX,
                taker_unit: AmountUnit::new_custom(2),
                taker_amount: Amount::from_msats(2_000_000),
            },
            state: s,
        }
    }

    fn mem_db() -> Database {
        Database::new(MemDatabase::new(), ModuleDecoderRegistry::default())
    }

    /// The crux of the Phase 5 review fix: after the maker SM's FIRST
    /// transition (`AwaitingAccept` resolving to acceptance) commits,
    /// `KeyIndexKey(offer_id)` must already be readable through the exact
    /// lookup [`crate::SwapClientModule::reclaim`] performs -- with NO
    /// separate post-submit write involved. Before the fix, this mapping was
    /// only ever written by a racy `begin_transaction`/`commit_tx` pair in
    /// `make_offer` running AFTER `finalize_and_submit_transaction` returned;
    /// a crash in between lost it forever (since `NoModuleBackup` + no
    /// seed-scan recovery means it's the ONLY way to re-derive the maker
    /// keypair). This test exercises the SM transition directly and would
    /// fail (mapping absent) against the pre-fix code, which wrote the
    /// mapping from `make_offer`, not from the SM.
    #[tokio::test]
    async fn accepted_transition_persists_key_index_for_reclaim() {
        let old = state(MakerSMState::AwaitingAccept);
        let offer_id = old.common.offer_id;

        let raw_db = mem_db();
        let (module_db, _access_token) = raw_db.with_prefix_module_id(TEST_MODULE_INSTANCE_ID);

        let mut dbtx = raw_db.begin_transaction().await;
        {
            let mut nc_dbtx = dbtx.to_ref_nc();
            let mut sm_dbtx =
                ClientSMDatabaseTransaction::new(&mut nc_dbtx, TEST_MODULE_INSTANCE_ID);
            let next = MakerStateMachine::transition_accepted(&mut sm_dbtx, Ok(()), old).await;
            assert_eq!(
                next.state,
                MakerSMState::AwaitingFill,
                "acceptance must advance AwaitingAccept -> AwaitingFill"
            );
        }
        dbtx.commit_tx().await;

        // Exactly mirrors `SwapClientModule::reclaim`'s lookup: a
        // non-caching read against the module-scoped db, keyed by offer_id.
        let mut read_tx = module_db.begin_transaction_nc().await;
        let stored_index = read_tx
            .get_value(&KeyIndexKey(offer_id))
            .await
            .expect("reclaim's key-index lookup must find the mapping after the first transition");
        assert_eq!(stored_index, TEST_INDEX);
    }

    /// Mirror image of the fix's other half (the Minor "orphan on rejected"
    /// note): a REJECTED `MakeOffer` must never leave a `KeyIndexKey` entry
    /// behind, since the offer id never became a real offer.
    #[tokio::test]
    async fn rejected_transition_does_not_persist_key_index() {
        let old = state(MakerSMState::AwaitingAccept);
        let offer_id = old.common.offer_id;

        let raw_db = mem_db();
        let (module_db, _access_token) = raw_db.with_prefix_module_id(TEST_MODULE_INSTANCE_ID);

        let mut dbtx = raw_db.begin_transaction().await;
        {
            let mut nc_dbtx = dbtx.to_ref_nc();
            let mut sm_dbtx =
                ClientSMDatabaseTransaction::new(&mut nc_dbtx, TEST_MODULE_INSTANCE_ID);
            let next =
                MakerStateMachine::transition_accepted(&mut sm_dbtx, Err("boom".to_string()), old)
                    .await;
            assert_eq!(
                next.state,
                MakerSMState::Failed {
                    error: "boom".to_string()
                }
            );
        }
        dbtx.commit_tx().await;

        let mut read_tx = module_db.begin_transaction_nc().await;
        assert_eq!(
            read_tx.get_value(&KeyIndexKey(offer_id)).await,
            None,
            "a rejected MakeOffer must not orphan a KeyIndexKey entry"
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
