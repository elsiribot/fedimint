#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::bail;
use api::SwapFederationApi as _;
use db::{DbKeyPrefix, KeyIndexKey, KeyIndexPrefixAll, NextKeyIndexKey, NextKeyIndexPrefixAll};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule};
use fedimint_client_module::sm::{Context, DynState, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, ClientOutputSM,
    TransactionBuilder,
};
use fedimint_client_module::{DynGlobalClientContext, sm_enum_variant_translation};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{
    AutocommitError, Database, DatabaseTransaction, DatabaseVersion,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_core::{
    Amount, OutPoint, OutPointRange, apply, async_trait_maybe_send, push_db_pair_items,
};
use fedimint_derive_secret::{ChildId, DerivableSecret};
pub use fedimint_swap_common as common;
use fedimint_swap_common::{KIND, Offer, OfferState, SwapInput, SwapModuleTypes, SwapOutput};
use futures::StreamExt;
use maker_sm::{MakerSMCommon, MakerSMState, MakerStateMachine};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use taker_sm::{TakerSMCommon, TakerSMState, TakerStateMachine};

pub mod api;
pub mod db;
mod maker_sm;
mod taker_sm;

/// Structured-logging target for this module's client.
pub(crate) const LOG_CLIENT_MODULE_SWAP: &str = "fm::client::module::swap";

/// Namespaces swap offer keys under the module root secret: every maker/taker
/// keypair is derived as `module_root_secret.child_key(SWAP_KEY_CHILD)
/// .child_key(ChildId(index))` (see
/// [`SwapClientModule::offer_keypair_static`]). A single child domain suffices
/// because maker and taker keys always draw distinct indices from the same
/// monotonic counter.
const SWAP_KEY_CHILD: ChildId = ChildId(0);

/// Wrapper enum over the swap module's two client state machines (mirrors
/// `fedimint-dummy-client`'s `DummyStateMachine`).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum SwapStateMachines {
    Maker(MakerStateMachine),
    Taker(TakerStateMachine),
}

impl State for SwapStateMachines {
    type ModuleContext = SwapClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            SwapStateMachines::Maker(sm) => {
                sm_enum_variant_translation!(
                    sm.transitions(context, global_context),
                    SwapStateMachines::Maker
                )
            }
            SwapStateMachines::Taker(sm) => {
                sm_enum_variant_translation!(
                    sm.transitions(context, global_context),
                    SwapStateMachines::Taker
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            SwapStateMachines::Maker(sm) => sm.operation_id(),
            SwapStateMachines::Taker(sm) => sm.operation_id(),
        }
    }
}

impl IntoDynInstance for SwapStateMachines {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

/// Client module for the atomic-swap module. NON-primary: it holds no spendable
/// balance of its own (its outputs/inputs are funded by, and reissued through,
/// the mint), so it never overrides `supports_being_primary` (defaulting to
/// `PrimaryModuleSupport::None`).
pub struct SwapClientModule {
    client_ctx: ClientContext<Self>,
    db: Database,
    module_api: DynModuleApi,
    /// This module's root secret, from which all maker/taker keypairs are
    /// deterministically derived (see [`Self::offer_keypair_for_index`]).
    /// Persisting nothing but an index (per offer) in the client DB lets a
    /// restarted client re-derive the keypair to sign a `Claim`/`Reclaim`.
    module_root_secret: DerivableSecret,
}

impl std::fmt::Debug for SwapClientModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwapClientModule").finish_non_exhaustive()
    }
}

/// Data needed by the state machines (mirrors `fedimint-usdt-client`'s
/// `UsdtClientContext`): the federation module API, so the maker SM can poll
/// `get_offer`.
#[derive(Debug, Clone)]
pub struct SwapClientContext {
    pub module_api: DynModuleApi,
}

impl Context for SwapClientContext {
    const KIND: Option<ModuleKind> = None;
}

/// Metadata recorded in the client's operation log for a swap transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwapOperationMeta {
    MakeOffer {
        maker_unit: AmountUnit,
        maker_amount: Amount,
        taker_unit: AmountUnit,
        taker_amount: Amount,
        expiry: u64,
    },
    Fill {
        offer_id: OutPoint,
    },
    Reclaim {
        offer_id: OutPoint,
    },
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for SwapClientModule {
    type Init = SwapClientInit;
    type Common = SwapModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = SwapClientContext;
    type States = SwapStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        SwapClientContext {
            module_api: self.module_api.clone(),
        }
    }

    // Every swap input (`Claim`/`Reclaim`) balances at par against a same-unit
    // mint leg with no module fee; the transaction-balancing framework sums
    // this across all modules, so it must return `Some(ZERO)` for every input.
    fn input_fee(
        &self,
        _amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        Some(Amounts::ZERO)
    }

    // Every swap output (`MakeOffer`/`Fill`) is funded at par by a same-unit
    // mint input with no module fee (matching the server's `process_output`,
    // which reports `fees: Amounts::ZERO`).
    fn output_fee(
        &self,
        _amount: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        Some(Amounts::ZERO)
    }

    // Swap-denominated e-cash lives in the mint instance (the primary module
    // routed to per unit), not in this module's own database, so this module's
    // own balance is zero for every unit.
    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>, _unit: AmountUnit) -> Amount {
        Amount::ZERO
    }
}

impl SwapClientModule {
    /// The deterministic maker/taker keypair for seed-derivation `index`,
    /// derived purely from `module_root_secret` (see [`SWAP_KEY_CHILD`]).
    ///
    /// Deterministic: the same module root secret and `index` always yield the
    /// same keypair, and distinct indices yield distinct keypairs -- so a
    /// crash/restart re-derives the signing keypair for a pending
    /// `Claim`/`Reclaim`. Mirrors `fedimint-usdt-client`'s
    /// `claim_keypair_static`.
    #[must_use]
    fn offer_keypair_static(module_root_secret: &DerivableSecret, index: u64) -> Keypair {
        module_root_secret
            .child_key(SWAP_KEY_CHILD)
            .child_key(ChildId(index))
            .to_secp_key(SECP256K1)
    }

    /// The deterministic maker/taker keypair for seed-derivation `index` under
    /// this module's root secret (see [`Self::offer_keypair_static`]).
    #[must_use]
    fn offer_keypair_for_index(&self, index: u64) -> Keypair {
        Self::offer_keypair_static(&self.module_root_secret, index)
    }

    /// Atomically reads and increments the [`NextKeyIndexKey`] counter,
    /// returning the index to derive a fresh maker/taker keypair at. Mirrors
    /// `fedimint-usdt-client`'s `allocate_deposit` counter-bump pattern: a bare
    /// begin/commit pair would let two concurrent calls hand out colliding
    /// indices, so `autocommit` retries the closure until it commits cleanly.
    async fn allocate_key_index(&self) -> anyhow::Result<u64> {
        self.db
            .autocommit(
                |dbtx, _| {
                    Box::pin(async {
                        let index = dbtx.get_value(&NextKeyIndexKey).await.unwrap_or_default();
                        dbtx.insert_entry(&NextKeyIndexKey, &index.saturating_add(1))
                            .await;
                        Ok::<_, anyhow::Error>(index)
                    })
                },
                None,
            )
            .await
            .map_err(|e| match e {
                AutocommitError::ClosureError { error, .. } => error,
                AutocommitError::CommitFailed { last_error, .. } => {
                    anyhow::anyhow!("Commit to DB failed: {last_error}")
                }
            })
    }

    /// Opens a new offer, escrowing the maker leg. Builds a
    /// `SwapOutput::MakeOffer` funded (at par) by the mint, attaches the maker
    /// state machine (which auto-claims the taker leg once someone fills), and
    /// submits it. Returns the offer id (the `MakeOffer` output's `OutPoint`).
    ///
    /// `expiry` is a wall-clock second computed as `now + ttl_secs`; the
    /// client's clock is approximately the consensus median, and a `ttl_secs`
    /// on the order of hours makes the skew irrelevant.
    pub async fn make_offer(
        &self,
        maker_unit: AmountUnit,
        maker_amount: Amount,
        taker_unit: AmountUnit,
        taker_amount: Amount,
        ttl_secs: u64,
    ) -> anyhow::Result<OutPoint> {
        let index = self.allocate_key_index().await?;
        let maker_keypair = self.offer_keypair_for_index(index);
        let maker_pk = maker_keypair.public_key();
        let expiry = fedimint_core::time::duration_since_epoch()
            .as_secs()
            .saturating_add(ttl_secs);
        let operation_id = OperationId::new_random();

        // The maker SM, generated once the `MakeOffer` output's `OutPoint`
        // (i.e. the offer id) is known: the output is the sole one added here,
        // so it is always at `out_idx` 0 (the mint appends its funding leg
        // separately).
        let sm_gen = move |range: OutPointRange| {
            let offer_id = OutPoint {
                txid: range.txid(),
                out_idx: 0,
            };
            vec![SwapStateMachines::Maker(MakerStateMachine {
                common: MakerSMCommon {
                    operation_id,
                    offer_id,
                    maker_keypair,
                    index,
                    taker_unit,
                    taker_amount,
                },
                state: MakerSMState::AwaitingAccept,
            })]
        };

        let output = ClientOutputBundle::new(
            vec![ClientOutput {
                output: SwapOutput::MakeOffer {
                    maker_unit,
                    maker_amount,
                    taker_unit,
                    taker_amount,
                    expiry,
                    maker_pk,
                },
                amounts: Amounts::new_custom(maker_unit, maker_amount),
            }],
            vec![ClientOutputSM {
                state_machines: Arc::new(sm_gen),
            }],
        );
        let output = self.client_ctx.make_client_outputs(output);
        let tx = TransactionBuilder::new().with_outputs(output);

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                KIND.as_str(),
                move |_range| SwapOperationMeta::MakeOffer {
                    maker_unit,
                    maker_amount,
                    taker_unit,
                    taker_amount,
                    expiry,
                },
                tx,
            )
            .await?;

        let offer_id = OutPoint {
            txid: range.txid(),
            out_idx: 0,
        };

        // `KeyIndexKey(offer_id) -> index` is persisted by the maker SM's own
        // `AwaitingAccept` transition (see `maker_sm::MakerSMState::
        // AwaitingAccept`), NOT here: that transition's dbtx commits
        // atomically with the SM's own state advance, and the SM's initial
        // state was itself persisted atomically with the `MakeOffer`
        // submission above -- so the mapping `reclaim` depends on survives a
        // crash at any point, unlike a separate post-submit write here would.

        // Await consensus acceptance: turns a rejection (e.g. an expiry already
        // in the past, or the same unit on both legs) into an `Err` rather than
        // returning an offer id for a transaction that never landed.
        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(range.txid())
            .await
            .map_err(|err| anyhow::anyhow!("make_offer transaction was rejected: {err}"))?;

        Ok(offer_id)
    }

    /// Fills an open offer, escrowing the taker leg. Reads the offer to learn
    /// both legs, builds a `SwapOutput::Fill` funded (at par) by the mint,
    /// attaches the taker state machine (which auto-claims the maker leg once
    /// the fill is accepted), and submits it.
    pub async fn fill_offer(&self, offer_id: OutPoint) -> anyhow::Result<()> {
        let offer = self
            .module_api
            .get_offer(offer_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("offer {offer_id} does not exist"))?;
        if offer.state != OfferState::Open {
            bail!("offer {offer_id} is not open (already filled or settled)");
        }

        let index = self.allocate_key_index().await?;
        let taker_keypair = self.offer_keypair_for_index(index);
        let taker_pk = taker_keypair.public_key();
        let operation_id = OperationId::new_random();

        let taker_unit = offer.taker_unit;
        let taker_amount = offer.taker_amount;
        let maker_unit = offer.maker_unit;
        let maker_amount = offer.maker_amount;

        // The taker SM, generated once the `Fill` output's `OutPoint` is known.
        // The fill output is the sole one added here, so its txid is the tx's
        // txid; the taker SM awaits that tx's acceptance, then claims the maker
        // leg (whose unit/amount it carries, read from the offer above).
        let sm_gen = move |range: OutPointRange| {
            vec![SwapStateMachines::Taker(TakerStateMachine {
                common: TakerSMCommon {
                    operation_id,
                    offer_id,
                    fill_txid: range.txid(),
                    taker_keypair,
                    maker_unit,
                    maker_amount,
                },
                state: TakerSMState::AwaitingAccept,
            })]
        };

        let output = ClientOutputBundle::new(
            vec![ClientOutput {
                output: SwapOutput::Fill { offer_id, taker_pk },
                amounts: Amounts::new_custom(taker_unit, taker_amount),
            }],
            vec![ClientOutputSM {
                state_machines: Arc::new(sm_gen),
            }],
        );
        let output = self.client_ctx.make_client_outputs(output);
        let tx = TransactionBuilder::new().with_outputs(output);

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                KIND.as_str(),
                move |_range| SwapOperationMeta::Fill { offer_id },
                tx,
            )
            .await?;

        // Unlike the maker's `KeyIndexKey(offer_id)` (which `reclaim` reads),
        // nothing ever reads a `KeyIndexKey` keyed by the taker's fill
        // output -- the taker SM embeds `taker_keypair` directly for its own
        // `Claim` -- so, unlike the maker side, there is no mapping to
        // persist here at all.

        // Await acceptance: surfaces a losing fill (e.g. the offer was filled or
        // expired first) as an `Err` rather than a silent `Ok`.
        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(range.txid())
            .await
            .map_err(|err| anyhow::anyhow!("fill_offer transaction was rejected: {err}"))?;

        Ok(())
    }

    /// Reclaims the maker leg of an offer that is still `Open` (voluntary
    /// cancel, or after expiry). Re-derives the maker keypair from the
    /// persisted index, builds a `SwapInput::Reclaim` (which the mint
    /// reissues as e-cash back to the client), and submits it. Only the
    /// maker of the offer (this client) can call this.
    pub async fn reclaim(&self, offer_id: OutPoint) -> anyhow::Result<()> {
        // Re-derive the maker keypair from the persisted index. Absent means
        // this client is not the maker of `offer_id`.
        let index = {
            let mut dbtx = self.db.begin_transaction_nc().await;
            dbtx.get_value(&KeyIndexKey(offer_id)).await
        }
        .ok_or_else(|| {
            anyhow::anyhow!("no local key for offer {offer_id}; this client did not make it")
        })?;
        let maker_keypair = self.offer_keypair_for_index(index);

        // Read the maker leg to fund the reissuance; a filled/absent offer
        // cannot be reclaimed (the server enforces this too).
        let offer =
            self.module_api.get_offer(offer_id).await?.ok_or_else(|| {
                anyhow::anyhow!("offer {offer_id} does not exist (already settled)")
            })?;
        if offer.state != OfferState::Open {
            bail!("offer {offer_id} is not open; a filled offer's maker leg cannot be reclaimed");
        }

        let input = ClientInput::<SwapInput> {
            input: SwapInput::Reclaim { offer_id },
            keys: vec![maker_keypair],
            amounts: Amounts::new_custom(offer.maker_unit, offer.maker_amount),
        };

        let operation_id = OperationId::new_random();
        let tx = TransactionBuilder::new().with_inputs(
            self.client_ctx
                .make_client_inputs(ClientInputBundle::new_no_sm(vec![input])),
        );

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                KIND.as_str(),
                move |_range| SwapOperationMeta::Reclaim { offer_id },
                tx,
            )
            .await?;

        // Await acceptance: a losing reclaim (the offer was filled first)
        // surfaces as an `Err`.
        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(range.txid())
            .await
            .map_err(|err| anyhow::anyhow!("reclaim transaction was rejected: {err}"))?;

        Ok(())
    }

    /// Lists every currently `Open` offer (thin wrapper over
    /// [`SwapFederationApi::list_open_offers`]).
    pub async fn list_open_offers(&self) -> anyhow::Result<Vec<(OutPoint, Offer)>> {
        Ok(self.module_api.list_open_offers().await?)
    }
}

#[derive(Debug, Clone)]
pub struct SwapClientInit;

impl ModuleInit for SwapClientInit {
    type Common = fedimint_swap_common::SwapCommonInit;

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
                DbKeyPrefix::KeyIndex => {
                    push_db_pair_items!(
                        dbtx,
                        KeyIndexPrefixAll,
                        KeyIndexKey,
                        u64,
                        items,
                        "Swap Key Index"
                    );
                }
                DbKeyPrefix::NextKeyIndex => {
                    push_db_pair_items!(
                        dbtx,
                        NextKeyIndexPrefixAll,
                        NextKeyIndexKey,
                        u64,
                        items,
                        "Swap Next Key Index"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

/// Generates the client module
#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for SwapClientInit {
    type Module = SwapClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(SwapClientModule {
            client_ctx: args.context(),
            db: args.db().clone(),
            module_api: args.module_api().clone(),
            module_root_secret: args.module_root_secret().clone(),
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::module::AmountUnit;
    use fedimint_core::secp256k1::PublicKey;
    use fedimint_core::{Amount, BitcoinHash as _, TransactionId, secp256k1};
    use fedimint_derive_secret::DerivableSecret;
    use fedimint_swap_common::{Offer, OfferState};

    use super::*;

    fn out_point(out_idx: u64) -> OutPoint {
        OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx,
        }
    }

    fn pubkey(seed: u8) -> PublicKey {
        secp256k1::SecretKey::from_slice(&[seed; 32])
            .expect("valid scalar")
            .public_key(secp256k1::SECP256K1)
    }

    fn sample_offer() -> Offer {
        Offer {
            maker_pk: pubkey(0x11),
            maker_unit: AmountUnit::new_custom(1),
            maker_amount: Amount::from_msats(1_000_000),
            taker_unit: AmountUnit::new_custom(2),
            taker_amount: Amount::from_msats(2_000_000),
            expiry: 1_800_000_000,
            state: OfferState::Open,
            maker_claimed: false,
            taker_claimed: false,
        }
    }

    /// The maker/taker key derivation must be deterministic from the seed (so a
    /// restart re-derives the same signing keypair) and distinct per index
    /// (so maker and taker keys never collide). Mirrors
    /// `fedimint-usdt-client`'s `claim_keypair_is_deterministic_from_seed`.
    #[test]
    fn offer_keypair_is_deterministic_from_seed() {
        let secret = DerivableSecret::new_root(b"swap-key-derivation-test-seed", b"salt");

        // Same secret + index => identical key.
        for index in [0u64, 1, 2, 7, 100, u64::MAX] {
            assert_eq!(
                SwapClientModule::offer_keypair_static(&secret, index),
                SwapClientModule::offer_keypair_static(&secret, index),
                "key for index {index} must be reproducible from the seed"
            );
        }

        // Distinct indices => distinct keys.
        let keys: Vec<_> = (0..16u64)
            .map(|index| SwapClientModule::offer_keypair_static(&secret, index).public_key())
            .collect();
        for (i, ki) in keys.iter().enumerate() {
            for (j, kj) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(ki, kj, "indices {i} and {j} must derive distinct keys");
                }
            }
        }

        // A different root secret => a different key at the same index.
        let other = DerivableSecret::new_root(b"a-different-seed", b"salt");
        assert_ne!(
            SwapClientModule::offer_keypair_static(&secret, 0),
            SwapClientModule::offer_keypair_static(&other, 0),
            "a different seed must derive a different key"
        );
    }

    /// The `get_offer` response wire type (`Option<Offer>`) must round-trip
    /// through the JSON encoding the federation API transports it over, for
    /// both the present and absent cases.
    #[test]
    fn get_offer_response_json_round_trips() {
        for resp in [Some(sample_offer()), None] {
            let json = serde_json::to_value(&resp).expect("Option<Offer> serializes");
            let decoded: Option<Offer> =
                serde_json::from_value(json).expect("Option<Offer> round-trips");
            assert_eq!(resp, decoded);
        }
    }

    /// The `list_open_offers` response wire type (`Vec<(OutPoint, Offer)>`)
    /// must round-trip through the JSON encoding the federation API transports
    /// it over.
    #[test]
    fn list_open_offers_response_json_round_trips() {
        let resp: Vec<(OutPoint, Offer)> = vec![
            (out_point(0), sample_offer()),
            (out_point(3), sample_offer()),
        ];
        let json = serde_json::to_value(&resp).expect("Vec<(OutPoint, Offer)> serializes");
        let decoded: Vec<(OutPoint, Offer)> =
            serde_json::from_value(json).expect("Vec<(OutPoint, Offer)> round-trips");
        assert_eq!(resp, decoded);
    }

    /// The `get_offer` request wire type (`OutPoint`) must round-trip through
    /// JSON.
    #[test]
    fn get_offer_request_json_round_trips() {
        let req = out_point(7);
        let json = serde_json::to_value(req).expect("OutPoint serializes");
        let decoded: OutPoint = serde_json::from_value(json).expect("OutPoint round-trips");
        assert_eq!(req, decoded);
    }
}
