#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

use std::collections::BTreeMap;

use async_trait::async_trait;
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, SupportedModuleApiVersions, TransactionItemAmounts,
};
use fedimint_core::{Amount, InPoint, NumPeers, OutPoint, PeerId, push_db_pair_items};
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
pub use fedimint_swap_common as common;
use fedimint_swap_common::config::{
    SwapClientConfig, SwapConfig, SwapConfigConsensus, SwapConfigPrivate,
};
use fedimint_swap_common::{
    MODULE_CONSENSUS_VERSION, Offer, OfferState, Party, SwapCommonInit, SwapConsensusItem,
    SwapInput, SwapInputError, SwapModuleTypes, SwapOutput, SwapOutputError, SwapOutputOutcome,
};
use futures::StreamExt;
use strum::IntoEnumIterator;

use crate::db::{ConsensusTsKey, ConsensusTsPrefix, DbKeyPrefix, OfferKey, OfferPrefix};

pub mod db;

/// Minimum staleness (in seconds) before a guardian re-proposes its
/// wall-clock time in `consensus_proposal`. Throttles the consensus item to
/// roughly once per interval instead of once per session.
const PROPOSE_INTERVAL_SECS: u64 = 60;

/// Generates the module
#[derive(Debug, Clone)]
pub struct SwapInit;

impl ModuleInit for SwapInit {
    type Common = SwapCommonInit;

    /// Dumps all database items for debugging
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
                DbKeyPrefix::Offer => {
                    push_db_pair_items!(dbtx, OfferPrefix, OfferKey, Offer, items, "Swap Offer");
                }
                DbKeyPrefix::ConsensusTs => {
                    push_db_pair_items!(
                        dbtx,
                        ConsensusTsPrefix,
                        ConsensusTsKey,
                        u64,
                        items,
                        "Swap Consensus Timestamp"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

/// Implementation of server module non-consensus functions
#[async_trait]
impl ServerModuleInit for SwapInit {
    type Module = Swap;
    type Params = ();

    /// Returns the version of this module
    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 0)],
        )
    }

    /// Initialize the module
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Swap::new(
            args.cfg().to_typed()?,
            args.our_peer_id(),
            args.num_peers(),
        ))
    }

    /// Generates configs for all peers in a trusted manner for testing
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        _args: &ConfigGenModuleArgs,
        _params: &Self::Params,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        // Generate a config for each peer
        peers
            .iter()
            .map(|&peer| {
                let config = SwapConfig {
                    private: SwapConfigPrivate,
                    consensus: SwapConfigConsensus,
                };
                (peer, config.to_erased())
            })
            .collect()
    }

    /// Generates configs for all peers in an untrusted manner
    async fn distributed_gen(
        &self,
        _peers: &(dyn PeerHandleOps + Send + Sync),
        _args: &ConfigGenModuleArgs,
        _params: &Self::Params,
    ) -> anyhow::Result<ServerModuleConfig> {
        Ok(SwapConfig {
            private: SwapConfigPrivate,
            consensus: SwapConfigConsensus,
        }
        .to_erased())
    }

    /// Converts the consensus config into the client config
    fn get_client_config(
        &self,
        _config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<SwapClientConfig> {
        Ok(SwapClientConfig)
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    /// DB migrations to move from old to newer versions
    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Swap>> {
        BTreeMap::new()
    }
}

/// Swap module
#[derive(Debug)]
pub struct Swap {
    pub cfg: SwapConfig,
    /// This guardian's own id, used to key its row in `ConsensusTsKey` (both
    /// `consensus_proposal`'s throttle read and the row it proposes into).
    our_peer_id: PeerId,
    /// The federation's peer count, used to zero-pad `consensus_timestamp`'s
    /// median so a minority of voters cannot move the clock (see
    /// `consensus_timestamp`'s doc comment).
    num_peers: NumPeers,
}

/// Implementation of consensus for the server module
#[async_trait]
impl ServerModule for Swap {
    /// Define the consensus types
    type Common = SwapModuleTypes;
    type Init = SwapInit;

    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<SwapConsensusItem> {
        let now_secs = fedimint_core::time::duration_since_epoch().as_secs();
        let last = dbtx
            .get_value(&ConsensusTsKey(self.our_peer_id))
            .await
            .unwrap_or(0);
        // Throttle: only propose when our last accepted value is at least
        // PROPOSE_INTERVAL_SECS stale, so we don't emit an item every session.
        if now_secs >= last.saturating_add(PROPOSE_INTERVAL_SECS) {
            vec![SwapConsensusItem {
                unix_secs: now_secs,
            }]
        } else {
            vec![]
        }
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: SwapConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        // WARNING: `process_consensus_item` should return an `Err` for items that do
        // not change any internal consensus state. Failure to do so, will result in an
        // (potentially significantly) increased consensus history size.
        let last = dbtx.get_value(&ConsensusTsKey(peer_id)).await.unwrap_or(0);
        // Monotonic per peer: reject a non-advancing value. This also satisfies
        // the "process_consensus_item must Err on no-ops" history-size rule
        // above. CRITICAL: no wall-clock read here -- this must be a pure
        // function of the item plus prior DB state, so every honest guardian
        // reaches the same result when replaying consensus. No sanity-clamp
        // against "now" either, since that would be non-deterministic; per-peer
        // monotonicity is the only guard, and the median over up to `max_evil`
        // Byzantine peers among `num_peers` stays honest-bounded without one.
        if consensus_item.unix_secs <= last {
            anyhow::bail!(
                "swap: timestamp {} not newer than stored {last} for peer {peer_id}",
                consensus_item.unix_secs
            );
        }
        dbtx.insert_entry(&ConsensusTsKey(peer_id), &consensus_item.unix_secs)
            .await;
        Ok(())
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b SwapInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, SwapInputError> {
        match input {
            SwapInput::Claim { offer_id, party } => {
                let mut offer = dbtx
                    .get_value(&OfferKey(*offer_id))
                    .await
                    .ok_or(SwapInputError::UnknownOffer)?;

                // Only a filled offer has claimable legs; `taker_pk` comes from
                // the `Filled` state so a `Taker` claim demands the taker's key.
                let taker_pk = match &offer.state {
                    OfferState::Filled { taker_pk } => *taker_pk,
                    OfferState::Open => return Err(SwapInputError::OfferNotFilled),
                };

                // Each party withdraws the OTHER party's leg, in that leg's own
                // unit. The `*_claimed` flag is the exactly-once replay guard: a
                // second claim of the same leg errors instead of double-paying.
                let (amounts, pub_key) = match party {
                    Party::Maker => {
                        if offer.maker_claimed {
                            return Err(SwapInputError::LegAlreadyClaimed);
                        }
                        offer.maker_claimed = true;
                        (
                            Amounts::new_custom(offer.taker_unit, offer.taker_amount),
                            offer.maker_pk,
                        )
                    }
                    Party::Taker => {
                        if offer.taker_claimed {
                            return Err(SwapInputError::LegAlreadyClaimed);
                        }
                        offer.taker_claimed = true;
                        (
                            Amounts::new_custom(offer.maker_unit, offer.maker_amount),
                            taker_pk,
                        )
                    }
                };

                // Once both legs are claimed the offer is fully settled and can
                // be garbage-collected; otherwise persist the updated flags.
                if offer.maker_claimed && offer.taker_claimed {
                    dbtx.remove_entry(&OfferKey(*offer_id)).await;
                } else {
                    dbtx.insert_entry(&OfferKey(*offer_id), &offer).await;
                }

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts,
                        fees: Amounts::ZERO,
                    },
                    pub_key,
                })
            }
            SwapInput::Reclaim { offer_id } => {
                let offer = dbtx
                    .get_value(&OfferKey(*offer_id))
                    .await
                    .ok_or(SwapInputError::UnknownOffer)?;

                // Reclaim is only valid while the offer is still Open (covers both
                // voluntary cancel and post-expiry reclaim). A filled offer's
                // maker leg belongs to the taker now, so it cannot be reclaimed.
                if offer.state != OfferState::Open {
                    return Err(SwapInputError::OfferNotOpen);
                }

                dbtx.remove_entry(&OfferKey(*offer_id)).await;

                Ok(InputMeta {
                    amount: TransactionItemAmounts {
                        amounts: Amounts::new_custom(offer.maker_unit, offer.maker_amount),
                        fees: Amounts::ZERO,
                    },
                    pub_key: offer.maker_pk,
                })
            }
            SwapInput::Default { .. } => Err(SwapInputError::UnknownOffer),
        }
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a SwapOutput,
        out_point: OutPoint,
    ) -> Result<TransactionItemAmounts, SwapOutputError> {
        match output {
            SwapOutput::MakeOffer {
                maker_unit,
                maker_amount,
                taker_unit,
                taker_amount,
                expiry,
                maker_pk,
            } => {
                if *maker_amount == Amount::ZERO || *taker_amount == Amount::ZERO {
                    return Err(SwapOutputError::ZeroAmount);
                }
                if maker_unit == taker_unit {
                    return Err(SwapOutputError::SameUnit);
                }
                if *expiry <= consensus_timestamp(dbtx, self.num_peers).await {
                    return Err(SwapOutputError::ExpiryInPast);
                }

                let offer = Offer {
                    maker_pk: *maker_pk,
                    maker_unit: *maker_unit,
                    maker_amount: *maker_amount,
                    taker_unit: *taker_unit,
                    taker_amount: *taker_amount,
                    expiry: *expiry,
                    state: OfferState::Open,
                    maker_claimed: false,
                    taker_claimed: false,
                };
                // The offer id is this output's `OutPoint`.
                dbtx.insert_new_entry(&OfferKey(out_point), &offer).await;

                // The maker leg's e-cash is provided by a mint input in the same
                // tx; balance it here in the maker leg's own unit, at par.
                Ok(TransactionItemAmounts {
                    amounts: Amounts::new_custom(*maker_unit, *maker_amount),
                    fees: Amounts::ZERO,
                })
            }
            SwapOutput::Fill { offer_id, taker_pk } => {
                let mut offer = dbtx
                    .get_value(&OfferKey(*offer_id))
                    .await
                    .ok_or(SwapOutputError::UnknownOffer)?;

                if offer.state != OfferState::Open {
                    return Err(SwapOutputError::OfferAlreadyFilled);
                }
                if consensus_timestamp(dbtx, self.num_peers).await >= offer.expiry {
                    return Err(SwapOutputError::OfferExpired);
                }

                offer.state = OfferState::Filled {
                    taker_pk: *taker_pk,
                };
                dbtx.insert_entry(&OfferKey(*offer_id), &offer).await;

                // The taker leg's e-cash is provided by a mint input in the same
                // tx; balance it here in the taker leg's own unit, at par.
                Ok(TransactionItemAmounts {
                    amounts: Amounts::new_custom(offer.taker_unit, offer.taker_amount),
                    fees: Amounts::ZERO,
                })
            }
            SwapOutput::Default { .. } => Err(SwapOutputError::UnknownOffer),
        }
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<SwapOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        // The module physically holds each unclaimed leg's e-cash and owes it
        // back, so every held leg is a LIABILITY (negative). A swap holds two
        // DIFFERENT units, so the maker leg (maker_unit) and taker leg
        // (taker_unit) are reported in TWO separate passes — one `AuditItem`
        // per leg, each in its own unit — so that no single item ever mixes
        // units. (The core `Audit`/`AuditSummary` API carries only a scalar
        // `milli_sat` per item and sums them into one `net_assets`, so the
        // whole-federation figure collapses units regardless — a core-level
        // limitation shared by every module; see the phase-3 report. Each leg
        // is balanced at par against a same-unit mint leg in its own tx, so
        // the collapsed net remains solvency-consistent.)
        //
        // Maker leg held while: Open (maker deposited it, no taker yet), or
        // Filled and the taker has not yet claimed it.
        audit
            .add_items(dbtx, module_instance_id, &OfferPrefix, |_k, offer| {
                let held = match &offer.state {
                    OfferState::Open => true,
                    OfferState::Filled { .. } => !offer.taker_claimed,
                };
                if held {
                    -i64::try_from(offer.maker_amount.msats).unwrap_or(i64::MAX)
                } else {
                    0
                }
            })
            .await;
        // Taker leg held only once Filled (the taker deposited it) and the
        // maker has not yet claimed it.
        audit
            .add_items(dbtx, module_instance_id, &OfferPrefix, |_k, offer| {
                let held = match &offer.state {
                    OfferState::Open => false,
                    OfferState::Filled { .. } => !offer.maker_claimed,
                };
                if held {
                    -i64::try_from(offer.taker_amount.msats).unwrap_or(i64::MAX)
                } else {
                    0
                }
            })
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        // Phase 5 adds `list_open_offers`/`get_offer`.
        Vec::new()
    }
}

impl Swap {
    /// Create new module instance
    pub fn new(cfg: SwapConfig, our_peer_id: PeerId, num_peers: NumPeers) -> Swap {
        Swap {
            cfg,
            our_peer_id,
            num_peers,
        }
    }
}

/// Median of the latest per-peer proposed timestamps, zero-padded up to
/// `num_peers`; `0` if no peer has proposed yet.
///
/// PURE consensus-DB read — deterministic (no wall-clock, no `our_peer_id`), so
/// it is safe to call inside `process_input`/`process_output`. Phase 4
/// populates the `ConsensusTsKey` table (one row per peer); here we only read
/// it.
///
/// Matches `consensus_block_count`'s exact padding
/// (`modules/fedimint-ln-server/src/lib.rs`): sort ascending and zero-pad up
/// to `num_peers.total()` BEFORE taking the median at index `len / 2`. This
/// clock gates offer expiry (→ reclaim/fill), which moves money, so a
/// minority of voters (e.g. during federation ramp-up, or while a peer is
/// offline) must not be able to move it off the floor -- padding with `0`
/// for peers that haven't voted yet ensures the median only advances once a
/// majority has proposed a value.
async fn consensus_timestamp(dbtx: &mut DatabaseTransaction<'_>, num_peers: NumPeers) -> u64 {
    let peer_count = num_peers.total();
    let mut timestamps = dbtx
        .find_by_prefix(&ConsensusTsPrefix)
        .await
        .map(|(_, ts)| ts)
        .collect::<Vec<u64>>()
        .await;

    assert!(timestamps.len() <= peer_count);
    while timestamps.len() < peer_count {
        timestamps.push(0);
    }

    timestamps.sort_unstable();
    timestamps[peer_count / 2]
}

#[cfg(test)]
mod tests {
    use fedimint_core::db::mem_impl::MemDatabase;
    use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
    use fedimint_core::module::AmountUnit;
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use fedimint_core::secp256k1::PublicKey;
    use fedimint_core::{Amount, BitcoinHash as _, InPoint, OutPoint, TransactionId, secp256k1};
    use fedimint_swap_common::config::{SwapConfig, SwapConfigConsensus, SwapConfigPrivate};
    use fedimint_swap_common::{OfferState, Party, SwapInput, SwapInputError, SwapOutput};

    use super::*;
    use crate::db::ConsensusTsKey;

    // Fixed per-leg fixtures. The two legs are deliberately in DIFFERENT units
    // and DIFFERENT amounts so any accidental unit/leg swap is caught.
    const MAKER_UNIT: AmountUnit = AmountUnit::new_custom(1);
    const TAKER_UNIT: AmountUnit = AmountUnit::new_custom(2);
    const MAKER_AMOUNT: Amount = Amount::from_msats(1_000_000);
    const TAKER_AMOUNT: Amount = Amount::from_msats(3_000_000);
    const EXPIRY: u64 = 1_800_000_000;
    // A consensus clock strictly before `EXPIRY`.
    const NOW: u64 = 1_000_000_000;

    /// `num_peers = 1` matches the single-row seeding (`seed_clock(&[NOW])`,
    /// or a lone `ConsensusTsKey(PeerId::from(0))` insert) that the bulk of
    /// this module's tests use, so `consensus_timestamp`'s zero-padding is a
    /// no-op for them and the pre-Phase-4 median assertions are unaffected.
    fn module() -> Swap {
        module_with(PeerId::from(0), NumPeers::from(1))
    }

    fn module_with(our_peer_id: PeerId, num_peers: NumPeers) -> Swap {
        Swap::new(
            SwapConfig {
                private: SwapConfigPrivate,
                consensus: SwapConfigConsensus,
            },
            our_peer_id,
            num_peers,
        )
    }

    fn new_db() -> Database {
        Database::new(MemDatabase::new(), ModuleDecoderRegistry::default())
    }

    fn pk(seed: u8) -> PublicKey {
        secp256k1::SecretKey::from_slice(&[seed; 32])
            .expect("valid scalar")
            .public_key(secp256k1::SECP256K1)
    }

    fn maker_pk() -> PublicKey {
        pk(0x11)
    }

    fn taker_pk() -> PublicKey {
        pk(0x22)
    }

    fn out_point(out_idx: u64) -> OutPoint {
        OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx,
        }
    }

    fn in_point(in_idx: u64) -> InPoint {
        InPoint {
            txid: TransactionId::all_zeros(),
            in_idx,
        }
    }

    /// Seed the consensus clock. Each `ts` is a distinct peer row; the module's
    /// `consensus_timestamp` returns their median.
    async fn seed_clock(dbtx: &mut DatabaseTransaction<'_>, timestamps: &[u64]) {
        for (i, ts) in timestamps.iter().enumerate() {
            let peer = u16::try_from(i).expect("test seeds few peers");
            dbtx.insert_new_entry(&ConsensusTsKey(PeerId::from(peer)), ts)
                .await;
        }
    }

    fn make_offer() -> SwapOutput {
        SwapOutput::MakeOffer {
            maker_unit: MAKER_UNIT,
            maker_amount: MAKER_AMOUNT,
            taker_unit: TAKER_UNIT,
            taker_amount: TAKER_AMOUNT,
            expiry: EXPIRY,
            maker_pk: maker_pk(),
        }
    }

    fn amounts(unit: AmountUnit, amount: Amount) -> Amounts {
        Amounts::new_custom(unit, amount)
    }

    // ---- consensus_timestamp (median) ---------------------------------------

    #[tokio::test]
    async fn consensus_timestamp_is_zero_when_unseeded() {
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        // num_peers = 1: unseeded pads to a single `0` row, median = 0.
        assert_eq!(
            consensus_timestamp(&mut dbtx.to_ref_nc(), NumPeers::from(1)).await,
            0
        );
    }

    #[tokio::test]
    async fn consensus_timestamp_is_median_of_peer_rows() {
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        // Insert out of order; num_peers = 3 matches the 3 seeded rows, so
        // padding is a no-op. Median of {10, 20, 30} is 20 (index len/2 = 1).
        seed_clock(&mut dbtx.to_ref_nc(), &[30, 10, 20]).await;
        assert_eq!(
            consensus_timestamp(&mut dbtx.to_ref_nc(), NumPeers::from(3)).await,
            20
        );
    }

    #[tokio::test]
    async fn consensus_timestamp_pads_lone_voter_to_the_floor() {
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        // num_peers = 4, only ONE row seeded to a high value `v`. Padded to
        // [v, 0, 0, 0], sorted [0, 0, 0, v], index 4/2 = 2 -> 0. A lone voter
        // cannot move the clock off the floor.
        let v = 1_800_000_000;
        seed_clock(&mut dbtx.to_ref_nc(), &[v]).await;
        assert_eq!(
            consensus_timestamp(&mut dbtx.to_ref_nc(), NumPeers::from(4)).await,
            0
        );
    }

    #[tokio::test]
    async fn consensus_timestamp_reaches_v_once_a_majority_agree() {
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        // Contrast with the lone-voter case above: num_peers = 4, THREE rows
        // seeded to `v`. Padded to [v, v, v, 0], sorted [0, v, v, v], index
        // 4/2 = 2 -> v.
        let v = 1_800_000_000;
        seed_clock(&mut dbtx.to_ref_nc(), &[v, v, v]).await;
        assert_eq!(
            consensus_timestamp(&mut dbtx.to_ref_nc(), NumPeers::from(4)).await,
            v
        );
    }

    // ---- MakeOffer ----------------------------------------------------------

    #[tokio::test]
    async fn make_offer_writes_open_offer_and_returns_maker_leg() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;

        let op = out_point(0);
        let meta = m
            .process_output(&mut dbtx.to_ref_nc(), &make_offer(), op)
            .await
            .expect("valid MakeOffer");

        assert_eq!(meta.amounts, amounts(MAKER_UNIT, MAKER_AMOUNT));
        assert_eq!(meta.fees, Amounts::ZERO);

        let stored = dbtx
            .to_ref_nc()
            .get_value(&OfferKey(op))
            .await
            .expect("offer stored");
        assert_eq!(stored.maker_pk, maker_pk());
        assert_eq!(stored.maker_unit, MAKER_UNIT);
        assert_eq!(stored.maker_amount, MAKER_AMOUNT);
        assert_eq!(stored.taker_unit, TAKER_UNIT);
        assert_eq!(stored.taker_amount, TAKER_AMOUNT);
        assert_eq!(stored.expiry, EXPIRY);
        assert_eq!(stored.state, OfferState::Open);
        assert!(!stored.maker_claimed);
        assert!(!stored.taker_claimed);
    }

    #[tokio::test]
    async fn make_offer_rejects_zero_maker_amount() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;

        let output = SwapOutput::MakeOffer {
            maker_unit: MAKER_UNIT,
            maker_amount: Amount::ZERO,
            taker_unit: TAKER_UNIT,
            taker_amount: TAKER_AMOUNT,
            expiry: EXPIRY,
            maker_pk: maker_pk(),
        };
        assert_eq!(
            m.process_output(&mut dbtx.to_ref_nc(), &output, out_point(0))
                .await,
            Err(SwapOutputError::ZeroAmount)
        );
    }

    #[tokio::test]
    async fn make_offer_rejects_zero_taker_amount() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;

        let output = SwapOutput::MakeOffer {
            maker_unit: MAKER_UNIT,
            maker_amount: MAKER_AMOUNT,
            taker_unit: TAKER_UNIT,
            taker_amount: Amount::ZERO,
            expiry: EXPIRY,
            maker_pk: maker_pk(),
        };
        assert_eq!(
            m.process_output(&mut dbtx.to_ref_nc(), &output, out_point(0))
                .await,
            Err(SwapOutputError::ZeroAmount)
        );
    }

    #[tokio::test]
    async fn make_offer_rejects_same_unit() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;

        let output = SwapOutput::MakeOffer {
            maker_unit: MAKER_UNIT,
            maker_amount: MAKER_AMOUNT,
            taker_unit: MAKER_UNIT,
            taker_amount: TAKER_AMOUNT,
            expiry: EXPIRY,
            maker_pk: maker_pk(),
        };
        assert_eq!(
            m.process_output(&mut dbtx.to_ref_nc(), &output, out_point(0))
                .await,
            Err(SwapOutputError::SameUnit)
        );
    }

    #[tokio::test]
    async fn make_offer_rejects_expiry_at_or_before_clock() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[EXPIRY]).await;

        // expiry == clock is in the past (must be strictly greater).
        assert_eq!(
            m.process_output(&mut dbtx.to_ref_nc(), &make_offer(), out_point(0))
                .await,
            Err(SwapOutputError::ExpiryInPast)
        );
    }

    // ---- Fill ---------------------------------------------------------------

    /// Make an offer at `NOW`, returning its id.
    async fn open_offer(m: &Swap, dbtx: &mut DatabaseTransaction<'_>) -> OutPoint {
        let op = out_point(0);
        m.process_output(&mut dbtx.to_ref_nc(), &make_offer(), op)
            .await
            .expect("valid MakeOffer");
        op
    }

    #[tokio::test]
    async fn fill_flips_open_to_filled_and_returns_taker_leg() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = open_offer(&m, &mut dbtx.to_ref_nc()).await;

        let meta = m
            .process_output(
                &mut dbtx.to_ref_nc(),
                &SwapOutput::Fill {
                    offer_id,
                    taker_pk: taker_pk(),
                },
                out_point(1),
            )
            .await
            .expect("valid Fill");

        assert_eq!(meta.amounts, amounts(TAKER_UNIT, TAKER_AMOUNT));
        assert_eq!(meta.fees, Amounts::ZERO);

        let stored = dbtx
            .to_ref_nc()
            .get_value(&OfferKey(offer_id))
            .await
            .expect("offer stored");
        assert_eq!(
            stored.state,
            OfferState::Filled {
                taker_pk: taker_pk()
            }
        );
    }

    #[tokio::test]
    async fn fill_rejects_unknown_offer() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;

        assert_eq!(
            m.process_output(
                &mut dbtx.to_ref_nc(),
                &SwapOutput::Fill {
                    offer_id: out_point(99),
                    taker_pk: taker_pk(),
                },
                out_point(1),
            )
            .await,
            Err(SwapOutputError::UnknownOffer)
        );
    }

    #[tokio::test]
    async fn fill_rejects_already_filled() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = open_offer(&m, &mut dbtx.to_ref_nc()).await;

        let fill = SwapOutput::Fill {
            offer_id,
            taker_pk: taker_pk(),
        };
        m.process_output(&mut dbtx.to_ref_nc(), &fill, out_point(1))
            .await
            .expect("first Fill");
        assert_eq!(
            m.process_output(&mut dbtx.to_ref_nc(), &fill, out_point(2))
                .await,
            Err(SwapOutputError::OfferAlreadyFilled)
        );
    }

    #[tokio::test]
    async fn fill_rejects_expired_offer() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = open_offer(&m, &mut dbtx.to_ref_nc()).await;

        // Advance the clock to exactly the expiry (clock >= expiry rejects).
        dbtx.to_ref_nc()
            .insert_entry(&ConsensusTsKey(PeerId::from(0)), &EXPIRY)
            .await;

        assert_eq!(
            m.process_output(
                &mut dbtx.to_ref_nc(),
                &SwapOutput::Fill {
                    offer_id,
                    taker_pk: taker_pk(),
                },
                out_point(1),
            )
            .await,
            Err(SwapOutputError::OfferExpired)
        );
    }

    // ---- Claim --------------------------------------------------------------

    /// Make + Fill an offer, returning its id.
    async fn filled_offer(m: &Swap, dbtx: &mut DatabaseTransaction<'_>) -> OutPoint {
        let offer_id = open_offer(m, &mut dbtx.to_ref_nc()).await;
        m.process_output(
            &mut dbtx.to_ref_nc(),
            &SwapOutput::Fill {
                offer_id,
                taker_pk: taker_pk(),
            },
            out_point(1),
        )
        .await
        .expect("valid Fill");
        offer_id
    }

    #[tokio::test]
    async fn claim_maker_pays_taker_leg_to_maker_pk() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = filled_offer(&m, &mut dbtx.to_ref_nc()).await;

        let meta = m
            .process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Claim {
                    offer_id,
                    party: Party::Maker,
                },
                in_point(0),
            )
            .await
            .expect("valid Maker claim");

        // Maker withdraws the TAKER leg, to the maker's key.
        assert_eq!(meta.amount.amounts, amounts(TAKER_UNIT, TAKER_AMOUNT));
        assert_eq!(meta.amount.fees, Amounts::ZERO);
        assert_eq!(meta.pub_key, maker_pk());

        let stored = dbtx
            .to_ref_nc()
            .get_value(&OfferKey(offer_id))
            .await
            .expect("offer still present (taker unclaimed)");
        assert!(stored.maker_claimed);
        assert!(!stored.taker_claimed);
    }

    #[tokio::test]
    async fn claim_taker_pays_maker_leg_to_taker_pk() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = filled_offer(&m, &mut dbtx.to_ref_nc()).await;

        let meta = m
            .process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Claim {
                    offer_id,
                    party: Party::Taker,
                },
                in_point(0),
            )
            .await
            .expect("valid Taker claim");

        // Taker withdraws the MAKER leg, to the taker's key.
        assert_eq!(meta.amount.amounts, amounts(MAKER_UNIT, MAKER_AMOUNT));
        assert_eq!(meta.pub_key, taker_pk());

        let stored = dbtx
            .to_ref_nc()
            .get_value(&OfferKey(offer_id))
            .await
            .expect("offer still present (maker unclaimed)");
        assert!(!stored.maker_claimed);
        assert!(stored.taker_claimed);
    }

    #[tokio::test]
    async fn both_claims_delete_offer() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = filled_offer(&m, &mut dbtx.to_ref_nc()).await;

        m.process_input(
            &mut dbtx.to_ref_nc(),
            &SwapInput::Claim {
                offer_id,
                party: Party::Maker,
            },
            in_point(0),
        )
        .await
        .expect("Maker claim");
        m.process_input(
            &mut dbtx.to_ref_nc(),
            &SwapInput::Claim {
                offer_id,
                party: Party::Taker,
            },
            in_point(1),
        )
        .await
        .expect("Taker claim");

        assert_eq!(dbtx.to_ref_nc().get_value(&OfferKey(offer_id)).await, None);
    }

    #[tokio::test]
    async fn claim_rejects_open_offer() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = open_offer(&m, &mut dbtx.to_ref_nc()).await;

        assert_eq!(
            m.process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Claim {
                    offer_id,
                    party: Party::Maker,
                },
                in_point(0),
            )
            .await,
            Err(SwapInputError::OfferNotFilled)
        );
    }

    #[tokio::test]
    async fn second_claim_of_same_party_rejected() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = filled_offer(&m, &mut dbtx.to_ref_nc()).await;

        let claim = SwapInput::Claim {
            offer_id,
            party: Party::Maker,
        };
        m.process_input(&mut dbtx.to_ref_nc(), &claim, in_point(0))
            .await
            .expect("first Maker claim");
        assert_eq!(
            m.process_input(&mut dbtx.to_ref_nc(), &claim, in_point(1))
                .await,
            Err(SwapInputError::LegAlreadyClaimed)
        );
    }

    #[tokio::test]
    async fn claim_rejects_unknown_offer() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;

        assert_eq!(
            m.process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Claim {
                    offer_id: out_point(99),
                    party: Party::Maker,
                },
                in_point(0),
            )
            .await,
            Err(SwapInputError::UnknownOffer)
        );
    }

    // ---- Reclaim ------------------------------------------------------------

    #[tokio::test]
    async fn reclaim_open_pays_maker_leg_and_deletes_offer() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = open_offer(&m, &mut dbtx.to_ref_nc()).await;

        let meta = m
            .process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Reclaim { offer_id },
                in_point(0),
            )
            .await
            .expect("valid Reclaim");

        assert_eq!(meta.amount.amounts, amounts(MAKER_UNIT, MAKER_AMOUNT));
        assert_eq!(meta.pub_key, maker_pk());
        assert_eq!(dbtx.to_ref_nc().get_value(&OfferKey(offer_id)).await, None);
    }

    #[tokio::test]
    async fn reclaim_rejects_filled_offer() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = filled_offer(&m, &mut dbtx.to_ref_nc()).await;

        assert_eq!(
            m.process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Reclaim { offer_id },
                in_point(0),
            )
            .await,
            Err(SwapInputError::OfferNotOpen)
        );
    }

    #[tokio::test]
    async fn reclaim_rejects_unknown_offer() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;

        assert_eq!(
            m.process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Reclaim {
                    offer_id: out_point(99),
                },
                in_point(0),
            )
            .await,
            Err(SwapInputError::UnknownOffer)
        );
    }

    // ---- Consensus / safety -------------------------------------------------

    #[tokio::test]
    async fn fill_then_reclaim_serializes_reclaim_loses() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = open_offer(&m, &mut dbtx.to_ref_nc()).await;

        // Fill wins the race.
        m.process_output(
            &mut dbtx.to_ref_nc(),
            &SwapOutput::Fill {
                offer_id,
                taker_pk: taker_pk(),
            },
            out_point(1),
        )
        .await
        .expect("Fill wins");

        // Reclaim now sees a Filled offer and loses with no state change.
        assert_eq!(
            m.process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Reclaim { offer_id },
                in_point(0),
            )
            .await,
            Err(SwapInputError::OfferNotOpen)
        );
        // Offer is still there, Filled — untouched by the losing Reclaim.
        let stored = dbtx
            .to_ref_nc()
            .get_value(&OfferKey(offer_id))
            .await
            .expect("offer intact");
        assert_eq!(
            stored.state,
            OfferState::Filled {
                taker_pk: taker_pk()
            }
        );
    }

    #[tokio::test]
    async fn reclaim_then_fill_serializes_fill_loses() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = open_offer(&m, &mut dbtx.to_ref_nc()).await;

        // Reclaim wins the race, deleting the offer.
        m.process_input(
            &mut dbtx.to_ref_nc(),
            &SwapInput::Reclaim { offer_id },
            in_point(0),
        )
        .await
        .expect("Reclaim wins");

        // Fill now sees no offer and loses with no state change.
        assert_eq!(
            m.process_output(
                &mut dbtx.to_ref_nc(),
                &SwapOutput::Fill {
                    offer_id,
                    taker_pk: taker_pk(),
                },
                out_point(1),
            )
            .await,
            Err(SwapOutputError::UnknownOffer)
        );
        assert_eq!(dbtx.to_ref_nc().get_value(&OfferKey(offer_id)).await, None);
    }

    #[tokio::test]
    async fn two_taker_race_second_fill_rejected() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = open_offer(&m, &mut dbtx.to_ref_nc()).await;

        // First taker fills.
        m.process_output(
            &mut dbtx.to_ref_nc(),
            &SwapOutput::Fill {
                offer_id,
                taker_pk: taker_pk(),
            },
            out_point(1),
        )
        .await
        .expect("first taker fills");

        // Second taker (different key) is rejected; the offer keeps the first
        // taker's key.
        assert_eq!(
            m.process_output(
                &mut dbtx.to_ref_nc(),
                &SwapOutput::Fill {
                    offer_id,
                    taker_pk: pk(0x33),
                },
                out_point(2),
            )
            .await,
            Err(SwapOutputError::OfferAlreadyFilled)
        );
        let stored = dbtx
            .to_ref_nc()
            .get_value(&OfferKey(offer_id))
            .await
            .expect("offer intact");
        assert_eq!(
            stored.state,
            OfferState::Filled {
                taker_pk: taker_pk()
            }
        );
    }

    // ---- Per-unit solvency invariant ----------------------------------------

    #[tokio::test]
    async fn per_unit_value_conserved_over_full_lifecycle() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;

        // Outputs consume tx funding into escrow; inputs release it. Track both
        // per unit; value must be conserved per unit (no mint, no burn).
        let mut consumed = Amounts::ZERO;
        let mut released = Amounts::ZERO;

        // MakeOffer consumes the maker leg.
        let offer_id = out_point(0);
        let make = m
            .process_output(&mut dbtx.to_ref_nc(), &make_offer(), offer_id)
            .await
            .expect("MakeOffer");
        consumed = consumed.checked_add(&make.amounts).expect("no overflow");

        // Fill consumes the taker leg.
        let fill = m
            .process_output(
                &mut dbtx.to_ref_nc(),
                &SwapOutput::Fill {
                    offer_id,
                    taker_pk: taker_pk(),
                },
                out_point(1),
            )
            .await
            .expect("Fill");
        consumed = consumed.checked_add(&fill.amounts).expect("no overflow");

        // Maker claim releases the taker leg.
        let maker_claim = m
            .process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Claim {
                    offer_id,
                    party: Party::Maker,
                },
                in_point(0),
            )
            .await
            .expect("Maker claim");
        released = released
            .checked_add(&maker_claim.amount.amounts)
            .expect("no overflow");

        // Taker claim releases the maker leg.
        let taker_claim = m
            .process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Claim {
                    offer_id,
                    party: Party::Taker,
                },
                in_point(1),
            )
            .await
            .expect("Taker claim");
        released = released
            .checked_add(&taker_claim.amount.amounts)
            .expect("no overflow");

        // Value conserved PER UNIT: what escrow consumed equals what it released,
        // unit by unit. `Amounts` equality is per-unit, so this proves no
        // over/under-release and no unit collapse.
        assert_eq!(consumed, released);
        assert_eq!(consumed.get(&MAKER_UNIT).copied(), Some(MAKER_AMOUNT));
        assert_eq!(consumed.get(&TAKER_UNIT).copied(), Some(TAKER_AMOUNT));
    }

    #[tokio::test]
    async fn rejected_reclaim_after_partial_claim_releases_nothing() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = filled_offer(&m, &mut dbtx.to_ref_nc()).await;

        // Maker claims the taker leg.
        let maker_claim = m
            .process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Claim {
                    offer_id,
                    party: Party::Maker,
                },
                in_point(0),
            )
            .await
            .expect("Maker claim");
        let mut released = Amounts::ZERO;
        released = released
            .checked_add(&maker_claim.amount.amounts)
            .expect("no overflow");

        // A Reclaim now (offer is Filled) must be rejected and release NOTHING —
        // the maker leg is still owed to the taker, so over-release is prevented.
        assert_eq!(
            m.process_input(
                &mut dbtx.to_ref_nc(),
                &SwapInput::Reclaim { offer_id },
                in_point(1),
            )
            .await,
            Err(SwapInputError::OfferNotOpen)
        );

        // Only the taker leg has been released so far; the maker leg is intact.
        assert_eq!(released, amounts(TAKER_UNIT, TAKER_AMOUNT));
        let stored = dbtx
            .to_ref_nc()
            .get_value(&OfferKey(offer_id))
            .await
            .expect("offer intact, maker leg still escrowed");
        assert!(stored.maker_claimed);
        assert!(!stored.taker_claimed);
    }

    // ---- Audit (per-unit liability) -----------------------------------------

    /// Net assets summed by the core `Audit` over this module's items.
    async fn audit_net(m: &Swap, dbtx: &mut DatabaseTransaction<'_>) -> i64 {
        let mut audit = Audit::default();
        m.audit(&mut dbtx.to_ref_nc(), &mut audit, 0).await;
        audit.net_assets().expect("no overflow").milli_sat
    }

    #[tokio::test]
    async fn audit_open_offer_is_maker_leg_liability() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        open_offer(&m, &mut dbtx.to_ref_nc()).await;

        // Open: only the maker leg is held (a liability).
        assert_eq!(
            audit_net(&m, &mut dbtx.to_ref_nc()).await,
            -(MAKER_AMOUNT.msats as i64)
        );
    }

    #[tokio::test]
    async fn audit_filled_offer_holds_both_legs() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        filled_offer(&m, &mut dbtx.to_ref_nc()).await;

        // Filled, nothing claimed: both legs held.
        assert_eq!(
            audit_net(&m, &mut dbtx.to_ref_nc()).await,
            -((MAKER_AMOUNT.msats + TAKER_AMOUNT.msats) as i64)
        );
    }

    #[tokio::test]
    async fn audit_drops_claimed_legs() {
        let m = module();
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        seed_clock(&mut dbtx.to_ref_nc(), &[NOW]).await;
        let offer_id = filled_offer(&m, &mut dbtx.to_ref_nc()).await;

        // Maker claims the taker leg → only the maker leg remains held.
        m.process_input(
            &mut dbtx.to_ref_nc(),
            &SwapInput::Claim {
                offer_id,
                party: Party::Maker,
            },
            in_point(0),
        )
        .await
        .expect("Maker claim");
        assert_eq!(
            audit_net(&m, &mut dbtx.to_ref_nc()).await,
            -(MAKER_AMOUNT.msats as i64)
        );

        // Taker claims the maker leg → offer deleted, no liability.
        m.process_input(
            &mut dbtx.to_ref_nc(),
            &SwapInput::Claim {
                offer_id,
                party: Party::Taker,
            },
            in_point(1),
        )
        .await
        .expect("Taker claim");
        assert_eq!(audit_net(&m, &mut dbtx.to_ref_nc()).await, 0);
    }

    // ---- process_consensus_item / consensus_proposal (Phase 4 clock) --------

    #[tokio::test]
    async fn process_consensus_item_stores_value_and_median_reflects_it() {
        let m = module_with(PeerId::from(0), NumPeers::from(3));
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;

        for (peer, ts) in [(0u16, 10u64), (1, 30), (2, 20)] {
            m.process_consensus_item(
                &mut dbtx.to_ref_nc(),
                SwapConsensusItem { unix_secs: ts },
                PeerId::from(peer),
            )
            .await
            .expect("first proposal from this peer is accepted");
        }

        // 3 rows, num_peers = 3: no padding. Median of {10, 20, 30} is 20.
        assert_eq!(
            consensus_timestamp(&mut dbtx.to_ref_nc(), NumPeers::from(3)).await,
            20
        );
    }

    #[tokio::test]
    async fn process_consensus_item_rejects_non_advancing_value() {
        let m = module_with(PeerId::from(0), NumPeers::from(1));
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        let peer = PeerId::from(0);

        m.process_consensus_item(
            &mut dbtx.to_ref_nc(),
            SwapConsensusItem { unix_secs: 100 },
            peer,
        )
        .await
        .expect("first proposal accepted");

        // A value not strictly newer than the stored one is rejected...
        assert!(
            m.process_consensus_item(
                &mut dbtx.to_ref_nc(),
                SwapConsensusItem { unix_secs: 50 },
                peer,
            )
            .await
            .is_err()
        );

        // ...and leaves the stored value unchanged.
        assert_eq!(
            dbtx.to_ref_nc().get_value(&ConsensusTsKey(peer)).await,
            Some(100)
        );
    }

    #[tokio::test]
    async fn process_consensus_item_rejects_exact_repeat_as_a_no_op() {
        let m = module_with(PeerId::from(0), NumPeers::from(1));
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        let peer = PeerId::from(0);
        let item = SwapConsensusItem { unix_secs: 100 };

        m.process_consensus_item(&mut dbtx.to_ref_nc(), item.clone(), peer)
            .await
            .expect("first proposal accepted");

        // Re-applying the exact same value is a no-op and must Err (the
        // history-size rule: process_consensus_item must Err on no-ops).
        assert!(
            m.process_consensus_item(&mut dbtx.to_ref_nc(), item, peer)
                .await
                .is_err()
        );
        assert_eq!(
            dbtx.to_ref_nc().get_value(&ConsensusTsKey(peer)).await,
            Some(100)
        );
    }

    #[tokio::test]
    async fn fill_expires_once_clock_advances_past_expiry_via_consensus_items() {
        let m = module_with(PeerId::from(0), NumPeers::from(1));
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        let peer = PeerId::from(0);

        // Seed the clock through the real population path (not `seed_clock`).
        m.process_consensus_item(
            &mut dbtx.to_ref_nc(),
            SwapConsensusItem { unix_secs: NOW },
            peer,
        )
        .await
        .expect("seed clock");

        let expiry = NOW + 100;
        let offer_id = out_point(0);
        m.process_output(
            &mut dbtx.to_ref_nc(),
            &SwapOutput::MakeOffer {
                maker_unit: MAKER_UNIT,
                maker_amount: MAKER_AMOUNT,
                taker_unit: TAKER_UNIT,
                taker_amount: TAKER_AMOUNT,
                expiry,
                maker_pk: maker_pk(),
            },
            offer_id,
        )
        .await
        .expect("valid MakeOffer just above the clock");

        // Advance the clock past `expiry` via more `process_consensus_item`
        // calls.
        m.process_consensus_item(
            &mut dbtx.to_ref_nc(),
            SwapConsensusItem {
                unix_secs: expiry + 1,
            },
            peer,
        )
        .await
        .expect("advance clock past expiry");

        assert_eq!(
            m.process_output(
                &mut dbtx.to_ref_nc(),
                &SwapOutput::Fill {
                    offer_id,
                    taker_pk: taker_pk(),
                },
                out_point(1),
            )
            .await,
            Err(SwapOutputError::OfferExpired)
        );
    }

    #[tokio::test]
    async fn fill_succeeds_while_clock_still_below_expiry_via_consensus_items() {
        let m = module_with(PeerId::from(0), NumPeers::from(1));
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;
        let peer = PeerId::from(0);

        m.process_consensus_item(
            &mut dbtx.to_ref_nc(),
            SwapConsensusItem { unix_secs: NOW },
            peer,
        )
        .await
        .expect("seed clock");

        let expiry = NOW + 100;
        let offer_id = out_point(0);
        m.process_output(
            &mut dbtx.to_ref_nc(),
            &SwapOutput::MakeOffer {
                maker_unit: MAKER_UNIT,
                maker_amount: MAKER_AMOUNT,
                taker_unit: TAKER_UNIT,
                taker_amount: TAKER_AMOUNT,
                expiry,
                maker_pk: maker_pk(),
            },
            offer_id,
        )
        .await
        .expect("valid MakeOffer just above the clock");

        // Advance the clock, but keep it strictly below `expiry`.
        m.process_consensus_item(
            &mut dbtx.to_ref_nc(),
            SwapConsensusItem {
                unix_secs: expiry - 1,
            },
            peer,
        )
        .await
        .expect("advance clock, still below expiry");

        let meta = m
            .process_output(
                &mut dbtx.to_ref_nc(),
                &SwapOutput::Fill {
                    offer_id,
                    taker_pk: taker_pk(),
                },
                out_point(1),
            )
            .await
            .expect("Fill succeeds: clock still below expiry");
        assert_eq!(meta.amounts, amounts(TAKER_UNIT, TAKER_AMOUNT));
    }

    #[tokio::test]
    async fn consensus_proposal_is_empty_when_last_value_is_far_future() {
        let m = module_with(PeerId::from(0), NumPeers::from(1));
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;

        dbtx.to_ref_nc()
            .insert_new_entry(&ConsensusTsKey(PeerId::from(0)), &u64::MAX)
            .await;

        assert_eq!(
            m.consensus_proposal(&mut dbtx.to_ref_nc()).await,
            Vec::new()
        );
    }

    #[tokio::test]
    async fn consensus_proposal_returns_item_when_stale_or_absent() {
        let m = module_with(PeerId::from(0), NumPeers::from(1));
        let db = new_db();
        let mut dbtx = db.begin_transaction().await;

        // No `ConsensusTsKey(our_peer_id)` row: defaults to 0, which is stale.
        let items = m.consensus_proposal(&mut dbtx.to_ref_nc()).await;
        assert_eq!(items.len(), 1);
        assert!(items[0].unix_secs > 0);
    }
}
