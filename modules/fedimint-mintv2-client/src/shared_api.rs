use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use bitcoin_hashes::sha256;
use fedimint_api_client::api::DynModuleApi;
use fedimint_api_client::shared_cache::{SharedApiScope, SharedCache};
use fedimint_core::PeerId;
use fedimint_core::encoding::Encodable;
use fedimint_mintv2_common::RecoveryItem;
use rand::seq::IteratorRandom;
use rand::thread_rng;

use crate::api::MintV2ModuleApi;

/// Shared, hash-verified recovery history for one federation module.
///
/// Pass the same `Arc` through `MintClientInit::shared_api` for each account.
/// Only public recovery items are shared; note reconstruction stays
/// account-local. Recovery counts are deliberately fetched fresh when starting
/// a recovery.
#[derive(Debug)]
pub struct MintV2SharedApi {
    pub(crate) scope: SharedApiScope,
    slices: SharedCache<(u64, u64), Vec<RecoveryItem>>,
    peers: OnceLock<PeerSelector>,
}

impl Default for MintV2SharedApi {
    fn default() -> Self {
        Self {
            scope: SharedApiScope::default(),
            slices: SharedCache::new(NonZeroUsize::new(32).expect("non-zero capacity"), None),
            peers: OnceLock::new(),
        }
    }
}

impl MintV2SharedApi {
    pub(crate) async fn verified_recovery_slice(
        &self,
        api: &DynModuleApi,
        start: u64,
        end: u64,
    ) -> Arc<Vec<RecoveryItem>> {
        self.slices
            .get_or_try_init((start, end), || async {
                let hash = api.fetch_recovery_slice_hash(start, end).await;
                let peers = self
                    .peers
                    .get_or_init(|| PeerSelector::new(api.all_peers().clone()));
                Ok::<_, Infallible>(download_slice_with_hash(api, peers, start, end, hash).await)
            })
            .await
            .expect("verified recovery download retries indefinitely")
    }
}

#[derive(Debug, Clone)]
struct PeerSelector {
    latency: Arc<RwLock<BTreeMap<PeerId, Duration>>>,
}

impl PeerSelector {
    fn new(peers: BTreeSet<PeerId>) -> Self {
        let latency = peers
            .into_iter()
            .map(|peer| (peer, Duration::ZERO))
            .collect();

        Self {
            latency: Arc::new(RwLock::new(latency)),
        }
    }

    /// Pick 2 peers at random, return the one with lower latency
    fn choose_peer(&self) -> PeerId {
        let latency = self.latency.read().expect("peer selector lock poisoned");

        let peer_a = latency
            .iter()
            .choose(&mut thread_rng())
            .expect("at least one honest peer remains");
        let peer_b = latency
            .iter()
            .choose(&mut thread_rng())
            .expect("at least one honest peer remains");

        if peer_a.1 <= peer_b.1 {
            *peer_a.0
        } else {
            *peer_b.0
        }
    }

    // Update with exponential moving average (α = 0.1)
    fn report(&self, peer: PeerId, duration: Duration) {
        self.latency
            .write()
            .expect("peer selector lock poisoned")
            .entry(peer)
            .and_modify(|latency| *latency = *latency * 9 / 10 + duration * 1 / 10)
            .or_insert(duration);
    }

    fn remove(&self, peer: PeerId) {
        self.latency
            .write()
            .expect("peer selector lock poisoned")
            .remove(&peer);
    }
}

/// Download a slice with hash verification and peer selection
async fn download_slice_with_hash(
    module_api: &DynModuleApi,
    peer_selector: &PeerSelector,
    start: u64,
    end: u64,
    expected_hash: sha256::Hash,
) -> Vec<RecoveryItem> {
    const TIMEOUT: Duration = Duration::from_secs(30);

    loop {
        let peer = peer_selector.choose_peer();
        let start_time = fedimint_core::time::now();

        if let Ok(data) = module_api
            .fetch_recovery_slice(peer, TIMEOUT, start, end)
            .await
        {
            let elapsed = fedimint_core::time::now()
                .duration_since(start_time)
                .unwrap_or_default();

            peer_selector.report(peer, elapsed);

            if data.consensus_hash::<sha256::Hash>() == expected_hash {
                return data;
            }

            peer_selector.remove(peer);
        } else {
            peer_selector.report(peer, TIMEOUT);
        }
    }
}
