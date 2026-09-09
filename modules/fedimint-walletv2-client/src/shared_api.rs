use std::num::NonZeroUsize;
use std::sync::Arc;

use fedimint_api_client::api::{DynModuleApi, FederationResult};
use fedimint_api_client::shared_cache::{SharedApiScope, SharedCache};
use fedimint_walletv2_common::OutputInfo;

use crate::api::WalletFederationApi;

/// Shared, consensus-aggregated deposit snapshots for one federation module.
///
/// Pass the same `Arc` through `WalletClientInit::shared_api` for each account.
/// Accounts retain their own scan cursors and claim logic. Snapshots (including
/// empty ones) expire because outputs can be added and their spent flags
/// change.
#[derive(Debug)]
pub struct WalletV2SharedApi {
    pub(crate) scope: SharedApiScope,
    outputs: SharedCache<(u64, u64), Vec<OutputInfo>>,
}

impl Default for WalletV2SharedApi {
    fn default() -> Self {
        Self {
            scope: SharedApiScope::default(),
            outputs: SharedCache::new(
                NonZeroUsize::new(32).expect("non-zero capacity"),
                Some(fedimint_walletv2_common::sleep_duration()),
            ),
        }
    }
}

impl WalletV2SharedApi {
    pub(crate) async fn output_info_slice(
        &self,
        api: &DynModuleApi,
        start: u64,
        end: u64,
    ) -> FederationResult<Arc<Vec<OutputInfo>>> {
        self.outputs
            .get_or_try_init((start, end), || api.output_info_slice(start, end))
            .await
    }
}
