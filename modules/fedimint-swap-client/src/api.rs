use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{OutPoint, apply, async_trait_maybe_send};
use fedimint_swap_common::Offer;
use fedimint_swap_common::endpoint_constants::{GET_OFFER_ENDPOINT, LIST_OPEN_OFFERS_ENDPOINT};

/// Client-side extension trait for the swap module's read endpoints (mirrors
/// `fedimint-usdt-client`'s `UsdtFederationApi`). Both reads are pure DB scans
/// on the server, so `request_current_consensus` (threshold-agreement) is safe:
/// every guardian answers identically.
#[apply(async_trait_maybe_send!)]
pub trait SwapFederationApi {
    /// Lists every currently `Open` offer, each paired with its offer id (the
    /// `MakeOffer` output's `OutPoint`).
    async fn list_open_offers(&self) -> FederationResult<Vec<(OutPoint, Offer)>>;

    /// Fetches a single offer's full record by its offer id, or `None` if no
    /// such offer exists (never made, reclaimed, or fully settled).
    async fn get_offer(&self, offer_id: OutPoint) -> FederationResult<Option<Offer>>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> SwapFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn list_open_offers(&self) -> FederationResult<Vec<(OutPoint, Offer)>> {
        self.request_current_consensus(
            LIST_OPEN_OFFERS_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
    }

    async fn get_offer(&self, offer_id: OutPoint) -> FederationResult<Option<Offer>> {
        self.request_current_consensus(
            GET_OFFER_ENDPOINT.to_string(),
            ApiRequestErased::new(offer_id),
        )
        .await
    }
}
