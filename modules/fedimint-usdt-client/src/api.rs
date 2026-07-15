use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, secp256k1};
use fedimint_usdt_common::endpoint_constants::GROUP_PUBLIC_KEY_ENDPOINT;

#[apply(async_trait_maybe_send!)]
pub trait UsdtFederationApi {
    /// Fetches the federation's aggregate (group) threshold-ECDSA public
    /// key, proving that DKG-produced config has been loaded and is
    /// queryable.
    async fn group_public_key(&self) -> FederationResult<secp256k1::PublicKey>;
}

#[apply(async_trait_maybe_send!)]
impl<T: ?Sized> UsdtFederationApi for T
where
    T: IModuleFederationApi + MaybeSend + MaybeSync + 'static,
{
    async fn group_public_key(&self) -> FederationResult<secp256k1::PublicKey> {
        self.request_current_consensus(
            GROUP_PUBLIC_KEY_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
    }
}
