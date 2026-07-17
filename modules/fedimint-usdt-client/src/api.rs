use fedimint_api_client::api::{FederationApiExt, FederationResult, IModuleFederationApi};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{apply, async_trait_maybe_send, secp256k1};
use fedimint_usdt_common::endpoint_constants::{
    CHECK_DEPOSIT_ENDPOINT, DEPOSIT_STATUS_ENDPOINT, GROUP_PUBLIC_KEY_ENDPOINT,
};
use fedimint_usdt_common::{
    CheckDepositRequest, CheckDepositResponse, DepositStatusRequest, DepositStatusResponse,
};

#[apply(async_trait_maybe_send!)]
pub trait UsdtFederationApi {
    /// Fetches the federation's aggregate (group) threshold-ECDSA public
    /// key, proving that DKG-produced config has been loaded and is
    /// queryable.
    async fn group_public_key(&self) -> FederationResult<secp256k1::PublicKey>;

    /// Enqueues this guardian's local deposit-checker task to start watching
    /// `claim_pk`'s deposit address, returning that derived address.
    async fn check_deposit(
        &self,
        claim_pk: secp256k1::PublicKey,
    ) -> FederationResult<CheckDepositResponse>;

    /// Reports the credited/claimed/claimable state of `claim_pk`'s deposit
    /// account.
    async fn deposit_status(
        &self,
        claim_pk: secp256k1::PublicKey,
    ) -> FederationResult<DepositStatusResponse>;
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

    async fn check_deposit(
        &self,
        claim_pk: secp256k1::PublicKey,
    ) -> FederationResult<CheckDepositResponse> {
        self.request_current_consensus(
            CHECK_DEPOSIT_ENDPOINT.to_string(),
            ApiRequestErased::new(CheckDepositRequest { claim_pk }),
        )
        .await
    }

    async fn deposit_status(
        &self,
        claim_pk: secp256k1::PublicKey,
    ) -> FederationResult<DepositStatusResponse> {
        self.request_current_consensus(
            DEPOSIT_STATUS_ENDPOINT.to_string(),
            ApiRequestErased::new(DepositStatusRequest { claim_pk }),
        )
        .await
    }
}
