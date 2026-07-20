use fedimint_api_client::api::{
    FederationApiExt, FederationError, FederationResult, IModuleFederationApi,
};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{PeerId, apply, async_trait_maybe_send, secp256k1};
use fedimint_usdt_common::endpoint_constants::{
    CHECK_DEPOSIT_ENDPOINT, DEBUG_START_SIGNING_ENDPOINT, DEPOSIT_STATUS_ENDPOINT,
    GROUP_PUBLIC_KEY_ENDPOINT, SIGNING_SESSION_STATUS_ENDPOINT,
};
use fedimint_usdt_common::{
    CheckDepositRequest, CheckDepositResponse, DepositStatusRequest, DepositStatusResponse,
    SigningSessionId,
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

    /// Test-only (Phase 6a acceptance): asks `peer` to queue `digest` into
    /// its `pending_signing_starts`, triggering a `StartSigning` consensus
    /// item that starts the session on every guardian. See
    /// `DEBUG_START_SIGNING_ENDPOINT`'s doc comment for why only one peer
    /// needs to be called.
    async fn debug_start_signing(&self, peer: PeerId, digest: [u8; 32]) -> FederationResult<()>;

    /// Queries `peer`'s consensus view of a signing session's outcome:
    /// `Some(compact signature)` once the federation has agreed on an
    /// `MpcSignature` for the session, `None` while still in progress. Any
    /// guardian can answer authoritatively (see
    /// `SIGNING_SESSION_STATUS_ENDPOINT`'s doc comment); this method is kept
    /// per-peer for callers that want to target a specific guardian.
    async fn signing_session_status(
        &self,
        peer: PeerId,
        session_id: SigningSessionId,
    ) -> FederationResult<Option<Vec<u8>>>;
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

    async fn debug_start_signing(&self, peer: PeerId, digest: [u8; 32]) -> FederationResult<()> {
        self.request_single_peer(
            DEBUG_START_SIGNING_ENDPOINT.to_string(),
            ApiRequestErased::new(digest),
            peer,
        )
        .await
        .map_err(|e| FederationError::new_one_peer(peer, DEBUG_START_SIGNING_ENDPOINT, digest, e))
    }

    async fn signing_session_status(
        &self,
        peer: PeerId,
        session_id: SigningSessionId,
    ) -> FederationResult<Option<Vec<u8>>> {
        self.request_single_peer(
            SIGNING_SESSION_STATUS_ENDPOINT.to_string(),
            ApiRequestErased::new(session_id),
            peer,
        )
        .await
        .map_err(|e| {
            FederationError::new_one_peer(peer, SIGNING_SESSION_STATUS_ENDPOINT, session_id, e)
        })
    }
}
