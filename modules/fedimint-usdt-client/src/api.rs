use fedimint_api_client::api::{
    FederationApiExt, FederationError, FederationResult, IModuleFederationApi,
};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{OutPoint, PeerId, apply, async_trait_maybe_send, secp256k1};
use fedimint_usdt_common::endpoint_constants::{
    CHECK_DEPOSIT_ENDPOINT, DEBUG_START_SIGNING_ENDPOINT, DEBUG_SUPPRESS_ATTEMPT0_ROUND_ENDPOINT,
    DEPOSIT_FEE_QUOTE_ENDPOINT, DEPOSIT_STATUS_ENDPOINT, GROUP_PUBLIC_KEY_ENDPOINT,
    POOL_STATE_ENDPOINT, SIGNING_SESSION_STATUS_ENDPOINT, USDT_STATUS_ENDPOINT,
    USEROP_STATUS_ENDPOINT, WITHDRAW_FEE_QUOTE_ENDPOINT, WITHDRAWAL_STATUS_ENDPOINT,
};
use fedimint_usdt_common::{
    CheckDepositRequest, CheckDepositResponse, DepositFeeQuoteRequest, DepositFeeQuoteResponse,
    DepositStatusRequest, DepositStatusResponse, PoolStateResponse, SigningSessionId,
    StatusResponse, UsdtAmount, UserOpStatusRequest, UserOpStatusResponse, WithdrawFeeQuoteRequest,
    WithdrawFeeQuoteResponse, WithdrawalStatusRequest, WithdrawalStatusResponse,
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

    /// Test-only (Phase 6b Task 4 degraded-federation acceptance harness):
    /// toggles `peer`'s LOCAL suppression of `MpcRound` proposals for
    /// attempt-0 signing sessions. See
    /// `DEBUG_SUPPRESS_ATTEMPT0_ROUND_ENDPOINT`'s doc comment.
    async fn debug_suppress_attempt0_round(
        &self,
        peer: PeerId,
        suppress: bool,
    ) -> FederationResult<()>;

    /// Reports `peer`'s consensus view of the pool `SimpleAccount`'s
    /// derived address and swept-in USDT balance (Phase 7, Task 5). Any
    /// guardian answers identically (read from consensus DB).
    async fn pool_state(&self, peer: PeerId) -> FederationResult<PoolStateResponse>;

    /// Reports `peer`'s consensus view of a `UserOp`'s lifecycle stage
    /// (Phase 7, Task 5). Any guardian answers identically (read from
    /// consensus DB).
    async fn userop_status(
        &self,
        peer: PeerId,
        op_hash: [u8; 32],
    ) -> FederationResult<UserOpStatusResponse>;

    /// Reports the federation's current withdrawal fee quote for `amount`
    /// (Phase 8, Task 1). Threshold-agreement (`request_current_consensus`,
    /// mirroring `deposit_status`): the quote is derived entirely from the
    /// consensus-agreed `FeeVote` median, so any guardian answers
    /// identically.
    async fn withdraw_fee_quote(
        &self,
        amount: UsdtAmount,
    ) -> FederationResult<WithdrawFeeQuoteResponse>;

    /// Reports the federation's current deposit fee quote, mirroring
    /// [`Self::withdraw_fee_quote`]. Threshold-agreement
    /// (`request_current_consensus`): the quote is derived entirely from
    /// the consensus-agreed `FeeVote` median, so any guardian answers
    /// identically.
    async fn deposit_fee_quote(&self) -> FederationResult<DepositFeeQuoteResponse>;

    /// Reports the consensus-agreed lifecycle stage of a queued withdrawal,
    /// identified by the `OutPoint` of the `UsdtOutput::V0` that enqueued it
    /// (Phase 8, Task 3). Threshold-agreement (`request_current_consensus`,
    /// mirroring [`Self::deposit_status`]/[`Self::withdraw_fee_quote`]): read
    /// directly from consensus DB, so any guardian answers identically.
    async fn withdrawal_status(
        &self,
        out_point: OutPoint,
    ) -> FederationResult<WithdrawalStatusResponse>;

    /// Reports the module's consensus-agreed readiness state (Part C):
    /// `AwaitingInfra`/`Ready`/`Degraded`, plus the per-condition tally.
    /// Threshold-agreement (`request_current_consensus`, mirroring
    /// [`Self::withdraw_fee_quote`]): derived entirely from the
    /// threshold-aggregated `BootstrapObservation` votes in consensus DB, so
    /// any guardian answers identically.
    async fn status(&self) -> FederationResult<StatusResponse>;
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

    async fn debug_suppress_attempt0_round(
        &self,
        peer: PeerId,
        suppress: bool,
    ) -> FederationResult<()> {
        self.request_single_peer(
            DEBUG_SUPPRESS_ATTEMPT0_ROUND_ENDPOINT.to_string(),
            ApiRequestErased::new(suppress),
            peer,
        )
        .await
        .map_err(|e| {
            FederationError::new_one_peer(peer, DEBUG_SUPPRESS_ATTEMPT0_ROUND_ENDPOINT, suppress, e)
        })
    }

    async fn pool_state(&self, peer: PeerId) -> FederationResult<PoolStateResponse> {
        self.request_single_peer(
            POOL_STATE_ENDPOINT.to_string(),
            ApiRequestErased::default(),
            peer,
        )
        .await
        .map_err(|e| FederationError::new_one_peer(peer, POOL_STATE_ENDPOINT, (), e))
    }

    async fn userop_status(
        &self,
        peer: PeerId,
        op_hash: [u8; 32],
    ) -> FederationResult<UserOpStatusResponse> {
        self.request_single_peer(
            USEROP_STATUS_ENDPOINT.to_string(),
            ApiRequestErased::new(UserOpStatusRequest { op_hash }),
            peer,
        )
        .await
        .map_err(|e| FederationError::new_one_peer(peer, USEROP_STATUS_ENDPOINT, op_hash, e))
    }

    async fn withdraw_fee_quote(
        &self,
        amount: UsdtAmount,
    ) -> FederationResult<WithdrawFeeQuoteResponse> {
        self.request_current_consensus(
            WITHDRAW_FEE_QUOTE_ENDPOINT.to_string(),
            ApiRequestErased::new(WithdrawFeeQuoteRequest { amount }),
        )
        .await
    }

    async fn deposit_fee_quote(&self) -> FederationResult<DepositFeeQuoteResponse> {
        self.request_current_consensus(
            DEPOSIT_FEE_QUOTE_ENDPOINT.to_string(),
            ApiRequestErased::new(DepositFeeQuoteRequest),
        )
        .await
    }

    async fn withdrawal_status(
        &self,
        out_point: OutPoint,
    ) -> FederationResult<WithdrawalStatusResponse> {
        self.request_current_consensus(
            WITHDRAWAL_STATUS_ENDPOINT.to_string(),
            ApiRequestErased::new(WithdrawalStatusRequest { out_point }),
        )
        .await
    }

    async fn status(&self) -> FederationResult<StatusResponse> {
        self.request_current_consensus(
            USDT_STATUS_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
    }
}
