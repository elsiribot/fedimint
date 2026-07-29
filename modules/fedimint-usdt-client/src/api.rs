use fedimint_api_client::api::{
    FederationApiExt, FederationError, FederationResult, IModuleFederationApi,
};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::{OutPoint, PeerId, apply, async_trait_maybe_send, secp256k1};
use fedimint_usdt_common::endpoint_constants::{
    DEPOSIT_FEE_QUOTE_ENDPOINT, DEPOSIT_STATUS_ENDPOINT, GROUP_PUBLIC_KEY_ENDPOINT,
    LATEST_ANCHORED_BLOCK_ENDPOINT, POOL_STATE_ENDPOINT, REFUND_STATUS_ENDPOINT,
    USDT_STATUS_ENDPOINT, USEROP_STATUS_ENDPOINT, WITHDRAW_FEE_QUOTE_ENDPOINT,
    WITHDRAWAL_STATUS_ENDPOINT,
};
use fedimint_usdt_common::{
    AnchoredBlockResponse, DepositFeeQuoteRequest, DepositFeeQuoteResponse, DepositStatusRequest,
    DepositStatusResponse, PoolStateResponse, RefundStatusRequest, RefundStatusResponse,
    StatusResponse, UsdtAmount, UserOpStatusRequest, UserOpStatusResponse, WithdrawFeeQuoteRequest,
    WithdrawFeeQuoteResponse, WithdrawalStatusRequest, WithdrawalStatusResponse,
};

#[apply(async_trait_maybe_send!)]
pub trait UsdtFederationApi {
    /// Fetches the federation's aggregate (group) threshold-ECDSA public
    /// key, proving that DKG-produced config has been loaded and is
    /// queryable.
    async fn group_public_key(&self) -> FederationResult<secp256k1::PublicKey>;

    /// Reports the credited/claimed/claimable state of `claim_pk`'s deposit
    /// account.
    async fn deposit_status(
        &self,
        claim_pk: secp256k1::PublicKey,
    ) -> FederationResult<DepositStatusResponse>;

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

    /// Reports the live refund record of a terminally-failed withdrawal
    /// (security finding 09): `(amount, reason)` for the reissued e-cash a
    /// `UsdtInput::RefundV0` can claim, or `None` if none exists (never
    /// failed, or already claimed). Threshold-agreement
    /// (`request_current_consensus`, mirroring [`Self::withdrawal_status`]).
    async fn refund_status(&self, out_point: OutPoint) -> FederationResult<RefundStatusResponse>;

    /// Reports the module's consensus-agreed readiness state (Part C):
    /// `AwaitingInfra`/`Ready`/`Degraded`, plus the per-condition tally.
    /// Threshold-agreement (`request_current_consensus`, mirroring
    /// [`Self::withdraw_fee_quote`]): derived entirely from the
    /// threshold-aggregated `BootstrapObservation` votes in consensus DB, so
    /// any guardian answers identically.
    async fn status(&self) -> FederationResult<StatusResponse>;

    /// Reports the newest confirmation-depth block height currently anchored
    /// in the federation's consensus block-hash ring, plus the ring's window
    /// length (deposit-by-proof, Task 7). A client picks an in-window,
    /// already-confirmed block to target its `eth_getProof` at (see
    /// [`crate::UsdtClientModule::submit_deposit_proof`]).
    /// Threshold-agreement (`request_current_consensus`): read directly from
    /// consensus DB, so any guardian answers identically.
    async fn latest_anchored_block(&self) -> FederationResult<AnchoredBlockResponse>;
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

    async fn refund_status(&self, out_point: OutPoint) -> FederationResult<RefundStatusResponse> {
        self.request_current_consensus(
            REFUND_STATUS_ENDPOINT.to_string(),
            ApiRequestErased::new(RefundStatusRequest { out_point }),
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

    async fn latest_anchored_block(&self) -> FederationResult<AnchoredBlockResponse> {
        self.request_current_consensus(
            LATEST_ANCHORED_BLOCK_ENDPOINT.to_string(),
            ApiRequestErased::default(),
        )
        .await
    }
}
