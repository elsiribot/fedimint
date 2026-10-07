//! Lightning backend that routes LNv2 payments through a bark Ark wallet.
//!
//! The gateway talks to `barkd` over its REST API. Lightning is provided by
//! the Ark server the wallet is connected to: invoices are hold invoices on
//! the Ark server's node and outgoing payments are paid by the Ark server.
//! Receiving requires a barkd that supports hold receives for an externally
//! chosen payment hash.
//!
//! Since the Ark server's node is shared by all of its users, the gateway
//! advertises a synthetic node id instead of the server's, and direct swaps
//! are recognised by payment hash (see
//! [`ILnRpcClient::detects_direct_swaps_by_payment_hash`]).

mod rest;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::sha256;
use fedimint_core::Amount;
use fedimint_core::runtime::sleep;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::{FmtCompact as _, SafeUrl};
use fedimint_gateway_common::{
    CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, ConnectPeerRequest,
    GetInvoiceRequest, GetInvoiceResponse, ListTransactionsResponse, OpenChannelRequest,
    SendOnchainRequest, SetChannelFeesRequest,
};
use fedimint_ln_common::contracts::Preimage;
use fedimint_logging::LOG_LIGHTNING;
use lightning_invoice::Bolt11Invoice;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, warn};

use self::rest::{
    BarkRestClient, BarkRestError, HoldInvoiceRequest, LightningReceiveInfo, PayRequest,
    SEND_STATE_FAILED, SEND_STATE_PAID, SEND_STATE_UNKNOWN,
};
use crate::{
    CreateInvoiceRequest, CreateInvoiceResponse, GetBalancesResponse, GetLnOnchainAddressResponse,
    GetNodeInfoResponse, GetRouteHintsResponse, ILnRpcClient, InterceptPaymentRequest,
    InterceptPaymentResponse, InvoiceDescription, LightningRpcError, ListChannelsResponse,
    NO_INCOMING_CIRCUIT, OpenChannelResponse, PayInvoiceResponse, PaymentAction, RouteHtlcStream,
    SendOnchainResponse,
};

/// How often barkd is polled for hold receives awaiting their preimage.
const RECEIVE_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How often barkd is polled for the outcome of an outgoing payment.
const SEND_POLL_INTERVAL: Duration = Duration::from_secs(1);

const BARK_ALIAS: &str = "bark";

#[derive(Debug, Clone)]
pub struct GatewayBarkClient {
    rest: BarkRestClient,
    /// Synthetic node id advertised to clients, see the module docs.
    node_id: PublicKey,
}

impl GatewayBarkClient {
    pub fn new(bark_url: SafeUrl, bark_token: String, node_id: PublicKey) -> Self {
        Self {
            rest: BarkRestClient::new(bark_url, bark_token),
            node_id,
        }
    }

    /// Polls barkd for hold receives awaiting their preimage and forwards each
    /// one to the gateway once per watcher lifetime. A restarted watcher
    /// forwards pending receives again, which the gateway handles
    /// idempotently.
    async fn watch_hold_receives(
        rest: BarkRestClient,
        sender: mpsc::Sender<InterceptPaymentRequest>,
    ) {
        let mut forwarded = BTreeSet::new();

        loop {
            match rest.pending_receives().await {
                Ok(receives) => {
                    let awaiting = receives
                        .into_iter()
                        .filter(LightningReceiveInfo::is_awaiting_preimage)
                        .collect::<Vec<_>>();

                    // Only hashes still awaiting a preimage can be forwarded
                    // again, so this keeps the set bounded.
                    forwarded.retain(|hash| awaiting.iter().any(|r| r.payment_hash == *hash));

                    for receive in awaiting {
                        if forwarded.contains(&receive.payment_hash) {
                            continue;
                        }

                        let Some(request) = intercept_request(&receive) else {
                            continue;
                        };

                        info!(
                            target: LOG_LIGHTNING,
                            payment_hash = %receive.payment_hash,
                            amount_msat = request.incoming_amount_msat,
                            "Bark hold receive is awaiting its preimage"
                        );

                        if sender.send(request).await.is_err() {
                            debug!(target: LOG_LIGHTNING, "HTLC stream closed, stopping bark receive watcher");
                            return;
                        }

                        forwarded.insert(receive.payment_hash);
                    }
                }
                Err(err) => {
                    warn!(
                        target: LOG_LIGHTNING,
                        err = %err.fmt_compact(),
                        "Failed to poll barkd for pending lightning receives"
                    );
                }
            }

            sleep(RECEIVE_POLL_INTERVAL).await;
        }
    }

    /// Polls the outcome of an outgoing payment until barkd reports it as
    /// paid or failed. Never gives up on its own: an error here forfeits the
    /// outgoing contract, so only barkd gets to declare the payment failed.
    async fn await_send_outcome(
        &self,
        payment_hash: sha256::Hash,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        loop {
            match self.rest.send_status(payment_hash).await {
                Ok(status) => match status.state.as_str() {
                    SEND_STATE_PAID => {
                        if let Some(preimage) = parse_preimage(status.preimage.as_deref()) {
                            return Ok(PayInvoiceResponse { preimage });
                        }

                        // Failing here would forfeit a contract we paid for.
                        error!(
                            target: LOG_LIGHTNING,
                            %payment_hash,
                            "barkd reported the payment as paid without a valid preimage"
                        );
                    }
                    SEND_STATE_FAILED => {
                        return Err(LightningRpcError::FailedPayment {
                            failure_reason: status
                                .failure_reason
                                .unwrap_or_else(|| "barkd reported the payment as failed".into()),
                        });
                    }
                    SEND_STATE_UNKNOWN => {
                        warn!(
                            target: LOG_LIGHTNING,
                            %payment_hash,
                            "barkd has no record of a dispatched payment, waiting for it to reappear"
                        );
                    }
                    _ => {}
                },
                Err(err) => {
                    warn!(
                        target: LOG_LIGHTNING,
                        %payment_hash,
                        err = %err.fmt_compact(),
                        "Failed to poll barkd for payment status"
                    );
                }
            }

            sleep(SEND_POLL_INTERVAL).await;
        }
    }

    /// Reads barkd's state for an outgoing payment, retrying until barkd
    /// answers.
    async fn read_send_state(&self, payment_hash: sha256::Hash) -> String {
        loop {
            match self.rest.send_status(payment_hash).await {
                Ok(status) => return status.state,
                Err(err) => {
                    warn!(
                        target: LOG_LIGHTNING,
                        %payment_hash,
                        err = %err.fmt_compact(),
                        "Failed to read bark payment status"
                    );
                }
            }

            sleep(SEND_POLL_INTERVAL).await;
        }
    }

    /// Checks that a fresh payment can be dispatched within the gateway's
    /// limits. The Ark server pays the invoice against HTLC VTXOs that expire
    /// `htlc_send_expiry_delta` blocks from now; the preimage must be known
    /// before the outgoing contract expires even if the gateway has to exit
    /// those VTXOs unilaterally.
    async fn check_dispatch_limits(&self, max_delay: u64) -> Result<(), LightningRpcError> {
        let ark_info =
            self.rest
                .ark_info()
                .await
                .map_err(|err| LightningRpcError::FailedPayment {
                    failure_reason: format!("Failed to fetch Ark server info: {err}"),
                })?;

        let required_delay =
            u64::from(ark_info.htlc_send_expiry_delta) + u64::from(ark_info.vtxo_exit_delta);
        if max_delay < required_delay {
            return Err(LightningRpcError::FailedPayment {
                failure_reason: format!(
                    "max_delay of {max_delay} blocks is below the {required_delay} blocks a bark payment may take to resolve"
                ),
            });
        }

        Ok(())
    }
}

/// Builds the request forwarded to the gateway for a hold receive awaiting
/// its preimage. The amount is the invoice amount, which the Ark server's
/// hold invoice only accepts HTLCs for in full; bark's receive fee is taken
/// out of the VTXOs afterwards and is covered by the gateway's fees.
fn intercept_request(receive: &LightningReceiveInfo) -> Option<InterceptPaymentRequest> {
    let amount_msat = match Bolt11Invoice::from_str(&receive.invoice) {
        Ok(invoice) => invoice.amount_milli_satoshis(),
        Err(err) => {
            warn!(
                target: LOG_LIGHTNING,
                payment_hash = %receive.payment_hash,
                err = %err,
                "barkd returned an unparseable invoice for a hold receive"
            );
            return None;
        }
    };

    let Some(amount_msat) = amount_msat else {
        warn!(
            target: LOG_LIGHTNING,
            payment_hash = %receive.payment_hash,
            "barkd returned an amountless invoice for a hold receive"
        );
        return None;
    };

    let (incoming_chan_id, htlc_id) = NO_INCOMING_CIRCUIT;
    Some(InterceptPaymentRequest {
        payment_hash: receive.payment_hash,
        amount_msat,
        incoming_amount_msat: amount_msat,
        // Not used on the LNv2 path; bark enforces its own claim deadline.
        expiry: 0,
        incoming_chan_id,
        short_channel_id: None,
        htlc_id,
    })
}

fn parse_preimage(preimage: Option<&str>) -> Option<Preimage> {
    let bytes = hex::decode(preimage?).ok()?;
    Some(Preimage(<[u8; 32]>::try_from(bytes).ok()?))
}

fn unsupported(operation: &str) -> String {
    format!("{operation} is not supported by the bark backend")
}

fn completion_error(payment_hash: sha256::Hash, err: &BarkRestError) -> LightningRpcError {
    let failure_reason = format!("barkd could not complete hold receive {payment_hash}: {err}");
    if err.is_client_error() {
        LightningRpcError::HtlcCompletionRejected { failure_reason }
    } else {
        LightningRpcError::FailedToCompleteHtlc { failure_reason }
    }
}

#[async_trait]
impl ILnRpcClient for GatewayBarkClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        let to_error = |err: BarkRestError| LightningRpcError::FailedToGetNodeInfo {
            failure_reason: err.to_string(),
        };

        let ark_info = self.rest.ark_info().await.map_err(to_error)?;
        let tip = self.rest.tip().await.map_err(to_error)?;
        let connected = self.rest.connected().await.map_err(to_error)?;

        Ok(GetNodeInfoResponse {
            pub_key: self.node_id,
            alias: BARK_ALIAS.to_string(),
            network: ark_info.network,
            block_height: tip.tip_height,
            // Not being connected to the Ark server means we can neither
            // receive nor pay, which the gateway treats like being unsynced.
            synced_to_chain: connected.connected,
        })
    }

    async fn routehints(
        &self,
        _num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        Ok(GetRouteHintsResponse {
            route_hints: vec![],
        })
    }

    async fn pay(
        &self,
        invoice: Bolt11Invoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let payment_hash = *invoice.payment_hash();

        // Consult barkd's record before enforcing any limits, see the trait
        // docs: a resumed payment may be passed a placeholder `max_delay`.
        if self.read_send_state(payment_hash).await != SEND_STATE_UNKNOWN {
            return self.await_send_outcome(payment_hash).await;
        }

        self.check_dispatch_limits(max_delay).await?;

        let request = PayRequest {
            destination: invoice.to_string(),
            max_fee_sat: max_fee.msats / 1000,
        };

        if let Err(err) = self.rest.pay(&request).await {
            // Only a payment barkd has no record of is known not to be in
            // flight; anything else must be awaited.
            if self.read_send_state(payment_hash).await == SEND_STATE_UNKNOWN {
                return Err(LightningRpcError::FailedPayment {
                    failure_reason: format!("barkd refused the payment: {err}"),
                });
            }

            warn!(
                target: LOG_LIGHTNING,
                %payment_hash,
                err = %err.fmt_compact(),
                "barkd payment request failed but the payment may be in flight"
            );
        }

        self.await_send_outcome(payment_hash).await
    }

    async fn outbound_payment_exists(
        &self,
        payment_hash: sha256::Hash,
    ) -> Result<bool, LightningRpcError> {
        let status = self.rest.send_status(payment_hash).await.map_err(|err| {
            LightningRpcError::FailedPayment {
                failure_reason: format!("Failed to fetch bark payment status: {err}"),
            }
        })?;

        Ok(status.state != SEND_STATE_UNKNOWN)
    }

    fn detects_direct_swaps_by_payment_hash(&self) -> bool {
        true
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        // Fail early if barkd is unreachable so the gateway retries instead of
        // reporting itself as connected.
        self.rest.pending_receives().await.map_err(|err| {
            LightningRpcError::FailedToRouteHtlcs {
                failure_reason: err.to_string(),
            }
        })?;

        let (sender, receiver) = mpsc::channel(1024);
        let rest = self.rest.clone();
        task_group.spawn_cancellable(
            "bark hold receive watcher",
            Self::watch_hold_receives(rest, sender),
        );

        Ok((Box::pin(ReceiverStream::new(receiver)), Arc::new(*self)))
    }

    async fn complete_htlc(&self, htlc: InterceptPaymentResponse) -> Result<(), LightningRpcError> {
        if let Some(circuit) = htlc.incoming_circuit() {
            return Err(LightningRpcError::HtlcCompletionRejected {
                failure_reason: format!(
                    "The bark backend never intercepts forwarded HTLCs, got circuit {circuit:?}"
                ),
            });
        }

        let payment_hash = htlc.payment_hash;
        match htlc.action {
            PaymentAction::Settle(preimage) => self
                .rest
                .settle_receive(payment_hash, preimage.0)
                .await
                .map_err(|err| completion_error(payment_hash, &err)),
            PaymentAction::Cancel | PaymentAction::Forward => {
                warn!(
                    target: LOG_LIGHTNING,
                    %payment_hash,
                    "Abandoning bark hold receive because the action was not `Settle`"
                );
                self.rest
                    .abandon_receive(payment_hash)
                    .await
                    .map_err(|err| completion_error(payment_hash, &err))
            }
        }
    }

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        let to_error =
            |failure_reason: String| LightningRpcError::FailedToGetInvoice { failure_reason };

        let payment_hash = create_invoice_request
            .payment_hash
            .ok_or_else(|| to_error(unsupported("Creating invoices without a payment hash")))?;

        if !create_invoice_request.amount_msat.is_multiple_of(1000) {
            return Err(to_error(format!(
                "bark only receives whole satoshis, got {} msat",
                create_invoice_request.amount_msat
            )));
        }

        let description = match create_invoice_request.description {
            None => None,
            Some(InvoiceDescription::Direct(description)) => Some(description),
            Some(InvoiceDescription::Hash(_)) => {
                return Err(to_error(unsupported("Description hash invoices")));
            }
        };

        let invoice = self
            .rest
            .create_hold_invoice(&HoldInvoiceRequest {
                amount_sat: create_invoice_request.amount_msat / 1000,
                payment_hash,
                description,
                expiry_secs: u64::from(create_invoice_request.expiry_secs),
            })
            .await
            .map_err(|err| to_error(err.to_string()))?;

        Ok(CreateInvoiceResponse {
            invoice: invoice.invoice,
        })
    }

    async fn get_ln_onchain_address(
        &self,
    ) -> Result<GetLnOnchainAddressResponse, LightningRpcError> {
        self.rest
            .onchain_address()
            .await
            .map(|address| GetLnOnchainAddressResponse {
                address: address.address,
            })
            .map_err(|err| LightningRpcError::FailedToGetLnOnchainAddress {
                failure_reason: err.to_string(),
            })
    }

    async fn send_onchain(
        &self,
        _payload: SendOnchainRequest,
    ) -> Result<SendOnchainResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToWithdrawOnchain {
            failure_reason: unsupported("Withdrawing on-chain (use barkd directly)"),
        })
    }

    async fn open_channel(
        &self,
        _payload: OpenChannelRequest,
    ) -> Result<OpenChannelResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToOpenChannel {
            failure_reason: unsupported("Opening channels"),
        })
    }

    async fn connect_peer(&self, _payload: ConnectPeerRequest) -> Result<(), LightningRpcError> {
        Err(LightningRpcError::FailedToConnectToPeer {
            failure_reason: unsupported("Connecting to peers"),
        })
    }

    async fn close_channels_with_peer(
        &self,
        _payload: CloseChannelsWithPeerRequest,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToCloseChannelsWithPeer {
            failure_reason: unsupported("Closing channels"),
        })
    }

    async fn list_channels(&self) -> Result<ListChannelsResponse, LightningRpcError> {
        Ok(ListChannelsResponse { channels: vec![] })
    }

    async fn set_channel_fees(
        &self,
        _payload: SetChannelFeesRequest,
    ) -> Result<(), LightningRpcError> {
        Err(LightningRpcError::FailedToSetChannelFees {
            failure_reason: unsupported("Setting channel fees"),
        })
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        let to_error = |err: BarkRestError| LightningRpcError::FailedToGetBalances {
            failure_reason: err.to_string(),
        };

        let balance = self.rest.balance().await.map_err(to_error)?;
        // barkd may run without an on-chain wallet.
        let onchain_balance_sats = match self.rest.onchain_balance().await {
            Ok(balance) => balance.total_sat,
            Err(err) => {
                debug!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "No bark on-chain balance");
                0
            }
        };

        Ok(GetBalancesResponse {
            onchain_balance_sats,
            lightning_balance_msats: balance.spendable_sat * 1000,
            // Receiving is limited by the Ark server, not by channels.
            inbound_lightning_liquidity_msats: 0,
        })
    }

    async fn get_invoice(
        &self,
        _get_invoice_request: GetInvoiceRequest,
    ) -> Result<Option<GetInvoiceResponse>, LightningRpcError> {
        Err(LightningRpcError::FailedToGetInvoice {
            failure_reason: unsupported("Looking up invoices"),
        })
    }

    async fn list_transactions(
        &self,
        _start_secs: u64,
        _end_secs: u64,
    ) -> Result<ListTransactionsResponse, LightningRpcError> {
        Err(LightningRpcError::FailedToListTransactions {
            failure_reason: unsupported("Listing transactions"),
        })
    }

    fn create_offer(
        &self,
        _amount: Option<Amount>,
        _description: Option<String>,
        _expiry_secs: Option<u32>,
        _quantity: Option<u64>,
    ) -> Result<String, LightningRpcError> {
        Err(LightningRpcError::Bolt12Error {
            failure_reason: unsupported("Creating offers"),
        })
    }

    async fn pay_offer(
        &self,
        _offer: String,
        _quantity: Option<u64>,
        _amount: Option<Amount>,
        _payer_note: Option<String>,
    ) -> Result<Preimage, LightningRpcError> {
        Err(LightningRpcError::Bolt12Error {
            failure_reason: unsupported("Paying offers"),
        })
    }

    fn sync_wallet(&self) -> Result<(), LightningRpcError> {
        Ok(())
    }
}
