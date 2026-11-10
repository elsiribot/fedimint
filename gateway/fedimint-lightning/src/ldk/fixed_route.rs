//! Payments over a route whose first hop we choose, and circular rebalances.
//!
//! A rebalance moves outbound liquidity from one of our channels to another:
//! we invoice ourselves, then pay that invoice over a route that leaves
//! through the source channel and comes back over the destination channel.
//! ldk-node claims the payment like any invoice of ours, so the only cost is
//! the routing fee. The same machinery pays an operator invoice out of a
//! chosen channel.
//!
//! LDK does not retry a fixed route, so this module does: when a route fails,
//! LDK has already marked the channel it failed at in the scorer, the next
//! route leaves it out explicitly too, and routing again finds a way around
//! it. It stops at the first route that settles, after
//! [`MAX_ROUTES`] routes, when the recipient rejects the payment, or when a
//! route does not settle in time (it may still complete, so nothing more is
//! sent).

use std::time::{Duration, SystemTime};

use bitcoin::OutPoint;
use bitcoin::hashes::{Hash, HashEngine, sha256};
use fedimint_core::Amount;
use fedimint_core::task::block_in_place;
use fedimint_core::util::FmtCompact;
use fedimint_gateway_common::{
    RebalanceChannelRequest, RebalanceChannelResponse, RebalanceStatus, RouteHopSummary,
};
use fedimint_ln_common::contracts::Preimage;
use fedimint_logging::LOG_LIGHTNING;
use ldk_node::lightning::ln::bolt11_payment::payment_parameters_from_invoice;
use ldk_node::lightning::routing::router::Route;
use ldk_node::payment::{FixedRouteError, PaymentOutcome};
use lightning::ln::channelmanager::PaymentId;
use lightning::types::payment::{PaymentHash, PaymentSecret};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use tokio::sync::broadcast;
use tracing::info;

use crate::{LightningRpcError, PayInvoiceResponse};

/// Routes one rebalance or first-hop payment tries before giving up.
pub(crate) const MAX_ROUTES: u32 = 5;

/// How long one route gets to settle. A payment that is still in flight
/// after this may yet complete, so nothing more is sent.
const ROUTE_SETTLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Fee cap of a rebalance when the request sets none, in parts per million of
/// the amount.
pub(crate) const DEFAULT_REBALANCE_MAX_FEE_PPM: u64 = 1_000;

/// How long the invoice a rebalance pays to ourselves stays payable. Only its
/// own routes pay it, all within minutes.
const REBALANCE_INVOICE_EXPIRY_SECS: u32 = 3_600;

/// The cap on a rebalance's total fee: the lower of the request's ppm and
/// sats caps, the default ppm cap if it sets neither.
pub(crate) fn rebalance_fee_cap_msat(
    amount_msat: u64,
    max_fee_ppm: Option<u64>,
    max_fee_sats: Option<u64>,
) -> u64 {
    let by_ppm = max_fee_ppm.map(|ppm| amount_msat.saturating_mul(ppm) / 1_000_000);
    let by_sats = max_fee_sats.map(|sats| sats.saturating_mul(1_000));
    match (by_ppm, by_sats) {
        (Some(a), Some(b)) => a.min(b),
        (Some(cap), None) | (None, Some(cap)) => cap,
        (None, None) => amount_msat.saturating_mul(DEFAULT_REBALANCE_MAX_FEE_PPM) / 1_000_000,
    }
}

/// How one route ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteOutcome {
    Sent {
        preimage: [u8; 32],
        fee_paid_msat: Option<u64>,
    },
    Failed {
        failed_channel: Option<u64>,
        /// The recipient rejected the payment: no other route will do.
        permanently: bool,
    },
    TimedOut,
}

/// Waits for the outcome of the payment sent with `payment_id`.
pub(crate) async fn wait_for_payment(
    outcomes: &mut broadcast::Receiver<PaymentOutcome>,
    payment_id: PaymentId,
    timeout: Duration,
) -> RouteOutcome {
    let mut failed_channel = None;
    let mut permanently = false;
    let settled = fedimint_core::runtime::timeout(timeout, async {
        loop {
            match outcomes.recv().await {
                Ok(outcome) if outcome.payment_id() == payment_id => match outcome {
                    PaymentOutcome::Sent {
                        payment_preimage,
                        fee_paid_msat,
                        ..
                    } => {
                        return Some(RouteOutcome::Sent {
                            preimage: payment_preimage.0,
                            fee_paid_msat,
                        });
                    }
                    PaymentOutcome::PathFailed {
                        failed_channel: channel,
                        permanently: rejected,
                        ..
                    } => {
                        failed_channel = failed_channel.or(channel);
                        permanently |= rejected;
                    }
                    PaymentOutcome::Failed { .. } => {
                        return Some(RouteOutcome::Failed {
                            failed_channel,
                            permanently,
                        });
                    }
                },
                Ok(_) => {}
                // A missed outcome leaves us waiting until the timeout, which
                // only ends this payment early.
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
    .await;
    settled.ok().flatten().unwrap_or(RouteOutcome::TimedOut)
}

/// Everything the routes of one payment came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sending {
    pub status: RebalanceStatus,
    pub preimage: Option<[u8; 32]>,
    pub fee_paid_msat: Option<u64>,
    pub attempts: u32,
    pub route: Vec<RouteHopSummary>,
    pub failed_channels: Vec<u64>,
    pub error: Option<String>,
}

impl Sending {
    fn new() -> Self {
        Self {
            status: RebalanceStatus::NoRoute,
            preimage: None,
            fee_paid_msat: None,
            attempts: 0,
            route: Vec::new(),
            failed_channels: Vec::new(),
            error: None,
        }
    }

    /// Takes in how a route ended; says whether to try another.
    pub(crate) fn record(&mut self, outcome: RouteOutcome, max_routes: u32) -> bool {
        match outcome {
            RouteOutcome::Sent {
                preimage,
                fee_paid_msat,
            } => {
                self.status = RebalanceStatus::Succeeded;
                self.preimage = Some(preimage);
                self.fee_paid_msat = fee_paid_msat;
                self.error = None;
                false
            }
            RouteOutcome::Failed {
                failed_channel,
                permanently,
            } => {
                self.status = RebalanceStatus::Failed;
                if let Some(channel) = failed_channel
                    && !self.failed_channels.contains(&channel)
                {
                    self.failed_channels.push(channel);
                }
                if permanently {
                    self.error = Some("the recipient rejected the payment".to_string());
                    return false;
                }
                self.error = Some(match failed_channel {
                    Some(channel) => format!("last route failed at channel {channel}"),
                    None => "last route failed".to_string(),
                });
                // Without knowing where it failed, routing again finds the
                // same route.
                failed_channel.is_some() && self.attempts < max_routes
            }
            RouteOutcome::TimedOut => {
                self.status = RebalanceStatus::Timeout;
                self.error = Some(
                    "the last route did not settle in time and may still complete".to_string(),
                );
                false
            }
        }
    }

    /// Takes in that no route could be found or sent; after an earlier route
    /// was sent the payment counts as failed, before it as unroutable.
    pub(crate) fn could_not_send(&mut self, err: &FixedRouteError) {
        if self.attempts == 0 {
            self.status = RebalanceStatus::NoRoute;
        }
        self.error = Some(err.to_string());
    }
}

fn hop_summary(route: &Route) -> Vec<RouteHopSummary> {
    route
        .paths
        .iter()
        .flat_map(|path| path.hops.iter())
        .map(|hop| RouteHopSummary {
            node_id: hop.pubkey,
            short_channel_id: hop.short_channel_id,
        })
        .collect()
}

/// A fresh id for one route of the payment with `payment_hash`. Never
/// `PaymentId(payment_hash)`: ldk-node keys a payment's store record by that,
/// and for a rebalance the record is our own inbound side.
fn route_payment_id(payment_hash: &PaymentHash, attempt: u32) -> PaymentId {
    let mut engine = sha256::Hash::engine();
    engine.input(b"fixed-route payment");
    engine.input(&payment_hash.0);
    engine.input(&attempt.to_be_bytes());
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    engine.input(&nanos.to_be_bytes());
    PaymentId(sha256::Hash::from_engine(engine).to_byte_array())
}

/// Sends routes from `find` (given the channels earlier routes failed at)
/// until one settles, see the module docs.
async fn send_until_settled(
    node: &ldk_node::Node,
    payment_hash: PaymentHash,
    payment_secret: PaymentSecret,
    mut find: impl FnMut(
        &ldk_node::payment::FixedRoutePayment,
        &[u64],
    ) -> Result<Route, FixedRouteError>,
) -> Sending {
    let payments = node.fixed_route_payment();
    // Subscribed before sending, so no outcome can come too early.
    let mut outcomes = payments.subscribe_payment_outcomes();
    let mut sending = Sending::new();
    loop {
        // Route finding walks the whole network graph, which is CPU work that
        // must not stall the async workers.
        let route = match block_in_place(|| find(&payments, &sending.failed_channels)) {
            Ok(route) => route,
            Err(err) => {
                sending.could_not_send(&err);
                break;
            }
        };
        sending.route = hop_summary(&route);
        let payment_id = route_payment_id(&payment_hash, sending.attempts);
        if let Err(err) = payments.send_route(route, payment_hash, payment_secret, payment_id) {
            sending.could_not_send(&err);
            break;
        }
        sending.attempts += 1;
        let outcome = wait_for_payment(&mut outcomes, payment_id, ROUTE_SETTLE_TIMEOUT).await;
        if !sending.record(outcome, MAX_ROUTES) {
            break;
        }
    }
    sending
}

/// Moves `request.amount_sats` of outbound liquidity from the source channel
/// to the destination channel, see the module docs.
pub(crate) async fn rebalance(
    node: &ldk_node::Node,
    request: RebalanceChannelRequest,
) -> Result<RebalanceChannelResponse, LightningRpcError> {
    let invalid = |reason: String| LightningRpcError::FailedToRebalanceChannel {
        failure_reason: reason,
    };
    if request.amount_sats == 0 {
        return Err(invalid("amount must be positive".to_string()));
    }
    if request.source == request.destination {
        return Err(invalid(
            "source and destination are the same channel".to_string(),
        ));
    }
    let amount_msat = request.amount_sats.saturating_mul(1_000);
    let max_fee_msat =
        rebalance_fee_cap_msat(amount_msat, request.max_fee_ppm, request.max_fee_sats);

    let description = Description::new("gateway channel rebalance".to_string())
        .map_err(|e| invalid(e.to_string()))?;
    let invoice = node
        .bolt11_payment()
        .receive(
            amount_msat,
            &Bolt11InvoiceDescription::Direct(description),
            REBALANCE_INVOICE_EXPIRY_SECS,
        )
        .map_err(|e| invalid(format!("could not invoice ourselves: {}", e.fmt_compact())))?;
    let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
    let payment_secret = PaymentSecret(invoice.payment_secret().0);
    let final_cltv = u32::try_from(invoice.min_final_cltv_expiry_delta()).unwrap_or(u32::MAX);

    let sending = send_until_settled(node, payment_hash, payment_secret, |payments, failed| {
        payments.find_rebalance_route(
            request.source,
            request.destination,
            amount_msat,
            max_fee_msat,
            final_cltv,
            failed,
        )
    })
    .await;

    info!(
        target: LOG_LIGHTNING,
        source = %request.source,
        destination = %request.destination,
        amount_msat,
        max_fee_msat,
        status = ?sending.status,
        fee_msat = ?sending.fee_paid_msat,
        routes = sending.attempts,
        failed_channels = %sending
            .failed_channels
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        error = sending.error.as_deref().unwrap_or(""),
        "Rebalance done"
    );

    Ok(RebalanceChannelResponse {
        status: sending.status,
        amount_sats: request.amount_sats,
        fee_msat: sending.fee_paid_msat,
        attempts: sending.attempts,
        route: sending.route,
        failed_channels: sending.failed_channels,
        error: sending.error,
    })
}

/// Pays `invoice` out of the channel funded by `first_hop`, spending at most
/// `max_fee` on routing.
///
/// Unlike the node's own `pay`, the attempts are not in ldk-node's payment
/// store, so calling this twice for one invoice could pay it twice if the
/// first call timed out with its payment still in flight; callers must not.
pub(crate) async fn pay_via_first_hop(
    node: &ldk_node::Node,
    invoice: &Bolt11Invoice,
    first_hop: OutPoint,
    max_fee: Amount,
) -> Result<PayInvoiceResponse, LightningRpcError> {
    let failed = |reason: String| LightningRpcError::FailedPayment {
        failure_reason: reason,
    };
    let (payment_hash, recipient_onion, mut route_params) =
        payment_parameters_from_invoice(invoice)
            .map_err(|()| failed("invoice has no amount".to_string()))?;
    let payment_secret = recipient_onion
        .payment_secret
        .ok_or_else(|| failed("invoice has no payment secret".to_string()))?;
    route_params.max_total_routing_fee_msat = Some(max_fee.msats);

    let sending = send_until_settled(node, payment_hash, payment_secret, |payments, failed| {
        let mut params = route_params.clone();
        params
            .payment_params
            .previously_failed_channels
            .extend_from_slice(failed);
        payments.find_route_via(first_hop, params)
    })
    .await;

    info!(
        target: LOG_LIGHTNING,
        %first_hop,
        payment_hash = %invoice.payment_hash(),
        status = ?sending.status,
        fee_msat = ?sending.fee_paid_msat,
        routes = sending.attempts,
        error = sending.error.as_deref().unwrap_or(""),
        "Payment via a chosen first hop done"
    );

    match (sending.status, sending.preimage) {
        (RebalanceStatus::Succeeded, Some(preimage)) => Ok(PayInvoiceResponse {
            preimage: Preimage(preimage),
        }),
        (status, _) => Err(failed(format!(
            "{status:?}: {}",
            sending.error.unwrap_or_default()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_cap_takes_the_lower_cap_or_the_default() {
        let amount = 2_000_000_000; // 2M sat
        assert_eq!(rebalance_fee_cap_msat(amount, None, None), 2_000_000);
        assert_eq!(rebalance_fee_cap_msat(amount, Some(500), None), 1_000_000);
        assert_eq!(rebalance_fee_cap_msat(amount, None, Some(300)), 300_000);
        assert_eq!(
            rebalance_fee_cap_msat(amount, Some(500), Some(300)),
            300_000
        );
        assert_eq!(
            rebalance_fee_cap_msat(amount, Some(100), Some(300)),
            200_000
        );
    }

    #[test]
    fn a_failure_at_a_known_channel_routes_again_until_the_cap() {
        let mut sending = Sending::new();
        sending.attempts = 1;
        let failed_at = |channel| RouteOutcome::Failed {
            failed_channel: Some(channel),
            permanently: false,
        };
        assert!(sending.record(failed_at(11), 3));
        sending.attempts = 2;
        assert!(sending.record(failed_at(12), 3));
        sending.attempts = 3;
        assert!(
            !sending.record(failed_at(11), 3),
            "the third route was the last"
        );
        assert_eq!(sending.status, RebalanceStatus::Failed);
        assert_eq!(sending.failed_channels, vec![11, 12]);
    }

    #[test]
    fn rejection_unknown_failures_and_timeouts_end_it() {
        let mut sending = Sending::new();
        sending.attempts = 1;
        assert!(!sending.record(
            RouteOutcome::Failed {
                failed_channel: Some(5),
                permanently: true
            },
            5
        ));
        assert!(!sending.record(
            RouteOutcome::Failed {
                failed_channel: None,
                permanently: false
            },
            5
        ));
        assert!(!sending.record(RouteOutcome::TimedOut, 5));
        assert_eq!(sending.status, RebalanceStatus::Timeout);
    }

    #[test]
    fn success_clears_the_error_and_keeps_the_fee() {
        let mut sending = Sending::new();
        sending.attempts = 2;
        sending.record(
            RouteOutcome::Failed {
                failed_channel: Some(9),
                permanently: false,
            },
            5,
        );
        assert!(!sending.record(
            RouteOutcome::Sent {
                preimage: [3; 32],
                fee_paid_msat: Some(1_234)
            },
            5
        ));
        assert_eq!(sending.status, RebalanceStatus::Succeeded);
        assert_eq!(
            (
                sending.fee_paid_msat,
                sending.error,
                sending.failed_channels
            ),
            (Some(1_234), None, vec![9])
        );
    }

    #[test]
    fn no_route_before_any_send_is_unroutable_after_one_is_failed() {
        let mut sending = Sending::new();
        sending.could_not_send(&FixedRouteError::NoRoute("none".to_string()));
        assert_eq!(sending.status, RebalanceStatus::NoRoute);

        let mut sending = Sending::new();
        sending.attempts = 1;
        sending.record(
            RouteOutcome::Failed {
                failed_channel: Some(1),
                permanently: false,
            },
            5,
        );
        sending.could_not_send(&FixedRouteError::NoRoute("none".to_string()));
        assert_eq!(sending.status, RebalanceStatus::Failed);
    }

    #[tokio::test]
    async fn waiting_matches_its_payment_and_collects_the_failed_channel() {
        let (sender, mut receiver) = broadcast::channel(16);
        let ours = PaymentId([1; 32]);
        let other = PaymentId([2; 32]);
        sender
            .send(PaymentOutcome::Failed {
                payment_id: other,
                reason: None,
            })
            .unwrap();
        sender
            .send(PaymentOutcome::PathFailed {
                payment_id: ours,
                failed_channel: Some(42),
                permanently: false,
            })
            .unwrap();
        sender
            .send(PaymentOutcome::Failed {
                payment_id: ours,
                reason: None,
            })
            .unwrap();
        assert_eq!(
            wait_for_payment(&mut receiver, ours, Duration::from_secs(5)).await,
            RouteOutcome::Failed {
                failed_channel: Some(42),
                permanently: false
            }
        );
    }

    #[tokio::test]
    async fn waiting_gives_up_after_the_timeout() {
        let (_sender, mut receiver) = broadcast::channel::<PaymentOutcome>(4);
        assert_eq!(
            wait_for_payment(&mut receiver, PaymentId([1; 32]), Duration::from_millis(20)).await,
            RouteOutcome::TimedOut
        );
    }

    #[test]
    fn route_ids_never_collide_with_the_hash_slot() {
        let hash = PaymentHash([7; 32]);
        let first = route_payment_id(&hash, 0);
        assert_ne!(first, PaymentId(hash.0));
        assert_ne!(first, route_payment_id(&hash, 1));
    }
}
