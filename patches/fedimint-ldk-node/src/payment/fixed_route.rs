// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Payments over a route the caller chose the first hop of, and circular rebalances.
//!
//! LDK's own payment methods let the router pick any of our channels as the first hop. Two
//! things need more control than that:
//! - paying an invoice out of one particular channel, e.g. one with outbound to spare, and
//! - moving outbound liquidity from one of our channels to another with a payment that leaves
//!   through the first and comes back through the second ("rebalance loop", which LDK's
//!   `send_payment_with_route` accepts as long as we appear only as the final hop).
//!
//! Both are single-path and are not retried here: the caller sends one route, waits for its
//! [`PaymentOutcome`], and routes again around the channel that failed if it wants to. LDK has
//! already fed a failure to the scorer when the outcome is published, so a new route takes it
//! into account.

use crate::logger::{log_info, LdkLogger, Logger};
use crate::types::{ChannelManager, Router};

use lightning::chain::transaction::OutPoint as LdkOutPoint;
use lightning::events::PaymentFailureReason;
use lightning::ln::channel_state::ChannelDetails as LdkChannelDetails;
use lightning::ln::channelmanager::{PaymentId, RecipientOnionFields};
use lightning::routing::router::{
	Path, PaymentParameters, Route, RouteHop, RouteParameters, Router as _,
};
use lightning_types::features::{ChannelFeatures, NodeFeatures};
use lightning_types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};

use bitcoin::secp256k1::PublicKey;
use bitcoin::OutPoint;

use std::fmt;
use std::sync::Arc;

/// How many payment outcomes a subscriber that falls behind may miss before it is told so.
pub(crate) const PAYMENT_OUTCOME_CAPACITY: usize = 1024;

/// Where the event handler publishes payment outcomes.
pub(crate) type PaymentOutcomeSender = tokio::sync::broadcast::Sender<PaymentOutcome>;

/// What became of an outbound payment, as LDK reported it. Published for every outbound
/// payment, whichever API sent it; subscribers match on the [`PaymentId`] they sent with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentOutcome {
	/// The payment was claimed by its recipient.
	Sent {
		/// The id the payment was sent with.
		payment_id: PaymentId,
		/// The recipient's proof of payment.
		payment_preimage: PaymentPreimage,
		/// What the route cost, if LDK knows.
		fee_paid_msat: Option<u64>,
	},
	/// One path of the payment failed. A [`PaymentOutcome::Failed`] follows once no path is
	/// left pending (a fixed route has one path, so it follows right away).
	PathFailed {
		/// The id the payment was sent with.
		payment_id: PaymentId,
		/// The channel the path failed at, where LDK knows it.
		failed_channel: Option<u64>,
		/// Whether the recipient rejected the payment, so no other route will do.
		permanently: bool,
	},
	/// The payment failed for good; nothing of it is in flight any more.
	Failed {
		/// The id the payment was sent with.
		payment_id: PaymentId,
		/// Why, where LDK knows.
		reason: Option<PaymentFailureReason>,
	},
}

impl PaymentOutcome {
	/// The id of the payment this outcome is about.
	pub fn payment_id(&self) -> PaymentId {
		match self {
			Self::Sent { payment_id, .. }
			| Self::PathFailed { payment_id, .. }
			| Self::Failed { payment_id, .. } => *payment_id,
		}
	}
}

/// Why a route could not be built or sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixedRouteError {
	/// [`crate::Node`] is not running.
	NotRunning,
	/// No usable (active, ready) channel of ours has this funding outpoint.
	UnknownChannel(OutPoint),
	/// The channel cannot carry the payment; says why.
	ChannelCannotCarry(String),
	/// The router found no route within the limits; says why.
	NoRoute(String),
	/// LDK refused to send the route; says why.
	SendFailed(String),
}

impl fmt::Display for FixedRouteError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::NotRunning => write!(f, "node is not running"),
			Self::UnknownChannel(outpoint) => {
				write!(f, "no usable channel with funding outpoint {outpoint}")
			},
			Self::ChannelCannotCarry(why) => write!(f, "channel cannot carry the payment: {why}"),
			Self::NoRoute(why) => write!(f, "no route: {why}"),
			Self::SendFailed(why) => write!(f, "could not send: {why}"),
		}
	}
}

impl std::error::Error for FixedRouteError {}

/// The last hop of a rebalance: the peer of the destination channel forwarding to us over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoopBack {
	/// Our own node, the payment's final hop.
	pub our_node_id: PublicKey,
	/// The short channel id the peer forwards to us over.
	pub short_channel_id: u64,
	/// Whether that channel is announced.
	pub announced: bool,
	/// The peer's forwarding fee towards us.
	pub fee_base_msat: u32,
	/// The peer's proportional forwarding fee towards us, in millionths.
	pub fee_proportional_millionths: u32,
	/// The peer's CLTV delta towards us.
	pub cltv_expiry_delta: u16,
}

impl LoopBack {
	/// What the peer charges to forward `amount_msat` to us.
	pub(crate) fn fee_msat(&self, amount_msat: u64) -> u64 {
		u64::from(self.fee_base_msat)
			+ amount_msat * u64::from(self.fee_proportional_millionths) / 1_000_000
	}

	/// Turns `path`, which the router found from us to the destination channel's peer for
	/// `amount_msat + self.fee_msat(amount_msat)`, into the loop back to us: the peer's hop now
	/// takes its forwarding fee and CLTV delta, and a final hop over the destination channel
	/// delivers `amount_msat` to us with `final_cltv_expiry_delta`.
	///
	/// The fees and CLTV deltas of the hops before the peer stay as the router computed them:
	/// they were found for forwarding exactly what reaches the peer now.
	pub(crate) fn close(
		&self, mut path: Path, our_features: NodeFeatures, amount_msat: u64,
		final_cltv_expiry_delta: u32,
	) -> Path {
		let peer_hop = path.hops.last_mut().expect("the router returns no empty paths");
		peer_hop.fee_msat = self.fee_msat(amount_msat);
		peer_hop.cltv_expiry_delta = u32::from(self.cltv_expiry_delta);
		path.hops.push(RouteHop {
			pubkey: self.our_node_id,
			node_features: our_features,
			short_channel_id: self.short_channel_id,
			channel_features: ChannelFeatures::empty(),
			fee_msat: amount_msat,
			cltv_expiry_delta: final_cltv_expiry_delta,
			maybe_announced_channel: self.announced,
		});
		path
	}
}

/// A payment handler for payments over a route whose first hop the caller chose, and for
/// circular rebalances between two of our channels.
///
/// Should be retrieved by calling [`crate::Node::fixed_route_payment`].
pub struct FixedRoutePayment {
	runtime: Arc<std::sync::RwLock<Option<Arc<tokio::runtime::Runtime>>>>,
	channel_manager: Arc<ChannelManager>,
	router: Arc<Router>,
	logger: Arc<Logger>,
	payment_outcomes: PaymentOutcomeSender,
}

impl FixedRoutePayment {
	pub(crate) fn new(
		runtime: Arc<std::sync::RwLock<Option<Arc<tokio::runtime::Runtime>>>>,
		channel_manager: Arc<ChannelManager>, router: Arc<Router>, logger: Arc<Logger>,
		payment_outcomes: PaymentOutcomeSender,
	) -> Self {
		Self { runtime, channel_manager, router, logger, payment_outcomes }
	}

	/// Outcomes of all outbound payments from now on. Subscribe before sending, or an outcome
	/// may arrive before the subscription.
	pub fn subscribe_payment_outcomes(&self) -> tokio::sync::broadcast::Receiver<PaymentOutcome> {
		self.payment_outcomes.subscribe()
	}

	fn ensure_running(&self) -> Result<(), FixedRouteError> {
		if self.runtime.read().unwrap().is_none() {
			return Err(FixedRouteError::NotRunning);
		}
		Ok(())
	}

	fn usable_channel(
		&self, funding_outpoint: OutPoint,
	) -> Result<LdkChannelDetails, FixedRouteError> {
		let wanted =
			LdkOutPoint { txid: funding_outpoint.txid, index: funding_outpoint.vout as u16 };
		self.channel_manager
			.list_usable_channels()
			.into_iter()
			.find(|c| c.funding_txo == Some(wanted))
			.ok_or(FixedRouteError::UnknownChannel(funding_outpoint))
	}

	/// A single-path route for `route_params` that leaves through the channel with
	/// `first_hop` as funding outpoint. Uses the node's router and scorer, so channels known to
	/// have failed are avoided like for any payment.
	pub fn find_route_via(
		&self, first_hop: OutPoint, mut route_params: RouteParameters,
	) -> Result<Route, FixedRouteError> {
		self.ensure_running()?;
		let channel = self.usable_channel(first_hop)?;
		route_params.payment_params.max_path_count = 1;
		let our_node_id = self.channel_manager.get_our_node_id();
		self.router
			.find_route(
				&our_node_id,
				&route_params,
				Some(&[&channel]),
				self.channel_manager.compute_inflight_htlcs(),
			)
			.map_err(|e| FixedRouteError::NoRoute(e.err))
	}

	/// The route of a circular rebalance moving `amount_msat` of outbound liquidity from the
	/// channel funded by `source` to the one funded by `destination`: out through `source`,
	/// across the network to the peer of `destination`, and back to us over `destination`.
	///
	/// `max_fee_msat` caps everything the loop costs, the destination peer's fee included.
	/// `failed_channels` are left out (the ones earlier routes of the same rebalance failed at).
	/// Single-path only: a rebalance that needs splitting is better asked for in parts.
	pub fn find_rebalance_route(
		&self, source: OutPoint, destination: OutPoint, amount_msat: u64, max_fee_msat: u64,
		final_cltv_expiry_delta: u32, failed_channels: &[u64],
	) -> Result<Route, FixedRouteError> {
		self.ensure_running()?;
		if source == destination {
			return Err(FixedRouteError::ChannelCannotCarry(
				"source and destination are the same channel".to_string(),
			));
		}
		let dest = self.usable_channel(destination)?;
		if dest.inbound_capacity_msat < amount_msat {
			return Err(FixedRouteError::ChannelCannotCarry(format!(
				"destination can receive {} msat, less than {} msat",
				dest.inbound_capacity_msat, amount_msat
			)));
		}
		if amount_msat < dest.inbound_htlc_minimum_msat.unwrap_or(0)
			|| dest.inbound_htlc_maximum_msat.is_some_and(|max| amount_msat > max)
		{
			return Err(FixedRouteError::ChannelCannotCarry(format!(
				"{} msat is outside the destination's HTLC limits {:?}..{:?}",
				amount_msat, dest.inbound_htlc_minimum_msat, dest.inbound_htlc_maximum_msat
			)));
		}
		let policy = dest.counterparty.forwarding_info.clone().ok_or_else(|| {
			FixedRouteError::ChannelCannotCarry(
				"the destination's peer has not told us its forwarding policy yet".to_string(),
			)
		})?;
		let short_channel_id = dest.get_inbound_payment_scid().ok_or_else(|| {
			FixedRouteError::ChannelCannotCarry(
				"the destination has no short channel id yet".to_string(),
			)
		})?;
		let loop_back = LoopBack {
			our_node_id: self.channel_manager.get_our_node_id(),
			short_channel_id,
			announced: dest.is_announced,
			fee_base_msat: policy.fee_base_msat,
			fee_proportional_millionths: policy.fee_proportional_millionths,
			cltv_expiry_delta: policy.cltv_expiry_delta,
		};
		let last_hop_fee_msat = loop_back.fee_msat(amount_msat);
		let to_peer_budget_msat = max_fee_msat.checked_sub(last_hop_fee_msat).ok_or_else(|| {
			FixedRouteError::NoRoute(format!(
				"the destination's peer alone charges {last_hop_fee_msat} msat, over the {max_fee_msat} msat cap"
			))
		})?;

		let mut payment_params = PaymentParameters::from_node_id(
			dest.counterparty.node_id,
			u32::from(policy.cltv_expiry_delta),
		);
		payment_params.previously_failed_channels = failed_channels.to_vec();
		// Never back through the destination channel itself on the way to its peer.
		payment_params.previously_failed_channels.push(short_channel_id);
		let mut route_params = RouteParameters::from_payment_params_and_value(
			payment_params,
			amount_msat + last_hop_fee_msat,
		);
		route_params.max_total_routing_fee_msat = Some(to_peer_budget_msat);

		let route = self.find_route_via(source, route_params)?;
		let path =
			route.paths.into_iter().next().ok_or_else(|| {
				FixedRouteError::NoRoute("the router returned no path".to_string())
			})?;
		let path = loop_back.close(
			path,
			self.channel_manager.node_features(),
			amount_msat,
			final_cltv_expiry_delta,
		);
		Ok(Route { paths: vec![path], route_params: None })
	}

	/// Sends `route` as a payment with `payment_hash` and `payment_secret`, tracked under
	/// `payment_id`. LDK does not retry it; watch [`Self::subscribe_payment_outcomes`].
	///
	/// The payment is not added to the node's payment store: for a rebalance its id would
	/// collide with the inbound side's record, and the caller reports the outcome itself.
	pub fn send_route(
		&self, route: Route, payment_hash: PaymentHash, payment_secret: PaymentSecret,
		payment_id: PaymentId,
	) -> Result<(), FixedRouteError> {
		self.ensure_running()?;
		let amount_msat = route.get_total_amount();
		let fee_msat = route.get_total_fees();
		self.channel_manager
			.send_payment_with_route(
				route,
				payment_hash,
				RecipientOnionFields::secret_only(payment_secret),
				payment_id,
			)
			.map_err(|e| FixedRouteError::SendFailed(format!("{e:?}")))?;
		log_info!(
			self.logger,
			"Sent {}msat over a fixed route (fee {}msat) with payment id {}",
			amount_msat,
			fee_msat,
			payment_id
		);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::secp256k1::{Secp256k1, SecretKey};

	fn key(byte: u8) -> PublicKey {
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[byte; 32]).unwrap())
	}

	fn hop(pubkey: PublicKey, scid: u64, fee_msat: u64, cltv: u32) -> RouteHop {
		RouteHop {
			pubkey,
			node_features: NodeFeatures::empty(),
			short_channel_id: scid,
			channel_features: ChannelFeatures::empty(),
			fee_msat,
			cltv_expiry_delta: cltv,
			maybe_announced_channel: true,
		}
	}

	#[test]
	fn closing_the_loop_hands_the_peer_its_fee_and_delivers_the_amount_to_us() {
		let (us, strike, middle, peer) = (key(1), key(2), key(3), key(4));
		let loop_back = LoopBack {
			our_node_id: us,
			short_channel_id: 77,
			announced: true,
			fee_base_msat: 1_000,
			fee_proportional_millionths: 100,
			cltv_expiry_delta: 40,
		};
		let amount = 2_000_000_000;
		let peer_fee = loop_back.fee_msat(amount);
		assert_eq!(peer_fee, 1_000 + 200_000);

		// What the router returns for paying the peer amount + peer_fee: the last hop carries
		// the final value, the hops before it their own forwarding fees.
		let path = Path {
			hops: vec![
				hop(strike, 10, 5_000, 80),
				hop(middle, 11, 3_000, 144),
				hop(peer, 12, amount + peer_fee, 40),
			],
			blinded_tail: None,
		};
		let before = path.fee_msat();
		let closed = loop_back.close(path, NodeFeatures::empty(), amount, 144);

		assert_eq!(closed.hops.len(), 4);
		let last = closed.hops.last().unwrap();
		assert_eq!(
			(last.pubkey, last.short_channel_id, last.fee_msat, last.cltv_expiry_delta),
			(us, 77, amount, 144)
		);
		let peer_hop = &closed.hops[2];
		assert_eq!((peer_hop.fee_msat, peer_hop.cltv_expiry_delta), (peer_fee, 40));
		// Everything before the peer is untouched, and the loop costs exactly the old route's
		// fees plus the peer's, delivering the amount.
		assert_eq!(closed.hops[0].fee_msat, 5_000);
		assert_eq!(closed.final_value_msat(), amount);
		assert_eq!(closed.fee_msat(), before + peer_fee);
	}

	#[test]
	fn outcomes_name_their_payment() {
		let id = PaymentId([7; 32]);
		let sent = PaymentOutcome::Sent {
			payment_id: id,
			payment_preimage: PaymentPreimage([1; 32]),
			fee_paid_msat: None,
		};
		assert_eq!(sent.payment_id(), id);
		assert_eq!(
			PaymentOutcome::PathFailed {
				payment_id: id,
				failed_channel: Some(1),
				permanently: false
			}
			.payment_id(),
			id
		);
		assert_eq!(PaymentOutcome::Failed { payment_id: id, reason: None }.payment_id(), id);
	}
}
