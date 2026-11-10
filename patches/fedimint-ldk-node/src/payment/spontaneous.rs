// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Holds a payment handler allowing to send spontaneous ("keysend") payments.

use crate::config::{Config, LDK_PAYMENT_RETRY_TIMEOUT};
use crate::error::Error;
use crate::logger::{log_error, log_info, LdkLogger, Logger};
use crate::payment::store::{PaymentDetails, PaymentDirection, PaymentKind, PaymentStatus};
use crate::payment::SendingParameters;
use crate::types::{ChannelManager, CustomTlvRecord, KeysManager, PaymentStore};

use lightning::ln::channelmanager::{PaymentId, RecipientOnionFields, Retry, RetryableSendFailure};
use lightning::routing::router::{PaymentParameters, RouteParameters};
use lightning::sign::EntropySource;

use lightning_types::payment::{PaymentHash, PaymentPreimage};

use bitcoin::secp256k1::PublicKey;

use std::sync::{Arc, RwLock};

// The default `final_cltv_expiry_delta` we apply when not set.
const LDK_DEFAULT_FINAL_CLTV_EXPIRY_DELTA: u32 = 144;

/// How many probe outcomes a subscriber that falls behind may miss before it is told so.
pub(crate) const PROBE_OUTCOME_CAPACITY: usize = 1024;

/// How one probe path ended, as LDK reported it with `ProbeSuccessful` or `ProbeFailed`.
///
/// LDK has already updated the scorer with it when it is published, so a route found after
/// receiving a failure takes that failure into account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOutcome {
	/// The id [`SpontaneousPayment::send_probe_paths_with_max_fee`] returned for the path.
	pub payment_id: PaymentId,
	/// Whether the probe reached its target.
	pub reached: bool,
	/// The channel the probe failed at, if it failed and LDK knows where.
	pub failed_channel: Option<u64>,
}

/// Where the event handler publishes probe outcomes.
pub(crate) type ProbeOutcomeSender = tokio::sync::broadcast::Sender<ProbeOutcome>;

/// A payment handler allowing to send spontaneous ("keysend") payments.
///
/// Should be retrieved by calling [`Node::spontaneous_payment`].
///
/// [`Node::spontaneous_payment`]: crate::Node::spontaneous_payment
pub struct SpontaneousPayment {
	runtime: Arc<RwLock<Option<Arc<tokio::runtime::Runtime>>>>,
	channel_manager: Arc<ChannelManager>,
	keys_manager: Arc<KeysManager>,
	payment_store: Arc<PaymentStore>,
	config: Arc<Config>,
	logger: Arc<Logger>,
	probe_outcomes: ProbeOutcomeSender,
}

impl SpontaneousPayment {
	pub(crate) fn new(
		runtime: Arc<RwLock<Option<Arc<tokio::runtime::Runtime>>>>,
		channel_manager: Arc<ChannelManager>, keys_manager: Arc<KeysManager>,
		payment_store: Arc<PaymentStore>, config: Arc<Config>, logger: Arc<Logger>,
		probe_outcomes: ProbeOutcomeSender,
	) -> Self {
		Self {
			runtime,
			channel_manager,
			keys_manager,
			payment_store,
			config,
			logger,
			probe_outcomes,
		}
	}

	/// Send a spontaneous aka. "keysend", payment.
	///
	/// If `sending_parameters` are provided they will override the default as well as the
	/// node-wide parameters configured via [`Config::sending_parameters`] on a per-field basis.
	pub fn send(
		&self, amount_msat: u64, node_id: PublicKey, sending_parameters: Option<SendingParameters>,
	) -> Result<PaymentId, Error> {
		self.send_inner(amount_msat, node_id, sending_parameters, None)
	}

	/// Send a spontaneous payment including a list of custom TLVs.
	pub fn send_with_custom_tlvs(
		&self, amount_msat: u64, node_id: PublicKey, sending_parameters: Option<SendingParameters>,
		custom_tlvs: Vec<CustomTlvRecord>,
	) -> Result<PaymentId, Error> {
		self.send_inner(amount_msat, node_id, sending_parameters, Some(custom_tlvs))
	}

	fn send_inner(
		&self, amount_msat: u64, node_id: PublicKey, sending_parameters: Option<SendingParameters>,
		custom_tlvs: Option<Vec<CustomTlvRecord>>,
	) -> Result<PaymentId, Error> {
		let rt_lock = self.runtime.read().unwrap();
		if rt_lock.is_none() {
			return Err(Error::NotRunning);
		}

		let payment_preimage = PaymentPreimage(self.keys_manager.get_secure_random_bytes());
		let payment_hash = PaymentHash::from(payment_preimage);
		let payment_id = PaymentId(payment_hash.0);

		if let Some(payment) = self.payment_store.get(&payment_id) {
			if payment.status == PaymentStatus::Pending
				|| payment.status == PaymentStatus::Succeeded
			{
				log_error!(self.logger, "Payment error: must not send duplicate payments.");
				return Err(Error::DuplicatePayment);
			}
		}

		let mut route_params = RouteParameters::from_payment_params_and_value(
			PaymentParameters::from_node_id(node_id, LDK_DEFAULT_FINAL_CLTV_EXPIRY_DELTA),
			amount_msat,
		);

		let override_params =
			sending_parameters.as_ref().or(self.config.sending_parameters.as_ref());
		if let Some(override_params) = override_params {
			override_params
				.max_total_routing_fee_msat
				.map(|f| route_params.max_total_routing_fee_msat = f.into());
			override_params
				.max_total_cltv_expiry_delta
				.map(|d| route_params.payment_params.max_total_cltv_expiry_delta = d);
			override_params.max_path_count.map(|p| route_params.payment_params.max_path_count = p);
			override_params
				.max_channel_saturation_power_of_half
				.map(|s| route_params.payment_params.max_channel_saturation_power_of_half = s);
		};

		let recipient_fields = match custom_tlvs {
			Some(tlvs) => RecipientOnionFields::spontaneous_empty()
				.with_custom_tlvs(tlvs.into_iter().map(|tlv| (tlv.type_num, tlv.value)).collect())
				.map_err(|e| {
					log_error!(self.logger, "Failed to send payment with custom TLVs: {:?}", e);
					Error::InvalidCustomTlvs
				})?,
			None => RecipientOnionFields::spontaneous_empty(),
		};

		match self.channel_manager.send_spontaneous_payment(
			Some(payment_preimage),
			recipient_fields,
			PaymentId(payment_hash.0),
			route_params,
			Retry::Timeout(LDK_PAYMENT_RETRY_TIMEOUT),
		) {
			Ok(_hash) => {
				log_info!(self.logger, "Initiated sending {}msat to {}.", amount_msat, node_id);

				let kind = PaymentKind::Spontaneous {
					hash: payment_hash,
					preimage: Some(payment_preimage),
				};
				let payment = PaymentDetails::new(
					payment_id,
					kind,
					Some(amount_msat),
					None,
					PaymentDirection::Outbound,
					PaymentStatus::Pending,
				);
				self.payment_store.insert(payment)?;

				Ok(payment_id)
			},
			Err(e) => {
				log_error!(self.logger, "Failed to send payment: {:?}", e);

				match e {
					RetryableSendFailure::DuplicatePayment => Err(Error::DuplicatePayment),
					_ => {
						let kind = PaymentKind::Spontaneous {
							hash: payment_hash,
							preimage: Some(payment_preimage),
						};
						let payment = PaymentDetails::new(
							payment_id,
							kind,
							Some(amount_msat),
							None,
							PaymentDirection::Outbound,
							PaymentStatus::Failed,
						);

						self.payment_store.insert(payment)?;
						Err(Error::PaymentSendingFailed)
					},
				}
			},
		}
	}

	/// Sends payment probes over all paths of a route that would be used to pay the given
	/// amount to the given `node_id`.
	///
	/// See [`Bolt11Payment::send_probes`] for more information.
	///
	/// [`Bolt11Payment::send_probes`]: crate::payment::Bolt11Payment
	pub fn send_probes(&self, amount_msat: u64, node_id: PublicKey) -> Result<(), Error> {
		let rt_lock = self.runtime.read().unwrap();
		if rt_lock.is_none() {
			return Err(Error::NotRunning);
		}

		let liquidity_limit_multiplier = Some(self.config.probing_liquidity_limit_multiplier);

		self.channel_manager
			.send_spontaneous_preflight_probes(
				node_id,
				amount_msat,
				LDK_DEFAULT_FINAL_CLTV_EXPIRY_DELTA,
				liquidity_limit_multiplier,
			)
			.map_err(|e| {
				log_error!(self.logger, "Failed to send payment probes: {:?}", e);
				Error::ProbeSendingFailed
			})?;

		Ok(())
	}

	/// Sends payment probes over all paths of a route that would be used to pay the given
	/// amount to the given `node_id`, looking only for routes that cost at most
	/// `max_total_routing_fee_msat`.
	///
	/// Unlike [`Self::send_probes`], which uses LDK's default fee limit, this lets the caller
	/// probe the paths a payment with that fee budget would take, so the scorer learns about
	/// exactly those. Returns the number of probes sent, which is zero if every path was skipped,
	/// e.g. because it has a single hop or would put our first hop under the liquidity limit.
	/// The caller gets no error back when nothing was sent, so it decides how loudly to report it.
	pub fn send_probes_with_max_fee(
		&self, amount_msat: u64, node_id: PublicKey, max_total_routing_fee_msat: u64,
	) -> Result<usize, Error> {
		self.send_probe_paths_with_max_fee(amount_msat, node_id, max_total_routing_fee_msat)
			.map(|ids| ids.len())
	}

	/// Like [`Self::send_probes_with_max_fee`], but returns the id of each probe path sent, so
	/// the caller can match them with the outcomes from [`Self::subscribe_probe_outcomes`].
	/// Subscribe before sending, or an outcome may arrive before the subscription.
	pub fn send_probe_paths_with_max_fee(
		&self, amount_msat: u64, node_id: PublicKey, max_total_routing_fee_msat: u64,
	) -> Result<Vec<PaymentId>, Error> {
		let rt_lock = self.runtime.read().unwrap();
		if rt_lock.is_none() {
			return Err(Error::NotRunning);
		}

		let payment_params =
			PaymentParameters::from_node_id(node_id, LDK_DEFAULT_FINAL_CLTV_EXPIRY_DELTA);
		let mut route_params =
			RouteParameters::from_payment_params_and_value(payment_params, amount_msat);
		route_params.max_total_routing_fee_msat = Some(max_total_routing_fee_msat);

		let liquidity_limit_multiplier = Some(self.config.probing_liquidity_limit_multiplier);

		let probes = self
			.channel_manager
			.send_preflight_probes(route_params, liquidity_limit_multiplier)
			.map_err(|_| Error::ProbeSendingFailed)?;

		Ok(probes.into_iter().map(|(_, payment_id)| payment_id).collect())
	}

	/// Outcomes of all probes sent from now on, one per path.
	pub fn subscribe_probe_outcomes(&self) -> tokio::sync::broadcast::Receiver<ProbeOutcome> {
		self.probe_outcomes.subscribe()
	}
}
