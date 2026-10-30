// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Holds a payment handler allowing to create and pay [BOLT 11] invoices.
//!
//! [BOLT 11]: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md

use crate::config::{Config, LDK_PAYMENT_RETRY_TIMEOUT};
use crate::connection::ConnectionManager;
use crate::data_store::DataStoreUpdateResult;
use crate::error::Error;
use crate::liquidity::LiquiditySource;
use crate::logger::{log_error, log_info, LdkLogger, Logger};
use crate::payment::store::{
	LSPFeeLimits, PaymentDetails, PaymentDetailsUpdate, PaymentDirection, PaymentKind,
	PaymentStatus,
};
use crate::payment::SendingParameters;
use crate::peer_store::{PeerInfo, PeerStore};
use crate::types::{ChannelManager, KeysManager, PaymentStore};

use lightning::ln::bolt11_payment;
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::channelmanager::{
	Bolt11InvoiceParameters, PaymentId, RecipientOnionFields, Retry, RetryableSendFailure,
};
use lightning::routing::gossip::RoutingFees;
use lightning::routing::router::{PaymentParameters, RouteParameters};
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning::sign::{NodeSigner, Recipient};

use lightning_types::payment::{PaymentHash, PaymentPreimage};

use lightning_invoice::Bolt11Invoice as LdkBolt11Invoice;
use lightning_invoice::Bolt11InvoiceDescription as LdkBolt11InvoiceDescription;
use lightning_invoice::InvoiceBuilder;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::Hash;

use std::sync::{Arc, RwLock};

/// How many channels to route hint peers an invoice gets a hint for, best inbound first.
const ROUTE_HINT_PEER_HINTS: usize = 2;

#[cfg(not(feature = "uniffi"))]
type Bolt11Invoice = LdkBolt11Invoice;
#[cfg(feature = "uniffi")]
type Bolt11Invoice = Arc<crate::uniffi_types::Bolt11Invoice>;

#[cfg(not(feature = "uniffi"))]
pub(crate) fn maybe_wrap_invoice(invoice: LdkBolt11Invoice) -> Bolt11Invoice {
	invoice
}
#[cfg(feature = "uniffi")]
pub(crate) fn maybe_wrap_invoice(invoice: LdkBolt11Invoice) -> Bolt11Invoice {
	Arc::new(invoice.into())
}

#[cfg(not(feature = "uniffi"))]
pub fn maybe_convert_invoice(invoice: &Bolt11Invoice) -> &LdkBolt11Invoice {
	invoice
}
#[cfg(feature = "uniffi")]
pub fn maybe_convert_invoice(invoice: &Bolt11Invoice) -> &LdkBolt11Invoice {
	&invoice.inner
}

#[cfg(not(feature = "uniffi"))]
type Bolt11InvoiceDescription = LdkBolt11InvoiceDescription;
#[cfg(feature = "uniffi")]
type Bolt11InvoiceDescription = crate::uniffi_types::Bolt11InvoiceDescription;

macro_rules! maybe_convert_description {
	($description: expr) => {{
		#[cfg(not(feature = "uniffi"))]
		{
			$description
		}
		#[cfg(feature = "uniffi")]
		{
			&LdkBolt11InvoiceDescription::try_from($description)?
		}
	}};
}

/// A payment handler allowing to create and pay [BOLT 11] invoices.
///
/// Should be retrieved by calling [`Node::bolt11_payment`].
///
/// [BOLT 11]: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
/// [`Node::bolt11_payment`]: crate::Node::bolt11_payment
pub struct Bolt11Payment {
	runtime: Arc<RwLock<Option<Arc<tokio::runtime::Runtime>>>>,
	channel_manager: Arc<ChannelManager>,
	connection_manager: Arc<ConnectionManager<Arc<Logger>>>,
	liquidity_source: Option<Arc<LiquiditySource<Arc<Logger>>>>,
	payment_store: Arc<PaymentStore>,
	peer_store: Arc<PeerStore<Arc<Logger>>>,
	config: Arc<Config>,
	keys_manager: Arc<KeysManager>,
	logger: Arc<Logger>,
}

impl Bolt11Payment {
	pub(crate) fn new(
		runtime: Arc<RwLock<Option<Arc<tokio::runtime::Runtime>>>>,
		channel_manager: Arc<ChannelManager>,
		connection_manager: Arc<ConnectionManager<Arc<Logger>>>,
		liquidity_source: Option<Arc<LiquiditySource<Arc<Logger>>>>,
		payment_store: Arc<PaymentStore>, peer_store: Arc<PeerStore<Arc<Logger>>>,
		config: Arc<Config>, keys_manager: Arc<KeysManager>, logger: Arc<Logger>,
	) -> Self {
		Self {
			runtime,
			channel_manager,
			connection_manager,
			liquidity_source,
			payment_store,
			peer_store,
			config,
			keys_manager,
			logger,
		}
	}

	/// Send a payment given an invoice.
	///
	/// If `sending_parameters` are provided they will override the default as well as the
	/// node-wide parameters configured via [`Config::sending_parameters`] on a per-field basis.
	pub fn send(
		&self, invoice: &Bolt11Invoice, sending_parameters: Option<SendingParameters>,
	) -> Result<PaymentId, Error> {
		let invoice = maybe_convert_invoice(invoice);
		let rt_lock = self.runtime.read().unwrap();
		if rt_lock.is_none() {
			return Err(Error::NotRunning);
		}

		let (payment_hash, recipient_onion, mut route_params) = bolt11_payment::payment_parameters_from_invoice(&invoice).map_err(|_| {
			log_error!(self.logger, "Failed to send payment due to the given invoice being \"zero-amount\". Please use send_using_amount instead.");
			Error::InvalidInvoice
		})?;

		let payment_id = PaymentId(invoice.payment_hash().to_byte_array());
		if let Some(payment) = self.payment_store.get(&payment_id) {
			if payment.status == PaymentStatus::Pending
				|| payment.status == PaymentStatus::Succeeded
			{
				log_error!(self.logger, "Payment error: an invoice must not be paid twice.");
				return Err(Error::DuplicatePayment);
			}
		}

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

		let payment_secret = Some(*invoice.payment_secret());
		let retry_strategy = Retry::Timeout(LDK_PAYMENT_RETRY_TIMEOUT);

		match self.channel_manager.send_payment(
			payment_hash,
			recipient_onion,
			payment_id,
			route_params,
			retry_strategy,
		) {
			Ok(()) => {
				let payee_pubkey = invoice.recover_payee_pub_key();
				let amt_msat = invoice.amount_milli_satoshis().unwrap();
				log_info!(self.logger, "Initiated sending {}msat to {}", amt_msat, payee_pubkey);

				let kind = PaymentKind::Bolt11 {
					hash: payment_hash,
					preimage: None,
					secret: payment_secret,
				};
				let payment = PaymentDetails::new(
					payment_id,
					kind,
					invoice.amount_milli_satoshis(),
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
						let kind = PaymentKind::Bolt11 {
							hash: payment_hash,
							preimage: None,
							secret: payment_secret,
						};
						let payment = PaymentDetails::new(
							payment_id,
							kind,
							invoice.amount_milli_satoshis(),
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

	/// Send a payment given an invoice and an amount in millisatoshis.
	///
	/// This will fail if the amount given is less than the value required by the given invoice.
	///
	/// This can be used to pay a so-called "zero-amount" invoice, i.e., an invoice that leaves the
	/// amount paid to be determined by the user.
	///
	/// If `sending_parameters` are provided they will override the default as well as the
	/// node-wide parameters configured via [`Config::sending_parameters`] on a per-field basis.
	pub fn send_using_amount(
		&self, invoice: &Bolt11Invoice, amount_msat: u64,
		sending_parameters: Option<SendingParameters>,
	) -> Result<PaymentId, Error> {
		let invoice = maybe_convert_invoice(invoice);
		let rt_lock = self.runtime.read().unwrap();
		if rt_lock.is_none() {
			return Err(Error::NotRunning);
		}

		if let Some(invoice_amount_msat) = invoice.amount_milli_satoshis() {
			if amount_msat < invoice_amount_msat {
				log_error!(
					self.logger,
					"Failed to pay as the given amount needs to be at least the invoice amount: required {}msat, gave {}msat.", invoice_amount_msat, amount_msat);
				return Err(Error::InvalidAmount);
			}
		}

		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_id = PaymentId(invoice.payment_hash().to_byte_array());
		if let Some(payment) = self.payment_store.get(&payment_id) {
			if payment.status == PaymentStatus::Pending
				|| payment.status == PaymentStatus::Succeeded
			{
				log_error!(self.logger, "Payment error: an invoice must not be paid twice.");
				return Err(Error::DuplicatePayment);
			}
		}

		let payment_secret = invoice.payment_secret();
		let expiry_time = invoice.duration_since_epoch().saturating_add(invoice.expiry_time());
		let mut payment_params = PaymentParameters::from_node_id(
			invoice.recover_payee_pub_key(),
			invoice.min_final_cltv_expiry_delta() as u32,
		)
		.with_expiry_time(expiry_time.as_secs())
		.with_route_hints(invoice.route_hints())
		.map_err(|_| Error::InvalidInvoice)?;
		if let Some(features) = invoice.features() {
			payment_params = payment_params
				.with_bolt11_features(features.clone())
				.map_err(|_| Error::InvalidInvoice)?;
		}
		let mut route_params =
			RouteParameters::from_payment_params_and_value(payment_params, amount_msat);

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

		let retry_strategy = Retry::Timeout(LDK_PAYMENT_RETRY_TIMEOUT);
		let recipient_fields = RecipientOnionFields::secret_only(*payment_secret);

		match self.channel_manager.send_payment(
			payment_hash,
			recipient_fields,
			payment_id,
			route_params,
			retry_strategy,
		) {
			Ok(()) => {
				let payee_pubkey = invoice.recover_payee_pub_key();
				log_info!(
					self.logger,
					"Initiated sending {} msat to {}",
					amount_msat,
					payee_pubkey
				);

				let kind = PaymentKind::Bolt11 {
					hash: payment_hash,
					preimage: None,
					secret: Some(*payment_secret),
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
						let kind = PaymentKind::Bolt11 {
							hash: payment_hash,
							preimage: None,
							secret: Some(*payment_secret),
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

	/// Allows to attempt manually claiming payments with the given preimage that have previously
	/// been registered via [`receive_for_hash`] or [`receive_variable_amount_for_hash`].
	///
	/// This should be called in reponse to a [`PaymentClaimable`] event as soon as the preimage is
	/// available.
	///
	/// Will check that the payment is known, and that the given preimage and claimable amount
	/// match our expectations before attempting to claim the payment, and will return an error
	/// otherwise.
	///
	/// When claiming the payment has succeeded, a [`PaymentReceived`] event will be emitted.
	///
	/// [`receive_for_hash`]: Self::receive_for_hash
	/// [`receive_variable_amount_for_hash`]: Self::receive_variable_amount_for_hash
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	/// [`PaymentReceived`]: crate::Event::PaymentReceived
	pub fn claim_for_hash(
		&self, payment_hash: PaymentHash, claimable_amount_msat: u64, preimage: PaymentPreimage,
	) -> Result<(), Error> {
		let payment_id = PaymentId(payment_hash.0);

		let expected_payment_hash = PaymentHash(Sha256::hash(&preimage.0).to_byte_array());

		if expected_payment_hash != payment_hash {
			log_error!(
				self.logger,
				"Failed to manually claim payment as the given preimage doesn't match the hash {}",
				payment_hash
			);
			return Err(Error::InvalidPaymentPreimage);
		}

		if let Some(details) = self.payment_store.get(&payment_id) {
			if let Some(expected_amount_msat) = details.amount_msat {
				if claimable_amount_msat < expected_amount_msat {
					log_error!(
						self.logger,
						"Failed to manually claim payment {} as the claimable amount is less than expected",
						payment_id
					);
					return Err(Error::InvalidAmount);
				}
			}
		} else {
			log_error!(
				self.logger,
				"Failed to manually claim unknown payment with hash: {}",
				payment_hash
			);
			return Err(Error::InvalidPaymentHash);
		}

		self.channel_manager.claim_funds(preimage);
		Ok(())
	}

	/// Allows to manually fail payments with the given hash that have previously
	/// been registered via [`receive_for_hash`] or [`receive_variable_amount_for_hash`].
	///
	/// This should be called in reponse to a [`PaymentClaimable`] event if the payment needs to be
	/// failed back, e.g., if the correct preimage can't be retrieved in time before the claim
	/// deadline has been reached.
	///
	/// Will check that the payment is known before failing the payment, and will return an error
	/// otherwise.
	///
	/// [`receive_for_hash`]: Self::receive_for_hash
	/// [`receive_variable_amount_for_hash`]: Self::receive_variable_amount_for_hash
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	pub fn fail_for_hash(&self, payment_hash: PaymentHash) -> Result<(), Error> {
		let payment_id = PaymentId(payment_hash.0);

		let update = PaymentDetailsUpdate {
			status: Some(PaymentStatus::Failed),
			..PaymentDetailsUpdate::new(payment_id)
		};

		match self.payment_store.update(&update) {
			Ok(DataStoreUpdateResult::Updated) | Ok(DataStoreUpdateResult::Unchanged) => (),
			Ok(DataStoreUpdateResult::NotFound) => {
				log_error!(
					self.logger,
					"Failed to manually fail unknown payment with hash {}",
					payment_hash,
				);
				return Err(Error::InvalidPaymentHash);
			},
			Err(e) => {
				log_error!(
					self.logger,
					"Failed to manually fail payment with hash {}: {}",
					payment_hash,
					e
				);
				return Err(e);
			},
		}

		self.channel_manager.fail_htlc_backwards(&payment_hash);
		Ok(())
	}

	/// Returns a payable invoice that can be used to request and receive a payment of the amount
	/// given.
	///
	/// The inbound payment will be automatically claimed upon arrival.
	pub fn receive(
		&self, amount_msat: u64, description: &Bolt11InvoiceDescription, expiry_secs: u32,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_convert_description!(description);
		let invoice = self.receive_inner(Some(amount_msat), description, expiry_secs, None)?;
		Ok(maybe_wrap_invoice(invoice))
	}

	/// Returns a payable invoice that can be used to request a payment of the amount
	/// given for the given payment hash.
	///
	/// We will register the given payment hash and emit a [`PaymentClaimable`] event once
	/// the inbound payment arrives.
	///
	/// **Note:** users *MUST* handle this event and claim the payment manually via
	/// [`claim_for_hash`] as soon as they have obtained access to the preimage of the given
	/// payment hash. If they're unable to obtain the preimage, they *MUST* immediately fail the payment via
	/// [`fail_for_hash`].
	///
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	/// [`claim_for_hash`]: Self::claim_for_hash
	/// [`fail_for_hash`]: Self::fail_for_hash
	pub fn receive_for_hash(
		&self, amount_msat: u64, description: &Bolt11InvoiceDescription, expiry_secs: u32,
		payment_hash: PaymentHash,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_convert_description!(description);
		let invoice =
			self.receive_inner(Some(amount_msat), description, expiry_secs, Some(payment_hash))?;
		Ok(maybe_wrap_invoice(invoice))
	}

	/// Returns a payable invoice that can be used to request and receive a payment for which the
	/// amount is to be determined by the user, also known as a "zero-amount" invoice.
	///
	/// The inbound payment will be automatically claimed upon arrival.
	pub fn receive_variable_amount(
		&self, description: &Bolt11InvoiceDescription, expiry_secs: u32,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_convert_description!(description);
		let invoice = self.receive_inner(None, description, expiry_secs, None)?;
		Ok(maybe_wrap_invoice(invoice))
	}

	/// Returns a payable invoice that can be used to request a payment for the given payment hash
	/// and the amount to be determined by the user, also known as a "zero-amount" invoice.
	///
	/// We will register the given payment hash and emit a [`PaymentClaimable`] event once
	/// the inbound payment arrives.
	///
	/// **Note:** users *MUST* handle this event and claim the payment manually via
	/// [`claim_for_hash`] as soon as they have obtained access to the preimage of the given
	/// payment hash. If they're unable to obtain the preimage, they *MUST* immediately fail the payment via
	/// [`fail_for_hash`].
	///
	/// [`PaymentClaimable`]: crate::Event::PaymentClaimable
	/// [`claim_for_hash`]: Self::claim_for_hash
	/// [`fail_for_hash`]: Self::fail_for_hash
	pub fn receive_variable_amount_for_hash(
		&self, description: &Bolt11InvoiceDescription, expiry_secs: u32, payment_hash: PaymentHash,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_convert_description!(description);
		let invoice = self.receive_inner(None, description, expiry_secs, Some(payment_hash))?;
		Ok(maybe_wrap_invoice(invoice))
	}

	pub(crate) fn receive_inner(
		&self, amount_msat: Option<u64>, invoice_description: &LdkBolt11InvoiceDescription,
		expiry_secs: u32, manual_claim_payment_hash: Option<PaymentHash>,
	) -> Result<LdkBolt11Invoice, Error> {
		let invoice = {
			let invoice_params = Bolt11InvoiceParameters {
				amount_msats: amount_msat,
				description: invoice_description.clone(),
				invoice_expiry_delta_secs: Some(expiry_secs),
				payment_hash: manual_claim_payment_hash,
				..Default::default()
			};

			let invoice = match self.channel_manager.create_bolt11_invoice(invoice_params) {
				Ok(inv) => inv,
				Err(e) => {
					log_error!(self.logger, "Failed to create invoice: {}", e);
					return Err(Error::InvoiceCreationFailed);
				},
			};
			let invoice = self.add_route_hint_peer_hint(invoice, invoice_description)?;
			log_info!(self.logger, "Invoice created: {}", invoice);
			invoice
		};

		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_secret = invoice.payment_secret();
		let id = PaymentId(payment_hash.0);
		let preimage = if manual_claim_payment_hash.is_none() {
			// If the user hasn't registered a custom payment hash, we're positive ChannelManager
			// will know the preimage at this point.
			let res = self
				.channel_manager
				.get_payment_preimage(payment_hash, payment_secret.clone())
				.ok();
			debug_assert!(res.is_some(), "We just let ChannelManager create an inbound payment, it can't have forgotten the preimage by now.");
			res
		} else {
			None
		};
		let kind = PaymentKind::Bolt11 {
			hash: payment_hash,
			preimage,
			secret: Some(payment_secret.clone()),
		};
		let payment = PaymentDetails::new(
			id,
			kind,
			amount_msat,
			None,
			PaymentDirection::Inbound,
			PaymentStatus::Pending,
		);
		self.payment_store.insert(payment)?;

		Ok(invoice)
	}

	/// Re-issues `invoice` with extra route hints through the [`ROUTE_HINT_PEER_HINTS`] usable
	/// channels to [`Config::route_hint_peers`] with the most inbound capacity, or returns it
	/// unchanged if there is none.
	///
	/// More than one hint lets a payer split a payment across channels, so a receive can be larger
	/// than any single channel's inbound capacity.
	///
	/// The payment hash and secret are kept, so the inbound payment `ChannelManager` registered
	/// for `invoice` still matches.
	fn add_route_hint_peer_hint(
		&self, invoice: LdkBolt11Invoice, invoice_description: &LdkBolt11InvoiceDescription,
	) -> Result<LdkBolt11Invoice, Error> {
		if self.config.route_hint_peers.is_empty() {
			return Ok(invoice);
		}

		let existing_hints = invoice.route_hints();
		let mut candidates: Vec<(ChannelDetails, RouteHint)> = self
			.channel_manager
			.list_usable_channels()
			.into_iter()
			.filter(|c| self.config.route_hint_peers.contains(&c.counterparty.node_id))
			.filter_map(|c| route_hint_for_channel(&c).map(|hint| (c, hint)))
			.filter(|(_, hint)| {
				!existing_hints.iter().any(|h| {
					h.0.iter().any(|hop| hop.short_channel_id == hint.0[0].short_channel_id)
				})
			})
			.collect();
		candidates.sort_by_key(|(c, _)| std::cmp::Reverse(c.inbound_capacity_msat));
		candidates.truncate(ROUTE_HINT_PEER_HINTS);
		if candidates.is_empty() {
			log_info!(self.logger, "No usable channel to a route hint peer, leaving invoice as is");
			return Ok(invoice);
		}

		let mut builder = InvoiceBuilder::new(invoice.currency())
			.invoice_description(invoice_description.clone())
			.duration_since_epoch(invoice.duration_since_epoch())
			.payee_pub_key(self.channel_manager.get_our_node_id())
			.payment_hash(*invoice.payment_hash())
			.payment_secret(*invoice.payment_secret())
			.basic_mpp()
			.min_final_cltv_expiry_delta(invoice.min_final_cltv_expiry_delta())
			.expiry_time(invoice.expiry_time());
		if let Some(amount_msat) = invoice.amount_milli_satoshis() {
			builder = builder.amount_milli_satoshis(amount_msat);
		}
		for existing_hint in existing_hints {
			builder = builder.private_route(existing_hint);
		}
		for (_, hint) in &candidates {
			builder = builder.private_route(hint.clone());
		}

		let raw_invoice = builder.build_raw().map_err(|e| {
			log_error!(self.logger, "Failed to rebuild invoice with route hint: {}", e);
			Error::InvoiceCreationFailed
		})?;
		let signature = self.keys_manager.sign_invoice(&raw_invoice, Recipient::Node);
		let signed_invoice = raw_invoice.sign(|_| signature).map_err(|()| {
			log_error!(self.logger, "Failed to sign invoice with route hint");
			Error::InvoiceCreationFailed
		})?;
		let invoice = LdkBolt11Invoice::from_signed(signed_invoice).map_err(|e| {
			log_error!(self.logger, "Invoice with route hint is invalid: {}", e);
			Error::InvoiceCreationFailed
		})?;

		for (channel, _) in &candidates {
			log_info!(
				self.logger,
				"Added route hint via channel {} with {} ({} msat inbound)",
				channel.channel_id,
				channel.counterparty.node_id,
				channel.inbound_capacity_msat
			);
		}
		Ok(invoice)
	}

	/// Returns a payable invoice that can be used to request a payment of the amount given and
	/// receive it via a newly created just-in-time (JIT) channel.
	///
	/// When the returned invoice is paid, the configured [LSPS2]-compliant LSP will open a channel
	/// to us, supplying just-in-time inbound liquidity.
	///
	/// If set, `max_total_lsp_fee_limit_msat` will limit how much fee we allow the LSP to take for opening the
	/// channel to us. We'll use its cheapest offer otherwise.
	///
	/// [LSPS2]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/blob/main/LSPS2/README.md
	pub fn receive_via_jit_channel(
		&self, amount_msat: u64, description: &Bolt11InvoiceDescription, expiry_secs: u32,
		max_total_lsp_fee_limit_msat: Option<u64>,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_convert_description!(description);
		let invoice = self.receive_via_jit_channel_inner(
			Some(amount_msat),
			description,
			expiry_secs,
			max_total_lsp_fee_limit_msat,
			None,
		)?;
		Ok(maybe_wrap_invoice(invoice))
	}

	/// Returns a payable invoice that can be used to request a variable amount payment (also known
	/// as "zero-amount" invoice) and receive it via a newly created just-in-time (JIT) channel.
	///
	/// When the returned invoice is paid, the configured [LSPS2]-compliant LSP will open a channel
	/// to us, supplying just-in-time inbound liquidity.
	///
	/// If set, `max_proportional_lsp_fee_limit_ppm_msat` will limit how much proportional fee, in
	/// parts-per-million millisatoshis, we allow the LSP to take for opening the channel to us.
	/// We'll use its cheapest offer otherwise.
	///
	/// [LSPS2]: https://github.com/BitcoinAndLightningLayerSpecs/lsp/blob/main/LSPS2/README.md
	pub fn receive_variable_amount_via_jit_channel(
		&self, description: &Bolt11InvoiceDescription, expiry_secs: u32,
		max_proportional_lsp_fee_limit_ppm_msat: Option<u64>,
	) -> Result<Bolt11Invoice, Error> {
		let description = maybe_convert_description!(description);
		let invoice = self.receive_via_jit_channel_inner(
			None,
			description,
			expiry_secs,
			None,
			max_proportional_lsp_fee_limit_ppm_msat,
		)?;
		Ok(maybe_wrap_invoice(invoice))
	}

	fn receive_via_jit_channel_inner(
		&self, amount_msat: Option<u64>, description: &LdkBolt11InvoiceDescription,
		expiry_secs: u32, max_total_lsp_fee_limit_msat: Option<u64>,
		max_proportional_lsp_fee_limit_ppm_msat: Option<u64>,
	) -> Result<LdkBolt11Invoice, Error> {
		let liquidity_source =
			self.liquidity_source.as_ref().ok_or(Error::LiquiditySourceUnavailable)?;

		let (node_id, address) =
			liquidity_source.get_lsps2_lsp_details().ok_or(Error::LiquiditySourceUnavailable)?;

		let rt_lock = self.runtime.read().unwrap();
		let runtime = rt_lock.as_ref().unwrap();

		let peer_info = PeerInfo { node_id, address };

		let con_node_id = peer_info.node_id;
		let con_addr = peer_info.address.clone();
		let con_cm = Arc::clone(&self.connection_manager);

		// We need to use our main runtime here as a local runtime might not be around to poll
		// connection futures going forward.
		tokio::task::block_in_place(move || {
			runtime.block_on(async move {
				con_cm.connect_peer_if_necessary(con_node_id, con_addr).await
			})
		})?;

		log_info!(self.logger, "Connected to LSP {}@{}. ", peer_info.node_id, peer_info.address);

		let liquidity_source = Arc::clone(&liquidity_source);
		let (invoice, lsp_total_opening_fee, lsp_prop_opening_fee) =
			tokio::task::block_in_place(move || {
				runtime.block_on(async move {
					if let Some(amount_msat) = amount_msat {
						liquidity_source
							.lsps2_receive_to_jit_channel(
								amount_msat,
								description,
								expiry_secs,
								max_total_lsp_fee_limit_msat,
							)
							.await
							.map(|(invoice, total_fee)| (invoice, Some(total_fee), None))
					} else {
						liquidity_source
							.lsps2_receive_variable_amount_to_jit_channel(
								description,
								expiry_secs,
								max_proportional_lsp_fee_limit_ppm_msat,
							)
							.await
							.map(|(invoice, prop_fee)| (invoice, None, Some(prop_fee)))
					}
				})
			})?;

		// Register payment in payment store.
		let payment_hash = PaymentHash(invoice.payment_hash().to_byte_array());
		let payment_secret = invoice.payment_secret();
		let lsp_fee_limits = LSPFeeLimits {
			max_total_opening_fee_msat: lsp_total_opening_fee,
			max_proportional_opening_fee_ppm_msat: lsp_prop_opening_fee,
		};
		let id = PaymentId(payment_hash.0);
		let preimage =
			self.channel_manager.get_payment_preimage(payment_hash, payment_secret.clone()).ok();
		let kind = PaymentKind::Bolt11Jit {
			hash: payment_hash,
			preimage,
			secret: Some(payment_secret.clone()),
			counterparty_skimmed_fee_msat: None,
			lsp_fee_limits,
		};
		let payment = PaymentDetails::new(
			id,
			kind,
			amount_msat,
			None,
			PaymentDirection::Inbound,
			PaymentStatus::Pending,
		);
		self.payment_store.insert(payment)?;

		// Persist LSP peer to make sure we reconnect on restart.
		self.peer_store.add_peer(peer_info)?;

		Ok(invoice)
	}

	/// Sends payment probes over all paths of a route that would be used to pay the given invoice.
	///
	/// This may be used to send "pre-flight" probes, i.e., to train our scorer before conducting
	/// the actual payment. Note this is only useful if there likely is sufficient time for the
	/// probe to settle before sending out the actual payment, e.g., when waiting for user
	/// confirmation in a wallet UI.
	///
	/// Otherwise, there is a chance the probe could take up some liquidity needed to complete the
	/// actual payment. Users should therefore be cautious and might avoid sending probes if
	/// liquidity is scarce and/or they don't expect the probe to return before they send the
	/// payment. To mitigate this issue, channels with available liquidity less than the required
	/// amount times [`Config::probing_liquidity_limit_multiplier`] won't be used to send
	/// pre-flight probes.
	pub fn send_probes(&self, invoice: &Bolt11Invoice) -> Result<(), Error> {
		let invoice = maybe_convert_invoice(invoice);
		let rt_lock = self.runtime.read().unwrap();
		if rt_lock.is_none() {
			return Err(Error::NotRunning);
		}

		let (_payment_hash, _recipient_onion, route_params) = bolt11_payment::payment_parameters_from_invoice(&invoice).map_err(|_| {
			log_error!(self.logger, "Failed to send probes due to the given invoice being \"zero-amount\". Please use send_probes_using_amount instead.");
			Error::InvalidInvoice
		})?;

		let liquidity_limit_multiplier = Some(self.config.probing_liquidity_limit_multiplier);

		self.channel_manager
			.send_preflight_probes(route_params, liquidity_limit_multiplier)
			.map_err(|e| {
				log_error!(self.logger, "Failed to send payment probes: {:?}", e);
				Error::ProbeSendingFailed
			})?;

		Ok(())
	}

	/// Sends payment probes over all paths of a route that would be used to pay the given
	/// zero-value invoice using the given amount.
	///
	/// This can be used to send pre-flight probes for a so-called "zero-amount" invoice, i.e., an
	/// invoice that leaves the amount paid to be determined by the user.
	///
	/// See [`Self::send_probes`] for more information.
	pub fn send_probes_using_amount(
		&self, invoice: &Bolt11Invoice, amount_msat: u64,
	) -> Result<(), Error> {
		let invoice = maybe_convert_invoice(invoice);
		let rt_lock = self.runtime.read().unwrap();
		if rt_lock.is_none() {
			return Err(Error::NotRunning);
		}

		let (_payment_hash, _recipient_onion, route_params) = if let Some(invoice_amount_msat) =
			invoice.amount_milli_satoshis()
		{
			if amount_msat < invoice_amount_msat {
				log_error!(
					self.logger,
					"Failed to send probes as the given amount needs to be at least the invoice amount: required {}msat, gave {}msat.", invoice_amount_msat, amount_msat);
				return Err(Error::InvalidAmount);
			}

			bolt11_payment::payment_parameters_from_invoice(&invoice).map_err(|_| {
				log_error!(self.logger, "Failed to send probes due to the given invoice unexpectedly being \"zero-amount\".");
				Error::InvalidInvoice
			})?
		} else {
			bolt11_payment::payment_parameters_from_variable_amount_invoice(&invoice, amount_msat).map_err(|_| {
				log_error!(self.logger, "Failed to send probes due to the given invoice unexpectedly being not \"zero-amount\".");
				Error::InvalidInvoice
			})?
		};

		let liquidity_limit_multiplier = Some(self.config.probing_liquidity_limit_multiplier);

		self.channel_manager
			.send_preflight_probes(route_params, liquidity_limit_multiplier)
			.map_err(|e| {
				log_error!(self.logger, "Failed to send payment probes: {:?}", e);
				Error::ProbeSendingFailed
			})?;

		Ok(())
	}
}

/// Builds a single-hop route hint from the channel's counterparty to us, mirroring LDK's own
/// invoice route hints. Announced channels use their real SCID, which the counterparty forwards on
/// regardless of SCID alias support. Returns `None` while the counterparty has not sent us its
/// forwarding parameters yet.
fn route_hint_for_channel(channel: &ChannelDetails) -> Option<RouteHint> {
	let forwarding_info = channel.counterparty.forwarding_info.as_ref()?;
	let short_channel_id = if channel.is_announced {
		channel.short_channel_id.or(channel.inbound_scid_alias)?
	} else {
		channel.get_inbound_payment_scid()?
	};
	Some(RouteHint(vec![RouteHintHop {
		src_node_id: channel.counterparty.node_id,
		short_channel_id,
		fees: RoutingFees {
			base_msat: forwarding_info.fee_base_msat,
			proportional_millionths: forwarding_info.fee_proportional_millionths,
		},
		cltv_expiry_delta: forwarding_info.cltv_expiry_delta,
		htlc_minimum_msat: channel.inbound_htlc_minimum_msat,
		htlc_maximum_msat: channel.inbound_htlc_maximum_msat,
	}]))
}
