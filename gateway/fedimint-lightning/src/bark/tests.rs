use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::secp256k1::{SECP256K1, SecretKey};
use fedimint_core::Amount;
use fedimint_core::secp256k1::rand::rngs::OsRng;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::SafeUrl;
use futures::StreamExt as _;
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};
use serde_json::{Value, json};

use super::GatewayBarkClient;
use crate::{
    CreateInvoiceRequest, ILnRpcClient, InterceptPaymentResponse, InvoiceDescription,
    LightningRpcError, NO_INCOMING_CIRCUIT, PaymentAction, Preimage,
};

const TOKEN: &str = "test-token";

const PREIMAGE: [u8; 32] = [7; 32];

/// `htlc_send_expiry_delta` + `vtxo_exit_delta` reported by the fake barkd.
const REQUIRED_MAX_DELAY: u64 = 258 + 144;

/// Scriptable stand-in for barkd's REST API.
#[derive(Default)]
struct FakeBarkd {
    receives: Vec<Value>,
    hold_invoice_requests: Vec<Value>,
    settled: Vec<(String, String)>,
    abandoned: Vec<String>,
    completion_status: Option<StatusCode>,
    /// Successive answers for `GET /lightning/sends/{hash}`; the last one
    /// repeats. Hashes without an entry are unknown.
    send_states: BTreeMap<String, VecDeque<Value>>,
    pay_requests: Vec<Value>,
    pay_status: Option<StatusCode>,
    /// Send states barkd moves to once a payment is requested.
    states_after_pay: Vec<Value>,
}

type Shared = Arc<Mutex<FakeBarkd>>;

fn status_or_ok(status: Option<StatusCode>) -> Response {
    match status {
        Some(status) => (status, "scripted failure").into_response(),
        None => Json(json!({})).into_response(),
    }
}

async fn require_token(request: Request, next: Next) -> Response {
    let authorized = request
        .headers()
        .get("authorization")
        .is_some_and(|value| value == format!("Bearer {TOKEN}").as_str());
    if !authorized {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}

async fn ark_info() -> Json<Value> {
    Json(json!({
        "network": "regtest",
        "vtxo_exit_delta": 144,
        "htlc_send_expiry_delta": 258,
        "server_pubkey": "ignored",
    }))
}

async fn create_hold_invoice(State(state): State<Shared>, Json(body): Json<Value>) -> Json<Value> {
    let payment_hash = body["payment_hash"]
        .as_str()
        .expect("payment hash is sent")
        .parse()
        .expect("payment hash is valid");
    let amount_msat = body["amount_sat"].as_u64().expect("amount is sent") * 1000;
    state
        .lock()
        .expect("lock poisoned")
        .hold_invoice_requests
        .push(body);
    Json(json!({ "invoice": invoice(payment_hash, amount_msat).to_string() }))
}

async fn receives(State(state): State<Shared>) -> Json<Value> {
    Json(Value::Array(
        state.lock().expect("lock poisoned").receives.clone(),
    ))
}

async fn settle(
    State(state): State<Shared>,
    Path(hash): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let mut state = state.lock().expect("lock poisoned");
    let preimage = body["preimage"].as_str().expect("preimage is sent");
    state.settled.push((hash, preimage.to_string()));
    status_or_ok(state.completion_status)
}

async fn abandon(State(state): State<Shared>, Path(hash): Path<String>) -> Response {
    let mut state = state.lock().expect("lock poisoned");
    state.abandoned.push(hash);
    status_or_ok(state.completion_status)
}

async fn send_status(State(state): State<Shared>, Path(hash): Path<String>) -> Json<Value> {
    let mut state = state.lock().expect("lock poisoned");
    let Some(states) = state.send_states.get_mut(&hash) else {
        return Json(json!({ "payment_hash": hash, "state": "unknown" }));
    };
    let current = if states.len() > 1 {
        states.pop_front().expect("states are not empty")
    } else {
        states.front().expect("states are not empty").clone()
    };
    Json(current)
}

async fn pay(State(state): State<Shared>, Json(body): Json<Value>) -> Response {
    let mut state = state.lock().expect("lock poisoned");
    let invoice: Bolt11Invoice = body["destination"]
        .as_str()
        .expect("destination is sent")
        .parse()
        .expect("destination is an invoice");
    state.pay_requests.push(body);
    if !state.states_after_pay.is_empty() {
        let states = state.states_after_pay.clone().into();
        state
            .send_states
            .insert(invoice.payment_hash().to_string(), states);
    }
    match state.pay_status {
        Some(status) => (status, "scripted failure").into_response(),
        None => Json(json!({ "message": "Payment initiated successfully" })).into_response(),
    }
}

async fn spawn_fake_barkd(fake: FakeBarkd) -> (GatewayBarkClient, Shared) {
    let (url, state) = serve_fake_barkd(fake).await;
    (
        GatewayBarkClient::new(url, TOKEN.to_string(), node_id()),
        state,
    )
}

async fn serve_fake_barkd(fake: FakeBarkd) -> (SafeUrl, Shared) {
    let state = Arc::new(Mutex::new(fake));
    let api = Router::new()
        .route("/wallet/ark-info", get(ark_info))
        .route(
            "/wallet/connected",
            get(|| async { Json(json!({ "connected": true })) }),
        )
        .route(
            "/bitcoin/tip",
            get(|| async { Json(json!({ "tip_height": 812 })) }),
        )
        .route(
            "/lightning/receives/hold-invoice",
            post(create_hold_invoice),
        )
        .route("/lightning/receives", get(receives))
        .route("/lightning/receives/{hash}/settle", post(settle))
        .route("/lightning/receives/{hash}/abandon", post(abandon))
        .route("/lightning/sends/{hash}", get(send_status))
        .route("/lightning/pay", post(pay))
        .layer(middleware::from_fn(require_token))
        .with_state(state.clone());
    let router = Router::new().nest("/api/v1", api);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake barkd");
    let addr = listener.local_addr().expect("listener has an address");
    tokio::spawn(async move { axum::serve(listener, router).await });

    let url = SafeUrl::parse(&format!("http://{addr}/")).expect("valid url");
    (url, state)
}

fn node_id() -> fedimint_core::secp256k1::PublicKey {
    SecretKey::from_slice(&[3; 32])
        .expect("valid secret key")
        .public_key(SECP256K1)
}

fn invoice(payment_hash: sha256::Hash, amount_msat: u64) -> Bolt11Invoice {
    let sk = SecretKey::new(&mut OsRng);
    InvoiceBuilder::new(Currency::Regtest)
        .description(String::new())
        .payment_hash(payment_hash)
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .payment_secret(PaymentSecret([0; 32]))
        .amount_milli_satoshis(amount_msat)
        .build_signed(|m| SECP256K1.sign_ecdsa_recoverable(m, &sk))
        .expect("Invoice creation failed")
}

fn payment_hash() -> sha256::Hash {
    sha256::Hash::hash(&PREIMAGE)
}

fn hold_receive(hash: sha256::Hash, state: &str, hold: bool, amount_msat: u64) -> Value {
    json!({
        "payment_hash": hash.to_string(),
        "state": state,
        "invoice": invoice(hash, amount_msat).to_string(),
        "payment_preimage": null,
        "amount_sat": amount_msat / 1000,
        "htlc_vtxo_ids": [],
        "hold": hold,
    })
}

fn paid() -> Value {
    json!({ "state": "paid", "preimage": hex::encode(PREIMAGE) })
}

fn completion(action: PaymentAction) -> InterceptPaymentResponse {
    let (incoming_chan_id, htlc_id) = NO_INCOMING_CIRCUIT;
    InterceptPaymentResponse {
        incoming_chan_id,
        htlc_id,
        payment_hash: payment_hash(),
        action,
    }
}

#[tokio::test]
async fn info_reports_synthetic_node_id_and_ark_state() {
    let (client, _) = spawn_fake_barkd(FakeBarkd::default()).await;

    let info = client.info().await.expect("info succeeds");

    assert_eq!(info.pub_key, node_id());
    assert_eq!(info.network, "regtest");
    assert_eq!(info.block_height, 812);
    assert!(info.synced_to_chain);
}

#[tokio::test]
async fn create_invoice_requests_hold_invoice_for_hash() {
    let (client, state) = spawn_fake_barkd(FakeBarkd::default()).await;

    let response = client
        .create_invoice(CreateInvoiceRequest {
            payment_hash: Some(payment_hash()),
            amount_msat: 21_000,
            expiry_secs: 600,
            description: Some(InvoiceDescription::Direct("coffee".to_string())),
        })
        .await
        .expect("invoice is created");

    let invoice: Bolt11Invoice = response.invoice.parse().expect("valid invoice");
    assert_eq!(*invoice.payment_hash(), payment_hash());

    let requests = state
        .lock()
        .expect("lock poisoned")
        .hold_invoice_requests
        .clone();
    assert_eq!(
        requests,
        vec![json!({
            "amount_sat": 21,
            "payment_hash": payment_hash().to_string(),
            "description": "coffee",
            "expiry_secs": 600,
        })]
    );
}

#[tokio::test]
async fn create_invoice_rejects_what_bark_cannot_receive() {
    let (client, state) = spawn_fake_barkd(FakeBarkd::default()).await;
    let request = CreateInvoiceRequest {
        payment_hash: Some(payment_hash()),
        amount_msat: 21_000,
        expiry_secs: 600,
        description: None,
    };

    for request in [
        CreateInvoiceRequest {
            payment_hash: None,
            ..request.clone()
        },
        CreateInvoiceRequest {
            amount_msat: 21_001,
            ..request.clone()
        },
        CreateInvoiceRequest {
            description: Some(InvoiceDescription::Hash(sha256::Hash::all_zeros())),
            ..request.clone()
        },
    ] {
        assert!(client.create_invoice(request).await.is_err());
    }

    assert!(
        state
            .lock()
            .expect("lock poisoned")
            .hold_invoice_requests
            .is_empty()
    );
}

#[tokio::test]
async fn awaiting_hold_receives_are_forwarded_once() {
    let other_hash = sha256::Hash::hash(&[8; 32]);
    let (client, _) = spawn_fake_barkd(FakeBarkd {
        receives: vec![
            hold_receive(payment_hash(), "awaiting_preimage", true, 50_000),
            // A regular receive is claimed by barkd itself.
            hold_receive(other_hash, "awaiting_preimage", false, 60_000),
            hold_receive(
                sha256::Hash::hash(&[9; 32]),
                "awaiting_payment",
                true,
                70_000,
            ),
        ],
        ..FakeBarkd::default()
    })
    .await;
    let task_group = TaskGroup::new();

    let (mut stream, _client) = Box::new(client)
        .route_htlcs(&task_group)
        .await
        .expect("routing starts");

    let request = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("a request is forwarded")
        .expect("stream is open");
    assert_eq!(request.payment_hash, payment_hash());
    assert_eq!(request.incoming_amount_msat, 50_000);
    assert_eq!(request.amount_msat, 50_000);
    assert_eq!(
        (request.incoming_chan_id, request.htlc_id),
        NO_INCOMING_CIRCUIT
    );
    assert_eq!(request.short_channel_id, None);

    // Several poll intervals pass without the receive being forwarded again.
    assert!(
        tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .is_err()
    );

    task_group
        .shutdown_join_all(None)
        .await
        .expect("watcher shuts down");
}

#[tokio::test]
async fn settle_supplies_preimage_and_cancel_abandons() {
    let (client, state) = spawn_fake_barkd(FakeBarkd::default()).await;

    client
        .complete_htlc(completion(PaymentAction::Settle(Preimage(PREIMAGE))))
        .await
        .expect("settle succeeds");
    client
        .complete_htlc(completion(PaymentAction::Cancel))
        .await
        .expect("cancel succeeds");

    let state = state.lock().expect("lock poisoned");
    assert_eq!(
        state.settled,
        vec![(payment_hash().to_string(), hex::encode(PREIMAGE))]
    );
    assert_eq!(state.abandoned, vec![payment_hash().to_string()]);
}

#[tokio::test]
async fn completion_errors_distinguish_rejection_from_transient_failure() {
    let settle = || completion(PaymentAction::Settle(Preimage(PREIMAGE)));

    let (client, _) = spawn_fake_barkd(FakeBarkd {
        completion_status: Some(StatusCode::BAD_REQUEST),
        ..FakeBarkd::default()
    })
    .await;
    assert!(matches!(
        client.complete_htlc(settle()).await,
        Err(LightningRpcError::HtlcCompletionRejected { .. })
    ));

    let (client, _) = spawn_fake_barkd(FakeBarkd {
        completion_status: Some(StatusCode::INTERNAL_SERVER_ERROR),
        ..FakeBarkd::default()
    })
    .await;
    assert!(matches!(
        client.complete_htlc(settle()).await,
        Err(LightningRpcError::FailedToCompleteHtlc { .. })
    ));

    // Forwarded HTLCs are never intercepted, so their completion can't apply.
    let (client, state) = spawn_fake_barkd(FakeBarkd::default()).await;
    let forwarded = InterceptPaymentResponse {
        incoming_chan_id: 101,
        htlc_id: 0,
        ..settle()
    };
    assert!(matches!(
        client.complete_htlc(forwarded).await,
        Err(LightningRpcError::HtlcCompletionRejected { .. })
    ));
    assert!(state.lock().expect("lock poisoned").settled.is_empty());
}

#[tokio::test]
async fn pay_dispatches_and_returns_preimage() {
    let (client, state) = spawn_fake_barkd(FakeBarkd {
        states_after_pay: vec![json!({ "state": "htlcs_sent" }), paid()],
        ..FakeBarkd::default()
    })
    .await;

    let response = client
        .pay(
            invoice(payment_hash(), 100_000),
            REQUIRED_MAX_DELAY,
            Amount::from_msats(5_999),
        )
        .await
        .expect("payment succeeds");

    assert_eq!(response.preimage, Preimage(PREIMAGE));
    let pay_requests = state.lock().expect("lock poisoned").pay_requests.clone();
    assert_eq!(pay_requests.len(), 1);
    assert_eq!(pay_requests[0]["max_fee_sat"], 5);
}

#[tokio::test]
async fn pay_resumes_known_payment_without_checking_limits() {
    let mut fake = FakeBarkd::default();
    fake.send_states.insert(
        payment_hash().to_string(),
        vec![json!({ "state": "htlcs_sent" }), paid()].into(),
    );
    let (client, state) = spawn_fake_barkd(fake).await;

    // A resumed state machine may pass a placeholder `max_delay` of zero.
    let response = client
        .pay(invoice(payment_hash(), 100_000), 0, Amount::ZERO)
        .await
        .expect("resumed payment succeeds");

    assert_eq!(response.preimage, Preimage(PREIMAGE));
    assert!(state.lock().expect("lock poisoned").pay_requests.is_empty());
}

#[tokio::test]
async fn pay_reports_failure_and_failed_payment_stays_failed() {
    let (client, state) = spawn_fake_barkd(FakeBarkd {
        states_after_pay: vec![json!({ "state": "failed", "failure_reason": "no route" })],
        ..FakeBarkd::default()
    })
    .await;
    let invoice = invoice(payment_hash(), 100_000);

    for _ in 0..2 {
        assert!(matches!(
            client
                .pay(invoice.clone(), REQUIRED_MAX_DELAY, Amount::from_sats(10))
                .await,
            Err(LightningRpcError::FailedPayment { failure_reason }) if failure_reason == "no route"
        ));
    }

    assert_eq!(state.lock().expect("lock poisoned").pay_requests.len(), 1);
}

#[tokio::test]
async fn pay_refuses_insufficient_max_delay() {
    let (client, state) = spawn_fake_barkd(FakeBarkd::default()).await;

    assert!(
        client
            .pay(
                invoice(payment_hash(), 100_000),
                REQUIRED_MAX_DELAY - 1,
                Amount::from_sats(10),
            )
            .await
            .is_err()
    );
    assert!(state.lock().expect("lock poisoned").pay_requests.is_empty());
}

#[tokio::test]
async fn pay_request_error_fails_only_undispatched_payments() {
    let (client, _) = spawn_fake_barkd(FakeBarkd {
        pay_status: Some(StatusCode::BAD_REQUEST),
        ..FakeBarkd::default()
    })
    .await;
    assert!(matches!(
        client
            .pay(
                invoice(payment_hash(), 100_000),
                REQUIRED_MAX_DELAY,
                Amount::from_sats(10)
            )
            .await,
        Err(LightningRpcError::FailedPayment { .. })
    ));

    // barkd failed to answer, but the payment went out and succeeds.
    let (client, _) = spawn_fake_barkd(FakeBarkd {
        pay_status: Some(StatusCode::INTERNAL_SERVER_ERROR),
        states_after_pay: vec![paid()],
        ..FakeBarkd::default()
    })
    .await;
    let response = client
        .pay(
            invoice(payment_hash(), 100_000),
            REQUIRED_MAX_DELAY,
            Amount::from_sats(10),
        )
        .await
        .expect("dispatched payment is awaited");
    assert_eq!(response.preimage, Preimage(PREIMAGE));
}

#[tokio::test]
async fn outbound_payment_exists_for_any_known_state() {
    let mut fake = FakeBarkd::default();
    let pending = sha256::Hash::hash(&[1; 32]);
    let failed = sha256::Hash::hash(&[2; 32]);
    fake.send_states.insert(
        pending.to_string(),
        vec![json!({ "state": "htlcs_sent" })].into(),
    );
    fake.send_states.insert(
        failed.to_string(),
        vec![json!({ "state": "failed" })].into(),
    );
    let (client, _) = spawn_fake_barkd(fake).await;

    assert!(
        !client
            .outbound_payment_exists(payment_hash())
            .await
            .expect("query succeeds")
    );
    assert!(
        client
            .outbound_payment_exists(pending)
            .await
            .expect("query succeeds")
    );
    assert!(
        client
            .outbound_payment_exists(failed)
            .await
            .expect("query succeeds")
    );
}

#[tokio::test]
async fn requests_without_token_are_rejected() {
    let (url, _) = serve_fake_barkd(FakeBarkd::default()).await;
    let unauthorized = GatewayBarkClient::new(url, "wrong".to_string(), node_id());

    assert!(unauthorized.info().await.is_err());
}
