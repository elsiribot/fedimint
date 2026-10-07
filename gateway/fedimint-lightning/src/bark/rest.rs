//! Minimal client for the subset of barkd's REST API the gateway uses.
//!
//! The types mirror barkd's JSON schema (`bark-json`) field by field instead
//! of depending on bark's crates, which would pull a second `libsqlite3-sys`
//! into the workspace.

use std::fmt;

use bitcoin::hashes::sha256;
use fedimint_core::util::SafeUrl;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Receive state barkd reports for a hold receive whose HTLC VTXOs have been
/// granted by the Ark server and which is waiting for the gateway to supply
/// the preimage.
pub const RECEIVE_STATE_AWAITING_PREIMAGE: &str = "awaiting_preimage";

pub const SEND_STATE_UNKNOWN: &str = "unknown";
pub const SEND_STATE_PAID: &str = "paid";
pub const SEND_STATE_FAILED: &str = "failed";

#[derive(Debug)]
pub enum BarkRestError {
    /// The request never produced a response, so its effect is unknown.
    Transport(reqwest::Error),
    /// barkd answered with a non-success status.
    Status { status: StatusCode, body: String },
    /// barkd answered with a body we could not parse.
    Decode(reqwest::Error),
}

impl BarkRestError {
    /// Whether barkd definitively rejected the request, as opposed to the
    /// outcome being unknown (transport failure or a server-side error).
    pub fn is_client_error(&self) -> bool {
        matches!(self, Self::Status { status, .. } if status.is_client_error())
    }
}

impl fmt::Display for BarkRestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(err) => write!(f, "barkd request failed: {err}"),
            Self::Status { status, body } => write!(f, "barkd returned {status}: {body}"),
            Self::Decode(err) => write!(f, "failed to decode barkd response: {err}"),
        }
    }
}

impl std::error::Error for BarkRestError {}

#[derive(Debug, Clone, Deserialize)]
pub struct ArkInfo {
    pub network: String,
    pub vtxo_exit_delta: u16,
    pub htlc_send_expiry_delta: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TipResponse {
    pub tip_height: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectedResponse {
    pub connected: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Balance {
    pub spendable_sat: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnchainBalance {
    pub total_sat: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OnchainAddress {
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HoldInvoiceRequest {
    pub amount_sat: u64,
    pub payment_hash: sha256::Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub expiry_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InvoiceInfo {
    pub invoice: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LightningReceiveInfo {
    pub payment_hash: sha256::Hash,
    pub state: String,
    pub invoice: String,
    #[serde(default)]
    pub hold: bool,
}

impl LightningReceiveInfo {
    pub fn is_awaiting_preimage(&self) -> bool {
        self.hold && self.state == RECEIVE_STATE_AWAITING_PREIMAGE
    }
}

#[derive(Debug, Clone, Serialize)]
struct SettleRequest {
    preimage: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayRequest {
    pub destination: String,
    pub max_fee_sat: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LightningSendInfo {
    pub state: String,
    #[serde(default)]
    pub preimage: Option<String>,
    #[serde(default)]
    pub failure_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Ignored {}

#[derive(Clone)]
pub struct BarkRestClient {
    http: reqwest::Client,
    base_url: SafeUrl,
    token: String,
}

impl fmt::Debug for BarkRestClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token grants full control over the bark wallet.
        f.debug_struct("BarkRestClient")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl BarkRestClient {
    pub fn new(base_url: SafeUrl, token: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url,
            token,
        }
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&(impl Serialize + Sync)>,
    ) -> Result<T, BarkRestError> {
        let url = self
            .base_url
            .join(&format!("api/v1/{path}"))
            .expect("barkd API paths are valid relative URLs");

        let mut request = self
            .http
            .request(method, url.to_unsafe())
            .bearer_auth(&self.token);
        if let Some(body) = body {
            request = request.json(body);
        }

        let response = request.send().await.map_err(BarkRestError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(BarkRestError::Status { status, body });
        }

        response.json().await.map_err(BarkRestError::Decode)
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, BarkRestError> {
        self.request(Method::GET, path, None::<&()>).await
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &(impl Serialize + Sync),
    ) -> Result<T, BarkRestError> {
        self.request(Method::POST, path, Some(body)).await
    }

    pub async fn ark_info(&self) -> Result<ArkInfo, BarkRestError> {
        self.get("wallet/ark-info").await
    }

    pub async fn tip(&self) -> Result<TipResponse, BarkRestError> {
        self.get("bitcoin/tip").await
    }

    pub async fn connected(&self) -> Result<ConnectedResponse, BarkRestError> {
        self.get("wallet/connected").await
    }

    pub async fn balance(&self) -> Result<Balance, BarkRestError> {
        self.get("wallet/balance").await
    }

    pub async fn onchain_balance(&self) -> Result<OnchainBalance, BarkRestError> {
        self.get("onchain/balance").await
    }

    pub async fn onchain_address(&self) -> Result<OnchainAddress, BarkRestError> {
        self.post("onchain/addresses/next", &()).await
    }

    pub async fn create_hold_invoice(
        &self,
        request: &HoldInvoiceRequest,
    ) -> Result<InvoiceInfo, BarkRestError> {
        self.post("lightning/receives/hold-invoice", request).await
    }

    pub async fn pending_receives(&self) -> Result<Vec<LightningReceiveInfo>, BarkRestError> {
        self.get("lightning/receives").await
    }

    pub async fn settle_receive(
        &self,
        payment_hash: sha256::Hash,
        preimage: [u8; 32],
    ) -> Result<(), BarkRestError> {
        self.post::<Ignored>(
            &format!("lightning/receives/{payment_hash}/settle"),
            &SettleRequest {
                preimage: hex::encode(preimage),
            },
        )
        .await
        .map(|_| ())
    }

    pub async fn abandon_receive(&self, payment_hash: sha256::Hash) -> Result<(), BarkRestError> {
        self.post::<Ignored>(&format!("lightning/receives/{payment_hash}/abandon"), &())
            .await
            .map(|_| ())
    }

    pub async fn send_status(
        &self,
        payment_hash: sha256::Hash,
    ) -> Result<LightningSendInfo, BarkRestError> {
        self.get(&format!("lightning/sends/{payment_hash}")).await
    }

    pub async fn pay(&self, request: &PayRequest) -> Result<(), BarkRestError> {
        self.post::<Ignored>("lightning/pay", request)
            .await
            .map(|_| ())
    }
}
