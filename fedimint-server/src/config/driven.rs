//! Wire protocol used when an external process drives federation setup.
//!
//! Setting [`FM_DKG_CTRL_ENV`] to `1` activates the protocol and suppresses all
//! interactive setup services. The parent supplies its end of a connected
//! AF_UNIX `SOCK_STREAM` socketpair as the child's stdin. Both protocol
//! directions use that duplex stdin socket; stdout and stderr remain ordinary
//! log channels and are never used for protocol frames.
//! The child sends [`ChildMessage::Hello`] first. The parent may send exactly
//! one [`ParentMessage::RunDkg`] frame when parameters are needed, after which
//! the child streams lifecycle messages until consensus starts or setup fails.
//! Frames are a little-endian `u32` byte length followed by one CBOR map and
//! are limited to [`MAX_FRAME_LEN`] bytes. There are no protocol timeouts.
//!
//! Each child process begins a fresh conversation; the parent resends the same
//! request after any death. [`ChildMessage::ParamsRejected`] and
//! [`ChildMessage::DkgFailed`] are followed by channel EOF and a nonzero child
//! exit. Oversized, malformed, or unexpected frames also cause a logged nonzero
//! exit, potentially without a final protocol message. After
//! [`ChildMessage::ConsensusStarted`], EOF instead means the setup channel was
//! successfully retired while the same child continues running consensus.
//!
//! [`PROTOCOL_VERSION`] is incremented for incompatible changes. New optional
//! map fields may be added within a version; peers must ignore fields they do
//! not understand according to Serde's normal map behavior.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::sync::Arc;

use anyhow::{Context, ensure};
use fedimint_core::base32::{FEDIMINT_PREFIX, decode_prefixed};
use fedimint_core::config::META_FEDERATION_NAME_KEY;
use fedimint_core::envs::{FM_DISABLE_BASE_FEES_ENV, is_env_var_set};
use fedimint_core::module::ApiAuth;
use fedimint_core::setup_code::{PeerEndpoints, PeerSetupCode};
use fedimint_core::{PeerId, base32};
use rustls::client::danger::ServerCertVerifier as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio_rustls::rustls;

use super::io::{
    CLIENT_CONFIG, CLIENT_INVITE_CODE_FILE, CONSENSUS_CONFIG, DB_FILE, ENCRYPTED_EXT, JSON_EXT,
    LOCAL_CONFIG, PRIVATE_CONFIG, SALT_FILE,
};
use super::{ConfigGenParams, ConfigGenSettings};
use crate::net::p2p_connector::dns_sanitize;

/// Boolean environment switch selecting driven DKG over the stdin socket.
pub const FM_DKG_CTRL_ENV: &str = "FM_DKG_CTRL";

/// Current driven-DKG wire protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum encoded CBOR payload size accepted by the protocol.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// Child-to-parent messages sent during driven setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildMessage {
    /// Initial message sent before the child reads from the control socket.
    Hello {
        /// Wire protocol version spoken by the child.
        proto: u32,
        /// Fedimint release/vendor version used for DKG compatibility.
        code_version: String,
        /// Whether setup parameters are needed or configuration already exists.
        state: ChildState,
    },
    /// Supplied parameters failed validation before any peer contact.
    ParamsRejected {
        /// Human-readable validation failure. This never contains secret input.
        reason: String,
    },
    /// Driven DKG execution has commenced and P2P setup may now begin.
    DkgStarted {},
    /// Distributed configuration generation failed after peer contact began.
    DkgFailed {
        /// Bounded public failure reason; full details are only in child logs.
        reason: String,
    },
    /// A complete configuration was atomically installed in the final data dir.
    ConfigPersisted {
        /// Canonical client invite code for the generated federation.
        invite_code: String,
        /// This guardian's configured API URL.
        api_url: String,
    },
    /// Consensus startup has begun; the child closes the control channel next.
    ConsensusStarted {},
}

/// Configuration state reported in the initial hello.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChildState {
    /// No complete final configuration exists; the parent must send parameters.
    NeedsParams,
    /// A complete final configuration exists and the child will boot it.
    AlreadyConfigured {
        /// Canonical client invite code read from the installed configuration.
        invite_code: String,
    },
}

/// The single parent-to-child message allowed in a fresh conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParentMessage {
    /// Validate explicit peer ordering and run distributed key generation.
    RunDkg {
        /// Index into `codes`; this exact index becomes the local `PeerId`.
        our_index: u16,
        /// Canonical base32 setup codes in explicit peer-id order, including
        /// us.
        codes: Vec<String>,
        /// Raw 32-byte Iroh API secret key.
        iroh_api_sk: [u8; 32],
        /// Raw 32-byte Iroh P2P secret key.
        iroh_p2p_sk: [u8; 32],
        /// TLS private key in secret DER form; present only for TCP
        /// deployments.
        tls_key: Option<Vec<u8>>,
        /// Guardian API authentication secret.
        api_auth: String,
        /// Bitcoin network name accepted by `bitcoin::Network::from_str`.
        network: String,
    },
}

/// Parameters supplied by a parent to start a fresh driven-DKG ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDkgParams {
    /// Index into `codes`; this exact index becomes the local `PeerId`.
    pub our_index: u16,
    /// Canonical base32 setup codes in explicit peer-id order, including us.
    pub codes: Vec<String>,
    /// Raw 32-byte Iroh API secret key.
    pub iroh_api_sk: [u8; 32],
    /// Raw 32-byte Iroh P2P secret key.
    pub iroh_p2p_sk: [u8; 32],
    /// TLS private key in secret DER form; present only for TCP deployments.
    pub tls_key: Option<Vec<u8>>,
    /// Guardian API authentication secret.
    pub api_auth: String,
    /// Bitcoin network name accepted by `bitcoin::Network::from_str`.
    pub network: String,
}

impl From<RunDkgParams> for ParentMessage {
    fn from(params: RunDkgParams) -> Self {
        Self::RunDkg {
            our_index: params.our_index,
            codes: params.codes,
            iroh_api_sk: params.iroh_api_sk,
            iroh_p2p_sk: params.iroh_p2p_sk,
            tls_key: params.tls_key,
            api_auth: params.api_auth,
            network: params.network,
        }
    }
}

/// A validated lifecycle event in a driven-DKG child conversation.
///
/// [`Self::ParamsRejected`] and [`Self::DkgFailed`] end the conversation.
/// [`Self::ControlChannelRetired`] is the successful terminal event and is
/// produced only when EOF follows [`Self::ConsensusStarted`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrivenDkgEvent {
    /// Supplied parameters were rejected before peer contact.
    ParamsRejected {
        /// Human-readable validation failure reported by the child.
        reason: String,
    },
    /// Distributed key generation has begun.
    DkgStarted,
    /// Distributed key generation or configuration persistence failed.
    DkgFailed {
        /// Bounded public failure reason reported by the child.
        reason: String,
    },
    /// The generated configuration was atomically installed.
    ConfigPersisted {
        /// Canonical client invite code for the generated federation.
        invite_code: String,
        /// This guardian's configured API URL.
        api_url: String,
    },
    /// Consensus startup has begun; the next valid protocol observation is EOF.
    ConsensusStarted,
    /// The control channel closed after consensus startup and is retired.
    ControlChannelRetired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParentPhase {
    NeedsRequest,
    AwaitingDkgStart,
    DkgRunning,
    ConfigPersisted,
    AwaitingConsensus,
    AwaitingRetirement,
    Terminal,
}

/// Parent-side handle for one driven-DKG child conversation.
///
/// The caller owns process lifecycle and timeout policy. This handle owns only
/// framing, handshake validation, and protocol sequencing over the supplied
/// duplex stream.
#[derive(Debug)]
pub struct DrivenDkgClient<S> {
    stream: S,
    code_version: String,
    child_state: ChildState,
    phase: ParentPhase,
}

impl<S> DrivenDkgClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Read and validate the child's initial hello over `stream`.
    pub async fn connect(mut stream: S) -> anyhow::Result<Self> {
        let hello: ChildMessage = read_frame(&mut stream)
            .await
            .context("Reading driven-DKG child hello")?;
        let ChildMessage::Hello {
            proto,
            code_version,
            state,
        } = hello
        else {
            anyhow::bail!("Driven-DKG child sent a lifecycle message before hello");
        };
        ensure!(
            proto == PROTOCOL_VERSION,
            "Driven-DKG protocol version mismatch: child speaks {proto}, parent speaks {PROTOCOL_VERSION}"
        );
        let phase = match &state {
            ChildState::NeedsParams => ParentPhase::NeedsRequest,
            ChildState::AlreadyConfigured { .. } => ParentPhase::AwaitingConsensus,
        };
        Ok(Self {
            stream,
            code_version,
            child_state: state,
            phase,
        })
    }

    /// Return the Fedimint release/vendor version reported by the child.
    pub fn code_version(&self) -> &str {
        &self.code_version
    }

    /// Return the configuration state reported by the child.
    pub fn child_state(&self) -> &ChildState {
        &self.child_state
    }

    /// Send the sole setup request allowed for a child that needs parameters.
    pub async fn run_dkg(&mut self, params: RunDkgParams) -> anyhow::Result<()> {
        ensure!(
            self.phase == ParentPhase::NeedsRequest,
            "Driven-DKG child is not awaiting parameters"
        );
        write_frame(&mut self.stream, &ParentMessage::from(params))
            .await
            .context("Sending driven-DKG parameters")?;
        self.phase = ParentPhase::AwaitingDkgStart;
        Ok(())
    }

    /// Read the next validated lifecycle event.
    ///
    /// Returns `None` after a terminal failure event or successful channel
    /// retirement. EOF at any earlier phase is reported as child death.
    pub async fn next_event(&mut self) -> Option<anyhow::Result<DrivenDkgEvent>> {
        if self.phase == ParentPhase::Terminal {
            return None;
        }

        let message = match read_frame::<_, ChildMessage>(&mut self.stream).await {
            Ok(message) => message,
            Err(error) if is_eof(&error) && self.phase == ParentPhase::AwaitingRetirement => {
                self.phase = ParentPhase::Terminal;
                return Some(Ok(DrivenDkgEvent::ControlChannelRetired));
            }
            Err(error) => {
                let phase = self.phase;
                self.phase = ParentPhase::Terminal;
                return Some(
                    Err(error).context(format!("Driven-DKG child channel ended during {phase:?}")),
                );
            }
        };

        let message_kind = match &message {
            ChildMessage::Hello { .. } => "Hello",
            ChildMessage::ParamsRejected { .. } => "ParamsRejected",
            ChildMessage::DkgStarted {} => "DkgStarted",
            ChildMessage::DkgFailed { .. } => "DkgFailed",
            ChildMessage::ConfigPersisted { .. } => "ConfigPersisted",
            ChildMessage::ConsensusStarted {} => "ConsensusStarted",
        };
        let event = match (self.phase, message) {
            (ParentPhase::AwaitingDkgStart, ChildMessage::ParamsRejected { reason }) => {
                self.phase = ParentPhase::Terminal;
                DrivenDkgEvent::ParamsRejected { reason }
            }
            (ParentPhase::AwaitingDkgStart, ChildMessage::DkgStarted {}) => {
                self.phase = ParentPhase::DkgRunning;
                DrivenDkgEvent::DkgStarted
            }
            (ParentPhase::DkgRunning, ChildMessage::DkgFailed { reason }) => {
                self.phase = ParentPhase::Terminal;
                DrivenDkgEvent::DkgFailed { reason }
            }
            (
                ParentPhase::DkgRunning,
                ChildMessage::ConfigPersisted {
                    invite_code,
                    api_url,
                },
            ) => {
                self.phase = ParentPhase::ConfigPersisted;
                DrivenDkgEvent::ConfigPersisted {
                    invite_code,
                    api_url,
                }
            }
            (
                ParentPhase::ConfigPersisted | ParentPhase::AwaitingConsensus,
                ChildMessage::ConsensusStarted {},
            ) => {
                self.phase = ParentPhase::AwaitingRetirement;
                DrivenDkgEvent::ConsensusStarted
            }
            (phase, _) => {
                self.phase = ParentPhase::Terminal;
                return Some(Err(anyhow::anyhow!(
                    "Unexpected driven-DKG child message {message_kind} during {phase:?}"
                )));
            }
        };
        Some(Ok(event))
    }
}

fn is_eof(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|error| error.kind() == std::io::ErrorKind::UnexpectedEof)
}

/// Write one length-delimited CBOR message.
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut payload = Vec::new();
    ciborium::into_writer(message, &mut payload).context("Encoding driven-DKG CBOR frame")?;
    ensure!(
        payload.len() <= MAX_FRAME_LEN,
        "Driven-DKG frame exceeds {MAX_FRAME_LEN} bytes"
    );
    let length = u32::try_from(payload.len()).expect("maximum frame length fits in u32");
    writer.write_all(&length.to_le_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read and decode one length-delimited CBOR message.
pub async fn read_frame<R, T>(reader: &mut R) -> anyhow::Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let length = reader.read_u32_le().await? as usize;
    ensure!(
        length <= MAX_FRAME_LEN,
        "Driven-DKG frame length {length} exceeds {MAX_FRAME_LEN} bytes"
    );
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    ciborium::from_reader(payload.as_slice()).context("Decoding driven-DKG CBOR frame")
}

/// Validate the sole parent request and construct internal DKG parameters.
///
/// Validation completes before the caller constructs a P2P connector, so every
/// error from this function is safe to report as `ParamsRejected`.
pub(crate) fn validate_run_dkg(
    message: ParentMessage,
    settings: &ConfigGenSettings,
) -> anyhow::Result<ConfigGenParams> {
    let ParentMessage::RunDkg {
        our_index,
        codes,
        iroh_api_sk,
        iroh_p2p_sk,
        tls_key,
        api_auth,
        network,
    } = message;

    ensure!(
        usize::from(our_index) < codes.len(),
        "our_index {our_index} is out of range for {} setup codes",
        codes.len()
    );
    ensure!(!api_auth.is_empty(), "The API password is empty");
    ensure!(
        api_auth.trim() == api_auth,
        "The API password contains leading/trailing whitespace"
    );
    let decoded: Vec<PeerSetupCode> = codes
        .iter()
        .map(|code| decode_prefixed(FEDIMINT_PREFIX, code))
        .collect::<Result<_, _>>()
        .context("A supplied setup code is invalid")?;
    for (encoded, code) in codes.iter().zip(&decoded) {
        ensure!(
            *encoded == base32::encode_prefixed(FEDIMINT_PREFIX, code),
            "A supplied setup code is not canonically encoded"
        );
    }
    let sorted: BTreeSet<_> = decoded.iter().cloned().collect();
    ensure!(
        sorted.len() == decoded.len(),
        "The setup-code assignment contains duplicates"
    );
    ensure!(
        sorted.iter().eq(decoded.iter()),
        "The setup-code assignment is not in canonical peer-id order"
    );

    let tcp_spkis: Vec<_> = decoded
        .iter()
        .map(|code| match &code.endpoints {
            PeerEndpoints::Tcp { cert, .. } => tls_certificate_spki(cert, &code.name).map(Some),
            PeerEndpoints::Iroh { .. } => Ok(None),
        })
        .collect::<anyhow::Result<_>>()?;
    let mut iroh_public_keys = BTreeSet::new();
    for code in &decoded {
        if let PeerEndpoints::Iroh { api_pk, p2p_pk } = &code.endpoints {
            ensure!(
                iroh_public_keys.insert(*api_pk) && iroh_public_keys.insert(*p2p_pk),
                "Iroh public keys are reused across guardian identities or roles"
            );
        }
    }
    for (index, left) in decoded.iter().enumerate() {
        for (right_index, right) in decoded.iter().enumerate().skip(index + 1) {
            match (&left.endpoints, &right.endpoints) {
                (
                    PeerEndpoints::Iroh {
                        api_pk: left_api,
                        p2p_pk: left_p2p,
                    },
                    PeerEndpoints::Iroh {
                        api_pk: right_api,
                        p2p_pk: right_p2p,
                    },
                ) => {
                    ensure!(left_api != right_api, "Iroh API public keys are duplicated");
                    ensure!(left_p2p != right_p2p, "Iroh P2P public keys are duplicated");
                }
                (
                    PeerEndpoints::Tcp {
                        api_url: left_api,
                        p2p_url: left_p2p,
                        cert: left_cert,
                    },
                    PeerEndpoints::Tcp {
                        api_url: right_api,
                        p2p_url: right_p2p,
                        cert: right_cert,
                    },
                ) => {
                    ensure!(left_api != right_api, "TCP API URLs are duplicated");
                    ensure!(left_p2p != right_p2p, "TCP P2P URLs are duplicated");
                    ensure!(left_cert != right_cert, "TLS certificates are duplicated");
                    ensure!(
                        tcp_spkis[index] != tcp_spkis[right_index],
                        "TLS certificate public keys are duplicated"
                    );
                }
                _ => {}
            }
        }
    }

    for code in &decoded {
        ensure!(!code.name.is_empty(), "A guardian name is empty");
        if let Some(name) = &code.federation_name {
            ensure!(!name.is_empty(), "The federation name is empty");
        }
        if let Some(size) = code.federation_size {
            ensure!(
                size == 1 || 4 <= size,
                "Federation size must be 1 or at least 4"
            );
        }
    }
    ensure!(
        decoded
            .iter()
            .filter(|code| code.federation_name.is_some())
            .count()
            <= 1,
        "Federation name is configured by more than one setup code"
    );
    ensure!(
        decoded
            .iter()
            .filter(|code| code.disable_base_fees.is_some())
            .count()
            <= 1,
        "Base-fee behavior is configured by more than one setup code"
    );
    ensure!(
        decoded
            .iter()
            .filter(|code| code.module_params.is_some())
            .count()
            <= 1,
        "The module instance list is configured by more than one setup code"
    );
    ensure!(
        decoded
            .iter()
            .filter(|code| code.federation_size.is_some())
            .count()
            <= 1,
        "Federation size is configured by more than one setup code"
    );
    let leader = decoded
        .iter()
        .find(|code| code.federation_name.is_some())
        .context("We need one guardian to configure the federation name")?;
    ensure!(
        leader.federation_size == Some(decoded.len() as u32),
        "The federation-name setup code must set federation size to {}",
        decoded.len()
    );

    ensure!(
        decoded.len() == 1 || 4 <= decoded.len(),
        "The number of guardians is invalid"
    );
    if let Some(federation_size) = decoded.iter().find_map(|code| code.federation_size) {
        ensure!(
            decoded.len() == federation_size as usize,
            "Expected {federation_size} guardians but got {}",
            decoded.len()
        );
    }

    let own_code = &decoded[usize::from(our_index)];
    let iroh_api_sk = iroh::SecretKey::from_bytes(&iroh_api_sk);
    let iroh_p2p_sk = iroh::SecretKey::from_bytes(&iroh_p2p_sk);
    let tls_key = tls_key
        .map(rustls::pki_types::PrivateKeyDer::try_from)
        .transpose()
        .map_err(|error| anyhow::anyhow!("Invalid TLS secret key DER: {error}"))?
        .map(Arc::new);

    let uses_iroh = match &own_code.endpoints {
        PeerEndpoints::Iroh { api_pk, p2p_pk } => {
            ensure!(settings.enable_iroh, "Iroh setup code supplied in TCP mode");
            ensure!(tls_key.is_none(), "TLS key supplied for an Iroh deployment");
            ensure!(
                *api_pk == iroh_api_sk.public() && *p2p_pk == iroh_p2p_sk.public(),
                "our_index does not identify the setup code derived from the supplied Iroh keys"
            );
            ensure!(
                decoded
                    .iter()
                    .all(|code| matches!(code.endpoints, PeerEndpoints::Iroh { .. })),
                "Setup codes mix TCP and Iroh endpoints"
            );
            true
        }
        PeerEndpoints::Tcp {
            api_url,
            p2p_url,
            cert,
        } => {
            ensure!(
                !settings.enable_iroh,
                "TCP setup code supplied in Iroh mode"
            );
            ensure!(
                settings.api_url.as_ref() == Some(api_url)
                    && settings.p2p_url.as_ref() == Some(p2p_url),
                "our_index does not identify this server's configured API and P2P URLs"
            );
            let tls_key = tls_key
                .as_ref()
                .context("TCP deployment requires tls_key")?;
            let provider = rustls::crypto::CryptoProvider::get_default()
                .context("Rustls crypto provider is not installed")?;
            let signing_key = provider
                .key_provider
                .load_private_key(tls_key.as_ref().clone_key())
                .context("TLS private key is unsupported")?;
            rustls::sign::CertifiedKey::new(
                vec![rustls::pki_types::CertificateDer::from(cert.clone())],
                signing_key,
            )
            .keys_match()
            .context("TLS key does not match our setup-code certificate")?;
            ensure!(
                decoded
                    .iter()
                    .all(|code| matches!(code.endpoints, PeerEndpoints::Tcp { .. })),
                "Setup codes mix TCP and Iroh endpoints"
            );
            false
        }
    };

    let federation_name = leader
        .federation_name
        .clone()
        .expect("leader was selected by federation name");
    let disable_base_fees = decoded
        .iter()
        .find_map(|code| code.disable_base_fees)
        .unwrap_or(is_env_var_set(FM_DISABLE_BASE_FEES_ENV));
    // The module instance list is the source of truth for which module
    // instances the federation runs. If no setup code configured it, fall
    // back to the default instance list (one instance of each
    // default-enabled module kind, in canonical order).
    let module_params = decoded
        .iter()
        .find_map(|code| code.module_params.clone())
        .unwrap_or_else(|| {
            settings
                .available_module_params
                .select_kinds(&settings.default_modules)
        });
    let network = bitcoin::Network::from_str(&network).context("Invalid Bitcoin network")?;
    ensure!(
        network == settings.network,
        "Bitcoin network {network} does not match configured network {}",
        settings.network
    );

    Ok(ConfigGenParams {
        identity: PeerId::from(our_index),
        tls_key,
        iroh_api_sk: uses_iroh.then_some(iroh_api_sk),
        iroh_p2p_sk: uses_iroh.then_some(iroh_p2p_sk),
        api_auth: ApiAuth::new(api_auth),
        peers: (0..)
            .map(|index| PeerId::from(index as u16))
            .zip(decoded)
            .collect(),
        meta: BTreeMap::from([(META_FEDERATION_NAME_KEY.to_string(), federation_name)]),
        disable_base_fees,
        module_params,
        network,
    })
}

fn tls_certificate_spki(cert: &[u8], guardian_name: &str) -> anyhow::Result<Vec<u8>> {
    let mut store = rustls::RootCertStore::empty();
    let cert = rustls::pki_types::CertificateDer::from(cert.to_vec());
    store
        .add(cert.clone())
        .context("A TLS setup-code certificate is invalid")?;
    let spki = store.roots[0].subject_public_key_info.as_ref().to_vec();
    let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(store))
        .build()
        .context("Building TLS setup-code certificate verifier")?;
    let server_name = rustls::pki_types::ServerName::try_from(dns_sanitize(guardian_name))
        .context("Guardian name cannot be represented as a TLS server name")?;
    verifier
        .verify_server_cert(
            &cert,
            &[],
            &server_name,
            &[],
            rustls::pki_types::UnixTime::now(),
        )
        .context("TLS setup-code certificate is not valid for its guardian name")?;
    Ok(spki)
}

/// Return the disposable sibling directory used for driven DKG output.
fn staging_path(final_path: &Path) -> anyhow::Result<PathBuf> {
    let file_name = final_path
        .file_name()
        .context("Driven-DKG data directory must have a final path component")?;
    let mut staging_name = OsString::from(file_name);
    staging_name.push(".staging");
    Ok(final_path.with_file_name(staging_name))
}

/// Clear incomplete final state and create an empty disposable staging dir.
///
/// Callers must first establish that `final_path` does not contain a complete
/// configuration. Driven mode defines any other contents as disposable.
pub(crate) fn prepare_staging(final_path: &Path) -> anyhow::Result<PathBuf> {
    let staging = staging_path(final_path)?;
    if staging.exists() {
        fs::remove_dir_all(&staging).context("Removing stale driven-DKG staging directory")?;
    }
    if final_path.exists() {
        fs::remove_dir_all(final_path).context("Removing incomplete driven-DKG data directory")?;
    }
    let parent = final_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).context("Creating driven-DKG data-directory parent")?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(&staging)
        .context("Creating driven-DKG staging directory")?;
    fs::File::open(parent)?.sync_all()?;
    Ok(staging)
}

/// Refuse to treat a password-less final directory as disposable when any
/// formed-federation artifact remains.
pub(crate) fn ensure_no_config_artifacts(final_path: &Path) -> anyhow::Result<()> {
    let artifacts = [
        final_path.join(SALT_FILE),
        final_path.join(CLIENT_INVITE_CODE_FILE),
        final_path.join(DB_FILE),
        final_path.join(LOCAL_CONFIG).with_extension(JSON_EXT),
        final_path.join(CONSENSUS_CONFIG).with_extension(JSON_EXT),
        final_path.join(CLIENT_CONFIG).with_extension(JSON_EXT),
        final_path
            .join(PRIVATE_CONFIG)
            .with_extension(ENCRYPTED_EXT),
    ];
    if let Some(evidence) = artifacts.iter().find(|path| path.exists()) {
        anyhow::bail!(
            "The plaintext password is absent, but existing configuration artifact '{}' makes the data directory non-disposable",
            evidence.display()
        );
    }
    Ok(())
}

/// Fsync staged files and atomically rename the complete directory into place.
pub(crate) fn install_staging(staging: &Path, final_path: &Path) -> anyhow::Result<()> {
    ensure!(
        !final_path.exists(),
        "Final driven-DKG data directory unexpectedly exists"
    );
    for entry in fs::read_dir(staging).context("Reading driven-DKG staging directory")? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            fs::File::open(entry.path())?.sync_all()?;
        }
    }
    fs::File::open(staging)?.sync_all()?;
    fs::rename(staging, final_path).context("Installing complete driven-DKG data directory")?;
    let parent = final_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use fedimint_core::setup_code::PeerSetupCode;

    use super::*;

    fn settings() -> ConfigGenSettings {
        ConfigGenSettings {
            p2p_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 8173)),
            api_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 8174)),
            ui_bind: SocketAddr::from((Ipv4Addr::LOCALHOST, 8175)),
            p2p_url: None,
            api_url: None,
            enable_iroh: true,
            iroh_dns: None,
            iroh_relays: vec![],
            network: bitcoin::Network::Regtest,
            available_modules: BTreeSet::new(),
            default_modules: BTreeSet::new(),
            available_module_params:
                fedimint_core::config::ServerModuleConfigGenParamsRegistry::default(),
        }
    }

    fn valid_request() -> ParentMessage {
        let secrets: Vec<_> = (1_u8..=4)
            .map(|byte| {
                (
                    iroh::SecretKey::from_bytes(&[byte; 32]),
                    iroh::SecretKey::from_bytes(&[byte + 10; 32]),
                )
            })
            .collect();
        let codes: BTreeSet<_> = secrets
            .iter()
            .enumerate()
            .map(|(index, (api, p2p))| PeerSetupCode {
                name: format!("guardian-{index}"),
                endpoints: PeerEndpoints::Iroh {
                    api_pk: api.public(),
                    p2p_pk: p2p.public(),
                },
                federation_name: (index == 0).then(|| "test-fed".to_string()),
                disable_base_fees: None,
                module_params: None,
                federation_size: (index == 0).then_some(4),
            })
            .collect();
        let codes: Vec<_> = codes
            .iter()
            .map(|code| base32::encode_prefixed(FEDIMINT_PREFIX, code))
            .collect();
        let our_index = codes
            .iter()
            .position(|encoded| {
                let code: PeerSetupCode = decode_prefixed(FEDIMINT_PREFIX, encoded).unwrap();
                matches!(
                    code.endpoints,
                    PeerEndpoints::Iroh { api_pk, .. } if api_pk == secrets[0].0.public()
                )
            })
            .unwrap() as u16;

        ParentMessage::RunDkg {
            our_index,
            codes,
            iroh_api_sk: secrets[0].0.to_bytes(),
            iroh_p2p_sk: secrets[0].1.to_bytes(),
            tls_key: None,
            api_auth: "secret".to_string(),
            network: "regtest".to_string(),
        }
    }

    fn parent_params() -> RunDkgParams {
        RunDkgParams {
            our_index: 0,
            codes: vec!["code".to_string()],
            iroh_api_sk: [1; 32],
            iroh_p2p_sk: [2; 32],
            tls_key: None,
            api_auth: "secret".to_string(),
            network: "regtest".to_string(),
        }
    }

    async fn write_hello(stream: &mut tokio::io::DuplexStream, state: ChildState) {
        write_frame(
            stream,
            &ChildMessage::Hello {
                proto: PROTOCOL_VERSION,
                code_version: "test-version".to_string(),
                state,
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn parent_client_validates_happy_path_and_retirement() {
        let (parent, mut child) = tokio::io::duplex(4096);
        let child_task = tokio::spawn(async move {
            write_hello(&mut child, ChildState::NeedsParams).await;
            let _: ParentMessage = read_frame(&mut child).await.unwrap();
            write_frame(&mut child, &ChildMessage::DkgStarted {})
                .await
                .unwrap();
            write_frame(
                &mut child,
                &ChildMessage::ConfigPersisted {
                    invite_code: "invite".to_string(),
                    api_url: "wss://guardian.example".to_string(),
                },
            )
            .await
            .unwrap();
            write_frame(&mut child, &ChildMessage::ConsensusStarted {})
                .await
                .unwrap();
        });

        let mut client = DrivenDkgClient::connect(parent).await.unwrap();
        assert_eq!(client.code_version(), "test-version");
        assert_eq!(client.child_state(), &ChildState::NeedsParams);
        client.run_dkg(parent_params()).await.unwrap();
        assert_eq!(
            client.next_event().await.unwrap().unwrap(),
            DrivenDkgEvent::DkgStarted
        );
        assert_eq!(
            client.next_event().await.unwrap().unwrap(),
            DrivenDkgEvent::ConfigPersisted {
                invite_code: "invite".to_string(),
                api_url: "wss://guardian.example".to_string(),
            }
        );
        assert_eq!(
            client.next_event().await.unwrap().unwrap(),
            DrivenDkgEvent::ConsensusStarted
        );
        child_task.await.unwrap();
        assert_eq!(
            client.next_event().await.unwrap().unwrap(),
            DrivenDkgEvent::ControlChannelRetired
        );
        assert!(client.next_event().await.is_none());
    }

    #[tokio::test]
    async fn parent_client_accepts_already_configured_path() {
        let (parent, mut child) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            write_hello(
                &mut child,
                ChildState::AlreadyConfigured {
                    invite_code: "invite".to_string(),
                },
            )
            .await;
            write_frame(&mut child, &ChildMessage::ConsensusStarted {})
                .await
                .unwrap();
        });

        let mut client = DrivenDkgClient::connect(parent).await.unwrap();
        assert_eq!(
            client.child_state(),
            &ChildState::AlreadyConfigured {
                invite_code: "invite".to_string()
            }
        );
        assert!(client.run_dkg(parent_params()).await.is_err());
        assert_eq!(
            client.next_event().await.unwrap().unwrap(),
            DrivenDkgEvent::ConsensusStarted
        );
        assert_eq!(
            client.next_event().await.unwrap().unwrap(),
            DrivenDkgEvent::ControlChannelRetired
        );
    }

    #[tokio::test]
    async fn parent_client_reports_params_rejected_as_terminal() {
        let (parent, mut child) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            write_hello(&mut child, ChildState::NeedsParams).await;
            let _: ParentMessage = read_frame(&mut child).await.unwrap();
            write_frame(
                &mut child,
                &ChildMessage::ParamsRejected {
                    reason: "bad params".to_string(),
                },
            )
            .await
            .unwrap();
        });

        let mut client = DrivenDkgClient::connect(parent).await.unwrap();
        client.run_dkg(parent_params()).await.unwrap();
        assert_eq!(
            client.next_event().await.unwrap().unwrap(),
            DrivenDkgEvent::ParamsRejected {
                reason: "bad params".to_string()
            }
        );
        assert!(client.next_event().await.is_none());
    }

    #[tokio::test]
    async fn parent_client_redacts_unexpected_message_fields() {
        let (parent, mut child) = tokio::io::duplex(1024);
        write_frame(
            &mut child,
            &ChildMessage::ConfigPersisted {
                invite_code: "secret-invite".to_string(),
                api_url: "wss://secret.example".to_string(),
            },
        )
        .await
        .unwrap();
        let mut client = DrivenDkgClient {
            stream: parent,
            code_version: "test".to_string(),
            child_state: ChildState::NeedsParams,
            phase: ParentPhase::AwaitingDkgStart,
        };

        let error = client.next_event().await.unwrap().unwrap_err().to_string();

        assert!(error.contains("ConfigPersisted"));
        assert!(!error.contains("secret-invite"));
        assert!(!error.contains("secret.example"));
    }

    #[tokio::test]
    async fn parent_client_rejects_version_mismatch() {
        let (parent, mut child) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            write_frame(
                &mut child,
                &ChildMessage::Hello {
                    proto: PROTOCOL_VERSION + 1,
                    code_version: "future".to_string(),
                    state: ChildState::NeedsParams,
                },
            )
            .await
            .unwrap();
        });

        let error = DrivenDkgClient::connect(parent).await.unwrap_err();
        assert!(error.to_string().contains("version mismatch"));
    }

    #[tokio::test]
    async fn parent_client_rejects_oversized_hello() {
        let (parent, mut child) = tokio::io::duplex(4);
        child
            .write_all(&(MAX_FRAME_LEN as u32 + 1).to_le_bytes())
            .await
            .unwrap();

        let error = DrivenDkgClient::connect(parent).await.unwrap_err();
        assert!(error.to_string().contains("child hello"));
    }

    #[tokio::test]
    async fn parent_client_treats_eof_before_retirement_as_child_death() {
        for phase in [
            ParentPhase::NeedsRequest,
            ParentPhase::AwaitingDkgStart,
            ParentPhase::DkgRunning,
            ParentPhase::ConfigPersisted,
            ParentPhase::AwaitingConsensus,
        ] {
            let (parent, child) = tokio::io::duplex(64);
            drop(child);
            let mut client = DrivenDkgClient {
                stream: parent,
                code_version: "test".to_string(),
                child_state: ChildState::NeedsParams,
                phase,
            };
            let error = client.next_event().await.unwrap().unwrap_err();
            assert!(
                error.to_string().contains(&format!("during {phase:?}")),
                "{error:#}"
            );
            assert!(client.next_event().await.is_none());
        }

        let (parent, child) = tokio::io::duplex(64);
        drop(child);
        let error = DrivenDkgClient::connect(parent).await.unwrap_err();
        assert!(error.to_string().contains("child hello"));
    }

    #[tokio::test]
    async fn framing_round_trip() {
        let message = ParentMessage::RunDkg {
            our_index: 1,
            codes: vec!["code-a".to_string(), "code-b".to_string()],
            iroh_api_sk: [1; 32],
            iroh_p2p_sk: [2; 32],
            tls_key: None,
            api_auth: "secret".to_string(),
            network: "regtest".to_string(),
        };
        let (mut writer, mut reader) = tokio::io::duplex(MAX_FRAME_LEN + 4);

        write_frame(&mut writer, &message).await.unwrap();

        let decoded: ParentMessage = read_frame(&mut reader).await.unwrap();
        assert_eq!(decoded, message);
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_payload_read() {
        let (mut writer, mut reader) = tokio::io::duplex(4);
        writer
            .write_all(&(MAX_FRAME_LEN as u32 + 1).to_le_bytes())
            .await
            .unwrap();

        assert!(read_frame::<_, ParentMessage>(&mut reader).await.is_err());
    }

    #[test]
    fn validation_rejects_noncanonical_order() {
        let ParentMessage::RunDkg {
            our_index,
            mut codes,
            iroh_api_sk,
            iroh_p2p_sk,
            tls_key,
            api_auth,
            network,
        } = valid_request();
        codes.swap(0, 1);

        let error = validate_run_dkg(
            ParentMessage::RunDkg {
                our_index,
                codes,
                iroh_api_sk,
                iroh_p2p_sk,
                tls_key,
                api_auth,
                network,
            },
            &settings(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("canonical"));
    }

    #[test]
    fn validation_rejects_bad_index() {
        let ParentMessage::RunDkg {
            codes,
            iroh_api_sk,
            iroh_p2p_sk,
            tls_key,
            api_auth,
            network,
            ..
        } = valid_request();

        let error = validate_run_dkg(
            ParentMessage::RunDkg {
                our_index: codes.len() as u16,
                codes,
                iroh_api_sk,
                iroh_p2p_sk,
                tls_key,
                api_auth,
                network,
            },
            &settings(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("out of range"));
    }

    #[test]
    fn validation_rejects_network_mismatch() {
        let ParentMessage::RunDkg {
            our_index,
            codes,
            iroh_api_sk,
            iroh_p2p_sk,
            tls_key,
            api_auth,
            ..
        } = valid_request();

        let error = validate_run_dkg(
            ParentMessage::RunDkg {
                our_index,
                codes,
                iroh_api_sk,
                iroh_p2p_sk,
                tls_key,
                api_auth,
                network: "bitcoin".to_string(),
            },
            &settings(),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("does not match configured network")
        );
    }

    #[test]
    fn validation_rejects_duplicate_codes() {
        let ParentMessage::RunDkg {
            our_index,
            mut codes,
            iroh_api_sk,
            iroh_p2p_sk,
            tls_key,
            api_auth,
            network,
        } = valid_request();
        codes[1] = codes[0].clone();

        let error = validate_run_dkg(
            ParentMessage::RunDkg {
                our_index,
                codes,
                iroh_api_sk,
                iroh_p2p_sk,
                tls_key,
                api_auth,
                network,
            },
            &settings(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("duplicates"));
    }

    #[test]
    fn staging_install_replaces_incomplete_state_atomically() {
        let parent = tempfile::tempdir().unwrap();
        let final_path = parent.path().join("fedimintd");
        fs::create_dir(&final_path).unwrap();
        fs::write(final_path.join("partial"), b"partial").unwrap();
        let stale_staging = staging_path(&final_path).unwrap();
        fs::create_dir(&stale_staging).unwrap();
        fs::write(stale_staging.join("stale"), b"stale").unwrap();

        let staging = prepare_staging(&final_path).unwrap();
        assert!(!final_path.exists());
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&staging).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        fs::write(staging.join("complete"), b"complete").unwrap();

        install_staging(&staging, &final_path).unwrap();

        assert!(!staging.exists());
        assert_eq!(fs::read(final_path.join("complete")).unwrap(), b"complete");
    }

    #[test]
    fn passwordless_config_artifacts_are_preserved_and_refused() {
        let parent = tempfile::tempdir().unwrap();
        let final_path = parent.path().join("fedimintd");
        fs::create_dir(&final_path).unwrap();
        fs::write(final_path.join(SALT_FILE), b"existing salt").unwrap();

        let error = ensure_no_config_artifacts(&final_path).unwrap_err();

        assert!(error.to_string().contains("non-disposable"));
        assert_eq!(
            fs::read(final_path.join(SALT_FILE)).unwrap(),
            b"existing salt"
        );
    }
}
