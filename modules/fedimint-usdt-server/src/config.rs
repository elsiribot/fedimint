use std::collections::BTreeMap;

pub use fedimint_core::bitcoin::Network;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, plugin_types_trait_impl_config};
use fedimint_threshold_ecdsa::KeyShare;
use fedimint_usdt_common::UsdtCommonInit;
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

/// The full per-peer configuration: the private key share material plus the
/// consensus-visible parameters agreed on by the whole federation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsdtConfig {
    pub private: UsdtConfigPrivate,
    pub consensus: UsdtConfigConsensus,
}

/// The secrets this guardian alone holds: its share of the threshold-ECDSA
/// signing key, and the static secp256k1 key used to encrypt point-to-point
/// MPC protocol messages to/from this guardian.
///
/// Not `Encodable`/`Decodable`: private config is only ever
/// serde-(de)serialized to/from the guardian's local, encrypted config file
/// and never put on the wire or into consensus.
#[derive(Clone, Serialize, Deserialize)]
pub struct UsdtConfigPrivate {
    /// This guardian's complete CGGMP21 key share (DKG core share + auxiliary
    /// info).
    pub key_share: KeyShare,
    /// This guardian's static secp256k1 keypair (secret half) used to
    /// authenticate/decrypt MPC transport messages.
    pub mpc_encryption_sk: SecretKey,
}

// `cggmp21::KeyShare` does not implement `Debug`, and even if it did we would
// not want to print secret key material. Redact both fields explicitly
// instead of deriving `Debug`.
impl std::fmt::Debug for UsdtConfigPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsdtConfigPrivate")
            .field("key_share", &"<redacted>")
            .field("mpc_encryption_sk", &"<redacted>")
            .finish()
    }
}

/// The parameters every guardian in the federation agrees on.
#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct UsdtConfigConsensus {
    /// The aggregate (group) public key of the federation's threshold-ECDSA
    /// key, controlling the EVM account that custodies the pegged-in USDT.
    pub group_public_key: PublicKey,
    /// Every guardian's static MPC transport encryption public key, indexed
    /// by peer ID.
    pub mpc_encryption_pks: BTreeMap<PeerId, PublicKey>,
    /// The signing threshold `t`: any `t` of the federation's guardians can
    /// jointly produce a valid signature.
    pub threshold: u16,
    /// The network this federation is configured for, mirroring the
    /// `Network` type used by other fedimint modules (e.g. lnv2).
    pub network: Network,
}

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    UsdtCommonInit,
    UsdtConfig,
    UsdtConfigPrivate,
    UsdtConfigConsensus,
    fedimint_usdt_common::config::UsdtClientConfig
);
