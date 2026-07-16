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
/// MPC protocol messages to/from this guardian. Also carries this guardian's
/// [`UsdtConfigLocal`] (non-secret, but still per-guardian and not agreed on
/// by the federation).
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
    /// This guardian's local (non-consensus) configuration, e.g. which EVM
    /// RPC endpoint to use.
    ///
    /// `fedimint-core`'s `ServerModuleConfig`/`TypedServerModuleConfig`
    /// machinery only has two slots (`private`, `consensus`) for a module's
    /// config to travel through config-gen and get persisted to disk; there
    /// is no dedicated "local" slot (an earlier, now-removed generation of
    /// this machinery had one — see `WalletConfigLocal` in
    /// `fedimint-wallet-common`, which is presently unused dead code left
    /// over from that removal). Nesting [`UsdtConfigLocal`] inside the
    /// private part is the natural fit for the current two-slot shape: like
    /// the rest of `UsdtConfigPrivate`, it is guardian-specific and only
    /// ever serde-(de)serialized to/from this guardian's local config file,
    /// never shared with peers or put into consensus — it just isn't
    /// secret.
    pub local: UsdtConfigLocal,
}

// `cggmp21::KeyShare` does not implement `Debug`, and even if it did we would
// not want to print secret key material. Redact both secret fields
// explicitly instead of deriving `Debug`; `local` has nothing to hide.
impl std::fmt::Debug for UsdtConfigPrivate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsdtConfigPrivate")
            .field("key_share", &"<redacted>")
            .field("mpc_encryption_sk", &"<redacted>")
            .field("local", &self.local)
            .finish()
    }
}

/// This guardian's local (non-consensus, non-secret) configuration: which EVM
/// RPC endpoint this guardian's own server should use. Every guardian may
/// point at a different node, so unlike [`UsdtConfigConsensus`] this is never
/// agreed on by the federation.
#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct UsdtConfigLocal {
    pub evm_rpc_url: String,
}

/// Default EVM RPC URL used by [`crate::UsdtInit::trusted_dealer_gen`] and
/// [`crate::dkg::distributed_gen`] for local development/testing (mirrors
/// `default_client_bitcoin_rpc` in `fedimint-wallet-server`). Every
/// trusted-dealer peer gets this same value; production deployments are
/// expected to override it post-config-gen once a per-guardian override
/// mechanism lands (later phases).
pub fn default_evm_rpc_url() -> String {
    "http://127.0.0.1:8545".to_string()
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
