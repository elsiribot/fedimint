use std::collections::BTreeMap;

pub use fedimint_core::bitcoin::Network;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, plugin_types_trait_impl_config};
use fedimint_threshold_ecdsa::KeyShare;
use fedimint_usdt_common::{EvmAddress, UsdtCommonInit};
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
#[derive(Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct UsdtConfigLocal {
    pub evm_rpc_url: String,
    /// This guardian's broadcaster EOA private key (hex, optionally
    /// `0x`-prefixed), used to front gas for `EntryPoint.handleOps` calls
    /// (`AlloyEvmRpc::submit_user_ops`, Phase 7 Task 4). `None` in the
    /// trusted-dealer/DKG defaults below; a real deployment must configure
    /// one (or share a single federation-wide broadcaster key across
    /// guardians -- any guardian's broadcaster may submit a given `UserOp`,
    /// since the `EntryPoint` dedups by `(sender, nonce)` on-chain) before
    /// Phase 7 Task 5 wires guardian-local `UserOp` submission into
    /// production. Never put on the wire or into consensus (see this
    /// struct's own doc comment).
    pub broadcaster_private_key: Option<String>,
}

// `broadcaster_private_key` is secret key material (an EOA private key that
// fronts gas and could be used to drain the broadcaster account), so it must
// never leak into logs. Redact it explicitly instead of deriving `Debug`;
// `evm_rpc_url` is non-secret and stays visible. Mirrors the redaction style
// used by `UsdtConfigPrivate` above.
impl std::fmt::Debug for UsdtConfigLocal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsdtConfigLocal")
            .field("evm_rpc_url", &self.evm_rpc_url)
            .field(
                "broadcaster_private_key",
                &self.broadcaster_private_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
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
    /// The ERC-20 contract address of the USDT token this federation
    /// custodies deposits of.
    pub usdt_contract: EvmAddress,
    /// The EVM chain id this federation's deposit accounts are watched on.
    pub chain_id: u64,
    /// The number of block confirmations a deposit must accumulate before
    /// guardians consider it final.
    pub confirmation_depth: u64,
    /// The deployed ERC-4337 v0.7 `EntryPoint` contract address this
    /// federation's `UserOps` are submitted through (Phase 7). Placeholder;
    /// real deployments/tests must override.
    pub entry_point: EvmAddress,
    /// The deployed `SimpleAccountFactory` contract address used to
    /// counterfactually derive (and, on first sweep, deploy) deposit
    /// accounts (Phase 7, Task 2's CREATE2 derivation). Placeholder; real
    /// deployments/tests must override.
    pub account_factory: EvmAddress,
    /// The deployed `SimpleAccount` implementation contract address the
    /// `account_factory` proxies deposit accounts to (Phase 7, Task 2's
    /// CREATE2 `initCodeHash`). Placeholder; real deployments/tests must
    /// override.
    pub simple_account_impl: EvmAddress,
    /// Guardian-side: how many blocks a claimed-but-unconfirmed deposit
    /// check remains valid for before it must be re-issued.
    pub check_ttl_blocks: u64,
    /// The minimum ETH balance (in wei) a guardian's broadcaster EOA must
    /// hold to count as "funded" for the Part C readiness state machine (see
    /// `fedimint_usdt_common::BootstrapObservation::broadcaster_funded`).
    /// Consensus-agreed (identical on every guardian) so the readiness tally
    /// stays deterministic; genuinely per-chain, so a config field rather
    /// than a compiled constant.
    pub broadcaster_min_balance_wei: u64,
    /// Chainlink ETH/USD aggregator address each guardian reads to vote
    /// `FeeVote::usdt_per_eth_e6` (see
    /// `fedimint_usdt_common::UsdtGenParams::eth_usd_price_feed`). All-zero
    /// disables it (static fallback).
    pub eth_usd_price_feed: EvmAddress,
    /// Max age (seconds, chain time) of a Chainlink reading before a guardian
    /// abstains (see
    /// `fedimint_usdt_common::UsdtGenParams::price_feed_max_staleness_secs`).
    pub price_feed_max_staleness_secs: u64,
}

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    UsdtCommonInit,
    UsdtConfig,
    UsdtConfigPrivate,
    UsdtConfigConsensus,
    fedimint_usdt_common::config::UsdtClientConfig
);

#[cfg(test)]
mod tests {
    use super::{UsdtConfigLocal, default_evm_rpc_url};

    /// A guardian's broadcaster EOA private key is secret key material and
    /// must never appear in `Debug` output (which routinely reaches logs).
    #[test]
    fn local_config_debug_redacts_broadcaster_key() {
        let secret = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let cfg = UsdtConfigLocal {
            evm_rpc_url: default_evm_rpc_url(),
            broadcaster_private_key: Some(secret.to_string()),
        };

        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains(secret),
            "broadcaster private key leaked into Debug output: {rendered}"
        );
        assert!(
            rendered.contains("<redacted>"),
            "expected redaction marker in Debug output: {rendered}"
        );
        // The non-secret RPC URL stays visible.
        assert!(
            rendered.contains(&default_evm_rpc_url()),
            "evm_rpc_url should remain visible in Debug output: {rendered}"
        );

        // `None` renders as `None`, not `<redacted>`.
        let cfg_none = UsdtConfigLocal {
            evm_rpc_url: default_evm_rpc_url(),
            broadcaster_private_key: None,
        };
        let rendered_none = format!("{cfg_none:?}");
        assert!(rendered_none.contains("None"));
        assert!(!rendered_none.contains("<redacted>"));
    }
}
