pub use fedimint_core::bitcoin::Network;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1;
use serde::{Deserialize, Serialize};

use crate::EvmAddress;

/// Configuration needed by the client to interact with the USDT-on-EVM
/// module.
///
/// The server-side private and consensus configuration (which additionally
/// carries the threshold-ECDSA key share material) lives in
/// `fedimint-usdt-server` so that this crate can stay free of the
/// `fedimint-threshold-ecdsa`/`cggmp21` dependency chain and remain
/// WASM-compatible.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct UsdtClientConfig {
    /// The aggregate (group) public key of the federation's threshold-ECDSA
    /// key, controlling the EVM account that custodies the pegged-in USDT.
    pub group_public_key: secp256k1::PublicKey,
    /// The network this federation is configured for, mirroring the
    /// `Network` type used by other fedimint modules (e.g. lnv2) rather than
    /// introducing a bespoke EVM chain-id enum in this phase.
    pub network: Network,
    /// The ERC-20 contract address of the USDT token this federation
    /// custodies deposits of.
    pub usdt_contract: EvmAddress,
    /// The EVM chain id this federation's deposit accounts are watched on.
    pub chain_id: u64,
    /// The number of block confirmations a deposit must accumulate before
    /// guardians consider it final.
    pub confirmation_depth: u64,
}

impl std::fmt::Display for UsdtClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Interface B (pinned): the deposit address for `claim_pk` under this
/// federation's config. Thin wrapper over
/// [`crate::derive_deposit_account`] so client and server share one impl.
#[must_use]
pub fn derive_deposit_account(
    cfg: &UsdtClientConfig,
    claim_pk: &secp256k1::PublicKey,
) -> crate::EvmAddress {
    crate::derive_deposit_account(&cfg.group_public_key, claim_pk)
}
