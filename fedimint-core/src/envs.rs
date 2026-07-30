use std::collections::BTreeMap;
use std::str::FromStr;
use std::{cmp, env};

use anyhow::Context;
use fedimint_core::util::SafeUrl;
use fedimint_derive::{Decodable, Encodable};
use fedimint_logging::LOG_CORE;
use jsonrpsee_core::Serialize;
use serde::Deserialize;
use tracing::{debug, warn};

use crate::util::FmtCompact as _;

/// In tests we want to routinely enable an extra unknown module to ensure
/// all client code handles correct modules that client doesn't know about.
pub const FM_USE_UNKNOWN_MODULE_ENV: &str = "FM_USE_UNKNOWN_MODULE";

/// Disable automatic consensus version voting for testing and development
/// environments
pub const FM_WALLET_DISABLE_AUTOMATIC_CONSENSUS_VERSION_VOTING_ENV: &str =
    "FM_WALLET_DISABLE_AUTOMATIC_CONSENSUS_VERSION_VOTING";

pub const FM_ENABLE_MODULE_LNV1_ENV: &str = "FM_ENABLE_MODULE_LNV1";
pub const FM_ENABLE_MODULE_LNV2_ENV: &str = "FM_ENABLE_MODULE_LNV2";
pub const FM_ENABLE_MODULE_MINT_ENV: &str = "FM_ENABLE_MODULE_MINT";
pub const FM_ENABLE_MODULE_MINTV2_ENV: &str = "FM_ENABLE_MODULE_MINTV2";
pub const FM_ENABLE_MODULE_WALLET_ENV: &str = "FM_ENABLE_MODULE_WALLET";
pub const FM_ENABLE_MODULE_WALLETV2_ENV: &str = "FM_ENABLE_MODULE_WALLETV2";
pub const FM_ENABLE_MODULE_USDT_ENV: &str = "FM_ENABLE_MODULE_USDT";

/// Env var to override the USDT module's EVM RPC URL at runtime.
///
/// Takes priority over the per-guardian `evm_rpc_url` baked into the
/// encrypted private config. Used e.g. by `devimint` to point at its
/// dynamically allocated `anvil` port, which is never known at config-gen
/// time.
pub const FM_USDT_EVM_RPC_URL_ENV: &str = "FM_USDT_EVM_RPC_URL";

/// Optional API key appended as the final path segment of
/// [`FM_USDT_EVM_RPC_URL_ENV`] at runtime.
///
/// For providers (Alchemy, Infura, QuickNode, …) that authenticate via a key
/// in the URL path — e.g. base `https://eth-mainnet.g.alchemy.com/v2` + key →
/// `https://eth-mainnet.g.alchemy.com/v2/<key>`. Lets the (secret) key live in
/// its own env var instead of being baked into the RPC URL config. No-op when
/// unset (put the full authenticated URL in `FM_USDT_EVM_RPC_URL` instead).
/// A BUNDLER-capable provider is REQUIRED on a real chain: the module observes
/// `UserOp` receipts via ERC-4337 `eth_getUserOperationReceipt` (Alchemy,
/// Infura, QuickNode, … expose it on their standard endpoint); a plain node RPC
/// does not implement that method.
pub const FM_USDT_EVM_RPC_API_KEY_ENV: &str = "FM_USDT_EVM_RPC_API_KEY";

/// File-based fallback for [`FM_USDT_EVM_RPC_API_KEY_ENV`].
///
/// If [`FM_USDT_EVM_RPC_API_KEY_ENV`] is unset or empty and this env var is
/// set, the API key is instead read (and trimmed) from the file at the given
/// path. Avoids putting the secret directly in the process environment,
/// where it is visible to other same-user processes via
/// `/proc/<pid>/environ`. See [`env_secret_or_file`].
pub const FM_USDT_EVM_RPC_API_KEY_FILE_ENV: &str = "FM_USDT_EVM_RPC_API_KEY_FILE";

/// Env var to override the USDT module's `usdt_contract` config-gen param
/// (a `0x`-prefixed 20-byte hex EVM address).
///
/// The module's compiled-in default is a placeholder
/// (`EvmAddress([0u8; 20])`); this lets a config-gen leader (e.g. `devimint`,
/// after deploying a test ERC-20 to its `anvil` instance) point a real
/// federation at the actual deployed contract without a code change.
pub const FM_USDT_CONTRACT_ENV: &str = "FM_USDT_CONTRACT";

/// Env vars to override the USDT module's ERC-4337 contract addresses at
/// config-gen (each a `0x`-prefixed 20-byte hex EVM address).
///
/// Like [`FM_USDT_CONTRACT_ENV`], the module's compiled-in defaults are
/// placeholders (`EvmAddress([0u8; 20])`): the canonical `EntryPoint` and a
/// `SimpleAccountFactory`/`SimpleAccount` implementation are deployed per-chain
/// and are not known at compile time. These let a config-gen leader (e.g.
/// `devimint`, after deploying the 4337 stack to its `anvil` instance) point a
/// real federation at the actual deployed addresses without a code change --
/// required for the sweep/withdrawal (UserOp) paths, which the deposit-only
/// [`FM_USDT_CONTRACT_ENV`] flow does not exercise.
pub const FM_USDT_ENTRY_POINT_ENV: &str = "FM_USDT_ENTRY_POINT";
/// See [`FM_USDT_ENTRY_POINT_ENV`].
pub const FM_USDT_ACCOUNT_FACTORY_ENV: &str = "FM_USDT_ACCOUNT_FACTORY";
/// See [`FM_USDT_ENTRY_POINT_ENV`].
pub const FM_USDT_SIMPLE_ACCOUNT_IMPL_ENV: &str = "FM_USDT_SIMPLE_ACCOUNT_IMPL";

/// Env var to override this guardian's USDT broadcaster EOA private key at
/// runtime (hex, optionally `0x`-prefixed).
///
/// Takes priority over the `broadcaster_private_key` in the encrypted private
/// config (which is `None` by default -- config-gen does not assign one). Used
/// e.g. by `devimint` to hand every guardian a funded `anvil` dev-account key
/// so the sweep/withdrawal `UserOp` broadcasters can front gas, without baking
/// a key into config-gen. Any guardian's broadcaster may submit a given op, so
/// a shared key across guardians is fine.
pub const FM_USDT_BROADCASTER_PRIVATE_KEY_ENV: &str = "FM_USDT_BROADCASTER_PRIVATE_KEY";

/// File-based fallback for [`FM_USDT_BROADCASTER_PRIVATE_KEY_ENV`]. See
/// [`FM_USDT_EVM_RPC_API_KEY_FILE_ENV`] for the rationale and
/// [`env_secret_or_file`] for the resolution order.
pub const FM_USDT_BROADCASTER_PRIVATE_KEY_FILE_ENV: &str = "FM_USDT_BROADCASTER_PRIVATE_KEY_FILE";

/// Overrides the ERC-4337 USDT module's Chainlink ETH/USD price-feed address
/// (a 0x-prefixed 20-byte hex EVM address) for the config-gen leader.
pub const FM_USDT_ETH_USD_PRICE_FEED_ENV: &str = "FM_USDT_ETH_USD_PRICE_FEED";

/// Overrides the USDT module's `residual_recovery_recipient` config-gen param
/// (a 0x-prefixed 20-byte hex EVM address) for the config-gen leader.
///
/// This is the DETERMINISTIC recipient the federation withdraws stranded,
/// single-use deposit-account `EntryPoint` gas deposits to (finding A). Every
/// guardian builds the byte-identical `EntryPoint.withdrawTo(recipient,
/// amount)` recovery op, so it must be a consensus-agreed value -- the
/// per-guardian broadcaster EOA is non-deterministic and cannot be used.
/// Typically the federation's broadcaster-refill/treasury address. Defaults to
/// the placeholder zero address (accepted only on dev chains).
pub const FM_USDT_RESIDUAL_RECOVERY_RECIPIENT_ENV: &str = "FM_USDT_RESIDUAL_RECOVERY_RECIPIENT";

/// Overrides the USDT module's `chain_id` config-gen param for the config-gen
/// leader (a decimal EVM chain id, e.g. `11155111` for Sepolia).
///
/// REQUIRED for any non-anvil chain: `chain_id` is bound into the ERC-4337
/// `userOpHash` the federation signs, so a wrong value makes every signature
/// invalid on-chain. Defaults to `31337` (anvil).
pub const FM_USDT_CHAIN_ID_ENV: &str = "FM_USDT_CHAIN_ID";

/// Overrides the USDT module's `confirmation_depth` config-gen param for the
/// config-gen leader (a decimal block count).
///
/// Deposits are credited only at `head - confirmation_depth`; raise it for a
/// real chain's reorg characteristics. Defaults to `1` (anvil).
pub const FM_USDT_CONFIRMATION_DEPTH_ENV: &str = "FM_USDT_CONFIRMATION_DEPTH";

/// Overrides the USDT module's `broadcaster_min_balance_wei` config-gen param
/// for the config-gen leader (decimal wei).
///
/// The minimum broadcaster ETH balance for the Part C readiness
/// `broadcaster_funded` condition. Defaults to `50_000_000_000_000_000`
/// (0.05 ETH); lower it for a cheap real-network test so the gas wallet needn't
/// hold that much. Gas cost itself is unaffected.
pub const FM_USDT_BROADCASTER_MIN_BALANCE_WEI_ENV: &str = "FM_USDT_BROADCASTER_MIN_BALANCE_WEI";

/// Per-guardian override for how often (in seconds) the USDT module's
/// background observer loops poll the EVM RPC endpoint (block count, fee
/// estimate, bootstrap readiness, deposit scan, UserOp receipts).
///
/// This is a purely guardian-local runtime knob -- it changes only how
/// frequently this guardian refreshes its own chain view before proposing
/// observations to consensus, not any consensus-agreed value, so guardians
/// may safely run different intervals (e.g. matched to each provider's rate
/// limits). Lower is more responsive but consumes more RPC quota; each
/// guardian runs several independent loops, so total call volume scales with
/// `1 / interval`. Defaults to `15`; values below `5` are clamped to `5` to
/// avoid a busy loop. The slow-changing loops (fee estimate, and the
/// bootstrap-readiness loop once its immutable contract facts are cached) run
/// at a multiple of this. Ignored under the test harness (which uses a fixed
/// fast interval).
pub const FM_USDT_POLL_INTERVAL_SECS_ENV: &str = "FM_USDT_POLL_INTERVAL_SECS";

/// Explicit operator acknowledgement to run a non-dev `chain_id` with a
/// below-minimum `confirmation_depth`.
///
/// Compared against the module's minimum safe production depth
/// (`fedimint_usdt_common::MIN_PROD_CONFIRMATION_DEPTH`). Unset (or any value
/// other than `"1"`) means the low depth is rejected at config-gen/validation
/// time (sec-17 hardening) -- set to `"1"` only when the operator has
/// deliberately chosen a lower depth for their chain's reorg
/// characteristics.
pub const FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH_ENV: &str = "FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH";

/// Explicit operator acknowledgement to run the USDT module's EVM RPC over a
/// plaintext, non-loopback `http://` endpoint.
///
/// `AlloyEvmRpc::new` refuses any RPC URL that is neither `https://` nor a
/// loopback host (`127.0.0.1`, `::1`, `localhost`) unless this is set to
/// `"1"` (sec-18 hardening) -- a remote plaintext endpoint lets a
/// network-position attacker observe and tamper with every RPC-derived
/// guardian observation/submission. Set only when the operator has
/// deliberately accepted that MITM exposure (e.g. a private, otherwise-secured
/// network path).
pub const FM_USDT_UNSAFE_ALLOW_HTTP_ENV: &str = "FM_USDT_UNSAFE_ALLOW_HTTP";

/// Env var to override the `mintv2` module's `amount_unit` config-gen param
/// (a decimal [`crate::module::AmountUnit`] id, e.g. `1` for
/// `fedimint_usdt_common::USDT_UNIT`).
///
/// The module's compiled-in default denominates in the native Bitcoin unit
/// (`AmountUnit::BITCOIN`); this lets a config-gen leader stand up a
/// USDT-denominated `mintv2` instance -- e.g. for the usdt module's
/// devimint/anvil e2e, which needs a primary module registered for
/// `USDT_UNIT` to mint the claimed e-cash into -- without a code change.
pub const FM_MINTV2_AMOUNT_UNIT_ENV: &str = "FM_MINTV2_AMOUNT_UNIT";

/// Disable mint base fees for testing and development environments
pub const FM_DISABLE_BASE_FEES_ENV: &str = "FM_DISABLE_BASE_FEES";

/// Print sensitive secrets without redacting them. Use only for debugging.
pub const FM_DEBUG_SHOW_SECRETS_ENV: &str = "FM_DEBUG_SHOW_SECRETS";

/// Check if env variable is set and not equal `0` or `false` which are common
/// ways to disable something.
pub fn is_env_var_set(var: &str) -> bool {
    let Some(val) = std::env::var_os(var) else {
        return false;
    };
    match val.as_encoded_bytes() {
        b"0" | b"false" => false,
        b"1" | b"true" => true,
        _ => {
            warn!(
                target: LOG_CORE,
                %var,
                val = %val.to_string_lossy(),
                "Env var value invalid is invalid and ignored, assuming `true`"
            );
            true
        }
    }
}

/// Check if env variable is set and not equal `0` or `false` which are common
/// ways to disable a setting. `None` if env var not set at all, which allows
/// handling the default value.
pub fn is_env_var_set_opt(var: &str) -> Option<bool> {
    let val = std::env::var_os(var)?;
    match val.as_encoded_bytes() {
        b"0" | b"false" => Some(false),
        b"1" | b"true" => Some(true),
        _ => {
            warn!(
                target: LOG_CORE,
                %var,
                val = %val.to_string_lossy(),
                "Env var value invalid is invalid and ignored"
            );
            None
        }
    }
}

/// Use to detect if running in a test environment, either `cargo test` or
/// `devimint`.
pub fn is_running_in_test_env() -> bool {
    let unit_test = cfg!(test);

    unit_test || is_env_var_set("NEXTEST") || is_env_var_set(FM_IN_DEVIMINT_ENV)
}

/// Read a secret from an env var, falling back to a file whose path is given
/// by a second env var when the first is unset or empty.
///
/// Mirrors the `_FILE` fallback convention already used elsewhere in
/// fedimint (see `fedimintd`'s `bitcoind_url_password_file` /
/// `FM_BITCOIND_URL_PASSWORD_FILE_ENV`), so an operator can keep a secret
/// out of the process environment -- which is visible to other same-user
/// processes via `/proc/<pid>/environ` -- by instead pointing at a file only
/// the process needs to read.
///
/// Resolution order:
/// 1. If `inline_env` is set to a non-empty value, that value is returned.
/// 2. Else, if `file_env` is set (to a non-empty path), the file at that path
///    is read and its TRIMMED contents are returned -- most tooling that writes
///    a secret to a file appends a trailing newline.
/// 3. Else, `Ok(None)`.
///
/// Logs at `debug` which source supplied the secret (`"inline"` or
/// `"file"`), but NEVER the secret value itself.
pub fn env_secret_or_file(inline_env: &str, file_env: &str) -> anyhow::Result<Option<String>> {
    if let Some(val) = std::env::var(inline_env).ok().filter(|s| !s.is_empty()) {
        debug!(target: LOG_CORE, env = %inline_env, source = "inline", "Secret sourced from inline env var");
        return Ok(Some(val));
    }

    let Some(path) = std::env::var(file_env).ok().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };

    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read secret file at path from {file_env}"))?;

    debug!(target: LOG_CORE, env = %file_env, source = "file", "Secret sourced from file");

    Ok(Some(contents.trim().to_owned()))
}

/// Use to allow `process_output` to process RBF withdrawal outputs.
pub fn is_rbf_withdrawal_enabled() -> bool {
    is_env_var_set("FM_UNSAFE_ENABLE_RBF_WITHDRAWAL")
}

/// Use to disable automatic consensus version voting for testing and
/// development environments
pub fn is_automatic_consensus_version_voting_disabled() -> bool {
    is_env_var_set(FM_WALLET_DISABLE_AUTOMATIC_CONSENSUS_VERSION_VOTING_ENV)
}

/// Get value of `FEDIMINT_BUILD_CODE_VERSION` at compile time
#[macro_export]
macro_rules! fedimint_build_code_version_env {
    () => {
        env!("FEDIMINT_BUILD_CODE_VERSION")
    };
}

/// Env var for bitcoin RPC kind (obsolete, use FM_DEFAULT_* instead)
pub const FM_BITCOIN_RPC_KIND_ENV: &str = "FM_BITCOIN_RPC_KIND";
/// Env var for bitcoin URL (obsolete, use FM_DEFAULT_* instead)
pub const FM_BITCOIN_RPC_URL_ENV: &str = "FM_BITCOIN_RPC_URL";
/// Env var how often to poll bitcoin source
pub const FM_BITCOIN_POLLING_INTERVAL_SECS_ENV: &str = "FM_BITCOIN_POLLING_INTERVAL_SECS";

/// Env var for bitcoin RPC kind (default, used only as a default value for DKG
/// config settings)
pub const FM_DEFAULT_BITCOIN_RPC_KIND_ENV: &str = "FM_DEFAULT_BITCOIN_RPC_KIND";
pub const FM_DEFAULT_BITCOIN_RPC_KIND_BAD_ENV: &str = "FM_DEFAULT_BITCOIND_RPC_KIND";
/// Env var for bitcoin URL (default, used only as a default value for DKG
/// config settings)
pub const FM_DEFAULT_BITCOIN_RPC_URL_ENV: &str = "FM_DEFAULT_BITCOIN_RPC_URL";
pub const FM_DEFAULT_BITCOIN_RPC_URL_BAD_ENV: &str = "FM_DEFAULT_BITCOIND_RPC_URL";

/// Env var for bitcoin RPC kind (forced, takes priority over config settings)
pub const FM_FORCE_BITCOIN_RPC_KIND_ENV: &str = "FM_FORCE_BITCOIN_RPC_KIND";
pub const FM_FORCE_BITCOIN_RPC_KIND_BAD_ENV: &str = "FM_FORCE_BITCOIND_RPC_BAD_KIND";
/// Env var for bitcoin URL (default, takes priority over config settings)
pub const FM_FORCE_BITCOIN_RPC_URL_ENV: &str = "FM_FORCE_BITCOIN_RPC_URL";
pub const FM_FORCE_BITCOIN_RPC_URL_BAD_ENV: &str = "FM_FORCE_BITCOIND_RPC_URL";

/// Env var to override iroh connectivity, in the legacy iroh 0.35 `NodeTicket`
/// format.
///
/// Comma separated key-value list
/// (`<node_id>=<ticket>,<node_id>=<ticket>,...`). Only still read by pre-0.12
/// binaries that link iroh 0.35; current binaries
/// read [`FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV`] instead. iroh 1.0 no longer
/// ships the `NodeTicket` format, so the override format had to become version
/// agnostic; rather than overload this var with two incompatible formats, the
/// new format lives under its own name and both are emitted side by side.
pub const FM_IROH_CONNECT_OVERRIDES_ENV: &str = "FM_IROH_CONNECT_OVERRIDES";

/// Env var to override iroh connectivity, in the legacy iroh 0.35 `NodeTicket`
/// format. Gateway counterpart of [`FM_IROH_CONNECT_OVERRIDES_ENV`].
pub const FM_GW_IROH_CONNECT_OVERRIDES_ENV: &str = "FM_GW_IROH_CONNECT_OVERRIDES";

/// Env var to override iroh connectivity, in the plain `<id>=<addr>` format.
///
/// Comma separated key-value list (`<node_id>=<socket_addr>,...`). The value is
/// a single direct address; the consumer rebuilds the iroh node/endpoint
/// address from the id and address, so the format works on both iroh 0.35 and
/// iroh 1.0. Current binaries read this; pre-0.12 binaries read the legacy
/// [`FM_IROH_CONNECT_OVERRIDES_ENV`] instead.
pub const FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV: &str = "FM_IROH_CONNECT_OVERRIDES_PLAIN";

/// Env var to override iroh connectivity, in the plain `<id>=<addr>` format.
/// Gateway counterpart of [`FM_IROH_CONNECT_OVERRIDES_PLAIN_ENV`].
pub const FM_GW_IROH_CONNECT_OVERRIDES_PLAIN_ENV: &str = "FM_GW_IROH_CONNECT_OVERRIDES_PLAIN";

/// Env var to override iroh DNS server
pub const FM_IROH_DNS_ENV: &str = "FM_IROH_DNS";

/// Env var to override iroh relays server
pub const FM_IROH_RELAY_ENV: &str = "FM_IROH_RELAY";

/// Env var to disable Iroh's use of DHT
pub const FM_IROH_DHT_ENABLE_ENV: &str = "FM_IROH_DHT_ENABLE";

/// Env var to disable default n0 discovery
pub const FM_IROH_N0_DISCOVERY_ENABLE_ENV: &str = "FM_IROH_N0_DISCOVERY_ENABLE";

/// Env var to disable default pkarr resolver
pub const FM_IROH_PKARR_RESOLVER_ENABLE_ENV: &str = "FM_IROH_PKARR_RESOLVER_ENABLE";

/// Env var to disable default pkarr publisher
pub const FM_IROH_PKARR_PUBLISHER_ENABLE_ENV: &str = "FM_IROH_PKARR_PUBLISHER_ENABLE";

/// Env var to disable Iroh's use of relays
pub const FM_IROH_RELAYS_ENABLE_ENV: &str = "FM_IROH_RELAYS_ENABLE";

/// Env var to disable all pkarr publishing (enabled by default)
pub const FM_PKARR_ENABLE_ENV: &str = "FM_PKARR_ENABLE";

/// Env var to enable pkarr DHT publishing (disabled by default)
pub const FM_PKARR_DHT_ENABLE_ENV: &str = "FM_PKARR_DHT_ENABLE";

/// Env var to disable pkarr relay publishing (enabled by default)
pub const FM_PKARR_RELAYS_ENABLE_ENV: &str = "FM_PKARR_RELAYS_ENABLE";

/// Env var to override tcp api connectivity
///
/// Comma separated key-value list (`peer_id=url,peer_id=url`)
pub const FM_WS_API_CONNECT_OVERRIDES_ENV: &str = "FM_WS_API_CONNECT_OVERRIDES";

pub const FM_IROH_API_SECRET_KEY_OVERRIDE_ENV: &str = "FM_IROH_API_SECRET_KEY_OVERRIDE";
pub const FM_IROH_P2P_SECRET_KEY_OVERRIDE_ENV: &str = "FM_IROH_P2P_SECRET_KEY_OVERRIDE";

/// List of json api endpoint sources to use as a source of
/// fee rate estimation.
///
/// `;`-separated list of urls with part after `#`
/// ("fragment") specifying jq filter to extract sats/vB fee rate.
/// Eg. `https://mempool.space/api/v1/fees/recommended#.halfHourFee`
///
/// Note that `#` is a standalone separator and *not* parsed as a part of the
/// Url. Which means there's no need to escape it.
pub const FM_WALLET_FEERATE_SOURCES_ENV: &str = "FM_WALLET_FEERATE_SOURCES";

/// `devimint` will set when code is running inside `devimint`
pub const FM_IN_DEVIMINT_ENV: &str = "FM_IN_DEVIMINT";

/// Configuration for the bitcoin RPC
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct BitcoinRpcConfig {
    pub kind: String,
    pub url: SafeUrl,
}

impl BitcoinRpcConfig {
    pub fn get_defaults_from_env_vars() -> anyhow::Result<Self> {
        Ok(Self {
        kind: env::var(FM_FORCE_BITCOIN_RPC_KIND_ENV)
            .or_else(|_| env::var(FM_DEFAULT_BITCOIN_RPC_KIND_ENV))
            .or_else(|_| env::var(FM_BITCOIN_RPC_KIND_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_BITCOIN_RPC_KIND_ENV} is obsolete, use {FM_DEFAULT_BITCOIN_RPC_KIND_ENV} instead");
            }))
            .or_else(|_| env::var(FM_FORCE_BITCOIN_RPC_KIND_BAD_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_FORCE_BITCOIN_RPC_KIND_BAD_ENV} is obsolete, use {FM_FORCE_BITCOIN_RPC_KIND_ENV} instead");
            }))
            .or_else(|_| env::var(FM_DEFAULT_BITCOIN_RPC_KIND_BAD_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_DEFAULT_BITCOIN_RPC_KIND_BAD_ENV} is obsolete, use {FM_DEFAULT_BITCOIN_RPC_KIND_ENV} instead");
            }))
            .with_context(|| {
                anyhow::anyhow!("failure looking up env var for Bitcoin RPC kind")
            })?,
        url: env::var(FM_FORCE_BITCOIN_RPC_URL_ENV)
            .or_else(|_| env::var(FM_DEFAULT_BITCOIN_RPC_URL_ENV))
            .or_else(|_| env::var(FM_BITCOIN_RPC_URL_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_BITCOIN_RPC_URL_ENV} is obsolete, use {FM_DEFAULT_BITCOIN_RPC_URL_ENV} instead");
            }))
            .or_else(|_| env::var(FM_FORCE_BITCOIN_RPC_URL_BAD_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_FORCE_BITCOIN_RPC_URL_BAD_ENV} is obsolete, use {FM_FORCE_BITCOIN_RPC_URL_ENV} instead");
            }))
            .or_else(|_| env::var(FM_DEFAULT_BITCOIN_RPC_URL_BAD_ENV).inspect(|_v| {
                warn!(target: LOG_CORE, "{FM_DEFAULT_BITCOIN_RPC_URL_BAD_ENV} is obsolete, use {FM_DEFAULT_BITCOIN_RPC_URL_ENV} instead");
            }))
            .with_context(|| {
                anyhow::anyhow!("failure looking up env var for Bitcoin RPC URL")
            })?
            .parse()
            .with_context(|| {
                anyhow::anyhow!("failure parsing Bitcoin RPC URL")
            })?,
    })
    }
}

pub fn parse_kv_list_from_env<K, V>(env: &str) -> anyhow::Result<BTreeMap<K, V>>
where
    K: FromStr + cmp::Ord,
    <K as FromStr>::Err: std::error::Error,
    V: FromStr,
    <V as FromStr>::Err: std::error::Error,
{
    let mut map = BTreeMap::new();
    let Ok(env_value) = std::env::var(env) else {
        return Ok(BTreeMap::new());
    };
    for kv in env_value.split(',') {
        let kv = kv.trim();

        if kv.is_empty() {
            continue;
        }

        if let Some((k, v)) = kv.split_once('=') {
            let Some(k) = K::from_str(k)
                .inspect_err(|err| {
                    warn!(
                        target: LOG_CORE,
                        err = %err.fmt_compact(),
                        "Error parsing value"
                    );
                })
                .ok()
            else {
                continue;
            };
            let Some(v) = V::from_str(v)
                .inspect_err(|err| {
                    warn!(
                        target: LOG_CORE,
                        err = %err.fmt_compact(),
                        "Error parsing value"
                    );
                })
                .ok()
            else {
                continue;
            };

            map.insert(k, v);
        }
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::env_secret_or_file;

    /// Serializes tests that touch process-wide env vars so they cannot race
    /// under `cargo test`'s default parallel-test execution.
    static ENV_VAR_LOCK: Mutex<()> = Mutex::new(());

    const INLINE_ENV: &str = "FM_TEST_ENV_SECRET_OR_FILE_INLINE";
    const FILE_ENV: &str = "FM_TEST_ENV_SECRET_OR_FILE_FILE";

    /// Returns a path in the OS temp dir that is unique to this test
    /// process/thread/call, so parallel test binaries (and repeated calls
    /// within one test) never collide on the same file.
    fn unique_temp_path(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "fedimint-envs-test-{tag}-{}-{n}",
            std::process::id()
        ))
    }

    /// Clears both env vars used by these tests. Must only be called while
    /// holding `ENV_VAR_LOCK`.
    fn clear_env() {
        // SAFETY: caller holds `ENV_VAR_LOCK`, serializing all env var
        // mutation across this module's tests.
        unsafe {
            std::env::remove_var(INLINE_ENV);
            std::env::remove_var(FILE_ENV);
        }
    }

    #[test]
    fn env_secret_or_file_prefers_inline_then_file_then_none() {
        let _lock = ENV_VAR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_env();

        // Neither set -> None.
        assert_eq!(
            env_secret_or_file(INLINE_ENV, FILE_ENV)
                .expect("no file to read when file env is unset"),
            None
        );

        // Only file set -> trimmed file contents.
        let path = unique_temp_path("prefers-inline-then-file");
        // nosemgrep: ban-fs-write -- test-only: create a throwaway temp secret file
        std::fs::write(&path, "  from-file-secret\n\n").expect("can write temp secret file");
        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::set_var(FILE_ENV, &path);
        }
        assert_eq!(
            env_secret_or_file(INLINE_ENV, FILE_ENV).expect("file read must succeed"),
            Some("from-file-secret".to_owned())
        );

        // Both set -> inline wins, file is not even read (delete it to
        // prove that: a read attempt would error, not silently proceed).
        std::fs::remove_file(&path).expect("can remove temp secret file");
        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::set_var(INLINE_ENV, "from-inline-secret");
        }
        assert_eq!(
            env_secret_or_file(INLINE_ENV, FILE_ENV)
                .expect("inline must win without touching the (now-missing) file"),
            Some("from-inline-secret".to_owned())
        );

        clear_env();
    }

    #[test]
    fn env_secret_or_file_empty_inline_falls_back_to_file() {
        let _lock = ENV_VAR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_env();

        let path = unique_temp_path("empty-inline-falls-back");
        // nosemgrep: ban-fs-write -- test-only: create a throwaway temp secret file
        std::fs::write(&path, "from-file-secret").expect("can write temp secret file");
        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::set_var(INLINE_ENV, "");
            std::env::set_var(FILE_ENV, &path);
        }

        assert_eq!(
            env_secret_or_file(INLINE_ENV, FILE_ENV).expect("file read must succeed"),
            Some("from-file-secret".to_owned())
        );

        std::fs::remove_file(&path).expect("can remove temp secret file");
        clear_env();
    }

    #[test]
    fn env_secret_or_file_missing_file_path_errors() {
        let _lock = ENV_VAR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        clear_env();

        let path = unique_temp_path("missing-file-path-errors");
        // Deliberately do not create `path`.
        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::set_var(FILE_ENV, &path);
        }

        let err = env_secret_or_file(INLINE_ENV, FILE_ENV).expect_err(
            "a file env pointing at a nonexistent path must error, not silently return None",
        );
        assert!(err.to_string().contains(FILE_ENV));

        clear_env();
    }
}
