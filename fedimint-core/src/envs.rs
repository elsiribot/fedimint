use std::collections::BTreeMap;
use std::str::FromStr;
use std::{cmp, env};

use anyhow::Context;
use fedimint_core::util::SafeUrl;
use fedimint_derive::{Decodable, Encodable};
use fedimint_logging::LOG_CORE;
use jsonrpsee_core::Serialize;
use serde::Deserialize;
use tracing::warn;

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

/// Overrides the ERC-4337 USDT module's Chainlink ETH/USD price-feed address
/// (a 0x-prefixed 20-byte hex EVM address) for the config-gen leader.
pub const FM_USDT_ETH_USD_PRICE_FEED_ENV: &str = "FM_USDT_ETH_USD_PRICE_FEED";

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

/// Env var to override iroh connectivity
///
/// Comma separated key-value list (`<node_id>=<ticket>,<node_id>=<ticket>,...`)
pub const FM_IROH_CONNECT_OVERRIDES_ENV: &str = "FM_IROH_CONNECT_OVERRIDES";

/// Env var to override iroh connectivity
///
/// Comma separated key-value list (`<node_id>=<ticket>,<node_id>=<ticket>,...`)
pub const FM_GW_IROH_CONNECT_OVERRIDES_ENV: &str = "FM_GW_IROH_CONNECT_OVERRIDES";

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
