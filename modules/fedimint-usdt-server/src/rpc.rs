//! Server-side read (and, eventually, broadcast) access to an EVM node, via
//! an injectable [`IServerEvmRpc`] trait so the consensus/state-machine code
//! that will consume it (from Phase 5 onward) can be tested against a
//! `MockEvmRpc` instead of a live node.

use std::sync::Arc;

use alloy::eips::BlockId;
use alloy::network::TransactionBuilder as _;
use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::Context as _;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_usdt_common::user_op::{PackedUserOperation, SignedUserOp, UserOpReceipt};
use fedimint_usdt_common::{EvmAddress, FeeVote, UsdtAmount};
use tracing::{debug, warn};

use crate::factory_bytecode::{
    ARACHNID_DEPLOY_TX_COST_WEI, ARACHNID_DEPLOYER, ARACHNID_DEPLOYER_SIGNER,
    ARACHNID_RAW_DEPLOY_TX, factory_create2_salt, factory_init_code,
};

/// Type-erased handle to a [`IServerEvmRpc`] implementation.
pub type DynServerEvmRpc = Arc<dyn IServerEvmRpc>;

sol! {
    #[sol(rpc)]
    interface ISimpleAccountFactory {
        // Part C readiness: the counterfactual CREATE2 address the factory
        // would deploy `owner`'s `SimpleAccount` at for `salt`. Used to
        // cross-check the on-chain factory's immutable `accountImplementation`
        // + baked `ERC1967Proxy` initCode against this build's off-chain
        // `derive_deposit_account`/`derive_pool_account` CREATE2 math -- the
        // footgun-killer that proves derived deposit addresses are spendable.
        function getAddress(address owner, uint256 salt) external view returns (address);

        // sec-16 readiness deepening: the factory's immutable
        // `SimpleAccount` implementation address, read directly (rather than
        // only inferred through `getAddress`'s CREATE2 math) so readiness can
        // reject a factory whose `getAddress` happens to special-case the
        // sampled salts but whose deployed accounts would actually proxy to a
        // non-canonical implementation.
        function accountImplementation() external view returns (address);
    }

    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
        // Tether-specific transfer-fee parameter (`basisPointsRate` on the
        // mainnet `TetherToken`). NOT part of the ERC-20 standard: a call to it
        // on a standard token reverts, which the startup fee check treats as
        // "no transfer-fee mechanism". Currently 0 on mainnet USDT; a nonzero
        // value would make transfers deliver less than the requested amount.
        function basisPointsRate() external view returns (uint256);
    }

    // Chainlink's standard price-feed ABI (`AggregatorV3Interface`), used by
    // `AlloyEvmRpc::get_fee_estimate` to read the ETH/USD price each
    // guardian votes into `FeeVote::usdt_per_eth_e6` (see
    // `fedimint_usdt_common::chainlink_eth_usd_to_usdt_per_eth_e6`).
    #[sol(rpc)]
    interface IAggregatorV3 {
        function decimals() external view returns (uint8);
        function latestRoundData() external view returns (
            uint80 roundId, int256 answer, uint256 startedAt,
            uint256 updatedAt, uint80 answeredInRound);
    }
}

alloy::sol! {
    // Mirrors `fedimint_usdt_common::user_op::PackedUserOperation`
    // field-for-field: a distinct (this-module-local) Rust type from a
    // separate `sol!` invocation, needed because `EntryPoint.handleOps`'s
    // `#[sol(rpc)]` binding requires its own `SolCall`-implementing
    // parameter type. Same underlying `alloy-primitives`/`alloy-sol-types`
    // versions across the workspace (see the root `Cargo.toml`'s comment on
    // `alloy-primitives`), so fields copy across directly with no
    // conversion (see [`to_rpc_packed_user_op`]). Mirrors the identical
    // pattern already used by
    // `fedimint-usdt-tests/tests/user_op_hash.rs`.
    struct PackedUserOperationRpc {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }

    #[sol(rpc)]
    interface IEntryPoint {
        function handleOps(PackedUserOperationRpc[] calldata ops, address payable beneficiary) external;
        // Part B (auto-prefund): the `EntryPoint`'s own gas-*deposit*
        // accounting, used by `submit_user_ops` to self-fund each op sender's
        // deposit from the broadcaster before `handleOps`. `balanceOf` here is
        // the sender's ETH deposit held *inside the EntryPoint* to pay for its
        // UserOp gas -- NOT the ERC-20 `IERC20::balanceOf` above (a distinct
        // `sol!` interface, so the two generate distinct Rust `*Call` types
        // with no collision). `depositTo` tops that deposit up (payable).
        function depositTo(address account) external payable;
        function balanceOf(address account) external view returns (uint256);
    }

    /// `EntryPoint` v0.7's `UserOperationEvent`
    /// (`@account-abstraction/contracts@0.7.0`'s `interfaces/IEntryPoint.sol`),
    /// emitted once per `UserOp` processed by `handleOps` -- regardless of
    /// whether the op's `callData` execution itself succeeded (`success`
    /// tracks that; the event is always emitted for any op that passed
    /// validation and was included). Field layout confirmed against the
    /// vendored `EntryPoint.json` artifact's ABI.
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );
}

/// Converts the `-common` crate's [`PackedUserOperation`] into this module's
/// own `sol!`-generated [`PackedUserOperationRpc`], so it can be passed to
/// the `#[sol(rpc)]`-generated `handleOps` binding. Mirrors
/// `fedimint-usdt-tests/tests/user_op_hash.rs`'s `to_rpc_packed_user_op`.
fn to_rpc_packed_user_op(p: &PackedUserOperation) -> PackedUserOperationRpc {
    PackedUserOperationRpc {
        sender: p.sender,
        nonce: p.nonce,
        initCode: p.initCode.clone(),
        callData: p.callData.clone(),
        accountGasLimits: p.accountGasLimits,
        preVerificationGas: p.preVerificationGas,
        gasFees: p.gasFees,
        paymasterAndData: p.paymasterAndData.clone(),
        signature: p.signature.clone(),
    }
}

/// Server-side read (and broadcast) access to an EVM node, abstracted so
/// consensus logic can be driven against a `MockEvmRpc` in tests instead of a
/// live node (see the `fedimint-usdt-tests` acceptance harness).
#[async_trait::async_trait]
pub trait IServerEvmRpc: std::fmt::Debug + Send + Sync + 'static {
    /// The chain id the underlying node is configured for (e.g. `1` for
    /// Ethereum mainnet), used to sanity-check the guardian's RPC endpoint
    /// against the federation's configured network.
    async fn get_chain_id(&self) -> anyhow::Result<u64>;

    /// The most recent block number the underlying node has synced to.
    async fn get_block_number(&self) -> anyhow::Result<u64>;

    /// The ERC-20 `balanceOf(holder)` for `token`, evaluated *as of*
    /// `at_block` (not "latest") so callers can read a stable, confirmed
    /// balance regardless of how far the node has since advanced.
    async fn get_erc20_balance(
        &self,
        token: EvmAddress,
        holder: EvmAddress,
        at_block: u64,
    ) -> anyhow::Result<UsdtAmount>;

    /// The token's Tether-style `basisPointsRate` transfer-fee parameter, used
    /// by the startup solvency check ([`crate::UsdtInit::init`]). Returns `Err`
    /// if the token does not implement it (a standard ERC-20 — the
    /// `basisPointsRate()` call reverts) or the node is unreachable; both
    /// are treated as "no transfer fee, skip the check". A returned `Ok(n)`
    /// with `n != 0` means the token deducts a fee on transfer, which this
    /// module's accounting does NOT compensate for (see the audit
    /// register's fee-insolvency risk).
    async fn get_erc20_basis_points_rate(&self, token: EvmAddress) -> anyhow::Result<u64>;

    /// The current EVM fee market and USDT/ETH exchange rate, as seen by
    /// this guardian's node, forming this guardian's contribution to the
    /// federation's `FeeVote` consensus.
    async fn get_fee_estimate(&self) -> anyhow::Result<FeeVote>;

    /// The length of the contract code deployed at `addr`, used to
    /// distinguish EOAs (len 0) from contracts.
    async fn get_code_len(&self, addr: EvmAddress) -> anyhow::Result<usize>;

    /// `SimpleAccountFactory(factory).getAddress(owner, salt)`: the
    /// counterfactual CREATE2 address the factory would deploy `owner`'s
    /// `SimpleAccount` at for `salt` (Part C readiness verification). Compared
    /// against this build's off-chain
    /// [`fedimint_usdt_common::derive_pool_account`] to prove the on-chain
    /// factory matches this build's vendored proxy initCode (the footgun-
    /// killer). `salt` is the raw 32-byte CREATE2 salt (see
    /// [`fedimint_usdt_common::pool_salt`]).
    async fn factory_get_address(
        &self,
        factory: EvmAddress,
        owner: EvmAddress,
        salt: [u8; 32],
    ) -> anyhow::Result<EvmAddress>;

    /// `SimpleAccountFactory(factory).accountImplementation()`: the
    /// factory's immutable `SimpleAccount` implementation address (sec-16
    /// readiness deepening). Compared directly against the module's
    /// configured `simple_account_impl` by the bootstrap-readiness observer
    /// so a factory cannot satisfy readiness merely by special-casing
    /// `getAddress` for the salts readiness happens to sample while actually
    /// proxying accounts to a different (potentially malicious)
    /// implementation.
    async fn factory_account_implementation(
        &self,
        factory: EvmAddress,
    ) -> anyhow::Result<EvmAddress>;

    /// This guardian's broadcaster EOA's ETH balance, in wei (`None` if no
    /// broadcaster is configured for this instance). Used by the Part C
    /// readiness poller to decide `BootstrapObservation::broadcaster_funded`.
    /// A `u128` comfortably holds any real ETH balance (total supply is
    /// ~1e26 wei, far below `u128::MAX` ~3.4e38).
    async fn broadcaster_eth_balance(&self) -> anyhow::Result<Option<u128>>;

    /// Broadcasts a fully-signed raw transaction to the network, returning
    /// its transaction hash.
    async fn send_raw_transaction(&self, signed_tx: Vec<u8>) -> anyhow::Result<[u8; 32]>;

    /// Part A: ensures the canonical Arachnid CREATE2 deployer
    /// ([`crate::factory_bytecode::ARACHNID_DEPLOYER`]) exists on-chain, a
    /// prerequisite for [`Self::deploy_factory`]. Idempotent: a no-op if the
    /// deployer already has code (the common steady state — mainnet and public
    /// testnets ship it pre-deployed). Otherwise (e.g. a fresh `anvil` devnet)
    /// funds its one-time signer EOA from this guardian's broadcaster and
    /// broadcasts the canonical pre-signed deploy transaction. A guardian-local
    /// side effect that writes NO consensus item.
    ///
    /// # Errors
    ///
    /// Returns an error if no broadcaster is configured, or if any funding/
    /// deploy transaction fails to send or confirm, or if the deployer is still
    /// absent afterwards.
    async fn ensure_create2_deployer(&self) -> anyhow::Result<()>;

    /// Part A: CREATE2-deploys this module's `SimpleAccountFactory` (from the
    /// vendored [`crate::factory_bytecode::FACTORY_CREATION_CODE`] plus
    /// `abi.encode(entry_point)`, under
    /// [`crate::factory_bytecode::factory_create2_salt`]) by sending
    /// `salt ‖ initCode` calldata to the Arachnid deployer from this guardian's
    /// broadcaster. The resulting address equals
    /// [`crate::factory_bytecode::derive_account_factory`] (the config-gen'd
    /// `account_factory`). A guardian-local side effect that writes NO
    /// consensus item; requires [`Self::ensure_create2_deployer`] to have
    /// succeeded first. A redundant deploy (another guardian raced) reverts
    /// harmlessly.
    ///
    /// # Errors
    ///
    /// Returns an error if no broadcaster is configured, or if the deploy
    /// transaction fails to send or confirm (including reverting).
    async fn deploy_factory(&self, entry_point: EvmAddress) -> anyhow::Result<()>;

    /// Submits `ops` to the configured `EntryPoint` via `handleOps`, fronting
    /// gas from this guardian's (or the shared broadcaster's) EOA (Phase 7
    /// Task 4: self-bundling, no separate bundler service). Any federation
    /// guardian's broadcaster may submit a given op -- the `EntryPoint`
    /// dedups by `(sender, nonce)` on-chain, so a redundant submission simply
    /// reverts/no-ops rather than double-spending.
    ///
    /// This only confirms the `handleOps` transaction itself landed
    /// (validation passed for every op in the batch); it does NOT report
    /// whether each op's `callData` execution succeeded -- poll
    /// [`Self::get_user_op_receipt`] for that.
    async fn submit_user_ops(&self, ops: Vec<SignedUserOp>) -> anyhow::Result<()>;

    /// Looks up the `EntryPoint`'s `UserOperationEvent` for `user_op_hash`
    /// (via `eth_getLogs`, filtered on the event's indexed `userOpHash`
    /// topic), returning `None` if the op has not (yet, or ever) been
    /// included on-chain.
    async fn get_user_op_receipt(
        &self,
        user_op_hash: [u8; 32],
    ) -> anyhow::Result<Option<UserOpReceipt>>;

    /// Wraps `self` into a type-erased, cheaply-cloneable [`DynServerEvmRpc`]
    /// handle.
    fn into_dyn(self) -> DynServerEvmRpc
    where
        Self: Sized + 'static,
    {
        Arc::new(self)
    }
}

/// Strips credentials from an EVM RPC URL for `Debug`/logging/error-context
/// display (sec-18 hardening): removes userinfo (username/password), drops
/// the query string, and replaces the LAST path segment with `…` (provider
/// API keys -- Alchemy, Infura, `QuickNode`, … -- are commonly appended as the
/// final path segment, e.g. `https://host/v2/<key>`).
///
/// Never returns the raw input verbatim on any code path: a `url` that fails
/// to parse gets a coarse fallback redaction instead of being echoed back.
pub(crate) fn redact_rpc_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            // Strip userinfo. `set_username`/`set_password` only fail for
            // schemes that cannot have a host (e.g. `data:`); an RPC URL
            // always has one, but ignore the (impossible here) error rather
            // than panic.
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_query(None);
            parsed.set_fragment(None);

            let segments: Vec<&str> = parsed
                .path_segments()
                .map_or_else(Vec::new, Iterator::collect);
            if let Some((last, rest)) = segments.split_last() {
                // A `last` segment of "" means the path is empty/root (no
                // key-bearing segment to hide) -- leave it alone so plain
                // dev endpoints like `http://127.0.0.1:8545` stay readable.
                if !last.is_empty() {
                    let mut new_path = String::from("/");
                    new_path.push_str(&rest.join("/"));
                    if !rest.is_empty() {
                        new_path.push('/');
                    }
                    new_path.push('…');
                    parsed.set_path(&new_path);
                }
            }

            parsed.to_string()
        }
        // Coarse fallback: keep only `scheme://host`-looking prefix, discard
        // the rest -- never echo the raw (potentially credentialed) string.
        Err(_) => match url.split_once("://") {
            Some((scheme, rest)) => {
                let host_end = rest.find('/').unwrap_or(rest.len());
                format!("{scheme}://{}/…", &rest[..host_end])
            }
            None => "<redacted: unparseable RPC URL>".to_string(),
        },
    }
}

/// [`IServerEvmRpc`] backed by a real EVM node over JSON-RPC/HTTP, via
/// `alloy`.
pub struct AlloyEvmRpc {
    /// Type-erased so this struct's type doesn't need to name (or change
    /// with) the concrete filler stack `ProviderBuilder` happens to produce.
    provider: DynProvider,
    /// The real, potentially credentialed RPC URL (e.g. a provider API key
    /// appended as the final path segment). Used only to re-parse when
    /// building the wallet-connected broadcaster provider in
    /// [`Self::with_broadcaster`] -- deliberately NEVER `Debug`-printed or
    /// embedded in error context; use `display_url` for that (sec-18).
    url: String,
    /// Credential-redacted (see [`redact_rpc_url`]) form of `url`: userinfo,
    /// query string, and the final path segment (where provider API keys
    /// commonly live) are stripped. Safe to log, `Debug`-print, or embed in
    /// error context.
    display_url: String,
    /// A second, wallet-connected provider signing as this guardian's (or
    /// the shared) broadcaster EOA, used only by
    /// [`IServerEvmRpc::submit_user_ops`]. `None` until
    /// [`Self::with_broadcaster`] is called -- read-only construction via
    /// [`Self::new`] alone is still fully usable for every other
    /// [`IServerEvmRpc`] method.
    broadcaster: Option<DynProvider>,
    /// The broadcaster EOA's own address, set alongside `broadcaster`; used
    /// as `handleOps`'s `beneficiary` (self-bundling: whoever fronts the gas
    /// also collects the unspent-gas refund).
    broadcaster_address: Option<Address>,
    /// The `EntryPoint` contract address [`IServerEvmRpc::submit_user_ops`]/
    /// [`IServerEvmRpc::get_user_op_receipt`] target. `None` until
    /// [`Self::with_entry_point`] is called.
    entry_point: Option<EvmAddress>,
    /// Chainlink ETH/USD feed; `None` or all-zero -> static price fallback.
    eth_usd_price_feed: Option<EvmAddress>,
    price_feed_max_staleness_secs: u64,
}

impl std::fmt::Debug for AlloyEvmRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The `alloy` provider is deliberately omitted (it does not implement
        // `Debug`); only the endpoint URL and non-secret configuration are
        // printed (never the broadcaster's private key -- this struct never
        // even stores one past `with_broadcaster`'s own stack frame).
        f.debug_struct("AlloyEvmRpc")
            .field("url", &self.display_url)
            .field("has_broadcaster", &self.broadcaster.is_some())
            .field("entry_point", &self.entry_point)
            .finish_non_exhaustive()
    }
}

impl AlloyEvmRpc {
    /// Builds a new [`AlloyEvmRpc`] pointed at `rpc_url`. This does not
    /// perform any network I/O: the underlying `alloy` HTTP provider is
    /// lazy, so construction succeeds even against an unreachable endpoint
    /// and only the first actual call can fail.
    ///
    /// No broadcaster or `EntryPoint` is configured yet -- every read-only
    /// [`IServerEvmRpc`] method works immediately, but
    /// [`IServerEvmRpc::submit_user_ops`]/
    /// [`IServerEvmRpc::get_user_op_receipt`]
    /// need [`Self::with_broadcaster`]/[`Self::with_entry_point`] first.
    ///
    /// # Errors
    ///
    /// Returns an error if `rpc_url` cannot be parsed as a URL, or (sec-18
    /// hardening) if it is a plaintext `http://` endpoint on a non-loopback
    /// host and [`fedimint_core::envs::FM_USDT_UNSAFE_ALLOW_HTTP_ENV`] is not
    /// set to `"1"` -- such an endpoint lets a network-position attacker
    /// observe and tamper with every RPC-derived guardian observation/
    /// submission.
    pub fn new(rpc_url: &str) -> anyhow::Result<Self> {
        let display_url = redact_rpc_url(rpc_url);
        let url = rpc_url
            .parse()
            .with_context(|| format!("invalid EVM RPC URL: {display_url}"))?;

        // Separately parsed (not reused for `connect_http` below) purely for
        // the scheme/host transport-security check; keeps this check
        // decoupled from whatever concrete `Url` type `connect_http` expects.
        let parsed: url::Url = rpc_url
            .parse()
            .with_context(|| format!("invalid EVM RPC URL: {display_url}"))?;
        let is_https = parsed.scheme() == "https";
        // `Url::host_str` renders IPv6 hosts bracketed (`"[::1]"`), so match
        // on the parsed `Host` instead of the string form.
        let is_loopback_host = match parsed.host() {
            Some(url::Host::Domain("localhost")) => true,
            Some(url::Host::Ipv4(addr)) => addr.is_loopback(),
            Some(url::Host::Ipv6(addr)) => addr.is_loopback(),
            _ => false,
        };
        let unsafe_override =
            std::env::var(fedimint_core::envs::FM_USDT_UNSAFE_ALLOW_HTTP_ENV).as_deref() == Ok("1");
        anyhow::ensure!(
            is_https || is_loopback_host || unsafe_override,
            "refusing plaintext http:// EVM RPC endpoint {display_url}: scheme is not https and \
             host is not loopback; set {}=1 to override (traffic will be MITM-able)",
            fedimint_core::envs::FM_USDT_UNSAFE_ALLOW_HTTP_ENV,
        );
        if !is_https && !is_loopback_host && unsafe_override {
            warn!(
                target: "usdt",
                url = %display_url,
                "remote http:// RPC endpoint allowed via FM_USDT_UNSAFE_ALLOW_HTTP; traffic is MITM-able"
            );
        }

        let provider = ProviderBuilder::new().connect_http(url).erased();

        Ok(Self {
            provider,
            url: rpc_url.to_string(),
            display_url,
            broadcaster: None,
            broadcaster_address: None,
            entry_point: None,
            eth_usd_price_feed: None,
            price_feed_max_staleness_secs: 0,
        })
    }

    /// Configures the broadcaster EOA [`IServerEvmRpc::submit_user_ops`]
    /// signs and sends `handleOps` transactions from, given its private key
    /// (hex, optionally `0x`-prefixed). Any federation guardian's
    /// broadcaster may submit a given `UserOp` (see
    /// [`IServerEvmRpc::submit_user_ops`]'s doc comment on on-chain dedup),
    /// so in production every guardian may configure the same shared key or
    /// its own -- this task only wires the mechanism, not the policy of
    /// which key(s) a deployment uses.
    ///
    /// # Errors
    ///
    /// Returns an error if `broadcaster_private_key` is not a valid
    /// secp256k1 scalar, or if this instance's own `rpc_url` (captured at
    /// [`Self::new`]) fails to re-parse (which would indicate a bug, since
    /// [`Self::new`] already validated it).
    pub fn with_broadcaster(mut self, broadcaster_private_key: &str) -> anyhow::Result<Self> {
        let key_hex = broadcaster_private_key
            .strip_prefix("0x")
            .unwrap_or(broadcaster_private_key);
        let signer: PrivateKeySigner = key_hex
            .parse()
            .context("malformed broadcaster private key")?;
        let address = signer.address();
        let url = self
            .url
            .parse()
            .with_context(|| format!("invalid EVM RPC URL: {}", self.display_url))?;
        let provider = ProviderBuilder::new()
            .wallet(signer)
            .connect_http(url)
            .erased();

        self.broadcaster = Some(provider);
        self.broadcaster_address = Some(address);
        Ok(self)
    }

    /// Configures the `EntryPoint` contract address
    /// [`IServerEvmRpc::submit_user_ops`]/
    /// [`IServerEvmRpc::get_user_op_receipt`] target.
    #[must_use]
    pub fn with_entry_point(mut self, entry_point: EvmAddress) -> Self {
        self.entry_point = Some(entry_point);
        self
    }

    /// Configure the Chainlink ETH/USD feed the fee poller reads. An all-zero
    /// address disables it (static fallback).
    #[must_use]
    pub fn with_price_feed(mut self, feed: EvmAddress, max_staleness_secs: u64) -> Self {
        self.eth_usd_price_feed = (feed.0 != [0u8; 20]).then_some(feed);
        self.price_feed_max_staleness_secs = max_staleness_secs;
        self
    }
}

/// Static ETH/USD fallback (== $3000.000000/ETH) used only when NO Chainlink
/// feed is configured (e.g. local anvil). A real deployment configures a feed.
const STATIC_USDT_PER_ETH_E6: u64 = 3_000_000_000;

#[async_trait::async_trait]
impl IServerEvmRpc for AlloyEvmRpc {
    async fn get_chain_id(&self) -> anyhow::Result<u64> {
        Ok(self.provider.get_chain_id().await?)
    }

    async fn get_block_number(&self) -> anyhow::Result<u64> {
        Ok(self.provider.get_block_number().await?)
    }

    async fn get_erc20_balance(
        &self,
        token: EvmAddress,
        holder: EvmAddress,
        at_block: u64,
    ) -> anyhow::Result<UsdtAmount> {
        let contract = IERC20::new(Address::from(token.0), &self.provider);
        let balance: U256 = contract
            .balanceOf(Address::from(holder.0))
            .block(BlockId::number(at_block))
            .call()
            .await
            .with_context(|| format!("balanceOf({holder}) on {token} at block {at_block}"))?;

        let balance = u64::try_from(balance).with_context(|| {
            format!("ERC-20 balance {balance} for {holder} on {token} overflows u64")
        })?;

        Ok(UsdtAmount(balance))
    }

    async fn get_erc20_basis_points_rate(&self, token: EvmAddress) -> anyhow::Result<u64> {
        let contract = IERC20::new(Address::from(token.0), &self.provider);
        // On a standard ERC-20 (no `basisPointsRate`) this call reverts, which
        // surfaces as `Err` here; the caller treats that as "no transfer fee".
        let rate: U256 = contract
            .basisPointsRate()
            .call()
            .await
            .with_context(|| format!("basisPointsRate() on {token}"))?;
        u64::try_from(rate)
            .with_context(|| format!("basisPointsRate {rate} on {token} overflows u64"))
    }

    async fn get_fee_estimate(&self) -> anyhow::Result<FeeVote> {
        let gas_price_wei: u128 = self.provider.get_gas_price().await?;
        let max_fee_per_gas_wei = u64::try_from(gas_price_wei)
            .with_context(|| format!("gas price {gas_price_wei} wei overflows u64"))?;

        let usdt_per_eth_e6 = match self.eth_usd_price_feed {
            Some(feed) => {
                let feed_addr = Address::from(feed.0);
                let aggregator = IAggregatorV3::new(feed_addr, &self.provider);
                let decimals = aggregator.decimals().call().await?;
                let round = aggregator.latestRoundData().call().await?;
                let block = self
                    .provider
                    .get_block(BlockId::latest())
                    .await?
                    .context("latest block missing for price staleness check")?;
                let chain_now = block.header.timestamp;

                let answer: i128 = round
                    .answer
                    .try_into()
                    .context("Chainlink answer does not fit i128")?;
                let round_id = u128::try_from(round.roundId).unwrap_or(u128::MAX);
                let answered_in_round = u128::try_from(round.answeredInRound).unwrap_or(u128::MAX);
                let updated_at = u64::try_from(round.updatedAt).unwrap_or(u64::MAX);

                fedimint_usdt_common::chainlink_eth_usd_to_usdt_per_eth_e6(
                    answer,
                    decimals,
                    round_id,
                    answered_in_round,
                    updated_at,
                    chain_now,
                    self.price_feed_max_staleness_secs,
                )
                .context(
                    "Chainlink ETH/USD reading unusable (stale/invalid); abstaining from FeeVote",
                )?
            }
            None => STATIC_USDT_PER_ETH_E6,
        };

        Ok(FeeVote {
            max_fee_per_gas_wei,
            usdt_per_eth_e6,
        })
    }

    async fn get_code_len(&self, addr: EvmAddress) -> anyhow::Result<usize> {
        let code = self
            .provider
            .get_code_at(Address::from(addr.0))
            .latest()
            .await?;

        Ok(code.len())
    }

    async fn factory_get_address(
        &self,
        factory: EvmAddress,
        owner: EvmAddress,
        salt: [u8; 32],
    ) -> anyhow::Result<EvmAddress> {
        let contract = ISimpleAccountFactory::new(Address::from(factory.0), &self.provider);
        let address = contract
            .getAddress(Address::from(owner.0), U256::from_be_bytes(salt))
            .call()
            .await
            .with_context(|| format!("getAddress(owner, salt) on factory {factory}"))?;

        Ok(EvmAddress(address.into_array()))
    }

    async fn factory_account_implementation(
        &self,
        factory: EvmAddress,
    ) -> anyhow::Result<EvmAddress> {
        let contract = ISimpleAccountFactory::new(Address::from(factory.0), &self.provider);
        let address = contract
            .accountImplementation()
            .call()
            .await
            .with_context(|| format!("accountImplementation() on factory {factory}"))?;

        Ok(EvmAddress(address.into_array()))
    }

    async fn broadcaster_eth_balance(&self) -> anyhow::Result<Option<u128>> {
        let Some(address) = self.broadcaster_address else {
            return Ok(None);
        };
        let balance: U256 = self
            .provider
            .get_balance(address)
            .await
            .with_context(|| format!("get_balance({address}) for broadcaster"))?;
        let balance = u128::try_from(balance)
            .with_context(|| format!("broadcaster ETH balance {balance} wei overflows u128"))?;

        Ok(Some(balance))
    }

    async fn send_raw_transaction(&self, signed_tx: Vec<u8>) -> anyhow::Result<[u8; 32]> {
        let pending = self.provider.send_raw_transaction(&signed_tx).await?;

        Ok(pending.tx_hash().0)
    }

    async fn ensure_create2_deployer(&self) -> anyhow::Result<()> {
        // Idempotent: the common steady state (mainnet / public testnets ship
        // the proxy pre-deployed) short-circuits with no transaction at all.
        if self.get_code_len(ARACHNID_DEPLOYER).await? > 0 {
            return Ok(());
        }

        let broadcaster = self.broadcaster.as_ref().context(
            "AlloyEvmRpc::ensure_create2_deployer requires a broadcaster (see Self::with_broadcaster)",
        )?;

        // 1. Fund the canonical one-time signer with the deploy transaction's full gas
        //    budget (`gasLimit * gasPrice`), from this guardian's broadcaster. A plain
        //    value transfer never reverts at estimation, so the default nonce manager
        //    is safe here; awaited to its receipt so the signer is funded before the
        //    raw tx is broadcast.
        let fund_tx = TransactionRequest::default()
            .with_to(Address::from(ARACHNID_DEPLOYER_SIGNER.0))
            .with_value(U256::from(ARACHNID_DEPLOY_TX_COST_WEI));
        let fund_receipt = broadcaster
            .send_transaction(fund_tx)
            .await
            .context("send Arachnid deployer-signer funding transaction")?
            .get_receipt()
            .await
            .context("confirm Arachnid deployer-signer funding transaction")?;
        anyhow::ensure!(
            fund_receipt.status(),
            "Arachnid deployer-signer funding transaction reverted (tx {:?})",
            fund_receipt.transaction_hash
        );

        // 2. Broadcast the canonical, pre-signed (pre-EIP-155) deploy tx. It is
        //    self-signed by the one-time signer, so it is submitted via the read
        //    provider (not the broadcaster wallet). Deliberately NOT gated on
        //    `receipt.status()`: this ancient legacy tx can surface a misleading
        //    receipt status on some nodes (observed on `anvil`) even though it deploys
        //    correctly, so success is verified by the deployer's code appearing below.
        self.provider
            .send_raw_transaction(ARACHNID_RAW_DEPLOY_TX)
            .await
            .context("broadcast Arachnid CREATE2-deployer deploy transaction")?
            .get_receipt()
            .await
            .context("confirm Arachnid CREATE2-deployer deploy transaction")?;

        anyhow::ensure!(
            self.get_code_len(ARACHNID_DEPLOYER).await? > 0,
            "Arachnid CREATE2 deployer still has no code after broadcasting its deploy transaction",
        );

        Ok(())
    }

    async fn deploy_factory(&self, entry_point: EvmAddress) -> anyhow::Result<()> {
        let broadcaster = self.broadcaster.as_ref().context(
            "AlloyEvmRpc::deploy_factory requires a broadcaster (see Self::with_broadcaster)",
        )?;
        let broadcaster_address = self
            .broadcaster_address
            .expect("set alongside `broadcaster` in with_broadcaster");

        // Calldata the Arachnid deployer interprets as `salt (32 bytes) ‖
        // initCode`, CREATE2-deploying the factory at `derive_account_factory`.
        let mut calldata = factory_create2_salt().to_vec();
        calldata.extend_from_slice(&factory_init_code(entry_point));

        // Explicit pending nonce (like `submit_user_ops`): a redundant deploy
        // (another guardian already deployed the factory) reverts during gas
        // estimation, and the default cached nonce manager would leak a nonce on
        // that failed `.send()` and wedge later broadcaster transactions.
        // Deriving the nonce from chain state each call avoids that.
        let nonce = broadcaster
            .get_transaction_count(broadcaster_address)
            .pending()
            .await
            .context("fetch broadcaster nonce for factory deploy")?;

        let deploy_tx = TransactionRequest::default()
            .with_to(Address::from(ARACHNID_DEPLOYER.0))
            .with_input(calldata)
            .with_nonce(nonce);
        let receipt = broadcaster
            .send_transaction(deploy_tx)
            .await
            .context("send SimpleAccountFactory CREATE2 deploy transaction")?
            .get_receipt()
            .await
            .context("confirm SimpleAccountFactory CREATE2 deploy transaction")?;
        anyhow::ensure!(
            receipt.status(),
            "SimpleAccountFactory CREATE2 deploy transaction reverted (tx {:?})",
            receipt.transaction_hash
        );

        Ok(())
    }

    async fn submit_user_ops(&self, ops: Vec<SignedUserOp>) -> anyhow::Result<()> {
        let broadcaster = self.broadcaster.as_ref().context(
            "AlloyEvmRpc::submit_user_ops requires a broadcaster (see Self::with_broadcaster)",
        )?;
        let entry_point = self.entry_point.context(
            "AlloyEvmRpc::submit_user_ops requires an EntryPoint address (see Self::with_entry_point)",
        )?;
        let beneficiary = self
            .broadcaster_address
            .expect("set alongside `broadcaster` in with_broadcaster");

        let packed_ops: Vec<PackedUserOperationRpc> = ops
            .iter()
            .map(|op| to_rpc_packed_user_op(&op.pack()))
            .collect();

        let entry_point = IEntryPoint::new(Address::from(entry_point.0), broadcaster);

        // Part B (auto-prefund): before `handleOps`, self-fund each op sender's
        // `EntryPoint` gas *deposit* from the broadcaster, so no external
        // `depositTo` is ever required. Guardian-local, non-consensus -- purely
        // an on-chain side effect of the submit path.
        //
        // FAIL-SOFT: the whole read+top-up is wrapped so any error (RPC hiccup,
        // etc.) is logged and execution PROCEEDS to `handleOps` regardless --
        // prefunding is never fatal to submission. A genuinely-underfunded op
        // just fails validation and retries next tick, exactly as before this
        // change. Multiple guardians may each top up the same account: harmless
        // and refundable, so no coordination is needed.
        for op in &ops {
            let sender = Address::from(op.unsigned.sender.0);
            let prefund: anyhow::Result<()> = async {
                // The op's max L1 gas cost from its own static bounds, read
                // straight off the unpacked `UnsignedUserOp` (no bit-unpacking
                // of `accountGasLimits`/`gasFees` needed -- the unpacked gas
                // fields are carried directly). `need = (verificationGasLimit +
                // callGasLimit + preVerificationGas) * maxFeePerGas`.
                let u = &op.unsigned;
                let total_gas = U256::from(u.verification_gas_limit)
                    .saturating_add(U256::from(u.call_gas_limit))
                    .saturating_add(u.pre_verification_gas);
                let need = total_gas.saturating_mul(U256::from(u.max_fee_per_gas));
                // Safety margin (need * 1.5) to absorb fee/estimate drift
                // between now and inclusion.
                let need_with_margin = need.saturating_add(need / U256::from(2u8));

                // Read the sender's current EntryPoint *deposit* FIRST (a call,
                // no tx) so the common already-funded case sends no extra tx and
                // stays off the nonce hot path entirely.
                let deposit: U256 = entry_point
                    .balanceOf(sender)
                    .call()
                    .await
                    .context("EntryPoint.balanceOf(sender) deposit read")?;

                if deposit < need_with_margin {
                    let topup = need_with_margin - deposit;
                    // NONCE SEQUENCING: `depositTo` is a SECOND broadcaster tx.
                    // Set its nonce explicitly (NOT the provider's auto nonce
                    // filler) and `get_receipt()` on it BEFORE the `handleOps`
                    // pending-nonce fetch below, so the two txs never share or
                    // gap a nonce (re-introducing the nonce-leak wedge). Each
                    // iteration awaits its receipt, so the next pending fetch --
                    // this loop's next `depositTo` or the final `handleOps` --
                    // already reflects the mined tx.
                    let nonce = broadcaster
                        .get_transaction_count(beneficiary)
                        .pending()
                        .await
                        .context("fetch broadcaster nonce for depositTo")?;
                    let receipt = entry_point
                        .depositTo(sender)
                        .value(topup)
                        .nonce(nonce)
                        .send()
                        .await
                        .context("send EntryPoint.depositTo transaction")?
                        .get_receipt()
                        .await
                        .context("confirm EntryPoint.depositTo transaction")?;
                    anyhow::ensure!(
                        receipt.status(),
                        "EntryPoint.depositTo transaction reverted (tx {:?})",
                        receipt.transaction_hash
                    );
                    debug!(
                        target: "usdt",
                        %sender,
                        topup = %topup,
                        "auto-prefunded EntryPoint deposit for op sender",
                    );
                }
                Ok(())
            }
            .await;

            if let Err(err) = prefund {
                warn!(
                    target: "usdt",
                    %sender,
                    err = %err.fmt_compact_anyhow(),
                    "auto-prefund of EntryPoint deposit failed; proceeding to handleOps anyway",
                );
            }
        }

        // Fetch the broadcaster's *pending* nonce fresh from chain state and
        // set it explicitly on the transaction, instead of leaving it to the
        // provider's default cached nonce manager. That manager reserves and
        // locally increments a nonce inside `.send()` BEFORE gas estimation,
        // and does NOT roll it back when estimation then reverts -- which
        // happens routinely here: a guardian re-submitting a `UserOp` that
        // another guardian (or an earlier tick) already included reverts with
        // `AA10 sender already constructed` during estimation. Each such
        // failed send would leak a nonce, so the cached value drifts ahead of
        // the account's real on-chain nonce; a later `handleOps` transaction
        // then carries a future (gapped) nonce, sits un-mined in the mempool,
        // and the `get_receipt()` below blocks forever -- permanently wedging
        // every subsequent submission (e.g. a withdrawal batch submitted after
        // a sweep's `AA10` retries have leaked several nonces). Deriving the
        // nonce from chain state each call keeps a reverted send from
        // stranding future ones.
        let nonce = broadcaster
            .get_transaction_count(beneficiary)
            .pending()
            .await
            .context("failed to fetch broadcaster nonce")?;

        let receipt = entry_point
            .handleOps(packed_ops, beneficiary)
            .nonce(nonce)
            .send()
            .await
            .context("failed to send handleOps transaction")?
            .get_receipt()
            .await
            .context("failed to confirm handleOps transaction")?;

        anyhow::ensure!(
            receipt.status(),
            "handleOps transaction reverted (tx {:?})",
            receipt.transaction_hash
        );

        Ok(())
    }

    async fn get_user_op_receipt(
        &self,
        user_op_hash: [u8; 32],
    ) -> anyhow::Result<Option<UserOpReceipt>> {
        // Query the bundler for the op's receipt DIRECTLY by its hash (ERC-4337
        // `eth_getUserOperationReceipt`), rather than scanning `EntryPoint`
        // event logs. The op is identified by its consensus `userOpHash`, so
        // every guardian queries the same key and gets the same on-chain result
        // -- and this sidesteps the `eth_getLogs` block-range + archive limits
        // that free RPC tiers impose (as little as a 10-50 block range, and old
        // blocks paywalled), which made a log-scan approach unworkable on a real
        // chain. Requires a bundler-capable RPC (Alchemy/Infura/QuickNode/...
        // expose this method on their standard endpoint). `None` until mined.
        let op_hash_hex = format!("0x{}", alloy::hex::encode(user_op_hash));
        let resp: Option<BundlerUserOpReceipt> = self
            .provider
            .raw_request::<_, Option<BundlerUserOpReceipt>>(
                std::borrow::Cow::Borrowed("eth_getUserOperationReceipt"),
                (op_hash_hex,),
            )
            .await
            .context("eth_getUserOperationReceipt failed")?;

        let Some(receipt) = resp else {
            return Ok(None);
        };
        let actual_gas_cost = u64::try_from(receipt.actual_gas_cost).unwrap_or(u64::MAX);
        let block = u64::try_from(receipt.receipt.block_number)
            .context("UserOp receipt blockNumber overflows u64")?;
        Ok(Some(UserOpReceipt {
            success: receipt.success,
            block,
            actual_cost_usdt: UsdtAmount(actual_gas_cost),
        }))
    }
}

/// Subset of an ERC-4337 `eth_getUserOperationReceipt` response the module
/// needs (see [`AlloyEvmRpc::get_user_op_receipt`]). Hex-string numbers decode
/// via `alloy`'s `U256` serde.
#[derive(Debug, serde::Deserialize)]
struct BundlerUserOpReceipt {
    success: bool,
    #[serde(rename = "actualGasCost")]
    actual_gas_cost: U256,
    receipt: BundlerInnerReceipt,
}

#[derive(Debug, serde::Deserialize)]
struct BundlerInnerReceipt {
    #[serde(rename = "blockNumber")]
    block_number: U256,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructing an [`AlloyEvmRpc`] must not require a live node: the
    /// underlying `alloy` HTTP provider is lazy, so an unreachable endpoint
    /// still builds successfully (the failure only surfaces on the first
    /// actual RPC call). Real request/response behavior is exercised
    /// against `anvil` in the `fedimint-usdt-tests` acceptance harness.
    #[test]
    fn new_does_not_require_a_live_node() {
        AlloyEvmRpc::new("http://127.0.0.1:1").expect("construction is lazy and infallible here");
    }

    /// Serializes tests that touch the process-wide `FM_USDT_UNSAFE_ALLOW_HTTP`
    /// env var so they cannot race under `cargo test`'s default parallel-test
    /// execution (mirrors the `ENV_VAR_LOCK` pattern in `lib.rs`'s tests).
    static ENV_VAR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // sec-18 (a): `redact_rpc_url` must never let the secret substring
    // through, whether the key rides in the final path segment, in
    // userinfo, or in a query parameter -- and it must not echo the raw
    // string back verbatim when it fails to parse as a URL.

    #[test]
    fn redacts_final_path_key() {
        let secret = "sk_live_super_secret_key_123";
        let url = format!("https://eth-mainnet.g.alchemy.com/v2/{secret}");

        let redacted = redact_rpc_url(&url);

        assert!(
            !redacted.contains(secret),
            "API key leaked into redacted URL: {redacted}"
        );
        assert!(
            redacted.contains("eth-mainnet.g.alchemy.com"),
            "host should remain visible: {redacted}"
        );
    }

    #[test]
    fn redacts_userinfo() {
        let secret = "hunter2password";
        let url = format!("https://apiuser:{secret}@rpc.example.com/v1/path");

        let redacted = redact_rpc_url(&url);

        assert!(
            !redacted.contains(secret),
            "userinfo password leaked into redacted URL: {redacted}"
        );
        assert!(
            !redacted.contains("apiuser"),
            "userinfo username leaked into redacted URL: {redacted}"
        );
    }

    #[test]
    fn redacts_query_token() {
        let secret = "qtoken_abcdef123456";
        let url = format!("https://rpc.example.com/mainnet?api_key={secret}");

        let redacted = redact_rpc_url(&url);

        assert!(
            !redacted.contains(secret),
            "query-string token leaked into redacted URL: {redacted}"
        );
        assert!(
            !redacted.contains('?'),
            "query string should be dropped entirely: {redacted}"
        );
    }

    #[test]
    fn redacts_unparseable() {
        let secret = "SECRETTOKEN";
        let raw = format!("not a valid url with {secret} embedded");

        let redacted = redact_rpc_url(&raw);

        assert!(
            !redacted.contains(secret),
            "secret leaked from an unparseable URL: {redacted}"
        );
        assert_ne!(
            redacted, raw,
            "unparseable input must not be echoed back verbatim"
        );
    }

    // sec-18 (b): the redaction must actually be wired into `Debug`.

    #[test]
    fn debug_alloy_evm_rpc_hides_key() {
        let secret = "sk_live_super_secret_key_123";
        let url = format!("https://eth-mainnet.g.alchemy.com/v2/{secret}");
        let rpc = AlloyEvmRpc::new(&url).expect("a valid https URL constructs");

        let rendered = format!("{rpc:?}");

        assert!(
            !rendered.contains(secret),
            "API key leaked into AlloyEvmRpc Debug output: {rendered}"
        );
    }

    // sec-18 (c): remote plaintext `http://` is refused by default; loopback
    // `http://` and any `https://` remain allowed.

    #[test]
    fn remote_http_refused() {
        let _lock = ENV_VAR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::remove_var(fedimint_core::envs::FM_USDT_UNSAFE_ALLOW_HTTP_ENV);
        }

        let secret = "sk_live_super_secret_key_123";
        let url = format!("http://example.com/v2/{secret}");
        let err = AlloyEvmRpc::new(&url).expect_err("remote http:// must be refused by default");

        let rendered = format!("{err:#}");
        assert!(
            !rendered.contains(secret),
            "refusal error must use the redacted URL, not the raw one: {rendered}"
        );
    }

    #[test]
    fn loopback_http_ok() {
        AlloyEvmRpc::new("http://127.0.0.1:8545").expect("loopback http:// is allowed");
        AlloyEvmRpc::new("http://localhost:8545").expect("loopback http:// is allowed");
        AlloyEvmRpc::new("http://[::1]:8545").expect("loopback http:// is allowed");
    }

    #[test]
    fn https_ok() {
        AlloyEvmRpc::new("https://eth-mainnet.g.alchemy.com/v2/key").expect("https is allowed");
    }

    #[test]
    fn unsafe_override_allows_remote_http() {
        let _lock = ENV_VAR_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // SAFETY: serialized by `ENV_VAR_LOCK` above.
        unsafe {
            std::env::set_var(fedimint_core::envs::FM_USDT_UNSAFE_ALLOW_HTTP_ENV, "1");
        }
        let result = AlloyEvmRpc::new("http://example.com/v2/key");
        // SAFETY: see above.
        unsafe {
            std::env::remove_var(fedimint_core::envs::FM_USDT_UNSAFE_ALLOW_HTTP_ENV);
        }

        result.expect("remote http must be allowed once the unsafe override is set");
    }
}
