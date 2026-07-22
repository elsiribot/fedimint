//! Server-side read (and, eventually, broadcast) access to an EVM node, via
//! an injectable [`IServerEvmRpc`] trait so the consensus/state-machine code
//! that will consume it (from Phase 5 onward) can be tested against a
//! `MockEvmRpc` instead of a live node.

use std::sync::Arc;

use alloy::eips::BlockId;
use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::sol_types::SolEvent as _;
use anyhow::Context as _;
use fedimint_usdt_common::user_op::{PackedUserOperation, SignedUserOp, UserOpReceipt};
use fedimint_usdt_common::{EvmAddress, FeeVote, UsdtAmount};

/// Type-erased handle to a [`IServerEvmRpc`] implementation.
pub type DynServerEvmRpc = Arc<dyn IServerEvmRpc>;

sol! {
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

    /// Broadcasts a fully-signed raw transaction to the network, returning
    /// its transaction hash.
    async fn send_raw_transaction(&self, signed_tx: Vec<u8>) -> anyhow::Result<[u8; 32]>;

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

/// [`IServerEvmRpc`] backed by a real EVM node over JSON-RPC/HTTP, via
/// `alloy`.
pub struct AlloyEvmRpc {
    /// Type-erased so this struct's type doesn't need to name (or change
    /// with) the concrete filler stack `ProviderBuilder` happens to produce.
    provider: DynProvider,
    /// Kept only for [`std::fmt::Debug`] (the `alloy` provider itself does
    /// not implement `Debug`).
    url: String,
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
}

impl std::fmt::Debug for AlloyEvmRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The `alloy` provider is deliberately omitted (it does not implement
        // `Debug`); only the endpoint URL and non-secret configuration are
        // printed (never the broadcaster's private key -- this struct never
        // even stores one past `with_broadcaster`'s own stack frame).
        f.debug_struct("AlloyEvmRpc")
            .field("url", &self.url)
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
    /// Returns an error only if `rpc_url` cannot be parsed as a URL.
    pub fn new(rpc_url: &str) -> anyhow::Result<Self> {
        let url = rpc_url
            .parse()
            .with_context(|| format!("invalid EVM RPC URL: {rpc_url}"))?;
        let provider = ProviderBuilder::new().connect_http(url).erased();

        Ok(Self {
            provider,
            url: rpc_url.to_string(),
            broadcaster: None,
            broadcaster_address: None,
            entry_point: None,
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
            .with_context(|| format!("invalid EVM RPC URL: {}", self.url))?;
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
}

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

        Ok(FeeVote {
            max_fee_per_gas_wei,
            // Phase 4 has no price oracle wired up yet; Phase 8 wires a real
            // price source. `3_000_000_000` == 3000.000000 USDT/ETH (fixed
            // point, 1e-6 USDT precision), a placeholder in the right
            // ballpark so `FeeVote` consensus can be exercised end-to-end
            // before a real feed exists.
            usdt_per_eth_e6: 3_000_000_000,
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

    async fn send_raw_transaction(&self, signed_tx: Vec<u8>) -> anyhow::Result<[u8; 32]> {
        let pending = self.provider.send_raw_transaction(&signed_tx).await?;

        Ok(pending.tx_hash().0)
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

        let entry_point = IEntryPoint::new(Address::from(entry_point.0), broadcaster);
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
        let entry_point = self.entry_point.context(
            "AlloyEvmRpc::get_user_op_receipt requires an EntryPoint address (see Self::with_entry_point)",
        )?;

        let filter = Filter::new()
            .address(Address::from(entry_point.0))
            .event_signature(UserOperationEvent::SIGNATURE_HASH)
            .topic1(alloy::primitives::FixedBytes::<32>::from(user_op_hash))
            .from_block(0u64);

        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .context("eth_getLogs(UserOperationEvent) failed")?;

        let Some(log) = logs.into_iter().next() else {
            return Ok(None);
        };

        let block = log
            .block_number
            .context("UserOperationEvent log is missing a block_number")?;
        let decoded = log
            .log_decode::<UserOperationEvent>()
            .context("failed to decode UserOperationEvent log")?;

        let actual_gas_cost =
            u64::try_from(decoded.inner.data.actualGasCost).with_context(|| {
                format!(
                    "UserOperationEvent.actualGasCost {} overflows u64",
                    decoded.inner.data.actualGasCost
                )
            })?;

        Ok(Some(UserOpReceipt {
            success: decoded.inner.data.success,
            block,
            actual_cost_usdt: UsdtAmount(actual_gas_cost),
        }))
    }
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
}
