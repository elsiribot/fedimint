//! Server-side read (and, eventually, broadcast) access to an EVM node, via
//! an injectable [`IServerEvmRpc`] trait so the consensus/state-machine code
//! that will consume it (from Phase 5 onward) can be tested against a
//! `MockEvmRpc` instead of a live node.

use std::sync::Arc;

use alloy::eips::BlockId;
use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::sol;
use anyhow::Context as _;
use fedimint_usdt_common::{EvmAddress, FeeVote, UsdtAmount};

/// Type-erased handle to a [`IServerEvmRpc`] implementation.
pub type DynServerEvmRpc = Arc<dyn IServerEvmRpc>;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
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
}

impl std::fmt::Debug for AlloyEvmRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The `alloy` provider is deliberately omitted (it does not implement
        // `Debug`); only the endpoint URL is printed.
        f.debug_struct("AlloyEvmRpc")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl AlloyEvmRpc {
    /// Builds a new [`AlloyEvmRpc`] pointed at `rpc_url`. This does not
    /// perform any network I/O: the underlying `alloy` HTTP provider is
    /// lazy, so construction succeeds even against an unreachable endpoint
    /// and only the first actual call can fail.
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
        })
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
