//! A scriptable, in-memory [`IServerEvmRpc`] implementation, so Phase 5's
//! `fedimint-usdt-server` module unit tests can drive deposit-detection
//! consensus logic against known, programmable EVM state without spinning up
//! a real (or even `anvil`'d) chain.

use std::collections::HashMap;
use std::sync::Mutex;

use fedimint_usdt_common::{EvmAddress, FeeVote, UsdtAmount};
use fedimint_usdt_server::rpc::IServerEvmRpc;

/// In-memory state backing a [`MockEvmRpc`], guarded by a single [`Mutex`]
/// since this is test-only scaffolding, not a hot path.
#[derive(Debug)]
struct State {
    chain_id: u64,
    block_number: u64,
    /// Current ERC-20 balances, keyed by `(token, holder)`. `MockEvmRpc`
    /// does not model historical per-block balances: `get_erc20_balance`
    /// always returns the latest scripted value regardless of `at_block`,
    /// which is sufficient for module unit tests that script a sequence of
    /// deposits rather than asserting on confirmation-depth semantics
    /// (that property is instead proven against a real chain in
    /// `tests/evm_adapter.rs`).
    balances: HashMap<(EvmAddress, EvmAddress), UsdtAmount>,
    /// Addresses with "contract code" present, and its length.
    code_len: HashMap<EvmAddress, usize>,
    fee: FeeVote,
    sent_raw_transactions: Vec<Vec<u8>>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            chain_id: 0,
            block_number: 0,
            balances: HashMap::new(),
            code_len: HashMap::new(),
            fee: FeeVote {
                max_fee_per_gas_wei: 0,
                usdt_per_eth_e6: 0,
            },
            sent_raw_transactions: Vec::new(),
        }
    }
}

/// A scriptable, in-memory [`IServerEvmRpc`] for unit-testing consensus
/// logic without a real EVM node.
///
/// Construct with [`MockEvmRpc::new`], script state via the `set_*` methods,
/// then hand `.into_dyn()` (or use directly) wherever a `DynServerEvmRpc` /
/// `IServerEvmRpc` is expected.
#[derive(Debug, Default)]
pub struct MockEvmRpc {
    state: Mutex<State>,
}

impl MockEvmRpc {
    /// Creates a `MockEvmRpc` with all state zeroed (chain id 0, block
    /// number 0, no balances/code, a zeroed `FeeVote`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the chain id reported by [`IServerEvmRpc::get_chain_id`].
    pub fn set_chain_id(&self, chain_id: u64) {
        self.lock().chain_id = chain_id;
    }

    /// Sets the block number reported by
    /// [`IServerEvmRpc::get_block_number`].
    pub fn set_block_number(&self, block_number: u64) {
        self.lock().block_number = block_number;
    }

    /// Scripts the balance returned by
    /// [`IServerEvmRpc::get_erc20_balance`] for `(token, holder)`,
    /// regardless of the `at_block` argument passed at read time (see
    /// [`State::balances`]).
    pub fn set_erc20_balance(&self, token: EvmAddress, holder: EvmAddress, balance: UsdtAmount) {
        self.lock().balances.insert((token, holder), balance);
    }

    /// Scripts the code length returned by
    /// [`IServerEvmRpc::get_code_len`] for `addr`.
    pub fn set_code_len(&self, addr: EvmAddress, len: usize) {
        self.lock().code_len.insert(addr, len);
    }

    /// Scripts the [`FeeVote`] returned by
    /// [`IServerEvmRpc::get_fee_estimate`].
    pub fn set_fee_estimate(&self, fee: FeeVote) {
        self.lock().fee = fee;
    }

    /// Returns every raw transaction previously passed to
    /// [`IServerEvmRpc::send_raw_transaction`], in call order, so tests can
    /// assert on what consensus logic attempted to broadcast.
    #[must_use]
    pub fn sent_raw_transactions(&self) -> Vec<Vec<u8>> {
        self.lock().sent_raw_transactions.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("MockEvmRpc's internal mutex should never be poisoned in tests")
    }
}

#[async_trait::async_trait]
impl IServerEvmRpc for MockEvmRpc {
    async fn get_chain_id(&self) -> anyhow::Result<u64> {
        Ok(self.lock().chain_id)
    }

    async fn get_block_number(&self) -> anyhow::Result<u64> {
        Ok(self.lock().block_number)
    }

    async fn get_erc20_balance(
        &self,
        token: EvmAddress,
        holder: EvmAddress,
        _at_block: u64,
    ) -> anyhow::Result<UsdtAmount> {
        Ok(self
            .lock()
            .balances
            .get(&(token, holder))
            .copied()
            .unwrap_or(UsdtAmount(0)))
    }

    async fn get_fee_estimate(&self) -> anyhow::Result<FeeVote> {
        Ok(self.lock().fee)
    }

    async fn get_code_len(&self, addr: EvmAddress) -> anyhow::Result<usize> {
        Ok(self.lock().code_len.get(&addr).copied().unwrap_or(0))
    }

    async fn send_raw_transaction(&self, signed_tx: Vec<u8>) -> anyhow::Result<[u8; 32]> {
        let mut state = self.lock();
        // A deterministic, content-derived "hash" (not a real keccak256) is
        // sufficient here: tests only need distinct, stable identifiers,
        // and asserting on real transaction hashing is exercised against
        // `anvil` in `tests/evm_adapter.rs`.
        let mut hash = [0u8; 32];
        for (i, byte) in signed_tx.iter().enumerate() {
            hash[i % 32] ^= byte;
        }
        state.sent_raw_transactions.push(signed_tx);

        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_and_read_back_a_balance() {
        let mock = MockEvmRpc::new();
        let token = EvmAddress([0x01; 20]);
        let holder = EvmAddress([0x02; 20]);

        mock.set_erc20_balance(token, holder, UsdtAmount(42));

        assert_eq!(
            mock.get_erc20_balance(token, holder, 0)
                .await
                .expect("mock reads never fail"),
            UsdtAmount(42)
        );
    }

    #[tokio::test]
    async fn unknown_holder_reads_as_zero() {
        let mock = MockEvmRpc::new();
        let token = EvmAddress([0x01; 20]);
        let unknown_holder = EvmAddress([0xff; 20]);

        assert_eq!(
            mock.get_erc20_balance(token, unknown_holder, 0)
                .await
                .expect("mock reads never fail"),
            UsdtAmount(0)
        );
    }

    #[tokio::test]
    async fn chain_id_and_block_number_round_trip() {
        let mock = MockEvmRpc::new();
        mock.set_chain_id(31337);
        mock.set_block_number(100);

        assert_eq!(mock.get_chain_id().await.expect("infallible"), 31337);
        assert_eq!(mock.get_block_number().await.expect("infallible"), 100);
    }

    #[tokio::test]
    async fn code_len_defaults_to_zero_for_unset_addresses() {
        let mock = MockEvmRpc::new();
        let contract = EvmAddress([0x01; 20]);
        let eoa = EvmAddress([0x02; 20]);
        mock.set_code_len(contract, 128);

        assert_eq!(mock.get_code_len(contract).await.expect("infallible"), 128);
        assert_eq!(mock.get_code_len(eoa).await.expect("infallible"), 0);
    }

    #[tokio::test]
    async fn send_raw_transaction_records_calls() {
        let mock = MockEvmRpc::new();

        mock.send_raw_transaction(vec![1, 2, 3])
            .await
            .expect("infallible");
        mock.send_raw_transaction(vec![4, 5, 6])
            .await
            .expect("infallible");

        assert_eq!(
            mock.sent_raw_transactions(),
            vec![vec![1, 2, 3], vec![4, 5, 6]]
        );
    }
}
