//! A scriptable, in-memory [`IServerEvmRpc`] implementation, so Phase 5's
//! `fedimint-usdt-server` module unit tests can drive deposit-detection
//! consensus logic against known, programmable EVM state without spinning up
//! a real (or even `anvil`'d) chain.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use fedimint_usdt_common::user_op::{SignedUserOp, UserOpReceipt};
use fedimint_usdt_common::{EvmAddress, FeeVote, UsdtAmount};
use fedimint_usdt_server::rpc::IServerEvmRpc;

/// In-memory state backing a [`MockEvmRpc`], guarded by a single [`Mutex`]
/// since this is test-only scaffolding, not a hot path.
#[derive(Debug)]
struct State {
    chain_id: u64,
    block_number: u64,
    /// Current ERC-20 balances, keyed by `(token, holder)`, and then by the
    /// block at which each scripted value takes effect. `get_erc20_balance`
    /// returns the value for the greatest scripted block `<= at_block`,
    /// allowing tests to script balances that change across a sequence of
    /// blocks (needed for deposit-detection consensus tests that read
    /// balances "as of block N - confirmation_depth").
    balances: HashMap<(EvmAddress, EvmAddress), BTreeMap<u64, UsdtAmount>>,
    /// Addresses with "contract code" present, and its length.
    code_len: HashMap<EvmAddress, usize>,
    /// Scripted `factory_get_address` responses, keyed by `(factory, owner,
    /// salt)` (Part C readiness).
    factory_addresses: HashMap<(EvmAddress, EvmAddress, [u8; 32]), EvmAddress>,
    /// Scripted `factory_account_implementation` responses, keyed by
    /// `factory` (sec-16 readiness deepening). An unscripted factory reads
    /// as the all-zero address, which will fail a `== simple_account_impl`
    /// comparison (safe default: readiness fails closed rather than open).
    factory_account_implementations: HashMap<EvmAddress, EvmAddress>,
    /// Scripted broadcaster ETH balance (wei); `None` means "no broadcaster
    /// configured" (Part C readiness).
    broadcaster_eth_balance: Option<u128>,
    fee: FeeVote,
    sent_raw_transactions: Vec<Vec<u8>>,
    /// Every `SignedUserOp` batch previously passed to `submit_user_ops`, in
    /// call order (Phase 7 Task 4).
    submitted_user_ops: Vec<Vec<SignedUserOp>>,
    /// Scripted `get_user_op_receipt` responses, keyed by `user_op_hash`.
    user_op_receipts: HashMap<[u8; 32], UserOpReceipt>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            chain_id: 0,
            block_number: 0,
            balances: HashMap::new(),
            code_len: HashMap::new(),
            factory_addresses: HashMap::new(),
            factory_account_implementations: HashMap::new(),
            broadcaster_eth_balance: None,
            fee: FeeVote {
                max_fee_per_gas_wei: 0,
                usdt_per_eth_e6: 0,
            },
            sent_raw_transactions: Vec::new(),
            submitted_user_ops: Vec::new(),
            user_op_receipts: HashMap::new(),
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
    /// [`IServerEvmRpc::get_erc20_balance`] for `(token, holder)`, effective
    /// from block 0 onward. Shorthand for
    /// `set_erc20_balance_at(token, holder, 0, balance)`.
    pub fn set_erc20_balance(&self, token: EvmAddress, holder: EvmAddress, balance: UsdtAmount) {
        self.set_erc20_balance_at(token, holder, 0, balance);
    }

    /// Scripts the balance returned by
    /// [`IServerEvmRpc::get_erc20_balance`] for `(token, holder)`, effective
    /// from `block` onward: a read `at_block >= block` (and before any later
    /// scripted block) will see this value (see [`State::balances`]).
    pub fn set_erc20_balance_at(
        &self,
        token: EvmAddress,
        holder: EvmAddress,
        block: u64,
        balance: UsdtAmount,
    ) {
        self.lock()
            .balances
            .entry((token, holder))
            .or_default()
            .insert(block, balance);
    }

    /// Scripts the code length returned by
    /// [`IServerEvmRpc::get_code_len`] for `addr`.
    pub fn set_code_len(&self, addr: EvmAddress, len: usize) {
        self.lock().code_len.insert(addr, len);
    }

    /// Scripts the address returned by
    /// [`IServerEvmRpc::factory_get_address`] for `(factory, owner, salt)`
    /// (Part C readiness).
    pub fn set_factory_get_address(
        &self,
        factory: EvmAddress,
        owner: EvmAddress,
        salt: [u8; 32],
        address: EvmAddress,
    ) {
        self.lock()
            .factory_addresses
            .insert((factory, owner, salt), address);
    }

    /// Scripts the address returned by
    /// [`IServerEvmRpc::factory_account_implementation`] for `factory`
    /// (sec-16 readiness deepening).
    pub fn set_factory_account_implementation(
        &self,
        factory: EvmAddress,
        implementation: EvmAddress,
    ) {
        self.lock()
            .factory_account_implementations
            .insert(factory, implementation);
    }

    /// Scripts the broadcaster ETH balance (wei) returned by
    /// [`IServerEvmRpc::broadcaster_eth_balance`] (Part C readiness). `None`
    /// (the default) reports "no broadcaster configured".
    pub fn set_broadcaster_eth_balance(&self, balance: Option<u128>) {
        self.lock().broadcaster_eth_balance = balance;
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

    /// Every `SignedUserOp` batch previously passed to
    /// [`IServerEvmRpc::submit_user_ops`], in call order (Phase 7 Task 4).
    #[must_use]
    pub fn submitted_user_ops(&self) -> Vec<Vec<SignedUserOp>> {
        self.lock().submitted_user_ops.clone()
    }

    /// Scripts the [`UserOpReceipt`]
    /// [`IServerEvmRpc::get_user_op_receipt`] returns for `user_op_hash`.
    pub fn set_user_op_receipt(&self, user_op_hash: [u8; 32], receipt: UserOpReceipt) {
        self.lock().user_op_receipts.insert(user_op_hash, receipt);
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
        at_block: u64,
    ) -> anyhow::Result<UsdtAmount> {
        let state = self.lock();
        anyhow::ensure!(at_block <= state.block_number, "header not found");
        Ok(state
            .balances
            .get(&(token, holder))
            .and_then(|by_block| by_block.range(..=at_block).next_back().map(|(_, v)| *v))
            .unwrap_or(UsdtAmount(0)))
    }

    async fn get_erc20_basis_points_rate(&self, _token: EvmAddress) -> anyhow::Result<u64> {
        // Mock: a standard (fee-less) token.
        Ok(0)
    }

    async fn get_fee_estimate(&self) -> anyhow::Result<FeeVote> {
        Ok(self.lock().fee)
    }

    async fn get_code_len(&self, addr: EvmAddress) -> anyhow::Result<usize> {
        Ok(self.lock().code_len.get(&addr).copied().unwrap_or(0))
    }

    async fn factory_get_address(
        &self,
        factory: EvmAddress,
        owner: EvmAddress,
        salt: [u8; 32],
    ) -> anyhow::Result<EvmAddress> {
        Ok(self
            .lock()
            .factory_addresses
            .get(&(factory, owner, salt))
            .copied()
            .unwrap_or(EvmAddress([0u8; 20])))
    }

    async fn factory_account_implementation(
        &self,
        factory: EvmAddress,
    ) -> anyhow::Result<EvmAddress> {
        Ok(self
            .lock()
            .factory_account_implementations
            .get(&factory)
            .copied()
            .unwrap_or(EvmAddress([0u8; 20])))
    }

    async fn broadcaster_eth_balance(&self) -> anyhow::Result<Option<u128>> {
        Ok(self.lock().broadcaster_eth_balance)
    }

    async fn ensure_create2_deployer(&self) -> anyhow::Result<()> {
        // Hermetic tests never deploy anything (they script readiness directly
        // via `mock_ready_stack`); the Part A deploy path is exercised against
        // real `anvil` in `deploy_and_sweep_e2e`/`factory_pinning`.
        Ok(())
    }

    async fn deploy_factory(&self, _entry_point: EvmAddress) -> anyhow::Result<()> {
        Ok(())
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

    async fn submit_user_ops(&self, ops: Vec<SignedUserOp>) -> anyhow::Result<()> {
        self.lock().submitted_user_ops.push(ops);
        Ok(())
    }

    async fn get_user_op_receipt(
        &self,
        user_op_hash: [u8; 32],
    ) -> anyhow::Result<Option<UserOpReceipt>> {
        Ok(self.lock().user_op_receipts.get(&user_op_hash).copied())
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

        mock.set_block_number(1);
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

        mock.set_block_number(1);
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
    async fn balance_is_read_as_of_block() {
        let mock = MockEvmRpc::new();
        let (t, h) = (EvmAddress([1; 20]), EvmAddress([2; 20]));
        mock.set_block_number(100);
        mock.set_erc20_balance_at(t, h, 10, UsdtAmount(0));
        mock.set_erc20_balance_at(t, h, 20, UsdtAmount(5_000_000));

        assert_eq!(
            mock.get_erc20_balance(t, h, 15).await.unwrap(),
            UsdtAmount(0)
        );
        assert_eq!(
            mock.get_erc20_balance(t, h, 25).await.unwrap(),
            UsdtAmount(5_000_000)
        );
    }

    #[tokio::test]
    async fn reading_above_head_errors() {
        let mock = MockEvmRpc::new();
        mock.set_block_number(30);
        let err = mock
            .get_erc20_balance(EvmAddress([1; 20]), EvmAddress([2; 20]), 31)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("header not found"));
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

    #[tokio::test]
    async fn submit_user_ops_and_get_user_op_receipt_round_trip() {
        use fedimint_usdt_common::user_op::UnsignedUserOp;

        let mock = MockEvmRpc::new();

        let unsigned = UnsignedUserOp {
            sender: EvmAddress([0x11; 20]),
            nonce: alloy::primitives::U256::ZERO,
            init_code: vec![],
            call_data: vec![0xde, 0xad],
            verification_gas_limit: 1,
            call_gas_limit: 1,
            pre_verification_gas: alloy::primitives::U256::ZERO,
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 1,
            paymaster_and_data: vec![],
        };
        let signed = SignedUserOp {
            unsigned,
            signature: vec![0xaa; 65],
        };

        mock.submit_user_ops(vec![signed.clone()])
            .await
            .expect("infallible");
        assert_eq!(mock.submitted_user_ops(), vec![vec![signed]]);

        let user_op_hash = [0x22u8; 32];
        assert_eq!(
            mock.get_user_op_receipt(user_op_hash)
                .await
                .expect("infallible"),
            None
        );

        let receipt = UserOpReceipt {
            success: true,
            block: 7,
            actual_cost_usdt: UsdtAmount(500),
        };
        mock.set_user_op_receipt(user_op_hash, receipt);
        assert_eq!(
            mock.get_user_op_receipt(user_op_hash)
                .await
                .expect("infallible"),
            Some(receipt)
        );
    }
}
