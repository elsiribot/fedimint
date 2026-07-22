//! Test-support helpers shared by the `fedimint-usdt-tests` integration
//! tests: a hermetic `anvil` harness (used by `tests/evm_adapter.rs` to
//! exercise `AlloyEvmRpc` against a real, ephemeral EVM node) and a scriptable
//! `MockEvmRpc` (for Phase 5's module unit tests to script deposits without a
//! real chain).
//!
//! Each `tests/*.rs` integration test binary compiles this module (and its
//! submodules) independently via `mod common;`, so any given binary will
//! only use a subset of what's exposed here -- hence the blanket
//! `dead_code` allow, matching the standard idiom for shared cargo test
//! helper modules.
#![allow(dead_code, unused_imports)]

pub mod anvil;
pub mod mock;
pub mod ready;

pub use anvil::{
    ANVIL_ACCOUNT_0_PRIVATE_KEY, ANVIL_ACCOUNT_1_PRIVATE_KEY, AnvilHandle, Deployed4337,
    anvil_account_1_address, deploy_4337_stack, deploy_mock_price_feed,
    deploy_nonstandard_4337_stack, deploy_nonstandard_usdt, deploy_test_erc20, spawn_anvil,
    transfer_erc20_from_account_1, transfer_nonstandard_from_account_1,
};
pub use mock::MockEvmRpc;
pub use ready::{await_usdt_ready, mock_ready_stack};
