//! Part C readiness test helpers.
//!
//! The client's [`UsdtClientModule::allocate_deposit`] refuses to hand out a
//! deposit address unless the federation's readiness state machine reports
//! `Ready` (the module can honor the full deposit->claim->sweep->withdraw
//! lifecycle). Every integration test that allocates a deposit must therefore
//! first drive the module to `Ready` and wait for that state to propagate
//! through consensus. These two helpers do exactly that:
//!
//! - [`mock_ready_stack`] scripts a hermetic [`MockEvmRpc`] so this guardian's
//!   `observe_bootstrap` poll votes all-`true` (mirrors that server-side
//!   readiness poll's exact reads).
//! - [`await_usdt_ready`] polls the `usdt_status` endpoint until the state is
//!   `Ready`.
//!
//! Anvil-backed tests drive a REAL `AlloyEvmRpc` against a real deployed 4337
//! stack, so they need only [`await_usdt_ready`] (no mock scripting).

use std::time::Duration;

use fedimint_core::runtime::{Instant, sleep};
use fedimint_core::secp256k1::PublicKey;
use fedimint_usdt_client::UsdtClientModule;
use fedimint_usdt_common::{
    BootstrapState, EvmAddress, derive_pool_account, evm_address, pool_salt,
};

use super::mock::MockEvmRpc;

/// Scripts `mock` so a guardian's server-side `observe_bootstrap` poll (which
/// reads `get_code_len(entry_point/account_factory/simple_account_impl)`,
/// `factory_get_address(account_factory, evm_address(group_pk), pool_salt())`,
/// and `broadcaster_eth_balance()`) observes every Part C readiness condition
/// as met, so it votes an all-`true` `BootstrapObservation`.
///
/// The scripted `factory_get_address` return is computed with the SAME
/// [`derive_pool_account`] the real poll cross-checks against, so the
/// footgun-killer equivalence check passes. In the hermetic fixtures the three
/// contract addresses are all the all-zero placeholder
/// ([`EvmAddress`]`([0; 20])`); passing them explicitly keeps this helper
/// usable for any address set.
pub fn mock_ready_stack(
    mock: &MockEvmRpc,
    group_public_key: &PublicKey,
    entry_point: EvmAddress,
    account_factory: EvmAddress,
    simple_account_impl: EvmAddress,
) {
    // Any nonzero length satisfies `get_code_len(..) > 0`.
    mock.set_code_len(entry_point, 32);
    mock.set_code_len(account_factory, 32);
    mock.set_code_len(simple_account_impl, 32);

    let owner = evm_address(group_public_key);
    let pool = derive_pool_account(group_public_key, account_factory, simple_account_impl);
    mock.set_factory_get_address(account_factory, owner, pool_salt(), pool);

    // 1000 ETH in wei -- comfortably above any `broadcaster_min_balance_wei`
    // the tests configure.
    mock.set_broadcaster_eth_balance(Some(1_000_000_000_000_000_000_000));
}

/// Polls `usdt.status()` until the module reports
/// [`BootstrapState::Ready`], erroring (with the last observed status) if it
/// does not within `timeout`. Uses `fedimint_core::runtime::sleep` so it
/// works uniformly across native and wasm test runtimes.
pub async fn await_usdt_ready(usdt: &UsdtClientModule, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let status = usdt.status().await?;
        if status.state == BootstrapState::Ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "usdt module did not reach Ready within {timeout:?}; last status: {status:?}"
            );
        }
        sleep(Duration::from_millis(250)).await;
    }
}
