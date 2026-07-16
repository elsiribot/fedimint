//! Spawns and drives a local `anvil` (foundry) dev-node so
//! `tests/evm_adapter.rs` can exercise `AlloyEvmRpc` against a real,
//! ephemeral EVM node instead of mocking the JSON-RPC wire format.

use std::env;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::Context as _;
use fedimint_core::runtime::sleep;
use fedimint_usdt_common::{EvmAddress, UsdtAmount};
use fedimint_usdt_server::rpc::{AlloyEvmRpc, IServerEvmRpc};

/// Private key of `anvil`'s first deterministic default account (derived
/// from its well-known dev mnemonic), used as the deployer/miner-funded
/// account for contract creation in [`deploy_test_erc20`].
const ANVIL_ACCOUNT_0_PRIVATE_KEY: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Private key of `anvil`'s second deterministic default account. Exposed so
/// `tests/evm_adapter.rs` can seed this account as the ERC-20 holder and
/// later sign a `transfer` *from* it, proving `AlloyEvmRpc::get_erc20_balance`
/// correctly addresses historical blocks.
pub const ANVIL_ACCOUNT_1_PRIVATE_KEY: &str =
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

/// Derives the [`EvmAddress`] for [`ANVIL_ACCOUNT_1_PRIVATE_KEY`]. Computed
/// from the key itself (rather than hardcoded) so the key/address pairing
/// can never drift out of sync.
///
/// # Errors
///
/// Returns an error only if [`ANVIL_ACCOUNT_1_PRIVATE_KEY`] is malformed,
/// which would indicate a bug in this file, not the caller.
pub fn anvil_account_1_address() -> anyhow::Result<EvmAddress> {
    let signer: PrivateKeySigner = ANVIL_ACCOUNT_1_PRIVATE_KEY
        .parse()
        .context("malformed ANVIL_ACCOUNT_1_PRIVATE_KEY")?;

    Ok(EvmAddress(signer.address().into_array()))
}

sol! {
    #[sol(rpc)]
    interface ITestUsdt {
        function mint(address to, uint256 amount) external;
        function transfer(address to, uint256 amount) external returns (bool);
    }
}

/// A running `anvil` dev-node child process. Killed on drop.
pub struct AnvilHandle {
    child: Child,
    url: String,
}

impl AnvilHandle {
    /// The HTTP JSON-RPC URL this `anvil` instance is listening on.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Drop for AnvilHandle {
    fn drop(&mut self) {
        // Best-effort: the test process is exiting either way, and a leaked
        // anvil child is harmless beyond holding a port open briefly.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawns a local `anvil` dev-node for hermetic EVM integration tests.
///
/// Resolves the binary from the `FM_ANVIL_BASE_EXECUTABLE` env var, falling
/// back to `anvil` on `PATH`. If the binary can't be spawned at all (neither
/// is available), returns `Ok(None)` so callers can skip the test instead of
/// failing outright — anvil is a test-only dependency, not something every
/// dev/CI environment is guaranteed to have.
///
/// # Errors
///
/// Returns an error if the binary spawns but never becomes ready to serve
/// JSON-RPC requests within the poll budget, since that indicates a real
/// problem (as opposed to "anvil isn't installed").
pub async fn spawn_anvil() -> anyhow::Result<Option<AnvilHandle>> {
    let binary = env::var("FM_ANVIL_BASE_EXECUTABLE").unwrap_or_else(|_| "anvil".to_string());

    // Bind-and-release a free port rather than parsing anvil's stdout (which
    // `--silent` suppresses anyway). This has a small, accepted-for-tests
    // TOCTOU race between releasing the port and anvil binding it.
    let port = {
        let listener =
            TcpListener::bind("127.0.0.1:0").context("failed to allocate a free port")?;
        listener
            .local_addr()
            .context("failed to read allocated port")?
            .port()
    };

    let child = match Command::new(&binary)
        .args([
            "--port",
            &port.to_string(),
            "--chain-id",
            "31337",
            "--silent",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return Ok(None),
    };

    let mut handle = AnvilHandle {
        child,
        url: format!("http://127.0.0.1:{port}"),
    };

    // Poll until anvil is actually accepting RPC requests, using the exact
    // adapter under test (AlloyEvmRpc) to do so.
    let probe = AlloyEvmRpc::new(handle.url())?;
    let mut ready = false;
    for _ in 0..50 {
        if probe.get_chain_id().await.is_ok() {
            ready = true;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }

    if !ready {
        let _ = handle.child.kill();
        anyhow::bail!(
            "anvil ({binary}) spawned but never became ready to serve RPC at {}",
            handle.url
        );
    }

    Ok(Some(handle))
}

/// Builds a wallet-enabled `alloy` provider signing as `private_key`,
/// pointed at `anvil`.
fn wallet_provider(
    anvil: &AnvilHandle,
    private_key: &str,
) -> anyhow::Result<impl Provider + Clone> {
    let signer: PrivateKeySigner = private_key
        .parse()
        .context("malformed anvil dev-account private key")?;
    let url = anvil
        .url()
        .parse()
        .with_context(|| format!("invalid anvil URL: {}", anvil.url()))?;

    Ok(ProviderBuilder::new().wallet(signer).connect_http(url))
}

/// The vendored `TestUsdt` fixture's creation bytecode + ABI, compiled
/// offline (see `modules/fedimint-usdt-tests/contracts/TestUsdt.sol`) and
/// deployed here as-is: this test harness never invokes `solc`/`forge`.
const TEST_USDT_FIXTURE_JSON: &str = include_str!("../fixtures/test_usdt.json");

fn test_usdt_creation_bytecode() -> anyhow::Result<Vec<u8>> {
    let fixture: serde_json::Value = serde_json::from_str(TEST_USDT_FIXTURE_JSON)
        .context("failed to parse tests/fixtures/test_usdt.json")?;
    let bytecode_hex = fixture["bytecode"]
        .as_str()
        .context("fixture is missing a `bytecode` string field")?;
    let bytecode_hex = bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex);

    hex::decode(bytecode_hex).context("fixture `bytecode` is not valid hex")
}

/// Deploys the vendored `TestUsdt` ERC-20 fixture to `anvil` (as
/// `anvil`'s deterministic account 0) and mints `amount` to `holder`.
/// Returns the deployed contract's address.
pub async fn deploy_test_erc20(
    anvil: &AnvilHandle,
    holder: EvmAddress,
    amount: UsdtAmount,
) -> anyhow::Result<EvmAddress> {
    let provider = wallet_provider(anvil, ANVIL_ACCOUNT_0_PRIVATE_KEY)?;

    let bytecode = test_usdt_creation_bytecode()?;
    let deploy_tx = TransactionRequest::default().with_deploy_code(bytecode);
    let receipt = provider
        .send_transaction(deploy_tx)
        .await
        .context("failed to send TestUsdt creation transaction")?
        .get_receipt()
        .await
        .context("failed to confirm TestUsdt creation transaction")?;
    let token_address = receipt
        .contract_address
        .context("TestUsdt creation receipt is missing a contract_address")?;

    let contract = ITestUsdt::new(token_address, &provider);
    contract
        .mint(Address::from(holder.0), U256::from(amount.0))
        .send()
        .await
        .context("failed to send mint() transaction")?
        .get_receipt()
        .await
        .context("failed to confirm mint() transaction")?;

    Ok(EvmAddress(token_address.into_array()))
}

/// Transfers `amount` of `token` from `anvil`'s account 1 (see
/// [`ANVIL_ACCOUNT_1_PRIVATE_KEY`]/[`anvil_account_1_address`]) to `to`,
/// confirming the transaction before returning. Used by
/// `tests/evm_adapter.rs` to prove `AlloyEvmRpc::get_erc20_balance`'s
/// `at_block` addressing: reading the pre-transfer block must still show the
/// old balance even after this call lands.
pub async fn transfer_erc20_from_account_1(
    anvil: &AnvilHandle,
    token: EvmAddress,
    to: EvmAddress,
    amount: UsdtAmount,
) -> anyhow::Result<()> {
    let provider = wallet_provider(anvil, ANVIL_ACCOUNT_1_PRIVATE_KEY)?;
    let contract = ITestUsdt::new(Address::from(token.0), &provider);

    contract
        .transfer(Address::from(to.0), U256::from(amount.0))
        .send()
        .await
        .context("failed to send transfer() transaction")?
        .get_receipt()
        .await
        .context("failed to confirm transfer() transaction")?;

    Ok(())
}
