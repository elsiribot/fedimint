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
use alloy::sol_types::SolValue as _;
use anyhow::Context as _;
use fedimint_core::runtime::sleep;
use fedimint_usdt_common::{EvmAddress, UsdtAmount};
use fedimint_usdt_server::rpc::{AlloyEvmRpc, IServerEvmRpc};

/// Private key of `anvil`'s first deterministic default account (derived
/// from its well-known dev mnemonic), used as the deployer/miner-funded
/// account for contract creation in [`deploy_test_erc20`]/
/// [`deploy_4337_stack`], and (Phase 7 Task 4) as the broadcaster EOA
/// `tests/user_op_isolation.rs` fronts `handleOps` gas from.
pub const ANVIL_ACCOUNT_0_PRIVATE_KEY: &str =
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

sol! {
    // The NON-STANDARD, mainnet-USDT-faithful fixture (see
    // `tests/fixtures/nonstandard_usdt.json` /
    // `contracts/NonStandardUsdt.sol`). The critical divergence from
    // `ITestUsdt` above is that `transfer`/`transferFrom` are declared with NO
    // return value -- exactly as the real TetherToken exposes them. This forces
    // any Rust caller (like [`transfer_nonstandard_from_account_1`]) to invoke
    // them the way the void-returning contract actually behaves: alloy decodes
    // an EMPTY return, so declaring a `bool` return here (as `ITestUsdt` does)
    // would make the call revert on decode against this token. `setParams`
    // drives the Quirk-2 fee mechanism; `getBlackListStatus` is inert shape
    // fidelity.
    #[sol(rpc)]
    interface INonStandardUsdt {
        function mint(address to, uint256 amount) external;
        function transfer(address to, uint256 amount) external;
        function transferFrom(address from, address to, uint256 amount) external;
        function setParams(uint256 newBasisPoints, uint256 newMaxFee) external;
        function balanceOf(address account) external view returns (uint256);
        function getBlackListStatus(address maker) external view returns (bool);
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
/// back to `anvil` on `PATH`. If the binary genuinely isn't installed
/// (`std::io::ErrorKind::NotFound`), returns `Ok(None)` so callers can skip
/// the test instead of failing outright — anvil is a test-only dependency,
/// not something every dev/CI environment is guaranteed to have.
///
/// # Errors
///
/// Returns an error if the binary spawns but never becomes ready to serve
/// JSON-RPC requests within the poll budget, since that indicates a real
/// problem (as opposed to "anvil isn't installed"). Also returns an error
/// (rather than skipping) if the spawn itself fails for any reason other
/// than "binary not found" — e.g. a misconfigured `FM_ANVIL_BASE_EXECUTABLE`
/// pointing at a path with the wrong permissions should surface as a hard
/// failure, not silently skip the test.
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
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to spawn anvil binary ({binary})"));
        }
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

/// The vendored `NonStandardUsdt` fixture's creation bytecode + ABI, compiled
/// offline (see `modules/fedimint-usdt-tests/contracts/NonStandardUsdt.sol`)
/// and deployed here as-is, exactly like [`TEST_USDT_FIXTURE_JSON`]: this
/// harness never invokes `solc`/`forge`. This is the mainnet-USDT-faithful,
/// void-`transfer`-returning token (see [`INonStandardUsdt`]).
const NONSTANDARD_USDT_FIXTURE_JSON: &str = include_str!("../fixtures/nonstandard_usdt.json");

fn nonstandard_usdt_creation_bytecode() -> anyhow::Result<Vec<u8>> {
    let fixture: serde_json::Value = serde_json::from_str(NONSTANDARD_USDT_FIXTURE_JSON)
        .context("failed to parse tests/fixtures/nonstandard_usdt.json")?;
    let bytecode_hex = fixture["bytecode"]
        .as_str()
        .context("fixture is missing a `bytecode` string field")?;
    let bytecode_hex = bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex);

    hex::decode(bytecode_hex).context("fixture `bytecode` is not valid hex")
}

/// Deploys the vendored `NonStandardUsdt` fixture to `anvil` (as `anvil`'s
/// deterministic account 0) and mints `amount` to `holder`. The mainnet-USDT-
/// faithful counterpart of [`deploy_test_erc20`]: same deploy+mint shape, but
/// the deployed token's `transfer`/`transferFrom` return NOTHING and it carries
/// the `basisPointsRate`/`maximumFee` fee mechanism (default 0). Returns the
/// deployed contract's address.
pub async fn deploy_nonstandard_usdt(
    anvil: &AnvilHandle,
    holder: EvmAddress,
    amount: UsdtAmount,
) -> anyhow::Result<EvmAddress> {
    let provider = wallet_provider(anvil, ANVIL_ACCOUNT_0_PRIVATE_KEY)?;

    let bytecode = nonstandard_usdt_creation_bytecode()?;
    let deploy_tx = TransactionRequest::default().with_deploy_code(bytecode);
    let receipt = provider
        .send_transaction(deploy_tx)
        .await
        .context("failed to send NonStandardUsdt creation transaction")?
        .get_receipt()
        .await
        .context("failed to confirm NonStandardUsdt creation transaction")?;
    let token_address = receipt
        .contract_address
        .context("NonStandardUsdt creation receipt is missing a contract_address")?;

    let contract = INonStandardUsdt::new(token_address, &provider);
    contract
        .mint(Address::from(holder.0), U256::from(amount.0))
        .send()
        .await
        .context("failed to send NonStandardUsdt.mint() transaction")?
        .get_receipt()
        .await
        .context("failed to confirm NonStandardUsdt.mint() transaction")?;

    Ok(EvmAddress(token_address.into_array()))
}

/// Transfers `amount` of the NON-STANDARD `token` from `anvil`'s account 1 to
/// `to`, confirming the transaction before returning. The counterpart of
/// [`transfer_erc20_from_account_1`] used to fund a counterfactual deposit
/// account with the void-`transfer`-returning token: it drives
/// [`INonStandardUsdt::transfer`] (no `bool` return), so it exercises exactly
/// the wire shape the real TetherToken exposes. Reverts here would prove alloy
/// mis-decodes a void return -- it does not.
pub async fn transfer_nonstandard_from_account_1(
    anvil: &AnvilHandle,
    token: EvmAddress,
    to: EvmAddress,
    amount: UsdtAmount,
) -> anyhow::Result<()> {
    let provider = wallet_provider(anvil, ANVIL_ACCOUNT_1_PRIVATE_KEY)?;
    let contract = INonStandardUsdt::new(Address::from(token.0), &provider);

    contract
        .transfer(Address::from(to.0), U256::from(amount.0))
        .send()
        .await
        .context("failed to send NonStandardUsdt.transfer() transaction")?
        .get_receipt()
        .await
        .context("failed to confirm NonStandardUsdt.transfer() transaction")?;

    Ok(())
}

// --- ERC-4337 v0.7 stack (Phase 7, Task 1) -------------------------------
//
// Vendored artifacts live in `tests/fixtures/erc4337/` (fetched verbatim
// from `@account-abstraction/contracts@0.7.0` on unpkg). NOTE: the Phase-7
// master plan sketches these as living under
// `fedimint-usdt-common/contracts/`; that location is superseded here.
// These are test-harness *deploy inputs* (full ABI + creation/deployed
// bytecode, ~40-280KB each) for standing up a real ERC-4337 stack on
// `anvil`, not something that may ever enter `fedimint-usdt-common`
// (wasm-compiled, shipped to clients). Only Task 2's small derivation
// constants (e.g. the `ERC1967Proxy` creation-code hash ingredient) belong
// in `-common`; the deploy artifacts stay here, with the rest of this
// harness.

/// Canonical ERC-4337 v0.7 `EntryPoint` address, identical on every real
/// chain (deployed there via a deterministic CREATE2 factory). Kept only as
/// a documented historical reference now that [`deploy_4337_stack`]
/// real-constructor-deploys its own `EntryPoint` instance (see that
/// function's doc comment for why); no longer used by this harness. hermetic
/// tests must read the address from the returned [`Deployed4337::entry_point`]
/// instead of assuming this constant.
#[allow(dead_code)]
pub const ENTRY_POINT_V07_ADDRESS: EvmAddress = EvmAddress([
    0x00, 0x00, 0x00, 0x00, 0x71, 0x72, 0x7d, 0xe2, 0x2e, 0x5e, 0x9d, 0x8b, 0xaf, 0x0e, 0xda, 0xc6,
    0xf3, 0x7d, 0xa0, 0x32,
]);

const ENTRY_POINT_ARTIFACT_JSON: &str = include_str!("../fixtures/erc4337/EntryPoint.json");
const SIMPLE_ACCOUNT_FACTORY_ARTIFACT_JSON: &str =
    include_str!("../fixtures/erc4337/SimpleAccountFactory.json");
const LEGACY_TOKEN_PAYMASTER_ARTIFACT_JSON: &str =
    include_str!("../fixtures/erc4337/LegacyTokenPaymaster.json");
// Vendored for later Phase-7 tasks (Task 3's `PackedUserOperation`/
// `userOpHash` self-verification needs `SimpleAccount`'s
// `_validateSignature` wrapping behavior; Task 6 attempts the full
// oracle-priced `TokenPaymaster` before falling back to
// `LegacyTokenPaymaster` -- see the plan's paymaster-economics scope
// decision). Not read by this Task-1 harness, so `include_str!` would trip
// `dead_code`-style unused-const lints under some configurations; recorded
// here only as a doc pointer to where they live.
// - `tests/fixtures/erc4337/SimpleAccount.json`
// - `tests/fixtures/erc4337/TokenPaymaster.json`
// - `tests/fixtures/erc4337/OracleHelper.json`

/// Extracts a top-level hex-string field (`"0x..."`) from a vendored
/// artifact JSON, decoding it to raw bytes. Mirrors
/// [`test_usdt_creation_bytecode`]'s parsing for the `erc4337/` fixtures'
/// `bytecode`/`deployedBytecode` fields.
fn artifact_hex_field(artifact_json: &str, field: &str) -> anyhow::Result<Vec<u8>> {
    let artifact: serde_json::Value = serde_json::from_str(artifact_json)
        .with_context(|| format!("failed to parse erc4337 artifact JSON (`{field}` lookup)"))?;
    let hex_str = artifact[field]
        .as_str()
        .with_context(|| format!("artifact is missing a `{field}` string field"))?;
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    hex::decode(hex_str).with_context(|| format!("artifact `{field}` is not valid hex"))
}

sol! {
    #[sol(rpc)]
    interface ISimpleAccountFactory {
        function createAccount(address owner, uint256 salt) external returns (address);
        function getAddress(address owner, uint256 salt) external view returns (address);
        function accountImplementation() external view returns (address);
    }
}

sol! {
    #[sol(rpc)]
    interface ILegacyTokenPaymaster {
        function addStake(uint32 unstakeDelaySec) external payable;
        function deposit() external payable;
        function getDeposit() external view returns (uint256);
        function entryPoint() external view returns (address);
    }
}

/// The stake `anvil`'s account 0 puts up for [`Deployed4337`]'s paymaster on
/// the `EntryPoint`, via `addStake`. An arbitrary non-zero amount: `anvil`
/// account 0 is funded with far more than this by default.
const PAYMASTER_STAKE_WEI: u128 = 1_000_000_000_000_000_000; // 1 ETH
/// The gas deposit `anvil`'s account 0 funds [`Deployed4337`]'s paymaster
/// with on the `EntryPoint`, via `deposit`.
const PAYMASTER_DEPOSIT_WEI: u128 = 1_000_000_000_000_000_000; // 1 ETH
/// Arbitrary, comfortably non-zero unstake delay for `addStake`.
const PAYMASTER_UNSTAKE_DELAY_SECS: u32 = 86_400; // 1 day

/// The full ERC-4337 v0.7 stack [`deploy_4337_stack`] brings up on `anvil`.
#[derive(Debug, Clone, Copy)]
pub struct Deployed4337 {
    /// The freshly, real-constructor-deployed `EntryPoint` (see
    /// [`deploy_4337_stack`]'s doc comment for why this is a real deploy
    /// rather than `anvil_setCode` at the canonical address). Every other
    /// deployed contract in this stack (`factory`, `paymaster`) is
    /// constructed pointing at THIS address, and hermetic tests must read it
    /// from here rather than assuming the canonical
    /// [`ENTRY_POINT_V07_ADDRESS`].
    pub entry_point: EvmAddress,
    /// The freshly deployed `SimpleAccountFactory`.
    pub factory: EvmAddress,
    /// The `SimpleAccount` implementation the factory proxies deployed
    /// accounts to, read back from the factory's `accountImplementation()`.
    pub simple_account_impl: EvmAddress,
    /// The freshly deployed, staked, and deposit-funded paymaster. Always a
    /// `LegacyTokenPaymaster` (see [`deploy_4337_stack`]'s doc comment for
    /// why): the v0.7 sample `TokenPaymaster` (arbitrary ERC-20 via a price
    /// oracle) needs a Uniswap router plus mock price oracles to stand up,
    /// which is out of scope for this devnet harness (Phase 8 owns
    /// paymaster/fee economics; Phase 7 Task 6 may attempt the full
    /// `TokenPaymaster` path, falling back to broadcaster-fronted gas if
    /// that proves impractical).
    pub paymaster: EvmAddress,
    /// The vendored `TestUsdt` ERC-20 fixture (reusing
    /// [`deploy_test_erc20`]), independent of the paymaster's own internal
    /// gas token (see [`Deployed4337::paymaster`]'s doc comment).
    pub usdt: EvmAddress,
}

/// Brings up a full ERC-4337 v0.7 stack on `anvil`: a real, constructor-
/// deployed `EntryPoint`, a freshly deployed `SimpleAccountFactory`, a
/// staked and deposit-funded paymaster, and the vendored `TestUsdt` ERC-20
/// fixture minted to `usdt_holder`.
///
/// **EntryPoint: real deploy, not `anvil_setCode` at the canonical address.**
/// An earlier version of this harness faked the `EntryPoint` into existence
/// via `anvil_setCode` at [`ENTRY_POINT_V07_ADDRESS`] (never running its
/// constructor). That is broken for anything touching account creation:
/// `EntryPoint`'s constructor does `senderCreator = new SenderCreator();`
/// and stores the result in an **immutable**. Immutables are baked directly
/// into the `deployedBytecode` at the offsets the constructor's `CODECOPY`
/// picks -- `anvil_setCode`-ing only the `deployedBytecode` (no constructor
/// run) leaves that immutable's storage slot as whatever
/// `deployedBytecode`'s static template encodes, which for a bytecode
/// artifact fetched pre-deployment is zeroed. `EntryPoint.senderCreator()`
/// then returns `address(0)`, so `_createSenderIfNeeded`'s
/// `senderCreator().createSender(initCode)` call reverts for any UserOp
/// with a non-empty `initCode` -- i.e. `handleOps` can never deploy a
/// counterfactual account, which is the entire point of this module's
/// deposit-account model. Real-deploying `EntryPoint`'s own creation
/// `bytecode` from a funded EOA (mirroring how [`deploy_test_erc20`] and the
/// factory/paymaster below are already deployed) runs the real constructor,
/// so `senderCreator` is set correctly. The resulting address is not the
/// canonical mainnet one (`anvil` has no CREATE2 factory pre-deployed at the
/// canonical deployer nonce), but hermetic tests never need the canonical
/// address -- they read [`Deployed4337::entry_point`] and every other
/// contract in this stack is pointed at that same address.
///
/// **Paymaster choice:** deploys `LegacyTokenPaymaster`, not the v0.7 sample
/// `TokenPaymaster`. `TokenPaymaster`'s constructor requires a wrapped-native
/// token, a Uniswap v3 `ISwapRouter`, and a pair of Chainlink-style price
/// oracles (`OracleHelper`/`IOracle`) -- standing those up on a bare `anvil`
/// devnet is disproportionate for what this harness needs to prove (a real
/// `EntryPoint` + factory + staked paymaster exist and respond correctly).
/// `LegacyTokenPaymaster`'s constructor only needs `(accountFactory, symbol,
/// entryPoint)` and mints its own internal gas token, which this harness
/// funds/stakes via its own `addStake`/`deposit` (both forward to the
/// `EntryPoint`'s `StakeManager` under an `onlyOwner` gate, with the
/// deploying account -- `anvil` account 0 -- as owner). This matches the
/// Phase-7 plan's explicit fallback ("if its constructor needs oracles you
/// can't easily stand up on anvil, deploy `LegacyTokenPaymaster` instead")
/// and maintainer sign-off item 3.
///
/// # Errors
///
/// Returns an error if any deployment/configuration transaction fails to
/// send or confirm, or if a vendored artifact is malformed.
pub async fn deploy_4337_stack(
    anvil: &AnvilHandle,
    usdt_holder: EvmAddress,
    usdt_amount: UsdtAmount,
) -> anyhow::Result<Deployed4337> {
    let infra = deploy_4337_infra(anvil).await?;
    // Reuse the Phase-4 TestUsdt fixture deployer for the USDT token.
    let usdt = deploy_test_erc20(anvil, usdt_holder, usdt_amount).await?;
    Ok(infra.into_deployed(usdt))
}

/// The mainnet-USDT-faithful counterpart of [`deploy_4337_stack`]: an identical
/// ERC-4337 v0.7 stack (real `EntryPoint`, `SimpleAccountFactory` + impl,
/// staked paymaster), but the USDT token is the NON-STANDARD
/// [`deploy_nonstandard_usdt`] fixture (void-returning `transfer`/
/// `transferFrom` + the `basisPointsRate`/`maximumFee` fee mechanism) instead
/// of the standard `TestUsdt`. Used by `tests/nonstandard_usdt_e2e.rs` to prove
/// the whole sweep+withdrawal path survives real USDT's quirks. The returned
/// [`Deployed4337::usdt`] is the non-standard token's address.
///
/// # Errors
///
/// Returns an error if any deployment/configuration transaction fails to send
/// or confirm, or if a vendored artifact is malformed.
pub async fn deploy_nonstandard_4337_stack(
    anvil: &AnvilHandle,
    usdt_holder: EvmAddress,
    usdt_amount: UsdtAmount,
) -> anyhow::Result<Deployed4337> {
    let infra = deploy_4337_infra(anvil).await?;
    let usdt = deploy_nonstandard_usdt(anvil, usdt_holder, usdt_amount).await?;
    Ok(infra.into_deployed(usdt))
}

/// The token-independent part of a deployed ERC-4337 v0.7 stack: everything
/// [`Deployed4337`] holds except the USDT token address. Produced by
/// [`deploy_4337_infra`] and combined with a separately-deployed token
/// (standard or non-standard) via [`Infra4337::into_deployed`].
struct Infra4337 {
    entry_point: EvmAddress,
    factory: EvmAddress,
    simple_account_impl: EvmAddress,
    paymaster: EvmAddress,
}

impl Infra4337 {
    fn into_deployed(self, usdt: EvmAddress) -> Deployed4337 {
        Deployed4337 {
            entry_point: self.entry_point,
            factory: self.factory,
            simple_account_impl: self.simple_account_impl,
            paymaster: self.paymaster,
            usdt,
        }
    }
}

/// Deploys the token-independent ERC-4337 v0.7 infrastructure shared by
/// [`deploy_4337_stack`] and [`deploy_nonstandard_4337_stack`]: a real,
/// constructor-deployed `EntryPoint`, a freshly deployed `SimpleAccountFactory`
/// (+ its `SimpleAccount` implementation, read back), and a staked, deposit-
/// funded `LegacyTokenPaymaster`. See [`deploy_4337_stack`]'s doc comment for
/// the rationale behind the real-`EntryPoint`-deploy and paymaster choices.
async fn deploy_4337_infra(anvil: &AnvilHandle) -> anyhow::Result<Infra4337> {
    let provider = wallet_provider(anvil, ANVIL_ACCOUNT_0_PRIVATE_KEY)?;

    // 1. Real-constructor-deploy the EntryPoint (see this function's doc comment
    //    for why `anvil_setCode` at the canonical address is broken for
    //    initCode-based account creation). No constructor args.
    let entry_point_creation_bytecode = artifact_hex_field(ENTRY_POINT_ARTIFACT_JSON, "bytecode")
        .context("failed to extract EntryPoint bytecode")?;
    let entry_point_deploy_tx =
        TransactionRequest::default().with_deploy_code(entry_point_creation_bytecode);
    let entry_point_receipt = provider
        .send_transaction(entry_point_deploy_tx)
        .await
        .context("failed to send EntryPoint creation transaction")?
        .get_receipt()
        .await
        .context("failed to confirm EntryPoint creation transaction")?;
    let entry_point_address = entry_point_receipt
        .contract_address
        .context("EntryPoint creation receipt is missing a contract_address")?;

    // 2. Deploy SimpleAccountFactory (constructor: `address _entryPoint`), pointed
    //    at the EntryPoint just deployed above (every contract in this stack must
    //    agree on the one EntryPoint address). Its own constructor deploys the
    //    SimpleAccount implementation; capture that address by reading it back via
    //    `accountImplementation()` rather than trying to predict it, per the plan's
    //    guidance.
    let factory_creation_bytecode =
        artifact_hex_field(SIMPLE_ACCOUNT_FACTORY_ARTIFACT_JSON, "bytecode")
            .context("failed to extract SimpleAccountFactory bytecode")?;
    // Constructor arg encoding: a single static (32-byte) `address` param is
    // just its left-padded word -- `abi_encode_params` on a 1-tuple gives
    // exactly that, matching `abi.encode(entryPoint)`.
    let factory_ctor_args = (entry_point_address,).abi_encode_params();
    let mut factory_deploy_code = factory_creation_bytecode;
    factory_deploy_code.extend_from_slice(&factory_ctor_args);

    let factory_deploy_tx = TransactionRequest::default().with_deploy_code(factory_deploy_code);
    let factory_receipt = provider
        .send_transaction(factory_deploy_tx)
        .await
        .context("failed to send SimpleAccountFactory creation transaction")?
        .get_receipt()
        .await
        .context("failed to confirm SimpleAccountFactory creation transaction")?;
    let factory_address = factory_receipt
        .contract_address
        .context("SimpleAccountFactory creation receipt is missing a contract_address")?;

    let factory = ISimpleAccountFactory::new(factory_address, &provider);
    let simple_account_impl = factory
        .accountImplementation()
        .call()
        .await
        .context("failed to read SimpleAccountFactory.accountImplementation()")?;

    // 3. Deploy LegacyTokenPaymaster (constructor: `(address accountFactory, string
    //    _symbol, address _entryPoint)`), then stake + deposit-fund it on the
    //    EntryPoint (both forward through the paymaster's own `onlyOwner`
    //    `addStake`/`deposit`).
    let paymaster_creation_bytecode =
        artifact_hex_field(LEGACY_TOKEN_PAYMASTER_ARTIFACT_JSON, "bytecode")
            .context("failed to extract LegacyTokenPaymaster bytecode")?;
    let paymaster_ctor_args =
        (factory_address, "USDT".to_string(), entry_point_address).abi_encode_params();
    let mut paymaster_deploy_code = paymaster_creation_bytecode;
    paymaster_deploy_code.extend_from_slice(&paymaster_ctor_args);

    let paymaster_deploy_tx = TransactionRequest::default().with_deploy_code(paymaster_deploy_code);
    let paymaster_receipt = provider
        .send_transaction(paymaster_deploy_tx)
        .await
        .context("failed to send LegacyTokenPaymaster creation transaction")?
        .get_receipt()
        .await
        .context("failed to confirm LegacyTokenPaymaster creation transaction")?;
    let paymaster_address = paymaster_receipt
        .contract_address
        .context("LegacyTokenPaymaster creation receipt is missing a contract_address")?;

    let paymaster = ILegacyTokenPaymaster::new(paymaster_address, &provider);
    paymaster
        .addStake(PAYMASTER_UNSTAKE_DELAY_SECS)
        .value(U256::from(PAYMASTER_STAKE_WEI))
        .send()
        .await
        .context("failed to send LegacyTokenPaymaster.addStake()")?
        .get_receipt()
        .await
        .context("failed to confirm LegacyTokenPaymaster.addStake()")?;
    paymaster
        .deposit()
        .value(U256::from(PAYMASTER_DEPOSIT_WEI))
        .send()
        .await
        .context("failed to send LegacyTokenPaymaster.deposit()")?
        .get_receipt()
        .await
        .context("failed to confirm LegacyTokenPaymaster.deposit()")?;

    Ok(Infra4337 {
        entry_point: EvmAddress(entry_point_address.into_array()),
        factory: EvmAddress(factory_address.into_array()),
        simple_account_impl: EvmAddress(simple_account_impl.into_array()),
        paymaster: EvmAddress(paymaster_address.into_array()),
    })
}
