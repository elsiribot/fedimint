//! Real-chain (`devimint` + `anvil`) end-to-end test for the USDT-on-EVM
//! module: derive a deposit address, send a real ERC-20 `transfer` to it on
//! a real `anvil` chain, wait for the federation's guardians to reach
//! deposit-observation consensus over a real `AlephBFT` session, claim it,
//! and assert the resulting USDT-denominated e-cash balance -- all driven
//! through `fedimint-cli`'s `module usdt ...` subcommands (see
//! `fedimint_usdt_client::cli`), exactly as a human/gateway operator would.
//!
//! This complements (does not replace) the *gating* hermetic acceptance test
//! `deposit_becomes_claimable_usdt_ecash` in `tests/tests.rs`, which uses a
//! `MockEvmRpc` and `fedimint-testing`'s trusted-dealer config-gen: that one
//! is fast and runs in default CI; this one proves the same flow against a
//! real chain and a real `cggmp21` DKG, at the cost of ~100s+ per guardian
//! startup, and so is **not** part of the default CI lane -- see
//! `scripts/tests/usdt-e2e-test.sh` and the `test-usdt-e2e` `justfile`
//! recipe for how to run it manually in a real nix devshell (this binary is
//! deliberately never wired into `scripts/tests/test-ci-all.sh`/
//! `backend-test.sh`, unlike its fast sibling `mintv2-module-tests`, which
//! this file is modeled on).
//!
//! MINIMAL USDT-ONLY FEDERATION: this e2e deliberately mounts only the two
//! modules the USDT deposit/claim path needs -- the `usdt` wallet and a
//! single USDT-denominated `mintv2` (the primary module claimed e-cash is
//! minted into) -- and disables everything Bitcoin/Lightning (no Bitcoin
//! wallet, no Bitcoin-denominated mint, no lightning). A Fedimint federation
//! runs fine with no Bitcoin wallet module, so this keeps the test focused on
//! exactly the USDT flow. `devimint`'s real (non-hermetic) config-gen has no
//! mechanism yet to add a *second* instance of the same module kind with
//! distinct params to a live federation (tracked as a follow-up of the
//! `instance-list` refactor -- see the `d4cd4a32b98` commit message), so the
//! single `mintv2` instance is made USDT-denominated directly via
//! `FM_MINTV2_AMOUNT_UNIT`; a true dual-mint (Bitcoin + USDT) devimint
//! federation is left to whoever picks up that follow-up.

use std::ffi;
use std::time::Duration;

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::{Context, ensure};
use clap::Parser;
use devimint::cli::{self, cleanup_on_exit};
use devimint::cmd;
use devimint::external::{Anvil, Bitcoind};
use devimint::federation::{Client, Federation};
use devimint::tests::log_binary_versions;
use fedimint_core::envs::{
    FM_DISABLE_BASE_FEES_ENV, FM_ENABLE_MODULE_LNV1_ENV, FM_ENABLE_MODULE_LNV2_ENV,
    FM_ENABLE_MODULE_MINT_ENV, FM_ENABLE_MODULE_MINTV2_ENV, FM_ENABLE_MODULE_USDT_ENV,
    FM_ENABLE_MODULE_WALLET_ENV, FM_ENABLE_MODULE_WALLETV2_ENV, FM_MINTV2_AMOUNT_UNIT_ENV,
    FM_USDT_CONTRACT_ENV,
};
use fedimint_usdt_common::{EvmAddress, USDT_UNIT, UsdtAmount};
use tracing::info;

#[derive(Parser)]
#[command(name = "usdt-e2e-test")]
#[command(about = "Real-chain (devimint + anvil) usdt deposit->claim e2e", long_about = None)]
struct Cli {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _cli = Cli::parse();

    let args = cli::CommonArgs::parse_from::<_, ffi::OsString>(vec![]);
    let (process_mgr, task_group) = cli::setup(args).await?;

    let main = async {
        log_binary_versions().await?;

        info!("Starting bitcoind + anvil...");
        let bitcoind = Bitcoind::new(&process_mgr, false).await?;
        let anvil = Anvil::new(&process_mgr).await?;

        info!("Deploying the test ERC-20 and minting a supply to the sender account...");
        let holder = account_1_address()?;
        let token = deploy_test_erc20(&anvil, holder, UsdtAmount(10_000_000)).await?;

        // SAFETY: single-threaded at this point, and set before any
        // `fedimintd` subprocess is spawned below -- env vars are captured at
        // process-spawn time (`Command::envs`), so every guardian inherits
        // these from this process's environment.
        unsafe {
            // The usdt module's threshold-ECDSA DKG runs a per-guardian
            // Paillier aux-gen that exceeds devimint's default 60s config-gen
            // (invite-code) timeout; give it room (see the same var in
            // `devimint::federation`).
            std::env::set_var("FM_DEVIMINT_CONFIG_GEN_TIMEOUT_SECS", "300");

            // Minimal USDT-only federation: the ONLY modules are the usdt
            // wallet and a single USDT-denominated `mintv2` (the primary module
            // the usdt module mints claimed e-cash into). Everything Bitcoin/
            // Lightning is disabled -- no Bitcoin wallet, no Bitcoin-denominated
            // mint, no lightning -- so this e2e exercises exactly the usdt
            // deposit->claim path and nothing else.
            std::env::set_var(FM_ENABLE_MODULE_USDT_ENV, "1");
            std::env::set_var(FM_ENABLE_MODULE_MINTV2_ENV, "1");
            std::env::set_var(FM_ENABLE_MODULE_MINT_ENV, "0");
            std::env::set_var(FM_ENABLE_MODULE_WALLET_ENV, "0");
            std::env::set_var(FM_ENABLE_MODULE_WALLETV2_ENV, "0");
            std::env::set_var(FM_ENABLE_MODULE_LNV1_ENV, "0");
            std::env::set_var(FM_ENABLE_MODULE_LNV2_ENV, "0");
            std::env::set_var(
                FM_MINTV2_AMOUNT_UNIT_ENV,
                serde_json::to_value(USDT_UNIT)
                    .expect("AmountUnit is serializable")
                    .to_string(),
            );
            // Zero the mintv2 issuance fee so the claimed e-cash balance equals
            // the deposit exactly (mirrors the hermetic fixture's
            // `disable_mint_fees()`); this test asserts deposit/claim
            // correctness, not fee accounting.
            std::env::set_var(FM_DISABLE_BASE_FEES_ENV, "1");
            std::env::set_var(FM_USDT_CONTRACT_ENV, token.to_string());
        }

        info!(%token, "Starting the federation (real cggmp21 DKG)...");
        let fed = Federation::new(
            &process_mgr,
            bitcoind.clone(),
            false,
            false,
            false,
            0,
            "default".to_string(),
        )
        .await?;

        let client = fed.new_joined_client("usdt-e2e").await?;

        info!("Deriving a deposit address...");
        let deposit_address = cmd!(client, "module", "usdt", "deposit-address")
            .out_json()
            .await?;
        let claim_pk = deposit_address["claim_pk"]
            .as_str()
            .context("deposit-address response missing claim_pk")?
            .to_string();
        let account: EvmAddress = deposit_address["account"]
            .as_str()
            .context("deposit-address response missing account")?
            .parse()?;

        info!(%account, "Transferring USDT to the deposit address on-chain...");
        // Must be a multiple of the `mintv2` denomination granularity (512
        // msats) so the whole claimed amount mints into e-cash notes with no
        // sub-denomination dust remainder (2_048_000 = 4000 * 512); combined
        // with `FM_DISABLE_BASE_FEES` above, the issued balance then equals the
        // deposit exactly.
        let transfer_amount = UsdtAmount(2_048_000);
        transfer_erc20_from_account_1(&anvil, token, account, transfer_amount).await?;

        info!("Mining past confirmation_depth...");
        mine_blocks(&anvil, 3).await?;

        info!("Enqueuing the deposit checker (check-deposit)...");
        cmd!(client, "module", "usdt", "check-deposit", &claim_pk)
            .out_json()
            .await?;

        info!("Polling deposit-status until the guardians credit the deposit...");
        let deadline = fedimint_core::time::now() + Duration::from_secs(180);
        loop {
            let status = cmd!(client, "module", "usdt", "deposit-status", &claim_pk)
                .out_json()
                .await?;
            let claimable = status["claimable"]
                .as_u64()
                .context("deposit-status response missing claimable")?;
            if claimable > 0 {
                break;
            }
            ensure!(
                fedimint_core::time::now() < deadline,
                "deposit never became claimable before the deadline"
            );
            fedimint_core::runtime::sleep(Duration::from_secs(2)).await;
        }

        info!("Claiming...");
        let claimed = cmd!(client, "module", "usdt", "claim", &claim_pk)
            .out_json()
            .await?;
        let claimed_amount = claimed["claimed"]
            .as_u64()
            .context("claim response missing claimed")?;
        ensure!(
            claimed_amount == transfer_amount.0,
            "claimed amount ({claimed_amount}) != transferred amount ({})",
            transfer_amount.0
        );

        // The USDT client's `claim` awaits the USDT-denominated `mintv2`
        // issuance before returning (it uses the unit-aware
        // `await_primary_module_outputs_for_unit(USDT_UNIT)`), so by the time
        // the CLI `claim` above returns, the e-cash notes are issued and
        // persisted; the balance is therefore observable immediately. A short
        // poll is kept only to absorb any per-process client-load latency.
        info!("Verifying the USDT-denominated e-cash balance equals the transfer...");
        let balance_deadline = fedimint_core::time::now() + Duration::from_secs(30);
        let balance = loop {
            let balance = usdt_ecash_balance_msats(&client).await?;
            if balance == transfer_amount.0 {
                break balance;
            }
            ensure!(
                fedimint_core::time::now() < balance_deadline,
                "USDT e-cash balance ({balance} msats) never reached the transferred amount \
                 ({} msats) before the deadline",
                transfer_amount.0
            );
            fedimint_core::runtime::sleep(Duration::from_secs(1)).await;
        };
        ensure!(
            balance == transfer_amount.0,
            "USDT e-cash balance ({balance} msats) != transferred amount ({} msats)",
            transfer_amount.0
        );

        info!("Verifying a second claim of the same (already fully-claimed) deposit fails...");
        let second_claim = cmd!(client, "module", "usdt", "claim", &claim_pk)
            .out_json()
            .await;
        ensure!(
            second_claim.is_err(),
            "a second claim of an already-fully-claimed deposit must not succeed"
        );

        info!("usdt devimint/anvil e2e complete");

        Ok::<_, anyhow::Error>(())
    };

    cleanup_on_exit(main, task_group).await?;

    Ok(())
}

/// Sums the client's `mintv2` note counts by denomination into a total msat
/// balance. Reads the raw JSON of `module mintv2 count`
/// (`fedimint_mintv2_client::cli`'s `Opts::Count` ->
/// `MintClientModule::get_count_by_denomination`) rather than depending on
/// `fedimint_mintv2_common::Denomination`'s (de)serialization round-trip
/// through a JSON map with stringified keys.
///
/// Since this e2e overrides the federation's single `mintv2` instance to be
/// USDT-denominated (see the module doc comment), this is unambiguously the
/// USDT-denominated e-cash balance -- there is no second, Bitcoin-denominated
/// `mintv2` instance to disambiguate from.
async fn usdt_ecash_balance_msats(client: &Client) -> anyhow::Result<u64> {
    let counts = cmd!(client, "module", "mintv2", "count").out_json().await?;
    let counts = counts
        .as_object()
        .context("mintv2 count response is not a JSON object")?;

    let mut total = 0u64;
    for (denomination, count) in counts {
        let denomination: u32 = denomination
            .parse()
            .with_context(|| format!("non-numeric denomination key {denomination:?}"))?;
        let count = count
            .as_u64()
            .context("denomination count is not a number")?;
        total += (1u64 << denomination) * count;
    }

    Ok(total)
}

// --- anvil helpers -----------------------------------------------------
//
// Deliberately duplicated (in miniature) from
// `tests/common/anvil.rs::{deploy_test_erc20, transfer_erc20_from_account_1}`
// rather than shared: that module is scoped to this crate's `tests/`
// integration-test targets (hermetic, `MockEvmRpc`-backed), not its `bin/`
// targets, and is not published as a library other crates/targets can
// import from.

sol! {
    #[sol(rpc)]
    interface ITestUsdt {
        function mint(address to, uint256 amount) external;
        function transfer(address to, uint256 amount) external returns (bool);
    }
}

/// Private key of `anvil`'s first deterministic default account (derived
/// from its well-known dev mnemonic); used to deploy the test ERC-20 and to
/// fund block-mining transactions.
const ANVIL_ACCOUNT_0_PRIVATE_KEY: &str =
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Private key of `anvil`'s second deterministic default account, seeded as
/// the ERC-20 holder in [`deploy_test_erc20`] and used to `transfer()` from
/// in [`transfer_erc20_from_account_1`], mirroring an end user spending
/// already-owned tokens (rather than the contract owner's `mint()`
/// backdoor).
const ANVIL_ACCOUNT_1_PRIVATE_KEY: &str =
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

fn account_1_address() -> anyhow::Result<EvmAddress> {
    let signer: PrivateKeySigner = ANVIL_ACCOUNT_1_PRIVATE_KEY
        .parse()
        .context("malformed ANVIL_ACCOUNT_1_PRIVATE_KEY")?;
    Ok(EvmAddress(signer.address().into_array()))
}

fn wallet_provider(anvil: &Anvil, private_key: &str) -> anyhow::Result<impl Provider + Clone> {
    let signer: PrivateKeySigner = private_key
        .parse()
        .context("malformed anvil dev-account private key")?;
    let url = anvil
        .rpc_url()
        .parse()
        .with_context(|| format!("invalid anvil url: {}", anvil.rpc_url()))?;

    Ok(ProviderBuilder::new().wallet(signer).connect_http(url))
}

/// The vendored `TestUsdt` fixture's creation bytecode + ABI (see
/// `modules/fedimint-usdt-tests/contracts/TestUsdt.sol`, compiled offline;
/// this harness never invokes `solc`/`forge`), shared with
/// `tests/common/anvil.rs`.
const TEST_USDT_FIXTURE_JSON: &str = include_str!("../tests/fixtures/test_usdt.json");

fn test_usdt_creation_bytecode() -> anyhow::Result<Vec<u8>> {
    let fixture: serde_json::Value = serde_json::from_str(TEST_USDT_FIXTURE_JSON)
        .context("failed to parse tests/fixtures/test_usdt.json")?;
    let bytecode_hex = fixture["bytecode"]
        .as_str()
        .context("fixture is missing a `bytecode` string field")?;
    let bytecode_hex = bytecode_hex.strip_prefix("0x").unwrap_or(bytecode_hex);

    hex::decode(bytecode_hex).context("fixture `bytecode` is not valid hex")
}

/// Deploys the vendored `TestUsdt` ERC-20 fixture to `anvil` (as account 0)
/// and mints `amount` to `holder`. Returns the deployed contract's address.
async fn deploy_test_erc20(
    anvil: &Anvil,
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

/// Transfers `amount` of `token` from `anvil`'s account 1 to `to`,
/// confirming the transaction before returning.
async fn transfer_erc20_from_account_1(
    anvil: &Anvil,
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

/// Mines `n` additional blocks by sending trivial zero-value self-transfers
/// from account 0 -- `anvil`'s default automine mode mines exactly one block
/// per submitted transaction -- so a prior transaction becomes `n`
/// confirmations deep.
async fn mine_blocks(anvil: &Anvil, n: u32) -> anyhow::Result<()> {
    let provider = wallet_provider(anvil, ANVIL_ACCOUNT_0_PRIVATE_KEY)?;
    let signer: PrivateKeySigner = ANVIL_ACCOUNT_0_PRIVATE_KEY
        .parse()
        .context("malformed ANVIL_ACCOUNT_0_PRIVATE_KEY")?;

    for _ in 0..n {
        provider
            .send_transaction(
                TransactionRequest::default()
                    .with_to(signer.address())
                    .with_value(U256::ZERO),
            )
            .await
            .context("failed to send mining transaction")?
            .get_receipt()
            .await
            .context("failed to confirm mining transaction")?;
    }

    Ok(())
}
