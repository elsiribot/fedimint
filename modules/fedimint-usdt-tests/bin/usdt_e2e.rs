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
use devimint::envs::FM_DEVIMINT_CONFIG_GEN_TIMEOUT_SECS_ENV;
use devimint::external::{Anvil, Bitcoind};
use devimint::federation::{Client, Federation};
use devimint::tests::log_binary_versions;
use fedimint_core::envs::{
    FM_DISABLE_BASE_FEES_ENV, FM_ENABLE_MODULE_LNV1_ENV, FM_ENABLE_MODULE_LNV2_ENV,
    FM_ENABLE_MODULE_MINT_ENV, FM_ENABLE_MODULE_MINTV2_ENV, FM_ENABLE_MODULE_USDT_ENV,
    FM_ENABLE_MODULE_WALLET_ENV, FM_ENABLE_MODULE_WALLETV2_ENV, FM_MINTV2_AMOUNT_UNIT_ENV,
    FM_USDT_BROADCASTER_PRIVATE_KEY_ENV, FM_USDT_CONTRACT_ENV, FM_USDT_ENTRY_POINT_ENV,
    FM_USDT_ETH_USD_PRICE_FEED_ENV,
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

        // The withdrawal leg (unlike deposit->claim) submits real UserOps
        // through a real EntryPoint, so the EntryPoint must exist on the anvil
        // BEFORE config-gen: the derived `account_factory`/`simple_account_impl`
        // (and thus every deposit/pool account address) are a pure function of
        // `entry_point`, so it must be known at config-gen.
        //
        // Part A: deploy ONLY the EntryPoint here (canonical; the module never
        // deploys it). The SimpleAccountFactory + impl are derived from
        // `entry_point` at config-gen and SELF-DEPLOYED by the module via the
        // Arachnid CREATE2 proxy (which the module also bootstraps on this bare
        // anvil), so this harness deliberately does not deploy them.
        info!("Deploying the ERC-4337 EntryPoint (the module self-deploys its factory)...");
        let entry_point = deploy_entry_point(&anvil).await?;
        info!(%entry_point, "ERC-4337 EntryPoint deployed");

        // SAFETY: single-threaded at this point, and set before any
        // `fedimintd` subprocess is spawned below -- env vars are captured at
        // process-spawn time (`Command::envs`), so every guardian inherits
        // these from this process's environment.
        unsafe {
            // The usdt module's threshold-ECDSA DKG runs a per-guardian
            // Paillier aux-gen that exceeds devimint's default 60s config-gen
            // (invite-code) timeout; give it room (see the same var in
            // `devimint::federation`).
            std::env::set_var(FM_DEVIMINT_CONFIG_GEN_TIMEOUT_SECS_ENV, "300");

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

            // Point config-gen at the deployed EntryPoint. The config-gen
            // leader then DERIVES `account_factory`/`simple_account_impl` from
            // it deterministically (Part A), and the module self-deploys that
            // factory on-chain, so `FM_USDT_ACCOUNT_FACTORY`/
            // `FM_USDT_SIMPLE_ACCOUNT_IMPL` are deliberately NOT set here. The
            // guardians share the broadcaster-fronts-ETH model (no paymaster);
            // account 0 is pre-funded with ETH by anvil (it is also the
            // deployer/miner here; the deposit funder is account 1, so there is
            // no conflict) and is the broadcaster that fronts the factory-deploy
            // gas.
            std::env::set_var(FM_USDT_ENTRY_POINT_ENV, entry_point.to_string());
            std::env::set_var(
                FM_USDT_BROADCASTER_PRIVATE_KEY_ENV,
                ANVIL_ACCOUNT_0_PRIVATE_KEY,
            );

            // No Chainlink on anvil: all-zero disables the feed and falls
            // back to `AlloyEvmRpc`'s static ETH/USD price (see Task 4 of
            // the ETH/USD price-feed plan).
            std::env::set_var(
                FM_USDT_ETH_USD_PRICE_FEED_ENV,
                EvmAddress([0u8; 20]).to_string(),
            );
        }

        info!(%token, "Starting the federation (real cggmp21 DKG)...");
        let fed = Federation::new(
            &process_mgr,
            bitcoind.clone(),
            false,
            false,
            0,
            "default".to_string(),
        )
        .await?;

        let client = fed.new_joined_client("usdt-e2e").await?;

        // Part B (module self-prefund): no external `depositTo` here. The
        // module now funds each op sender's `EntryPoint` gas deposit from the
        // broadcaster inside its own submit path (see
        // `fedimint_usdt_server::rpc`'s `submit_user_ops`), so this harness only
        // funds the broadcaster EOA (via `FM_USDT_BROADCASTER_PRIVATE_KEY` =
        // anvil account 0, already ETH-rich) and lets the module top up the
        // pool + deposit accounts' deposits as it submits their UserOps.

        // Part C: the client refuses `deposit-address` unless the module's
        // readiness state machine reports `Ready` (EntryPoint/factory/impl
        // deployed + verified, plus a quorum of funded broadcasters and
        // healthy RPC). The real deployed 4337 stack + funded broadcaster
        // satisfy every condition; poll `status` until it propagates through
        // consensus, mirroring the deposit-status poll below.
        info!("Polling status until the module reports Ready...");
        let ready_deadline = fedimint_core::time::now() + Duration::from_secs(120);
        loop {
            let status = cmd!(client, "module", "usdt", "status").out_json().await?;
            let state = status["state"]
                .as_str()
                .context("status response missing state")?;
            if state == "Ready" {
                break;
            }
            ensure!(
                fedimint_core::time::now() < ready_deadline,
                "usdt module never reported Ready before the deadline (last status: {status})"
            );
            fedimint_core::runtime::sleep(Duration::from_secs(2)).await;
        }

        // Wait for a live `FeeVote` median to exist (the guardians' 1s poller
        // reads the real anvil gas price): `process_input` rejects a claim
        // with `DepositFeeInsufficient` before any median exists (the quote
        // endpoint reports a `0` sentinel until then), mirroring
        // `withdraw_e2e.rs`'s identical wait.
        info!("Polling deposit-fee-quote until a nonzero quote is available...");
        let fee_deadline = fedimint_core::time::now() + Duration::from_secs(60);
        let deposit_fee = loop {
            let quote = cmd!(client, "module", "usdt", "deposit-fee-quote")
                .out_json()
                .await?;
            let fee = quote["fee"]
                .as_u64()
                .context("deposit-fee-quote response missing fee")?;
            if fee > 0 {
                break fee;
            }
            ensure!(
                fedimint_core::time::now() < fee_deadline,
                "deposit-fee-quote never converged to a nonzero quote before the deadline"
            );
            fedimint_core::runtime::sleep(Duration::from_secs(1)).await;
        };

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

        // No manual EntryPoint prefund of the deposit account (Part B): the
        // module self-funds its deposit from the broadcaster when it submits
        // the automatic deploy-and-sweep UserOp sent FROM this account.

        info!(%account, "Transferring USDT to the deposit address on-chain...");
        // `min_net_transfer_amount` is the minimum NET e-cash this test needs
        // (2_048_000 = 4000 * 512, a multiple of the `mintv2` denomination
        // granularity so it mints into e-cash notes with no sub-denomination
        // dust remainder). The `deposit_fee` polled above is an early
        // snapshot, not the exact fee that will be charged: a live
        // (anvil-default, decaying-over-idle-blocks) gas price can drift
        // between this read and the claim actually being processed, so the
        // on-chain `transfer_amount` funds `min_net_transfer_amount` PLUS a 2x
        // margin over that snapshot -- absorbing the drift without needing to
        // predict the exact eventual fee (mirrors `withdraw_e2e.rs`'s/
        // `nonstandard_usdt_e2e.rs`'s identical handling).
        let min_net_transfer_amount = UsdtAmount(2_048_000);
        let transfer_amount = UsdtAmount(min_net_transfer_amount.0 + deposit_fee * 2);
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
        //
        // The claim mints `transfer_amount` minus the deposit fee ACTUALLY
        // charged at claim time, which may differ from the early `deposit_fee`
        // snapshot above (see its funding comment) -- so read the resulting
        // balance directly rather than asserting an exact value predicted
        // from a possibly-stale quote (mirrors `withdraw_e2e.rs`'s/
        // `nonstandard_usdt_e2e.rs`'s identical handling).
        info!("Verifying the USDT-denominated e-cash balance covers the minimum net amount...");
        let balance_deadline = fedimint_core::time::now() + Duration::from_secs(30);
        let net_transfer_amount = loop {
            let balance = usdt_ecash_balance_msats(&client).await?;
            if balance > 0 {
                break UsdtAmount(balance);
            }
            ensure!(
                fedimint_core::time::now() < balance_deadline,
                "USDT e-cash balance never became nonzero before the deadline"
            );
            fedimint_core::runtime::sleep(Duration::from_secs(1)).await;
        };
        ensure!(
            net_transfer_amount.0 >= min_net_transfer_amount.0,
            "USDT e-cash balance ({net_transfer_amount}) must comfortably cover the minimum net \
             transfer amount ({min_net_transfer_amount})"
        );

        info!("Verifying a second claim of the same (already fully-claimed) deposit fails...");
        let second_claim = cmd!(client, "module", "usdt", "claim", &claim_pk)
            .out_json()
            .await;
        ensure!(
            second_claim.is_err(),
            "a second claim of an already-fully-claimed deposit must not succeed"
        );

        // ---- Withdrawal leg: sweep -> claim -> withdraw back to a fresh EVM
        // address, proving deposit->credit->sweep->claim->withdraw end to end.
        //
        // Once the deposit was credited above, the module automatically
        // enqueues a deploy-and-sweep UserOp (the broadcaster fronts its gas)
        // that moves the deposited USDT into the federation pool. The
        // withdrawal batch below waits on that pool balance (a pool-funding
        // gate), so the whole sweep + batch + on-chain confirmation is what the
        // generous poll deadline below absorbs.
        //
        // Wait for the automatic deploy-and-sweep to move the whole deposit
        // into the pool before withdrawing: the withdrawal batch is gated on
        // the pool being funded, so poll pool-state's `balance` until it
        // equals the deposit (`transfer_amount`). Generous deadline -- this
        // absorbs the deploy-and-sweep UserOp's real MPC signing + on-chain
        // round-trip (the deposit account was prefunded above so it can pay
        // the gas).
        info!("Waiting for the automatic sweep to fund the pool...");
        let sweep_deadline = fedimint_core::time::now() + Duration::from_secs(300);
        loop {
            let pool_balance = cmd!(client, "module", "usdt", "pool-state")
                .out_json()
                .await?["balance"]
                .as_u64()
                .context("pool-state response missing balance")?;
            if pool_balance == transfer_amount.0 {
                info!(pool_balance, "Pool funded by the sweep");
                break;
            }
            ensure!(
                fedimint_core::time::now() < sweep_deadline,
                "pool balance ({pool_balance}) never reached the swept deposit amount ({}) \
                 before the deadline",
                transfer_amount.0
            );
            // Keep the real chain head advancing so the sweep's
            // confirmation-depth / block-count gates keep progressing.
            mine_blocks(&anvil, 3).await?;
            fedimint_core::runtime::sleep(Duration::from_secs(2)).await;
        }

        // Withdraw well under the claimed (net) balance (at least
        // `min_net_transfer_amount`, 2_048_000, and `net_transfer_amount` in
        // practice, which is >= that floor), leaving room for the
        // federation's withdrawal fee: the `withdraw` CLI fetches the fee
        // quote itself and burns `amount + max_fee` of e-cash, so the burn
        // must not exceed the balance. 1_024_000 is 512-aligned (the mintv2
        // client denomination granularity).
        let recipient = EvmAddress([0x99; 20]);
        let withdraw_amount = UsdtAmount(1_024_000);
        info!(%recipient, %withdraw_amount, "Submitting a USDT withdrawal to a fresh EVM address...");
        let withdrawal = cmd!(
            client,
            "module",
            "usdt",
            "withdraw",
            recipient.to_string(),
            withdraw_amount.0.to_string()
        )
        .out_json()
        .await?;
        // `withdraw` prints the enqueued withdrawal's `OutPoint` as the string
        // `"<txid>:<out_idx>"` (fedimint's `OutPoint` Display). Split it back
        // into the two positional args `withdrawal-status` expects.
        let out_point = withdrawal["out_point"]
            .as_str()
            .context("withdraw response missing out_point")?;
        let (txid, out_idx) = out_point
            .split_once(':')
            .with_context(|| format!("malformed withdraw out_point {out_point:?}"))?;
        info!(
            txid,
            out_idx, "Withdrawal enqueued; waiting for on-chain confirmation..."
        );

        // Mine empty blocks to push the real anvil chain head (and hence,
        // within a guardian poll cycle, `consensus_block_count`) past the
        // withdrawal batch's `batch_interval_blocks()` trigger. In-devimint the
        // interval is the small test-env value, but the chain head must still
        // advance beyond the block at which `withdraw` stamped the batch's
        // `requested_block`. Mirrors `withdraw_e2e.rs`'s post-withdraw mining.
        mine_blocks(&anvil, 15).await?;

        // Poll withdrawal-status until Confirmed (terminal), bailing on Failed
        // (terminal). The status field is a serde-externally-tagged
        // `WithdrawalStatus`: unit variants serialize as bare strings
        // (`"Queued"`/`"Unknown"`), struct variants as single-key objects
        // (`{"Confirmed":{"block":N}}` / `{"Failed":{"reason":"..."}}`).
        // Generous deadline: the sweep, the withdrawal batch's block-count
        // trigger, real MPC signing, and the on-chain round-trip all fall
        // within it.
        let withdraw_deadline = fedimint_core::time::now() + Duration::from_secs(240);
        loop {
            let status = cmd!(client, "module", "usdt", "withdrawal-status", txid, out_idx)
                .out_json()
                .await?;
            let status = &status["status"];
            if status.get("Confirmed").is_some() {
                info!(?status, "Withdrawal confirmed on-chain");
                break;
            }
            if let Some(failed) = status.get("Failed") {
                anyhow::bail!("withdrawal failed: {failed}");
            }
            ensure!(
                fedimint_core::time::now() < withdraw_deadline,
                "withdrawal never reached Confirmed before the deadline (last status {status})"
            );
            // Keep the real chain head advancing while we wait, so the batch
            // trigger fires and the submitted UserOp reaches confirmation
            // depth (anvil only mines on transactions; these empty blocks do
            // that explicitly).
            mine_blocks(&anvil, 3).await?;
            fedimint_core::runtime::sleep(Duration::from_secs(2)).await;
        }

        info!("Verifying the recipient received the withdrawn USDT on-chain...");
        let recipient_balance = erc20_balance_of(&anvil, token, recipient).await?;
        ensure!(
            recipient_balance == withdraw_amount.0,
            "recipient on-chain USDT balance ({recipient_balance}) != withdrawn amount ({})",
            withdraw_amount.0
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
        function balanceOf(address account) external view returns (uint256);
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

/// Reads `token`'s ERC-20 `balanceOf(account)` on `anvil` (a `view` call, so
/// any funded signer works -- account 0 is used only to build the provider).
async fn erc20_balance_of(
    anvil: &Anvil,
    token: EvmAddress,
    account: EvmAddress,
) -> anyhow::Result<u64> {
    let provider = wallet_provider(anvil, ANVIL_ACCOUNT_0_PRIVATE_KEY)?;
    let contract = ITestUsdt::new(Address::from(token.0), &provider);
    let balance = contract
        .balanceOf(Address::from(account.0))
        .call()
        .await
        .context("failed to read ERC-20 balanceOf()")?;

    balance.try_into().context("ERC-20 balance exceeds u64")
}

// --- ERC-4337 EntryPoint deploy ----------------------------------------
//
// Part A: this harness deploys ONLY the `EntryPoint` (canonical per-chain; the
// module never deploys it). The `SimpleAccountFactory` + its `SimpleAccount`
// implementation are DERIVED at config-gen from `entry_point` and SELF-DEPLOYED
// by the module (via the Arachnid CREATE2 proxy), so this harness deliberately
// does NOT deploy them -- proving the module stands up its own factory. The
// paymaster/stake pieces are likewise skipped: this federation fronts UserOp
// gas from the broadcaster EOA, not a paymaster. The `bin/` target can't import
// the `tests/` `common` module, so this (and the artifact) are duplicated,
// mirroring the ERC-20 helpers above.

/// The vendored ERC-4337 v0.7 `EntryPoint` creation artifact (compiled
/// offline; this harness never invokes `solc`/`forge`), shared with
/// `tests/common/anvil.rs`.
const ENTRY_POINT_ARTIFACT_JSON: &str = include_str!("../tests/fixtures/erc4337/EntryPoint.json");

/// Extracts a top-level hex-string field (`"0x..."`) from a vendored artifact
/// JSON, decoding it to raw bytes. Miniature copy of
/// `tests/common/anvil.rs::artifact_hex_field`.
fn artifact_hex_field(artifact_json: &str, field: &str) -> anyhow::Result<Vec<u8>> {
    let artifact: serde_json::Value = serde_json::from_str(artifact_json)
        .with_context(|| format!("failed to parse erc4337 artifact JSON (`{field}` lookup)"))?;
    let hex_str = artifact[field]
        .as_str()
        .with_context(|| format!("artifact is missing a `{field}` string field"))?;
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    hex::decode(hex_str).with_context(|| format!("artifact `{field}` is not valid hex"))
}

/// Real-constructor-deploys ONLY the ERC-4337 v0.7 `EntryPoint` (no ctor args)
/// as account 0, returning its address. The `SimpleAccountFactory`/impl are
/// derived from this address at config-gen and self-deployed by the module
/// (Part A), so they are intentionally NOT deployed here.
async fn deploy_entry_point(anvil: &Anvil) -> anyhow::Result<EvmAddress> {
    let provider = wallet_provider(anvil, ANVIL_ACCOUNT_0_PRIVATE_KEY)?;

    let entry_point_creation_bytecode = artifact_hex_field(ENTRY_POINT_ARTIFACT_JSON, "bytecode")
        .context("failed to extract EntryPoint bytecode")?;
    let entry_point_receipt = provider
        .send_transaction(
            TransactionRequest::default().with_deploy_code(entry_point_creation_bytecode),
        )
        .await
        .context("failed to send EntryPoint creation transaction")?
        .get_receipt()
        .await
        .context("failed to confirm EntryPoint creation transaction")?;
    let entry_point_address = entry_point_receipt
        .contract_address
        .context("EntryPoint creation receipt is missing a contract_address")?;

    Ok(EvmAddress(entry_point_address.into_array()))
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
