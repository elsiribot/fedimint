//! ADVERSARIAL security tool: point it at a LIVE federation (via an invite
//! code) and it plays a malicious client against the deposit-by-proof flow,
//! running the no-on-chain-funds attacks from the attack matrix
//! (`.superpowers/sdd/adversary-spec.md`) and reporting, per attack, whether
//! the federation's defense HELD (rejected) or was BREACHED (accepted/minted
//! value).
//!
//! It reuses the SAME attack constructors as the hermetic `tests/adversary.rs`
//! suite ([`fedimint_usdt_tests::attacks`]); the only difference is the target:
//! a real federation reached over iroh/websocket, whose block-hash-ring
//! consensus this tool cannot script. Attacks that (hermetically) rely on a
//! scripted anchor therefore fail here as an anchor mismatch rather than the
//! precise absence/stale rejection -- still a rejection, still no value
//! credited, which is all this tool asserts on a live fed.
//!
//! It needs a live fed to actually run (this is what gets pointed at the
//! mainnet fed); it is never part of any CI lane. NOT shipped in the
//! guardian/gateway image (it lives in `fedimint-usdt-tests`, and its
//! raw-submit primitive is behind the client's non-default `test-util`
//! feature).
//!
//! ```text
//! usdt-adversary --invite <code> --evm-rpc-url <url>
//! ```
//! The `--evm-rpc-url` is accepted for parity with the live client flow and to
//! fund the printed deposit address out of band; the no-funds attacks below do
//! not read on-chain state themselves.

use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use fedimint_bip39::{Bip39RootSecretStrategy, Mnemonic};
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_client::secret::RootSecretStrategy as _;
use fedimint_client::{Client, ClientHandleArc, RootSecret};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::runtime::sleep;
use fedimint_core::secp256k1::Keypair;
use fedimint_core::time::now;
use fedimint_mint_client::MintClientInit;
use fedimint_mintv2_client::MintClientInit as Mintv2ClientInit;
use fedimint_usdt_client::{CraftedInputOutcome, UsdtClientInit, UsdtClientModule};
use fedimint_usdt_common::UsdtAmount;
use fedimint_usdt_tests::attacks::{self, Attack};
use tracing::info;

#[derive(Parser)]
#[command(name = "usdt-adversary")]
#[command(about = "Adversarial deposit-by-proof attacks against a LIVE usdt federation", long_about = None)]
struct Cli {
    /// Federation invite code to join.
    #[arg(long)]
    invite: String,

    /// Ethereum JSON-RPC endpoint (for funding the printed deposit address out
    /// of band; the no-funds attacks do not use it directly).
    #[arg(long)]
    evm_rpc_url: Option<String>,
}

/// Fixed, throwaway client identity so the printed deposit address is stable
/// across runs (the operator can fund it once). This is an adversarial testing
/// tool with no real funds at stake.
const ADVERSARY_ENTROPY: [u8; 16] = [0x2a; 16];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fedimint_logging::TracingSetup::default().init().ok();
    let cli = Cli::parse();

    let invite: InviteCode = cli
        .invite
        .parse()
        .context("failed to parse --invite as a federation invite code")?;

    info!("Joining the federation from the invite code...");
    let client = join_client(&invite).await?;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    // Wait until the module reports Ready so `allocate_deposit` is permitted.
    wait_ready(&usdt).await?;

    // Allocate the adversary's own deposit accounts. `account_b` is the account
    // whose claim key the wrong-account attack submits under; `account_a` is a
    // second, unrelated account whose balance that attack falsely proves.
    let (claim_keypair_b, account_b) = usdt.allocate_deposit().await?;
    let (_claim_keypair_a, account_a) = usdt.allocate_deposit().await?;
    println!(
        "Adversary deposit address (fund THIS to also run the funded attacks manually): {account_b}"
    );
    if let Some(url) = &cli.evm_rpc_url {
        info!(%url, "EVM RPC endpoint provided (for out-of-band funding)");
    }

    let block = usdt.latest_anchored_block().await?.latest;
    anyhow::ensure!(
        block > 0,
        "federation has not anchored any confirmation-deep block yet; try again shortly"
    );

    let usdt_contract = usdt.config().usdt_contract;
    let claim_pk_b = claim_keypair_b.public_key();

    // The no-funds attacks (need no on-chain deposit): each is a pure fed-tx
    // submission of a crafted `UsdtInput::DepositProofV0`.
    let cases: Vec<(Attack, Vec<Keypair>)> = vec![
        (
            attacks::attack_forged_balance(
                usdt_contract,
                claim_pk_b,
                account_b,
                block,
                UsdtAmount(999_999_999_999),
            ),
            vec![claim_keypair_b],
        ),
        (
            attacks::attack_wrong_account(
                usdt_contract,
                claim_pk_b,
                account_a,
                block,
                UsdtAmount(500_000_000),
            ),
            vec![claim_keypair_b],
        ),
        (
            attacks::attack_unanchored(
                usdt_contract,
                claim_pk_b,
                account_b,
                block + 10_000,
                UsdtAmount(500_000_000),
            ),
            vec![claim_keypair_b],
        ),
        (
            attacks::attack_forged_header(
                usdt_contract,
                claim_pk_b,
                account_b,
                block,
                UsdtAmount(500_000_000),
            ),
            vec![claim_keypair_b],
        ),
        (
            attacks::attack_oversize(
                usdt_contract,
                claim_pk_b,
                account_b,
                block,
                UsdtAmount(500_000_000),
            ),
            vec![claim_keypair_b],
        ),
    ];

    let attack_count = cases.len();
    println!("\n== deposit-by-proof adversary: {attack_count} no-funds attacks ==");
    let mut breaches = 0usize;
    for (attack, keys) in cases {
        let name = attack.name;
        let declared = attack.declared;
        match usdt
            .submit_crafted_input_for_test(attack.input.clone(), keys, declared)
            .await
        {
            Ok(CraftedInputOutcome::Rejected { reason }) => {
                println!("  [REJECTED]  {name:<16} defense holds -- {reason}");
            }
            Ok(CraftedInputOutcome::Accepted { minted }) => {
                breaches += 1;
                println!(
                    "  [BREACHED]  {name:<16} !!! SECURITY FINDING: minted {minted} of USDT e-cash \
                     from a crafted input ({}). Input: {:?}",
                    attack.description, attack.input,
                );
            }
            Err(err) => {
                // Infrastructure error (not a fed rejection): report but do not
                // count as a breach.
                println!("  [ERROR]     {name:<16} submission errored (not a breach): {err:#}");
            }
        }
    }

    println!("\n{attack_count} attack(s) run, {breaches} breach(es).");
    if breaches > 0 {
        eprintln!("SECURITY FINDINGS present -- see [BREACHED] lines above.");
        exit(1);
    }
    println!("All defenses held.");
    Ok(())
}

/// Joins the federation fresh from an invite code with a fixed throwaway
/// identity (mirrors `fedimint-cli`'s client-join path, but with an in-memory
/// DB -- the adversary keeps no persistent state).
async fn join_client(invite: &InviteCode) -> anyhow::Result<ClientHandleArc> {
    let connectors = ConnectorRegistry::build_from_client_defaults()
        .bind()
        .await?;

    let mut inits = ClientModuleInitRegistry::new();
    inits.attach(Mintv2ClientInit);
    inits.attach(MintClientInit);
    inits.attach(UsdtClientInit);

    let mut builder = Client::builder().await?;
    builder.with_module_inits(inits);

    let db: Database = MemDatabase::new().into();
    let mnemonic = Mnemonic::from_entropy(&ADVERSARY_ENTROPY)
        .context("failed to build the adversary's throwaway mnemonic")?;
    let root_secret =
        RootSecret::StandardDoubleDerive(Bip39RootSecretStrategy::<12>::to_root_secret(&mnemonic));

    let client = builder
        .preview(connectors, invite)
        .await?
        .join(db, root_secret)
        .await
        .map(Arc::new)?;

    Ok(client)
}

/// Polls the module's readiness until it reports `Ready` (so `allocate_deposit`
/// is permitted), or bails after a generous deadline.
async fn wait_ready(usdt: &UsdtClientModule) -> anyhow::Result<()> {
    let deadline = now() + Duration::from_secs(120);
    loop {
        if let Ok(status) = usdt.status().await
            && status.state == fedimint_usdt_common::BootstrapState::Ready
        {
            return Ok(());
        }
        anyhow::ensure!(
            now() < deadline,
            "usdt module never reported Ready before the deadline"
        );
        sleep(Duration::from_secs(2)).await;
    }
}
