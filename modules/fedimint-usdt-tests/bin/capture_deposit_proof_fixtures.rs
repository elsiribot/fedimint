//! One-shot fixture generator for the deterministic MPT deposit-proof
//! verifier (`fedimint_usdt_server::proof`).
//!
//! Captures REAL Ethereum-mainnet `eth_getProof` responses at a PINNED block
//! and writes them, together with the block's RLP-encoded header and hash, as
//! committed JSON fixtures under
//! `modules/fedimint-usdt-tests/tests/fixtures/proofs/`. The verifier's unit
//! tests (`proof.rs` `mod tests`) then run entirely offline against these
//! committed files -- no RPC at test time.
//!
//! Run with (the block is pinned so the committed fixtures are stable):
//!
//! ```sh
//! cargo run -p fedimint-usdt-tests --bin capture-deposit-proof-fixtures -- <block_number>
//! ```
//!
//! If no block number is given, it pins `head - 32` (well within a full node's
//! ~128-block state window, so `eth_getProof` is served) and prints the number
//! it chose so it can be re-pinned. The generator itself asserts the two core
//! invariants while building each fixture: `keccak256(header_rlp) == blockHash`
//! and (for the funded account) a non-zero proven balance.

use std::path::PathBuf;

use alloy::consensus::Header;
use alloy::eips::BlockId;
use alloy::primitives::{Address, B256, keccak256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rlp::Encodable as _;
use anyhow::{Context as _, bail, ensure};
use fedimint_usdt_common::{EvmAddress, balances_storage_key};
use serde_json::json;

/// Public Ethereum mainnet RPC used to capture the fixtures.
const RPC_URL: &str = "https://ethereum-rpc.publicnode.com";

/// The USDT (Tether) ERC-20 contract on Ethereum mainnet.
const USDT_CONTRACT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";

/// A well-known, heavily-funded USDT holder (Binance hot wallet): its balance
/// slot is present in USDT's storage trie, so its storage proof is an
/// *inclusion* proof of a large non-zero balance.
const FUNDED_ACCOUNT: &str = "0xF977814e90dA44bFA03b6295A0616a897441aceC";

/// A deterministic, astronomically-unlikely-to-be-used address that holds zero
/// USDT: its balance slot is absent from USDT's storage trie, so its storage
/// proof is an *exclusion* proof (proven absence -> balance 0).
const EMPTY_ACCOUNT: &str = "0x1a2b3c4d5e6f00112233445566778899aAbBcCdD";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let block_arg = std::env::args().nth(1);

    let provider = ProviderBuilder::new().connect(RPC_URL).await?;

    let block_number = match block_arg {
        Some(s) => s.parse::<u64>().context("block number must be a u64")?,
        None => provider.get_block_number().await? - 32,
    };
    println!("pinning block {block_number}");

    let usdt: Address = USDT_CONTRACT.parse()?;
    let funded = EvmAddress(FUNDED_ACCOUNT.parse::<Address>()?.into_array());
    let empty = EvmAddress(EMPTY_ACCOUNT.parse::<Address>()?.into_array());

    // Fetch + RLP-encode the pinned block header; assert it round-trips to the
    // canonical block hash. This is exactly verify step 2 the module performs.
    let block = provider
        .get_block(BlockId::number(block_number))
        .await?
        .context("pinned block not found (beyond node head / state window?)")?;
    let header: &Header = &block.header.inner;
    let mut header_rlp = Vec::new();
    header.encode(&mut header_rlp);
    let block_hash: B256 = block.header.hash;
    ensure!(
        keccak256(&header_rlp) == block_hash,
        "RLP-encoded header does not hash to the block hash -- header schema mismatch"
    );
    println!("block_hash = {block_hash}");

    let out_dir = fixtures_dir();
    std::fs::create_dir_all(&out_dir)?;

    // Funded fixture: prove USDT's account against the state root, and the
    // funded holder's balance slot against USDT's storage root (inclusion).
    let funded_balance = write_fixture(
        &provider,
        &out_dir.join("funded.json"),
        block_number,
        block_hash,
        &header_rlp,
        usdt,
        funded,
        true,
    )
    .await?;
    ensure!(funded_balance > 0, "funded account proved a zero balance");
    println!("funded balance = {funded_balance}");

    // Empty fixture: same USDT account proof, but a *storage exclusion* proof
    // for an account that has never held USDT (proven absence -> 0).
    let empty_balance = write_fixture(
        &provider,
        &out_dir.join("empty.json"),
        block_number,
        block_hash,
        &header_rlp,
        usdt,
        empty,
        false,
    )
    .await?;
    ensure!(
        empty_balance == 0,
        "'empty' account unexpectedly holds USDT"
    );
    println!("empty balance = {empty_balance} (proven absence)");

    println!("wrote fixtures to {}", out_dir.display());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn write_fixture(
    provider: &impl Provider,
    path: &std::path::Path,
    block_number: u64,
    block_hash: B256,
    header_rlp: &[u8],
    usdt_contract: Address,
    account: EvmAddress,
    expect_inclusion: bool,
) -> anyhow::Result<u128> {
    let storage_key = B256::from(balances_storage_key(&account));
    let proof = provider
        .get_proof(usdt_contract, vec![storage_key])
        .block_id(BlockId::number(block_number))
        .await
        .context("eth_getProof failed")?;

    ensure!(
        proof.storage_proof.len() == 1,
        "expected exactly one storage proof, got {}",
        proof.storage_proof.len()
    );
    let storage = &proof.storage_proof[0];
    let balance: u128 = storage.value.try_into().context("balance overflows u128")?;
    if expect_inclusion {
        ensure!(balance > 0, "expected an inclusion proof but value is zero");
    } else if balance != 0 {
        bail!("expected an exclusion proof but value is {balance}");
    }

    let account_proof: Vec<String> = proof.account_proof.iter().map(hex_0x).collect();
    let storage_proof: Vec<String> = storage.proof.iter().map(hex_0x).collect();

    let fixture = json!({
        "_comment": "Real Ethereum-mainnet eth_getProof capture; see \
                     modules/fedimint-usdt-tests/bin/capture_deposit_proof_fixtures.rs",
        "rpc_url": RPC_URL,
        "block_number": block_number,
        "block_hash": hex_0x(block_hash.as_slice()),
        "header_rlp": hex_0x(header_rlp),
        "usdt_contract": format!("{usdt_contract:?}"),
        "account": account.to_string(),
        "balance": balance.to_string(),
        "account_proof": account_proof,
        "storage_proof": storage_proof,
    });

    std::fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(&fixture)?),
    )?;
    Ok(balance)
}

fn hex_0x(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proofs")
}
