//! Hermetic deposit-by-proof test helpers.
//!
//! The live client flow ([`UsdtClientModule::submit_deposit_proof`]) fetches an
//! `eth_getProof` from a real Ethereum JSON-RPC endpoint, reconstructs the
//! block header, and submits a [`UsdtInput::DepositProofV0`]. Hermetic tests
//! have no such endpoint (they drive a scriptable [`MockEvmRpc`] instead), so
//! [`credit_deposit_via_proof`] reproduces the server-verifiable half offline:
//! it builds a single-leaf Merkle-Patricia proof (a direct port of
//! `fedimint-usdt-server`'s own `synthetic_deposit_proof` test builder),
//! anchors the matching block hash in the federation's consensus ring by
//! scripting the mock's `get_block_hash` (so the guardians' block-hash observer
//! votes it in), and submits the proof through the real client path
//! ([`UsdtClientModule::submit_prebuilt_deposit_proof`]).
//!
//! Because deposit-by-proof credits AND mints the full proven balance in one
//! transaction with NO fee (unlike the legacy observe-then-claim path), the
//! federation credits -- and the submitting client's USDT e-cash balance grows
//! by -- exactly the proven `balance`.

use std::time::Duration;

use alloy_consensus::Header;
use alloy_primitives::{B256, U256, keccak256};
use alloy_rlp::Encodable as _;
use alloy_trie::nodes::LeafNode;
use alloy_trie::{Nibbles, TrieAccount};
use fedimint_core::runtime::{Instant, sleep};
use fedimint_core::secp256k1::Keypair;
use fedimint_usdt_client::UsdtClientModule;
use fedimint_usdt_common::{DepositProof, EvmAddress, UsdtAmount, balances_storage_key};

use super::mock::MockEvmRpc;

/// Builds a synthetic single-leaf MPT deposit proof the real
/// `fedimint_usdt_server::proof::verify_deposit_proof` accepts, wholly offline:
/// a state trie holding exactly `usdt_contract`'s account (whose storage trie
/// holds exactly `account`'s USDT balance slot), wrapped in a header whose
/// keccak is the returned canonical block hash. A direct port of the server's
/// own `synthetic_deposit_proof` test builder.
#[must_use]
pub fn synthetic_deposit_proof(
    usdt_contract: EvmAddress,
    account: EvmAddress,
    balance: u64,
    block_number: u64,
) -> (DepositProof, [u8; 32]) {
    // Storage trie: one leaf at keccak(balances_storage_key(account)),
    // value = rlp(balance word), root = keccak(rlp(leaf)).
    let storage_key = Nibbles::unpack(keccak256(balances_storage_key(&account)));
    let mut storage_value = Vec::new();
    U256::from(balance).encode(&mut storage_value);
    let mut storage_leaf_rlp = Vec::new();
    LeafNode::new(storage_key, storage_value).encode(&mut storage_leaf_rlp);
    let storage_root = B256::from(keccak256(&storage_leaf_rlp));

    // Account trie: one leaf at keccak(usdt_contract), value =
    // rlp(TrieAccount { storage_root, .. }), root = state root.
    let account_key = Nibbles::unpack(keccak256(usdt_contract.0));
    let mut account_value = Vec::new();
    TrieAccount {
        storage_root,
        ..Default::default()
    }
    .encode(&mut account_value);
    let mut account_leaf_rlp = Vec::new();
    LeafNode::new(account_key, account_value).encode(&mut account_leaf_rlp);
    let state_root = B256::from(keccak256(&account_leaf_rlp));

    // Header committing to that state root; its keccak is the block hash the
    // ring must anchor for the proof to verify.
    let mut header_rlp = Vec::new();
    Header {
        state_root,
        number: block_number,
        ..Default::default()
    }
    .encode(&mut header_rlp);
    let block_hash = keccak256(&header_rlp).0;

    (
        DepositProof {
            block_number,
            header_rlp,
            account_proof: vec![account_leaf_rlp],
            storage_proof: vec![storage_leaf_rlp],
        },
        block_hash,
    )
}

/// Hermetic stand-in for the client's live `eth_getProof` submit flow: credits
/// `balance` USDT into `claim_keypair`'s derived deposit `account` and mints it
/// as USDT e-cash, by
///
/// 1. waiting for the federation's block-hash ring to anchor a
///    confirmation-deep block `B` (polls `latest_anchored_block`),
/// 2. building a synthetic proof of `balance` at `B` and scripting the mock so
///    the block-hash observer re-anchors `B` to the proof's block hash, then
/// 3. submitting the proof through the real client path
///    ([`UsdtClientModule::submit_prebuilt_deposit_proof`]), retrying until the
///    ring has converged to the scripted hash and the proof verifies.
///
/// Deposit-by-proof charges no fee, so the submitting client's `USDT_UNIT`
/// e-cash balance grows by exactly `balance` (`balance` must be a 512-msat
/// multiple to avoid mintv2 denomination-rounding dust if the caller asserts
/// exact equality).
pub async fn credit_deposit_via_proof(
    usdt: &UsdtClientModule,
    mock: &MockEvmRpc,
    usdt_contract: EvmAddress,
    claim_keypair: &Keypair,
    account: EvmAddress,
    balance: UsdtAmount,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;

    // Wait for the ring to anchor a confirmation-deep block.
    let block = loop {
        let anchored = usdt.latest_anchored_block().await?;
        if anchored.latest > 0 {
            break anchored.latest;
        }
        if Instant::now() >= deadline {
            anyhow::bail!("block-hash ring never anchored a confirmation-deep block");
        }
        sleep(Duration::from_millis(200)).await;
    };

    // Build the proof for that height and make the ring anchor its block hash:
    // the observer re-observes `block` each tick and, since the hash changed,
    // the guardians re-vote and `write_block_hash_ring` overwrites the default
    // `mock_block_hash(block)` with our synthetic hash.
    let (proof, block_hash) = synthetic_deposit_proof(usdt_contract, account, balance.0, block);
    mock.set_block_hash(block, block_hash);

    // Retry until the ring has converged to the scripted hash and the proof
    // verifies server-side (the observer + consensus need a few 1s ticks).
    loop {
        match usdt
            .submit_prebuilt_deposit_proof(claim_keypair, proof.clone(), balance)
            .await
        {
            Ok(_) => return Ok(()),
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(err.context(
                        "deposit-by-proof submission never succeeded before the deadline",
                    ));
                }
                sleep(Duration::from_millis(300)).await;
            }
        }
    }
}
