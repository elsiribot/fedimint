//! Deterministic Merkle-Patricia (MPT) verification of an Ethereum
//! `eth_getProof` deposit proof.
//!
//! [`verify_deposit_proof`] is the security-critical core of the
//! "deposit-by-proof" feature: given a [`DepositProof`] and the canonical hash
//! of the block it was taken at, it *derives* the proven USDT balance of an
//! account straight from the proof's own trie nodes -- it never trusts a
//! client-supplied value. Every step is pure computation over the function's
//! inputs (keccak, RLP decode, trie walk): no RPC, no wall-clock, no
//! `our_peer_id`, no floating point, so every honest guardian computes a
//! byte-identical result and the whole thing can run inside consensus.
//!
//! The trust anchor is `expected_block_hash`, which the caller obtains from the
//! federation's own canonical block-hash tracking; from there the chain of
//! commitments is: `expected_block_hash == keccak256(header_rlp)` -> header's
//! `state_root` -> USDT contract account (and its `storage_root`) -> the
//! account's USDT balance storage slot.

use alloy_consensus::Header;
use alloy_primitives::{B256, Bytes, U256, keccak256};
use alloy_rlp::Decodable as _;
use alloy_trie::nodes::TrieNode;
use alloy_trie::proof::verify_proof;
use alloy_trie::{Nibbles, TrieAccount};
use anyhow::{Context as _, anyhow, ensure};
use fedimint_usdt_common::{
    DepositProof, EvmAddress, MAX_DEPOSIT_PROOF_BYTES, UsdtAmount, balances_storage_key,
};

/// Verifies that `proof` proves `account`'s USDT balance (held in
/// `usdt_contract`) at the block whose header hashes to `expected_block_hash`,
/// and returns the *proven* balance.
///
/// Proof-of-absence at any level -- the USDT contract account not existing, or
/// the account's balance slot being empty -- yields `UsdtAmount(0)` (a real,
/// verified fact: the account provably holds no USDT), not an error. An error
/// is returned only when the proof is malformed, oversized, or does not
/// actually commit to a value for the requested key under
/// `expected_block_hash`.
///
/// Deterministic: pure computation over the arguments (no RPC, no wall-clock,
/// no `our_peer_id`, no floats), so every guardian derives the same balance.
///
/// # Errors
///
/// Returns an error if the proof exceeds [`MAX_DEPOSIT_PROOF_BYTES`], the
/// header does not hash to `expected_block_hash`, the header/account/storage
/// RLP fails to decode, a sub-proof fails cryptographic verification against
/// its root, or the proven balance overflows [`u64`].
pub fn verify_deposit_proof(
    proof: &DepositProof,
    expected_block_hash: [u8; 32],
    usdt_contract: &EvmAddress,
    account: &EvmAddress,
) -> anyhow::Result<UsdtAmount> {
    // Step 1: bound the work an untrusted proof can make every guardian do.
    let encoded_len = proof.encoded_len_bytes();
    ensure!(
        encoded_len <= MAX_DEPOSIT_PROOF_BYTES,
        "deposit proof is oversized: {encoded_len} > {MAX_DEPOSIT_PROOF_BYTES} bytes"
    );

    // Step 2: anchor the proof to the canonical chain. The header is only
    // trustworthy because it hashes to the block hash the federation itself
    // tracks; everything downstream hangs off this equality.
    ensure!(
        keccak256(&proof.header_rlp).0 == expected_block_hash,
        "header_rlp does not hash to expected_block_hash"
    );

    // Step 3: decode the (now-authenticated) header and take only its state
    // root. Extra/newer header fields are irrelevant -- the RLP had to
    // round-trip to the committed hash, so whatever it decodes to is exactly
    // the canonical header.
    let header =
        Header::decode(&mut proof.header_rlp.as_slice()).context("decoding block header RLP")?;
    let state_root = header.state_root;

    // Step 4: prove the USDT contract account against the state root. Its trie
    // key is `keccak256(address)`. A proof of absence means the contract does
    // not exist at this block, so no USDT can have been deposited.
    let account_key = Nibbles::unpack(keccak256(usdt_contract.0));
    let Some(account_rlp) =
        proven_value(state_root, &account_key, &proof.account_proof).context("account proof")?
    else {
        return Ok(UsdtAmount(0));
    };
    let trie_account =
        TrieAccount::decode(&mut account_rlp.as_slice()).context("decoding account leaf RLP")?;
    let storage_root = trie_account.storage_root;

    // Step 5: prove the account's USDT balance slot against the contract's
    // storage root. Its trie key is `keccak256(balances_storage_key(account))`.
    // An empty slot (proof of absence) is a zero balance.
    let storage_key = Nibbles::unpack(keccak256(balances_storage_key(account)));
    let Some(value_rlp) =
        proven_value(storage_root, &storage_key, &proof.storage_proof).context("storage proof")?
    else {
        return Ok(UsdtAmount(0));
    };

    // A storage slot's value is an RLP-encoded big-endian integer word.
    let balance_word = U256::decode(&mut value_rlp.as_slice()).context("decoding storage word")?;
    let balance = u64::try_from(balance_word)
        .map_err(|_| anyhow!("proven USDT balance {balance_word} overflows u64"))?;
    Ok(UsdtAmount(balance))
}

/// Cryptographically verifies `nodes` against `root` at `key` and returns the
/// value the proof *actually commits to*: `Some(value)` for an inclusion
/// proof, `None` for a valid proof of absence.
///
/// The candidate value is extracted from the proof's own terminal node (never
/// supplied by a caller) and then confirmed by [`verify_proof`], which re-walks
/// the whole `(key, value)` pair up to `root`. `verify_proof` only *checks* a
/// caller-provided value against the root, so a value that does not match what
/// the trie truly commits to fails verification -- there is no path by which an
/// unverified, attacker-chosen value is returned.
fn proven_value(root: B256, key: &Nibbles, nodes: &[Vec<u8>]) -> anyhow::Result<Option<Vec<u8>>> {
    let proof_nodes: Vec<Bytes> = nodes.iter().map(|n| Bytes::copy_from_slice(n)).collect();

    // Candidate value read straight from the proof's terminal leaf. This is
    // only a hint -- it is worthless until `verify_proof` confirms it hashes up
    // to `root` at exactly `key`.
    if let Some(candidate) = terminal_leaf_value(nodes)
        && verify_proof(root, *key, Some(candidate.clone()), proof_nodes.iter()).is_ok()
    {
        return Ok(Some(candidate));
    }

    // Not a confirmable inclusion proof, so it must be a valid proof of
    // absence; anything else is a malformed/forged proof and errors out.
    verify_proof(root, *key, None, proof_nodes.iter())
        .map_err(|e| anyhow!("proof verification failed: {e}"))?;
    Ok(None)
}

/// Decodes the last node of `nodes` and, if it is a leaf, returns its value.
/// Any other terminal node shape (branch/extension/empty root) or a decode
/// failure yields `None`. Purely a candidate extractor: the returned bytes are
/// meaningless until confirmed by [`verify_proof`] in [`proven_value`].
fn terminal_leaf_value(nodes: &[Vec<u8>]) -> Option<Vec<u8>> {
    match TrieNode::decode(&mut nodes.last()?.as_slice()).ok()? {
        TrieNode::Leaf(leaf) => Some(leaf.value),
        TrieNode::Branch(_) | TrieNode::Extension(_) | TrieNode::EmptyRoot => None,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use fedimint_usdt_common::DepositProof;

    use super::*;

    /// A fixture captured by
    /// `modules/fedimint-usdt-tests/bin/capture_deposit_proof_fixtures.rs`.
    struct Fixture {
        proof: DepositProof,
        block_hash: [u8; 32],
        usdt_contract: EvmAddress,
        account: EvmAddress,
        balance: u64,
    }

    fn strip_0x(s: &str) -> &str {
        s.strip_prefix("0x").unwrap_or(s)
    }

    fn decode_hex(v: &serde_json::Value) -> Vec<u8> {
        hex::decode(strip_0x(v.as_str().expect("hex string"))).expect("valid hex")
    }

    fn decode_hex_list(v: &serde_json::Value) -> Vec<Vec<u8>> {
        v.as_array()
            .expect("array")
            .iter()
            .map(decode_hex)
            .collect()
    }

    fn load_fixture(name: &str) -> Fixture {
        // Fixtures live in the sibling `fedimint-usdt-tests` crate so the same
        // captured JSON is available to its integration tests too.
        let path = format!(
            "{}/../fedimint-usdt-tests/tests/fixtures/proofs/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let json: serde_json::Value = serde_json::from_str(&raw).expect("valid fixture JSON");

        let block_hash: [u8; 32] = decode_hex(&json["block_hash"])
            .try_into()
            .expect("32-byte block hash");
        let usdt_contract =
            EvmAddress::from_str(json["usdt_contract"].as_str().expect("usdt_contract"))
                .expect("valid usdt contract address");
        let account = EvmAddress::from_str(json["account"].as_str().expect("account"))
            .expect("valid account");
        let balance = json["balance"]
            .as_str()
            .expect("balance")
            .parse::<u64>()
            .expect("u64 balance");

        Fixture {
            proof: DepositProof {
                block_number: json["block_number"].as_u64().expect("block_number"),
                header_rlp: decode_hex(&json["header_rlp"]),
                account_proof: decode_hex_list(&json["account_proof"]),
                storage_proof: decode_hex_list(&json["storage_proof"]),
            },
            block_hash,
            usdt_contract,
            account,
            balance,
        }
    }

    #[test]
    fn funded_fixture_proves_known_balance() {
        let f = load_fixture("funded.json");
        assert!(
            f.balance > 0,
            "funded fixture should carry a non-zero balance"
        );

        let proven =
            verify_deposit_proof(&f.proof, f.block_hash, &f.usdt_contract, &f.account).unwrap();

        assert_eq!(proven, UsdtAmount(f.balance));
    }

    #[test]
    fn empty_fixture_proves_zero() {
        let f = load_fixture("empty.json");

        let proven =
            verify_deposit_proof(&f.proof, f.block_hash, &f.usdt_contract, &f.account).unwrap();

        assert_eq!(proven, UsdtAmount(0));
    }

    #[test]
    fn tampered_header_rlp_is_rejected() {
        let mut f = load_fixture("funded.json");
        // Flip a byte deep inside the header (past the RLP length prefix): now
        // `keccak256(header_rlp) != block_hash`, so the anchor check must fail.
        let mid = f.proof.header_rlp.len() / 2;
        f.proof.header_rlp[mid] ^= 0xff;

        let err = verify_deposit_proof(&f.proof, f.block_hash, &f.usdt_contract, &f.account)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not hash"), "unexpected error: {err}");
    }

    #[test]
    fn wrong_expected_block_hash_is_rejected() {
        let f = load_fixture("funded.json");

        let err = verify_deposit_proof(&f.proof, [0u8; 32], &f.usdt_contract, &f.account)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not hash"), "unexpected error: {err}");
    }

    #[test]
    fn wrong_account_storage_slot_is_zero_or_err() {
        // The funded fixture's storage proof commits to the funded account's
        // balance slot. Asking for a *different* account derives a different
        // storage key that this proof does not cover, so verification must
        // either prove absence (0) or fail -- never leak the funded balance.
        let f = load_fixture("funded.json");
        let other = EvmAddress([0x11u8; 20]);
        assert_ne!(other, f.account);

        if let Ok(a) = verify_deposit_proof(&f.proof, f.block_hash, &f.usdt_contract, &other) {
            assert_eq!(a, UsdtAmount(0), "must not return the funded balance");
        }
    }

    #[test]
    fn wrong_contract_account_is_zero_or_err() {
        // Asking about a contract the state root does not prove: the account
        // proof cannot be an inclusion proof for this key, so the result is a
        // proven-absence 0 or a verification error -- never the funded balance.
        let f = load_fixture("funded.json");
        let other_contract = EvmAddress([0x22u8; 20]);
        assert_ne!(other_contract, f.usdt_contract);

        if let Ok(a) = verify_deposit_proof(&f.proof, f.block_hash, &other_contract, &f.account) {
            assert_eq!(a, UsdtAmount(0));
        }
    }

    #[test]
    fn oversized_proof_is_rejected() {
        let mut f = load_fixture("funded.json");
        // Blow the encoded size past the cap with a single huge node.
        f.proof
            .storage_proof
            .push(vec![0u8; MAX_DEPOSIT_PROOF_BYTES + 1]);
        assert!(f.proof.encoded_len_bytes() > MAX_DEPOSIT_PROOF_BYTES);

        let err = verify_deposit_proof(&f.proof, f.block_hash, &f.usdt_contract, &f.account)
            .unwrap_err()
            .to_string();
        assert!(err.contains("oversized"), "unexpected error: {err}");
    }

    #[test]
    fn corrupt_account_proof_node_is_rejected() {
        // Corrupting an interior account-proof node breaks the hash chain from
        // the state root, so verification must fail rather than silently
        // treating it as absence.
        let mut f = load_fixture("funded.json");
        f.proof.account_proof[0][10] ^= 0xff;

        assert!(
            verify_deposit_proof(&f.proof, f.block_hash, &f.usdt_contract, &f.account).is_err()
        );
    }
}
