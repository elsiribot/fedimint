//! WASM-safe Ethereum JSON-RPC client for the deposit-by-proof submit flow.
//!
//! The client fetches an [`eth_getProof`](https://eips.ethereum.org/EIPS/eip-1186)
//! of a deposit account's USDT balance plus the block header via
//! `eth_getBlockByNumber`, reconstructs the block [`Header`] from the JSON and
//! RLP-encodes it, and asserts `keccak256(header_rlp) == blockHash` locally so
//! a bad reconstruction fails fast client-side (before the guardians ever see
//! the input). The resulting [`DepositProof`] is verified deterministically by
//! the server (`fedimint_usdt_server::proof::verify_deposit_proof`) against the
//! federation's own consensus block-hash ring anchor -- the RPC endpoint is
//! never trusted for anything but the raw bytes it returns.
//!
//! WASM-safety: the transport is [`reqwest`], which on `wasm32` compiles
//! against the browser Fetch API (the same path `fedimint-client-module` uses).
//! The header math is pure `alloy-consensus`/`alloy-rlp`/`alloy-primitives`
//! (keccak/RLP only) -- no `alloy-trie` (proof verification is server-side
//! only), no `alloy-provider`, no tokio.

use alloy_consensus::Header;
use alloy_primitives::{B256, U256, hex, keccak256};
use alloy_rlp::Encodable as _;
use anyhow::{Context as _, bail, ensure};
use fedimint_usdt_common::{
    DepositProof, EvmAddress, MAX_DEPOSIT_PROOF_BYTES, UsdtAmount, balances_storage_key,
};
use serde_json::{Value, json};
use tracing::debug;

/// Default free, no-API-key public Ethereum JSON-RPC endpoints the
/// deposit-by-proof flow targets when the caller supplies neither an explicit
/// `--evm-rpc-url` nor a client-DB override. Tried in order (first success
/// wins), so a single endpoint being down or rate-limiting degrades to the
/// next rather than failing the whole submit.
pub const DEFAULT_EVM_RPC_URLS: &[&str] = &[
    "https://ethereum-rpc.publicnode.com",
    "https://eth.llamarpc.com",
    "https://rpc.ankr.com/eth",
];

/// A minimal WASM-safe JSON-RPC client over a fixed, ordered list of endpoint
/// URLs (see [`DEFAULT_EVM_RPC_URLS`]).
pub struct EthJsonRpc {
    client: reqwest::Client,
    urls: Vec<String>,
}

impl EthJsonRpc {
    /// Builds a client over `urls` (tried in order). Errors if `urls` is empty
    /// or a `reqwest::Client` cannot be constructed.
    pub fn new(urls: Vec<String>) -> anyhow::Result<Self> {
        ensure!(!urls.is_empty(), "no EVM RPC URL configured");
        let client = reqwest::Client::builder()
            .build()
            .context("building the EVM JSON-RPC HTTP client")?;
        Ok(Self { client, urls })
    }

    /// Issues a single JSON-RPC `method(params)` call, falling back across
    /// [`Self::urls`] in order until one returns a non-error result. Returns
    /// the raw `result` value.
    async fn call(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let mut last_err: Option<anyhow::Error> = None;
        for url in &self.urls {
            match self.call_one(url, &body).await {
                Ok(result) => return Ok(result),
                Err(err) => {
                    debug!(
                        target: "usdt",
                        %url,
                        method,
                        err = %err,
                        "EVM JSON-RPC endpoint failed, trying next"
                    );
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no EVM RPC URL configured")))
            .with_context(|| format!("all EVM RPC endpoints failed for {method}"))
    }

    /// One JSON-RPC round-trip against a single `url`.
    async fn call_one(&self, url: &str, body: &Value) -> anyhow::Result<Value> {
        let response = self
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .context("sending JSON-RPC request")?;

        ensure!(
            response.status().is_success(),
            "JSON-RPC HTTP status {}",
            response.status()
        );

        let mut value: Value = response.json().await.context("parsing JSON-RPC response")?;

        if let Some(error) = value.get("error")
            && !error.is_null()
        {
            bail!("JSON-RPC error: {error}");
        }

        Ok(value.get_mut("result").map_or(Value::Null, Value::take))
    }

    /// Fetches an `eth_getProof` of `account`'s USDT balance in `usdt_contract`
    /// plus the `block_number` header, and assembles a [`DepositProof`] the
    /// server can verify.
    ///
    /// Reconstructs the block [`Header`] from the `eth_getBlockByNumber` JSON
    /// and RLP-encodes it, asserting `keccak256(header_rlp) == blockHash`
    /// locally BEFORE returning so a bad reconstruction (e.g. a hardfork field
    /// this build does not model) fails fast client-side rather than as an
    /// opaque server-side `DepositProofInvalid` after submission.
    ///
    /// Returns the proof plus the proven balance read from the storage proof's
    /// terminal value (used by the caller only to compute the credit delta;
    /// the authoritative balance is what the server independently derives from
    /// the trie).
    pub async fn fetch_deposit_proof(
        &self,
        usdt_contract: EvmAddress,
        account: EvmAddress,
        block_number: u64,
    ) -> anyhow::Result<(DepositProof, UsdtAmount)> {
        let block_tag = format!("0x{block_number:x}");
        let storage_key = balances_storage_key(&account);
        let storage_key_hex = format!("0x{}", hex::encode(storage_key));

        // eth_getProof(contract, [storage_key], block).
        let proof_json = self
            .call(
                "eth_getProof",
                json!([
                    format!("0x{}", hex::encode(usdt_contract.0)),
                    [storage_key_hex],
                    block_tag,
                ]),
            )
            .await?;

        let account_proof = parse_hex_node_array(&proof_json["accountProof"])
            .context("parsing eth_getProof accountProof")?;
        let storage_entry = &proof_json["storageProof"][0];
        let storage_proof = parse_hex_node_array(&storage_entry["proof"])
            .context("parsing eth_getProof storageProof[0].proof")?;
        let proven = parse_u256_hex(&storage_entry["value"])
            .context("parsing eth_getProof storageProof[0].value")?;

        // eth_getBlockByNumber(block, false) -- headers only, no transactions.
        let block_json = self
            .call("eth_getBlockByNumber", json!([block_tag, false]))
            .await?;
        ensure!(
            !block_json.is_null(),
            "block {block_number} not found by eth_getBlockByNumber"
        );

        let block_hash_hex = block_json["hash"]
            .as_str()
            .context("eth_getBlockByNumber response missing `hash`")?;
        let expected_hash = parse_b256(block_hash_hex).context("parsing block hash")?;

        // Reconstruct + RLP-encode the header. `alloy_consensus::Header`'s serde
        // representation is exactly the RPC block-header JSON (camelCase +
        // quantity helpers), and it ignores the extra block fields (`hash`,
        // `transactions`, `size`, ...), so the block object deserializes
        // directly into a `Header`.
        let header: Header = serde_json::from_value(block_json)
            .context("reconstructing block header from eth_getBlockByNumber JSON")?;
        let mut header_rlp = Vec::new();
        header.encode(&mut header_rlp);

        // Fail-fast: a reconstructed header that does not hash to the block's
        // own hash would be rejected server-side (`verify_deposit_proof`'s
        // `keccak256(header_rlp) == expected_block_hash` gate); catch it here
        // where the error names the real cause.
        ensure!(
            keccak256(&header_rlp).0 == expected_hash.0,
            "reconstructed block header does not hash to the reported block hash (unmodelled \
             header field for block {block_number}?)"
        );
        ensure!(
            header.number == block_number,
            "eth_getBlockByNumber returned header for block {} but {block_number} was requested",
            header.number
        );

        let proof = DepositProof {
            block_number,
            header_rlp,
            account_proof,
            storage_proof,
        };
        let encoded_len = proof.encoded_len_bytes();
        ensure!(
            encoded_len <= MAX_DEPOSIT_PROOF_BYTES,
            "deposit proof is oversized ({encoded_len} > {MAX_DEPOSIT_PROOF_BYTES} bytes); the \
             federation would reject it"
        );

        let proven = u64::try_from(proven)
            .map(UsdtAmount)
            .map_err(|_| anyhow::anyhow!("proven USDT balance {proven} overflows u64"))?;

        Ok((proof, proven))
    }
}

/// Parses a JSON array of `0x`-prefixed hex strings (an `eth_getProof`
/// account/storage proof node list) into raw byte vectors.
fn parse_hex_node_array(value: &Value) -> anyhow::Result<Vec<Vec<u8>>> {
    value
        .as_array()
        .context("expected a JSON array of hex-encoded trie nodes")?
        .iter()
        .map(|node| {
            let s = node.as_str().context("trie node was not a JSON string")?;
            let bytes =
                hex::decode(s.strip_prefix("0x").unwrap_or(s)).context("decoding hex trie node")?;
            Ok(bytes)
        })
        .collect()
}

/// Parses a `0x`-prefixed hex quantity into a [`U256`] (an `eth_getProof`
/// storage value is an RLP-free big-endian integer string like `0x1e8480`).
fn parse_u256_hex(value: &Value) -> anyhow::Result<U256> {
    let s = value
        .as_str()
        .context("expected a hex-quantity JSON string")?;
    U256::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
        .context("parsing hex quantity into U256")
}

/// Parses a `0x`-prefixed 32-byte hex string into a [`B256`].
fn parse_b256(s: &str) -> anyhow::Result<B256> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).context("decoding 32-byte hex")?;
    ensure!(bytes.len() == 32, "expected 32 bytes, got {}", bytes.len());
    Ok(B256::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Header;
    use alloy_primitives::{B256, keccak256};
    use alloy_rlp::Encodable as _;
    use serde_json::json;

    use super::{parse_b256, parse_hex_node_array, parse_u256_hex};

    /// The core client-side fail-fast invariant: a `Header` reconstructed from
    /// an `eth_getBlockByNumber`-shaped JSON object (with the extra block
    /// fields the RPC includes) round-trips through serde and RLP-encodes to a
    /// hash equal to the block's reported `hash`. This is exactly the local
    /// `keccak256(header_rlp) == blockHash` assertion `fetch_deposit_proof`
    /// makes before submitting.
    #[test]
    fn header_reconstructs_and_hashes_to_block_hash() {
        // A representative post-Merge header.
        let header = Header {
            number: 21_000_000,
            gas_limit: 30_000_000,
            gas_used: 12_345_678,
            timestamp: 1_700_000_000,
            base_fee_per_gas: Some(7_000_000_000),
            state_root: B256::repeat_byte(0xab),
            ..Default::default()
        };
        let mut header_rlp = Vec::new();
        header.encode(&mut header_rlp);
        let block_hash = keccak256(&header_rlp);

        // Serialize the header to its RPC JSON shape, then splice in the extra
        // block-object fields a real `eth_getBlockByNumber` returns -- proving
        // the reconstruction ignores them (no `deny_unknown_fields`).
        let mut block_json = serde_json::to_value(&header).expect("header serializes");
        let obj = block_json.as_object_mut().expect("header is a JSON object");
        obj.insert("hash".to_string(), json!(format!("0x{}", hex(block_hash))));
        obj.insert("size".to_string(), json!("0x220"));
        obj.insert("totalDifficulty".to_string(), json!("0x0"));
        obj.insert("transactions".to_string(), json!([]));
        obj.insert("uncles".to_string(), json!([]));

        let reconstructed: Header =
            serde_json::from_value(block_json).expect("block JSON deserializes into a Header");
        let mut reconstructed_rlp = Vec::new();
        reconstructed.encode(&mut reconstructed_rlp);

        assert_eq!(
            keccak256(&reconstructed_rlp).0,
            block_hash.0,
            "reconstructed header must hash to the block hash"
        );
    }

    fn hex(bytes: impl AsRef<[u8]>) -> String {
        alloy_primitives::hex::encode(bytes)
    }

    #[test]
    fn parses_hex_node_array() {
        let nodes = parse_hex_node_array(&json!(["0xdeadbeef", "0x01"])).expect("parses");
        assert_eq!(nodes, vec![vec![0xde, 0xad, 0xbe, 0xef], vec![0x01]]);
    }

    #[test]
    fn parses_u256_and_b256() {
        assert_eq!(
            parse_u256_hex(&json!("0x1e8480")).expect("parses"),
            2_000_000
        );
        let h = parse_b256(&format!("0x{}", "11".repeat(32))).expect("parses");
        assert_eq!(h.0, [0x11u8; 32]);
        parse_b256("0x1234").expect_err("a non-32-byte hash must be rejected");
    }
}
