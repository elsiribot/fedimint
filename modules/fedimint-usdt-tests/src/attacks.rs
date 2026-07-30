//! Adversarial deposit-by-proof attack constructors, shared by the hermetic
//! security integration tests (`tests/adversary.rs`) and the live-federation
//! security binary (`bin/usdt_adversary.rs`).
//!
//! Each `attack_*` function returns an [`Attack`]: a hand-crafted malicious
//! [`UsdtInput`] a submitter constructs to try to mint/steal value it does not
//! hold, plus the value it DECLARES, the expected rejection class, and (for the
//! hermetic driver only) a block-hash the mock must anchor before submission.
//! The submission itself is driven by
//! `UsdtClientModule::submit_crafted_input_for_test` (client `test-util`
//! feature), which bypasses every honest builder and its client-side gates.
//!
//! Attack -> matrix mapping (see `.superpowers/sdd/adversary-spec.md`):
//! - [`attack_forged_balance`]  #2 forged balance
//! - [`attack_wrong_account`]   #3 wrong account (prove A, claim as B)
//! - [`attack_unanchored`]      #4 block not in the guardians' ring
//! - [`attack_forged_header`]   #5 tampered header (anchor mismatch)
//! - [`attack_oversize`]        #8 proof exceeds `MAX_DEPOSIT_PROOF_BYTES`
//! - [`attack_over_mint_v0`]    #7 re-mint an already-minted delta via legacy
//!   V0
//! - [`attack_replay`]          #6 resubmit an already-credited proof
//! - [`attack_stale_growth`]    #9 prove an older, smaller balance

use alloy_consensus::Header;
use alloy_primitives::{B256, U256, keccak256};
use alloy_rlp::Encodable as _;
use alloy_trie::nodes::LeafNode;
use alloy_trie::{Nibbles, TrieAccount};
use fedimint_core::secp256k1::PublicKey;
use fedimint_usdt_common::{
    DepositProof, EvmAddress, MAX_DEPOSIT_PROOF_BYTES, UsdtAmount, UsdtInput, UsdtInputV0,
    balances_storage_key,
};

/// The rejection outcome an [`Attack`] is expected to produce. Each variant's
/// [`ExpectedRejection::matches`] recognizes the corresponding
/// [`fedimint_usdt_common::UsdtInputError`] by a stable fragment of its
/// `Display` (the reason string the federation returns for a rejected
/// transaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedRejection {
    /// `DepositProofNotAnchored`: the proof's block is not in the ring.
    NotAnchored,
    /// `DepositProofInvalid`: verification failed (anchor/header mismatch,
    /// tampering, or oversize).
    Invalid,
    /// `DepositProofStale`: the proof proves nothing new over `credited`
    /// (proof-of-absence for a wrong account => proven 0, or an older/smaller
    /// balance => delta 0).
    Stale,
    /// `InsufficientCredit`: a legacy `V0` claim for value already minted.
    InsufficientCredit,
}

impl ExpectedRejection {
    /// Whether `reason` (a federation transaction-rejection string) is the
    /// rejection this attack expected. Matched on stable `Display` fragments of
    /// [`fedimint_usdt_common::UsdtInputError`] so it is robust to any wrapping
    /// prefix the submission layer adds.
    #[must_use]
    pub fn matches(self, reason: &str) -> bool {
        let fragment = match self {
            ExpectedRejection::NotAnchored => "is not anchored in the federation's block-hash ring",
            ExpectedRejection::Invalid => "deposit proof verification failed",
            ExpectedRejection::Stale => "is already credited for this account",
            ExpectedRejection::InsufficientCredit => "still claimable for this account",
        };
        reason.contains(fragment)
    }

    /// A short human label for the pass/fail report.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ExpectedRejection::NotAnchored => "DepositProofNotAnchored",
            ExpectedRejection::Invalid => "DepositProofInvalid",
            ExpectedRejection::Stale => "DepositProofStale",
            ExpectedRejection::InsufficientCredit => "InsufficientCredit",
        }
    }
}

/// A single hand-crafted adversarial submission and its expected rejection.
pub struct Attack {
    /// Short attack name (matrix item), for the report.
    pub name: &'static str,
    /// What the attack tries to do and why it must fail.
    pub description: &'static str,
    /// The malicious input to submit (its embedded `claim_pk`, for
    /// `DepositProofV0`, dictates which claim keypair must sign it).
    pub input: UsdtInput,
    /// The value the attacker declares (the `ClientInput.amounts`/delta it
    /// funds into the transaction, paired 1:1 with a mint output). Chosen
    /// so a genuine breach would actually mint value (the transaction
    /// balances), making a breach observable rather than silently
    /// unbalancing.
    pub declared: UsdtAmount,
    /// HERMETIC DRIVER ONLY: if `Some((block, hash))`, script the mock EVM's
    /// block-hash for `block` to `hash` and wait for the ring to re-anchor it
    /// before submitting (so the crafted proof is evaluated against a KNOWN
    /// anchor). `None` => submit against whatever the ring already anchors.
    /// The live driver cannot script guardian consensus and ignores this.
    pub hermetic_anchor: Option<(u64, [u8; 32])>,
    /// The rejection the defense must produce.
    pub expected: ExpectedRejection,
}

/// Builds a synthetic single-leaf MPT deposit proof the real
/// `fedimint_usdt_server::proof::verify_deposit_proof` accepts, wholly offline
/// (a direct port of the server's own `synthetic_deposit_proof` test builder /
/// `tests/common/proof.rs`). Returns the proof and the canonical block hash its
/// header commits to (what the ring must anchor for the proof to verify).
#[must_use]
pub fn synthetic_deposit_proof(
    usdt_contract: EvmAddress,
    account: EvmAddress,
    balance: u64,
    block_number: u64,
) -> (DepositProof, [u8; 32]) {
    // Storage trie: one leaf at keccak(balances_storage_key(account)).
    let storage_key = Nibbles::unpack(keccak256(balances_storage_key(&account)));
    let mut storage_value = Vec::new();
    U256::from(balance).encode(&mut storage_value);
    let mut storage_leaf_rlp = Vec::new();
    LeafNode::new(storage_key, storage_value).encode(&mut storage_leaf_rlp);
    let storage_root = B256::from(keccak256(&storage_leaf_rlp));

    // Account trie: one leaf at keccak(usdt_contract).
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

    // Header committing to that state root; its keccak is the block hash.
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

/// #2 FORGED BALANCE: a proof claiming a `forged` on-chain balance the account
/// does not hold. Its header commits to the forged state root, so its hash is
/// NOT what the ring anchors for `block` -> anchor mismatch ->
/// `DepositProofInvalid`. (Anchoring the forged hash instead would require the
/// guardians to already agree the forged balance is canonical, which they never
/// do.)
#[must_use]
pub fn attack_forged_balance(
    usdt_contract: EvmAddress,
    claim_pk: PublicKey,
    account: EvmAddress,
    block: u64,
    forged: UsdtAmount,
) -> Attack {
    let (proof, _forged_hash) = synthetic_deposit_proof(usdt_contract, account, forged.0, block);
    Attack {
        name: "forged-balance",
        description: "proof claims a larger on-chain balance than the anchored state root commits \
                      to (anchor mismatch)",
        input: UsdtInput::DepositProofV0 { claim_pk, proof },
        declared: forged,
        // Rely on `block` being anchored to its genuine hash (!= the forged
        // hash) -> verification fails at the block-hash check.
        hermetic_anchor: None,
        expected: ExpectedRejection::Invalid,
    }
}

/// #3 WRONG ACCOUNT: a genuine, verifiable proof of account `other_account`'s
/// balance, submitted with `claim_pk` for a DIFFERENT account. The server
/// verifies against the DERIVED account's storage key (not `other_account`'s),
/// reads proof-of-absence -> proven 0 -> `DepositProofStale`. No
/// prove-A-credit-B.
///
/// Requires the ring to anchor the proof's own hash (so it verifies and reaches
/// the wrong-storage-key path), hence `hermetic_anchor` is set. On a live fed
/// (which cannot be scripted) this instead fails as an anchor mismatch, still a
/// rejection.
#[must_use]
pub fn attack_wrong_account(
    usdt_contract: EvmAddress,
    claim_pk: PublicKey,
    other_account: EvmAddress,
    block: u64,
    balance: UsdtAmount,
) -> Attack {
    let (proof, hash) = synthetic_deposit_proof(usdt_contract, other_account, balance.0, block);
    Attack {
        name: "wrong-account",
        description: "genuine proof of account A's balance submitted with claim_pk for account B",
        input: UsdtInput::DepositProofV0 { claim_pk, proof },
        declared: balance,
        hermetic_anchor: Some((block, hash)),
        expected: ExpectedRejection::Stale,
    }
}

/// #4 UNANCHORED BLOCK: a proof against a block the guardians have not anchored
/// in their ring (e.g. a far-future / fabricated height) ->
/// `DepositProofNotAnchored`.
#[must_use]
pub fn attack_unanchored(
    usdt_contract: EvmAddress,
    claim_pk: PublicKey,
    account: EvmAddress,
    unanchored_block: u64,
    balance: UsdtAmount,
) -> Attack {
    let (proof, _hash) =
        synthetic_deposit_proof(usdt_contract, account, balance.0, unanchored_block);
    Attack {
        name: "unanchored-block",
        description: "proof targets a block that is not in the guardians' block-hash ring",
        input: UsdtInput::DepositProofV0 { claim_pk, proof },
        declared: balance,
        hermetic_anchor: None,
        expected: ExpectedRejection::NotAnchored,
    }
}

/// #5 FORGED HEADER: a proof whose `header_rlp` has been tampered so
/// `keccak(header) != agreed ring hash` -> `DepositProofInvalid` (anchor
/// mismatch). The ring anchors the ORIGINAL (untampered) hash, so the failure
/// is specifically the header check (not a stale/absence delta).
#[must_use]
pub fn attack_forged_header(
    usdt_contract: EvmAddress,
    claim_pk: PublicKey,
    account: EvmAddress,
    block: u64,
    balance: UsdtAmount,
) -> Attack {
    let (mut proof, hash) = synthetic_deposit_proof(usdt_contract, account, balance.0, block);
    // Flip a byte deep inside the header: keccak(header_rlp) != anchored hash.
    let mid = proof.header_rlp.len() / 2;
    proof.header_rlp[mid] ^= 0xff;
    Attack {
        name: "forged-header",
        description: "header_rlp tampered so keccak(header) != the anchored ring hash",
        input: UsdtInput::DepositProofV0 { claim_pk, proof },
        declared: balance,
        // Anchor the ORIGINAL hash so the tampered header specifically fails the
        // block-hash check.
        hermetic_anchor: Some((block, hash)),
        expected: ExpectedRejection::Invalid,
    }
}

/// #8 OVERSIZE: a proof exceeding [`MAX_DEPOSIT_PROOF_BYTES`] -> rejected by the
/// size cap at the top of verification (`DepositProofInvalid`, reason
/// "oversized"). `block` must be anchored (the anchor lookup precedes
/// verification), so callers pass an anchored block.
#[must_use]
pub fn attack_oversize(
    usdt_contract: EvmAddress,
    claim_pk: PublicKey,
    account: EvmAddress,
    block: u64,
    balance: UsdtAmount,
) -> Attack {
    let (mut proof, _hash) = synthetic_deposit_proof(usdt_contract, account, balance.0, block);
    // Push the encoded size past the cap with a junk trie node.
    proof
        .storage_proof
        .push(vec![0u8; MAX_DEPOSIT_PROOF_BYTES + 1]);
    debug_assert!(proof.encoded_len_bytes() > MAX_DEPOSIT_PROOF_BYTES);
    Attack {
        name: "oversize",
        description: "proof exceeds MAX_DEPOSIT_PROOF_BYTES (rejected before verification)",
        input: UsdtInput::DepositProofV0 { claim_pk, proof },
        declared: balance,
        hermetic_anchor: None,
        expected: ExpectedRejection::Invalid,
    }
}

/// #7 OVER-MINT: after a deposit is credited AND minted via `DepositProofV0`
/// (which advances `claimed` alongside `credited`), a legacy `V0` claim for the
/// same account tries to re-mint the already-minted value. `available =
/// credited - claimed == 0`, so any nonzero `amount` is rejected as
/// `InsufficientCredit`. The `V0` input must be signed by the account's claim
/// keypair (its `pub_key` is `record.claim_pk`).
#[must_use]
pub fn attack_over_mint_v0(account: EvmAddress, amount: UsdtAmount) -> Attack {
    Attack {
        name: "over-mint-v0",
        description: "legacy V0 claim tries to re-mint value a DepositProofV0 already minted",
        input: UsdtInput::V0(UsdtInputV0 {
            account,
            amount,
            fee: UsdtAmount(0),
        }),
        declared: amount,
        hermetic_anchor: None,
        expected: ExpectedRejection::InsufficientCredit,
    }
}

/// #6 REPLAY: resubmit a valid, already-credited proof verbatim. `credited`
/// already equals `proven`, so the delta is 0 -> `DepositProofStale`. Pass the
/// exact `(proof, hash)` a prior honest credit anchored, so the resubmission
/// verifies (against the still-anchored hash) and is rejected on the delta, not
/// the anchor.
#[must_use]
pub fn attack_replay(claim_pk: PublicKey, proof: DepositProof, credited: UsdtAmount) -> Attack {
    Attack {
        name: "replay",
        description: "resubmit an already-credited proof (delta 0)",
        input: UsdtInput::DepositProofV0 { claim_pk, proof },
        // A replay proves the same balance; the attacker declares it hoping to
        // double-credit. The server's delta is 0, so a breach would mint this.
        declared: credited,
        hermetic_anchor: None,
        expected: ExpectedRejection::Stale,
    }
}

/// #9 STALE-GROWTH: after crediting balance X at a newer block, prove an OLDER
/// block where the balance was smaller. The high-water `credited` (X) already
/// dominates the older proven balance, so the delta saturates to 0 ->
/// `DepositProofStale`; no re-credit. The older proof's own hash is set as the
/// hermetic anchor so it verifies (and is rejected on the delta, not the
/// anchor).
#[must_use]
pub fn attack_stale_growth(
    usdt_contract: EvmAddress,
    claim_pk: PublicKey,
    account: EvmAddress,
    older_block: u64,
    smaller_balance: UsdtAmount,
) -> Attack {
    let (proof, hash) =
        synthetic_deposit_proof(usdt_contract, account, smaller_balance.0, older_block);
    Attack {
        name: "stale-growth",
        description: "prove an older block with a smaller balance than the current high-water",
        input: UsdtInput::DepositProofV0 { claim_pk, proof },
        // A high-water/monotonicity bug that re-credited the older proof would
        // mint exactly the (smaller) balance it proves.
        declared: smaller_balance,
        hermetic_anchor: Some((older_block, hash)),
        expected: ExpectedRejection::Stale,
    }
}
