use std::fmt;

use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex as _;
use fedimint_core::core::{DynInput, DynOutput};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::SerdeModuleEncoding;
use fedimint_core::{Amount, TransactionId};
use thiserror::Error;

use crate::config::ALEPH_BFT_UNIT_BYTE_LIMIT;
use crate::core::{DynInputError, DynOutputError};

/// An atomic value transfer operation within the Fedimint system and consensus
///
/// The mint enforces that the total value of the outputs equals the total value
/// of the inputs, to prevent creating funds out of thin air. In some cases, the
/// value of the inputs and outputs can both be 0 e.g. when creating an offer to
/// a Lightning Gateway.
#[derive(Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct Transaction {
    /// [`DynInput`]s consumed by the transaction
    pub inputs: Vec<DynInput>,
    /// [`DynOutput`]s created as a result of the transaction
    pub outputs: Vec<DynOutput>,
    /// No defined meaning, can be used to send the otherwise exactly same
    /// transaction multiple times if the module inputs and outputs don't
    /// introduce enough entropy.
    ///
    /// In the future the nonce can be used for grinding a tx hash that fulfills
    /// certain PoW requirements.
    pub nonce: [u8; 8],
    /// signatures for all the public keys of the inputs
    pub signatures: TransactionSignature,
}

impl fmt::Debug for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("txid", &self.tx_hash())
            .field("inputs", &self.inputs)
            .field("outputs", &self.outputs)
            .field("nonce", &self.nonce)
            .field("signatures", &self.signatures)
            .finish()
    }
}

pub type SerdeTransaction = SerdeModuleEncoding<Transaction>;

impl Transaction {
    /// Maximum size that a transaction can have while still fitting into an
    /// AlephBFT unit. Subtracting 32 bytes is overly conservative, even in the
    /// worst case the CI serialization around the transaction should never add
    /// that much overhead. But since the byte limit is 50kb right now a few
    /// bytes more or less won't make a difference and we can afford the safety
    /// margin.
    ///
    /// A realistic value would be 7:
    ///  * 1 byte for length of vector of CIs
    ///  * 1 byte for the CI enum variant
    ///  * 5 byte for the CI enum variant length
    pub const MAX_TX_SIZE: usize = ALEPH_BFT_UNIT_BYTE_LIMIT - 32;

    /// Hash of the transaction (excluding the signature).
    ///
    /// Transaction signature commits to this hash.
    /// To generate it without already having a signature use
    /// [`Self::tx_hash_from_parts`].
    pub fn tx_hash(&self) -> TransactionId {
        Self::tx_hash_from_parts(&self.inputs, &self.outputs, self.nonce)
    }

    /// Generate the transaction hash.
    pub fn tx_hash_from_parts(
        inputs: &[DynInput],
        outputs: &[DynOutput],
        nonce: [u8; 8],
    ) -> TransactionId {
        let mut engine = TransactionId::engine();
        inputs
            .consensus_encode(&mut engine)
            .expect("write to hash engine can't fail");
        outputs
            .consensus_encode(&mut engine)
            .expect("write to hash engine can't fail");
        nonce
            .consensus_encode(&mut engine)
            .expect("write to hash engine can't fail");
        TransactionId::from_engine(engine)
    }

    /// Validate the schnorr signatures signed over the `tx_hash`
    pub fn validate_signatures(
        &self,
        pub_keys: &[secp256k1::PublicKey],
    ) -> Result<(), TransactionError> {
        let signatures = match &self.signatures {
            TransactionSignature::NaiveMultisig(sigs) => sigs,
            // Not produced anywhere yet (see `Self::input_witnesses`); later tasks
            // teach the caller of `validate_signatures` to go through
            // `input_witnesses`/`verify_key_witness` instead, which understand it.
            TransactionSignature::Witnessed(_) => {
                return Err(TransactionError::UnsupportedSignatureScheme { variant: 1 });
            }
            TransactionSignature::Default { variant, .. } => {
                return Err(TransactionError::UnsupportedSignatureScheme { variant: *variant });
            }
        };

        if pub_keys.len() != signatures.len() {
            return Err(TransactionError::InvalidWitnessLength);
        }

        let txid = self.tx_hash();
        let msg = secp256k1::Message::from_digest_slice(&txid[..]).expect("txid has right length");

        for (pk, signature) in pub_keys.iter().zip(signatures) {
            if secp256k1::global::SECP256K1
                .verify_schnorr(signature, &msg, &pk.x_only_public_key().0)
                .is_err()
            {
                return Err(TransactionError::InvalidSignature {
                    tx: self.consensus_encode_to_hex(),
                    hash: self.tx_hash().consensus_encode_to_hex(),
                    sig: signature.consensus_encode_to_hex(),
                    key: pk.consensus_encode_to_hex(),
                });
            }
        }

        Ok(())
    }

    /// One witness per input, whichever encoding this transaction uses.
    ///
    /// Errors if the count does not match the input count, which is the check
    /// [`Self::validate_signatures`] used to perform against the collected
    /// public keys.
    pub fn input_witnesses(&self) -> Result<Vec<&[u8]>, TransactionError> {
        match &self.signatures {
            TransactionSignature::NaiveMultisig(sigs) => {
                if sigs.len() != self.inputs.len() {
                    return Err(TransactionError::InvalidWitnessLength);
                }
                Ok(sigs.iter().map(|sig| sig.as_ref() as &[u8]).collect())
            }
            TransactionSignature::Witnessed(witnesses) => {
                if witnesses.len() != self.inputs.len() {
                    return Err(TransactionError::InvalidWitnessLength);
                }
                Ok(witnesses.iter().map(Vec::as_slice).collect())
            }
            TransactionSignature::Default { variant, .. } => {
                Err(TransactionError::UnsupportedSignatureScheme { variant: *variant })
            }
        }
    }

    /// Verify a witness belonging to an `InputAuth::Key` input: exactly one
    /// 64-byte schnorr signature over the txid.
    pub fn verify_key_witness(
        witness: &[u8],
        msg: &secp256k1::Message,
        pub_key: &secp256k1::PublicKey,
    ) -> Result<(), TransactionError> {
        let sig = secp256k1::schnorr::Signature::from_slice(witness)
            .map_err(|_| TransactionError::InvalidWitnessLength)?;

        secp256k1::global::SECP256K1
            .verify_schnorr(&sig, msg, &pub_key.x_only_public_key().0)
            .map_err(|_| TransactionError::InvalidSignature {
                tx: String::new(),
                hash: msg.as_ref().to_lower_hex_string(),
                sig: sig.consensus_encode_to_hex(),
                key: pub_key.consensus_encode_to_hex(),
            })
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub enum TransactionSignature {
    NaiveMultisig(Vec<fedimint_core::secp256k1::schnorr::Signature>),
    /// One opaque witness per input, positionally aligned with
    /// [`Transaction::inputs`].
    ///
    /// For an input whose module returns `InputAuth::Key`, the witness is
    /// exactly the 64 bytes of its schnorr signature over the txid. For an
    /// input whose module returns `InputAuth::SelfVerified`, the bytes mean
    /// whatever that module decides they mean.
    Witnessed(Vec<Vec<u8>>),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl fmt::Debug for TransactionSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NaiveMultisig(multi) => {
                f.debug_struct("NaiveMultisig")
                    .field("len", &multi.len())
                    .finish()?;
            }
            Self::Witnessed(witnesses) => {
                f.debug_struct("Witnessed")
                    .field("len", &witnesses.len())
                    .finish()?;
            }
            Self::Default { variant, bytes } => {
                f.debug_struct(stringify!($name))
                    .field("variant", variant)
                    .field("bytes", &bytes.as_hex())
                    .finish()?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error, Encodable, Decodable, Clone, Eq, PartialEq)]
pub enum TransactionError {
    /// Transaction was not balanced
    ///
    /// Note: since this type existed before multi-unit amounts were implemented
    /// and can't change shape, the unit of the imbalance is not specified.
    #[error("The transaction is unbalanced (in={inputs}, out={outputs}, fee={fee})")]
    UnbalancedTransaction {
        inputs: Amount,
        outputs: Amount,
        fee: Amount,
    },
    #[error("The transaction's signature is invalid: tx={tx}, hash={hash}, sig={sig}, key={key}")]
    InvalidSignature {
        tx: String,
        hash: String,
        sig: String,
        key: String,
    },
    #[error("The transaction's signature scheme is not supported: variant={variant}")]
    UnsupportedSignatureScheme { variant: u64 },
    #[error("The transaction did not have the correct number of signatures")]
    InvalidWitnessLength,
    #[error("The transaction had an invalid input: {}", .0)]
    Input(DynInputError),
    #[error("The transaction had an invalid output: {}", .0)]
    Output(DynOutputError),
}

/// The transaction caused an overflow.
///
/// We can't add a new variant to transaction errors, so we define a special
/// case for the retroactively added overflow error type. In a second iteration
/// of the transaction submission API this should become a separate error
/// variant.
pub const TRANSACTION_OVERFLOW_ERROR: TransactionError = TransactionError::UnbalancedTransaction {
    inputs: Amount::ZERO,
    outputs: Amount::ZERO,
    fee: Amount::ZERO,
};

#[derive(Debug, Encodable, Decodable, Clone, Eq, PartialEq)]
pub struct TransactionSubmissionOutcome(pub Result<TransactionId, TransactionError>);

#[cfg(test)]
mod tests {
    use fedimint_core::secp256k1::rand::rngs::OsRng;
    use secp256k1::{Keypair, Message, Secp256k1};

    use super::*;

    fn dummy_msg() -> Message {
        Message::from_digest([7u8; 32])
    }

    #[test]
    fn key_witness_roundtrips() {
        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut OsRng);
        let sig = secp.sign_schnorr(&dummy_msg(), &kp);

        Transaction::verify_key_witness(sig.as_ref(), &dummy_msg(), &kp.public_key())
            .expect("a fresh signature over this message must verify");
    }

    #[test]
    fn key_witness_rejects_wrong_message() {
        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut OsRng);
        let sig = secp.sign_schnorr(&dummy_msg(), &kp);

        let other = Message::from_digest([9u8; 32]);
        assert!(matches!(
            Transaction::verify_key_witness(sig.as_ref(), &other, &kp.public_key()),
            Err(TransactionError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn key_witness_rejects_wrong_length() {
        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut OsRng);

        assert!(matches!(
            Transaction::verify_key_witness(&[0u8; 63], &dummy_msg(), &kp.public_key()),
            Err(TransactionError::InvalidWitnessLength)
        ));
    }

    #[test]
    fn input_auth_key_carries_its_key() {
        use fedimint_core::module::InputAuth;

        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut OsRng);

        let auth = InputAuth::Key(kp.public_key());
        match auth {
            InputAuth::Key(pk) => assert_eq!(pk, kp.public_key()),
            InputAuth::SelfVerified => panic!("expected Key"),
        }
    }

    #[test]
    fn auth_ctx_message_is_derived_from_the_txid() {
        use fedimint_core::module::InputAuthCtx;

        let txid = TransactionId::from_byte_array([3u8; 32]);
        let ctx = InputAuthCtx::new(txid, 0, &[]);

        assert_eq!(ctx.txid_message(), Message::from_digest([3u8; 32]));
        assert_eq!(ctx.in_idx(), 0);
        assert!(ctx.witness().is_empty());
    }

    #[test]
    fn auth_ctx_verify_schnorr_binds_to_the_txid() {
        use fedimint_core::module::InputAuthCtx;

        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut OsRng);

        let txid = TransactionId::from_byte_array([3u8; 32]);
        let other = TransactionId::from_byte_array([4u8; 32]);

        let ctx = InputAuthCtx::new(txid, 0, &[]);
        let sig = secp.sign_schnorr(&ctx.txid_message(), &kp);

        assert!(ctx.verify_schnorr(&kp.public_key(), &sig));

        let wrong = InputAuthCtx::new(other, 0, &[]);
        assert!(
            !wrong.verify_schnorr(&kp.public_key(), &sig),
            "a signature over a different txid must not verify"
        );
    }
}
