//! Guardian secret derivation for module config generation.
//!
//! Every guardian derives a config generation root secret with
//! domain-separated children per generation. Private module configs are
//! committed to consensus history encrypted under a per-generation key, so
//! a guardian can recover them from its root secret plus the federation's
//! signed history.
//!
//! PROTOTYPE: the root is currently derived from the guardian's broadcast
//! secret key. The design calls for a dedicated BIP39 guardian mnemonic as
//! the root; swapping the root source only changes [`config_gen_root`].

use fedimint_aead::LessSafeKey;
use fedimint_core::config_gen::ModuleGenerationId;
use fedimint_core::secp256k1::SecretKey;
use fedimint_derive_secret::{ChildId, DerivableSecret};

/// Domain separation children under the config generation root.
const RESULT_ENCRYPTION_CHILD_ID: ChildId = ChildId(0);

/// Derives the guardian's config generation root secret.
pub fn config_gen_root(broadcast_secret_key: &SecretKey) -> DerivableSecret {
    DerivableSecret::new_root(&broadcast_secret_key.secret_bytes(), b"fedimint-config-gen")
}

/// Derives the key encrypting this guardian's private module config of one
/// generation before it is committed to consensus history.
pub fn result_encryption_key(
    root: &DerivableSecret,
    generation_id: ModuleGenerationId,
) -> LessSafeKey {
    LessSafeKey::new(
        root.child_key(RESULT_ENCRYPTION_CHILD_ID)
            .tweak(&generation_id.0.to_le_bytes())
            .to_chacha20_poly1305_key(),
    )
}

#[cfg(test)]
mod tests {
    use fedimint_core::secp256k1::rand::rngs::OsRng;

    use super::*;

    #[test]
    fn result_encryption_roundtrip() {
        let secret_key = SecretKey::new(&mut OsRng);
        let root = config_gen_root(&secret_key);

        let plaintext = b"private module config".to_vec();

        let ciphertext = fedimint_aead::encrypt(
            plaintext.clone(),
            &result_encryption_key(&root, ModuleGenerationId(3)),
        )
        .expect("encryption succeeds");

        let mut ciphertext_copy = ciphertext.clone();
        let decrypted = fedimint_aead::decrypt(
            &mut ciphertext_copy,
            &result_encryption_key(&config_gen_root(&secret_key), ModuleGenerationId(3)),
        )
        .expect("decryption succeeds");

        assert_eq!(decrypted, plaintext);

        // A different generation's key does not decrypt the ciphertext
        let mut ciphertext_copy = ciphertext.clone();
        assert!(
            fedimint_aead::decrypt(
                &mut ciphertext_copy,
                &result_encryption_key(&root, ModuleGenerationId(4)),
            )
            .is_err()
        );
    }
}
