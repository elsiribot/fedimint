//! Bearer-token checks that run bcrypt once per token, not once per request.
//!
//! bcrypt at the default cost takes a few hundred milliseconds of CPU. Run on
//! every authenticated request (twice for the liquidity manager, whose token
//! is tried against the admin hash first), a client polling the API can keep
//! a small host's async workers busy enough that LDK's chain sync misses its
//! deadlines.

use std::collections::HashMap;
use std::sync::Mutex;

use bitcoin::hashes::{Hash, sha256};

/// Distinct tokens remembered at once. Only tokens that matched a password are
/// remembered, so this is reached only because bcrypt ignores input past 72
/// bytes and many tokens can match one password.
const MAX_VERIFIED_TOKENS: usize = 16;

/// Which password a token matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    LiquidityManager,
}

pub struct PasswordVerifier {
    admin_hash: String,
    liquidity_manager_hash: Option<String>,
    /// SHA-256 of tokens that passed bcrypt.
    verified: Mutex<HashMap<sha256::Hash, Role>>,
}

impl PasswordVerifier {
    pub fn new(admin_hash: String, liquidity_manager_hash: Option<String>) -> Self {
        Self {
            admin_hash,
            liquidity_manager_hash,
            verified: Mutex::new(HashMap::new()),
        }
    }

    /// The role `token` authenticates as, if any. A token seen before is
    /// answered from memory; a new one is checked with bcrypt on the blocking
    /// pool, so wrong tokens cannot stall the async runtime either.
    pub async fn verify(&self, token: &str) -> Option<Role> {
        let key = sha256::Hash::hash(token.as_bytes());
        if let Some(role) = self.lock().get(&key) {
            return Some(*role);
        }

        let token = token.to_owned();
        let admin_hash = self.admin_hash.clone();
        let liquidity_manager_hash = self.liquidity_manager_hash.clone();
        let role = fedimint_core::runtime::spawn_blocking(move || {
            if bcrypt_matches(&token, &admin_hash) {
                return Some(Role::Admin);
            }
            liquidity_manager_hash
                .filter(|hash| bcrypt_matches(&token, hash))
                .map(|_| Role::LiquidityManager)
        })
        .await?;

        let mut verified = self.lock();
        if verified.len() >= MAX_VERIFIED_TOKENS {
            verified.clear();
        }
        verified.insert(key, role);
        Some(role)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<sha256::Hash, Role>> {
        // The map only caches bcrypt results; one left by a panicking
        // holder is still correct.
        self.verified
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn bcrypt_matches(token: &str, hash: &str) -> bool {
    bcrypt::verify(token, hash).expect("Bcrypt hash is valid since we just stringified it")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verifier() -> PasswordVerifier {
        PasswordVerifier::new(
            bcrypt::hash("admin", 4).expect("hashes"),
            Some(bcrypt::hash("lm", 4).expect("hashes")),
        )
    }

    #[tokio::test]
    async fn tokens_map_to_their_role() {
        let verifier = verifier();
        assert_eq!(verifier.verify("admin").await, Some(Role::Admin));
        assert_eq!(verifier.verify("lm").await, Some(Role::LiquidityManager));
        assert_eq!(verifier.verify("wrong").await, None);
    }

    #[tokio::test]
    async fn only_matching_tokens_are_remembered() {
        let verifier = verifier();
        verifier.verify("admin").await;
        verifier.verify("wrong").await;
        let verified = verifier.lock();
        assert_eq!(verified.len(), 1);
        assert_eq!(
            verified.get(&sha256::Hash::hash(b"admin")),
            Some(&Role::Admin)
        );
    }

    #[tokio::test]
    async fn a_remembered_token_skips_bcrypt() {
        // A hash no token can match: only the cache can answer.
        let verifier = PasswordVerifier::new(bcrypt::hash("other", 4).expect("hashes"), None);
        verifier
            .lock()
            .insert(sha256::Hash::hash(b"admin"), Role::Admin);
        assert_eq!(verifier.verify("admin").await, Some(Role::Admin));
    }

    #[tokio::test]
    async fn the_cache_stays_bounded() {
        // bcrypt only reads the first 72 bytes, so all of these match.
        let base = "admin".to_owned() + &"x".repeat(80);
        let tokens: Vec<String> = (0..=MAX_VERIFIED_TOKENS)
            .map(|i| format!("{base}{i}"))
            .collect();
        let verifier = PasswordVerifier::new(bcrypt::hash(&tokens[0], 4).expect("hashes"), None);
        for token in &tokens {
            assert_eq!(verifier.verify(token).await, Some(Role::Admin));
        }
        assert!(verifier.lock().len() <= MAX_VERIFIED_TOKENS);
    }
}
