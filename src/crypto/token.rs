//! Opaque tokens for sessions and one-time links (email verification, password
//! reset, OAuth state).
//!
//! A token is 256 bits of CSPRNG entropy. The raw value is only ever sent to the
//! user (cookie, email, URL); what is persisted is its SHA-256 hash, via [`hash`].
//! Because tokens are high-entropy, a fast hash suffices — a store leak yields no
//! usable tokens, and there is nothing to brute-force.

use sha2::{Digest, Sha256};

/// Generate a fresh token: 32 random bytes, hex-encoded (64 chars).
pub fn generate() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable");
    hex::encode(bytes)
}

/// Hash a token for storage and lookup.
pub fn hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_sized() {
        let a = generate();
        let b = generate();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn hash_is_stable_and_not_the_token() {
        let t = generate();
        assert_eq!(hash(&t), hash(&t));
        assert_ne!(hash(&t), t);
    }
}
