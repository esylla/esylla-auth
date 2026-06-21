//! Argon2id password hashing.
//!
//! Parameters follow the OWASP Password Storage Cheat Sheet: Argon2id with
//! m = 19 MiB, t = 2, p = 1. Verification reads parameters from the stored hash,
//! so existing hashes stay valid if these defaults are tuned later.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::AuthError;

/// Upper bound on the password byte length, bounding Argon2 cost as a DoS guard.
/// Minimum/maximum policy belongs in the validation layer.
pub const MAX_PASSWORD_BYTES: usize = 4096;

fn hasher() -> Argon2<'static> {
    let params = Params::new(19 * 1024, 2, 1, None).expect("valid Argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hash a password into a PHC string (algorithm, parameters, salt, and digest).
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AuthError::PasswordTooLong);
    }
    let mut salt_bytes = [0u8; 16];
    getrandom::fill(&mut salt_bytes).map_err(|_| AuthError::Hashing)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| AuthError::Hashing)?;
    hasher()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AuthError::Hashing)
}

/// Verify a password against a stored PHC hash. Returns
/// [`AuthError::InvalidCredentials`] on mismatch without revealing which factor failed.
pub fn verify_password(password: &str, phc_hash: &str) -> Result<(), AuthError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AuthError::InvalidCredentials);
    }
    let parsed = PasswordHash::new(phc_hash).map_err(|_| AuthError::Hashing)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| AuthError::InvalidCredentials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_roundtrips() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        verify_password("correct horse battery staple", &hash).unwrap();
        assert!(verify_password("wrong", &hash).is_err());
    }

    #[test]
    fn rejects_overlong_password() {
        let long = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(matches!(
            hash_password(&long),
            Err(AuthError::PasswordTooLong)
        ));
    }
}
