//! Stateless JWT sessions (`jwt` feature). The token is HS256-signed and carries
//! the user id and expiry; nothing is stored server-side.
//!
//! Trade-off: because there is no server-side record, [`revoke`](JwtSessions) and
//! `revoke_user` cannot take effect immediately — a token stays valid until it
//! expires. Use a short TTL, or the default
//! [`OpaqueSessions`](crate::session::OpaqueSessions) when instant logout and
//! password-change invalidation are required.

use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AuthError;
use crate::session::SessionStrategy;

/// Bind tokens to this issuer/audience so a token signed with the same secret for
/// some other purpose is not accepted as a session.
const ISSUER: &str = "esylla-auth";
const AUDIENCE: &str = "esylla-auth:session";

/// Minimum HS256 secret length (OWASP: the key must be at least the hash size).
const MIN_SECRET_BYTES: usize = 32;

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: usize,
    iat: usize,
}

pub struct JwtSessions {
    encoding: EncodingKey,
    decoding: DecodingKey,
    ttl: Duration,
}

impl JwtSessions {
    /// HS256-signed sessions using a shared secret.
    ///
    /// # Panics
    /// Panics if `secret` is shorter than 32 bytes (256 bits); an HS256 key must be
    /// high-entropy and at least the hash length, so a short secret is a
    /// misconfiguration that should fail at startup.
    pub fn new(secret: &[u8], ttl: Duration) -> Self {
        assert!(
            secret.len() >= MIN_SECRET_BYTES,
            "JWT secret must be at least {MIN_SECRET_BYTES} bytes (256 bits) of high-entropy random data"
        );
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
            ttl,
        }
    }
}

#[async_trait]
impl SessionStrategy for JwtSessions {
    async fn issue(&self, user_id: Uuid) -> Result<String, AuthError> {
        let now = Utc::now();
        let ttl =
            chrono::Duration::from_std(self.ttl).unwrap_or_else(|_| chrono::Duration::hours(1));
        let claims = Claims {
            sub: user_id.to_string(),
            iss: ISSUER.to_owned(),
            aud: AUDIENCE.to_owned(),
            exp: (now + ttl).timestamp() as usize,
            iat: now.timestamp() as usize,
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding)
            .map_err(|_| AuthError::Session)
    }

    async fn resolve(&self, token: &str) -> Result<Option<Uuid>, AuthError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[AUDIENCE]);
        let Ok(data) = decode::<Claims>(token, &self.decoding, &validation) else {
            return Ok(None);
        };
        Ok(Uuid::parse_str(&data.claims.sub).ok())
    }

    // Stateless: revocation cannot precede expiry. See the module-level note.
    async fn revoke(&self, _token: &str) -> Result<(), AuthError> {
        Ok(())
    }

    async fn revoke_user(&self, _user_id: Uuid) -> Result<(), AuthError> {
        Ok(())
    }
}
