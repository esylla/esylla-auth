//! Session strategy: how a successful login becomes a token and how a token is
//! resolved back to a user. The default is opaque server-side sessions; the `jwt`
//! feature adds a stateless [`JwtSessions`](crate::jwt::JwtSessions) alternative.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use crate::crypto::token;
use crate::error::AuthError;
use crate::store::{SessionRecord, SessionStore};

#[async_trait]
pub trait SessionStrategy: Send + Sync {
    /// Issue a token for a freshly authenticated user.
    async fn issue(&self, user_id: Uuid) -> Result<String, AuthError>;

    /// Resolve a token to its user id, or `None` if it is invalid or expired.
    async fn resolve(&self, token: &str) -> Result<Option<Uuid>, AuthError>;

    /// Revoke a single token (logout).
    async fn revoke(&self, token: &str) -> Result<(), AuthError>;

    /// Revoke every token belonging to a user (password reset/change).
    async fn revoke_user(&self, user_id: Uuid) -> Result<(), AuthError>;
}

/// Opaque server-side sessions: a 256-bit random token stored hashed, with a
/// sliding idle window and a hard absolute cap. Supports instant revocation.
pub struct OpaqueSessions {
    store: Arc<dyn SessionStore>,
    idle_ttl: Duration,
    absolute_ttl: Duration,
}

impl OpaqueSessions {
    pub fn new(store: Arc<dyn SessionStore>, idle_ttl: Duration, absolute_ttl: Duration) -> Self {
        Self {
            store,
            idle_ttl,
            absolute_ttl,
        }
    }
}

#[async_trait]
impl SessionStrategy for OpaqueSessions {
    async fn issue(&self, user_id: Uuid) -> Result<String, AuthError> {
        let raw = token::generate();
        let absolute = (Utc::now()
            + chrono::Duration::from_std(self.absolute_ttl)
                .unwrap_or_else(|_| chrono::Duration::days(36_500)))
        .timestamp();
        self.store
            .create(
                &token::hash(&raw),
                SessionRecord {
                    user_id,
                    absolute_expiry: absolute,
                },
                self.idle_ttl,
            )
            .await?;
        Ok(raw)
    }

    async fn resolve(&self, token: &str) -> Result<Option<Uuid>, AuthError> {
        let hash = token::hash(token);
        let Some(record) = self.store.get(&hash).await? else {
            return Ok(None);
        };
        // Enforce the absolute cap here too, so it holds even for a custom store
        // whose `get` only honors the idle TTL.
        if record.absolute_expiry <= Utc::now().timestamp() {
            self.store.delete(&hash).await?;
            return Ok(None);
        }
        self.store.touch(&hash, self.idle_ttl).await?;
        Ok(Some(record.user_id))
    }

    async fn revoke(&self, token: &str) -> Result<(), AuthError> {
        self.store.delete(&token::hash(token)).await
    }

    async fn revoke_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.store.delete_for_user(user_id).await
    }
}
