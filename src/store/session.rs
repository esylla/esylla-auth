//! The session persistence seam.
//!
//! Sessions are keyed by the SHA-256 hash of the opaque token (see
//! [`crate::crypto::token`]); the raw token lives only in the client cookie. A
//! backend supplies the storage (Redis, Postgres, …) and honors the idle TTL.

use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthError;

#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub user_id: Uuid,
    /// Absolute expiry (unix seconds): the session is invalid past this regardless
    /// of activity.
    pub absolute_expiry: i64,
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Store `record` under `token_hash`, expiring after `idle_ttl` of inactivity.
    async fn create(
        &self,
        token_hash: &str,
        record: SessionRecord,
        idle_ttl: Duration,
    ) -> Result<(), AuthError>;

    async fn get(&self, token_hash: &str) -> Result<Option<SessionRecord>, AuthError>;

    /// Extend the idle window (sliding expiration) on use.
    async fn touch(&self, token_hash: &str, idle_ttl: Duration) -> Result<(), AuthError>;

    async fn delete(&self, token_hash: &str) -> Result<(), AuthError>;

    /// Remove every session for a user — used after password reset/change.
    async fn delete_for_user(&self, user_id: Uuid) -> Result<(), AuthError>;
}
