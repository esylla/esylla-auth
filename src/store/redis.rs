//! Redis-backed opaque session store (`redis` feature). The host owns the Redis
//! connection — shared with the rest of the app — and hands it in; the store is
//! then installed with [`AuthServices::with_session_store`](crate::AuthServices::with_session_store).
//!
//! Each session is a `session:<hash>` key holding the [`SessionRecord`], expiring
//! after the idle TTL (refreshed on `touch`) but never past the absolute cap. A
//! `user:<id>` set indexes a user's sessions so they can be revoked together.

use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use uuid::Uuid;

use ::redis::AsyncCommands;
use ::redis::aio::ConnectionManager;

use crate::error::AuthError;
use crate::store::{SessionRecord, SessionStore};

const DEFAULT_PREFIX: &str = "esylla:auth:";

#[derive(Clone)]
pub struct RedisSessionStore {
    conn: ConnectionManager,
    prefix: String,
}

impl RedisSessionStore {
    /// Build over a shared Redis connection. Create the `ConnectionManager` once
    /// and share it across the app (the same client can back caching, rate limits,
    /// etc.).
    pub fn new(conn: ConnectionManager) -> Self {
        Self {
            conn,
            prefix: DEFAULT_PREFIX.to_owned(),
        }
    }

    /// Override the key prefix (default `esylla:auth:`).
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn session_key(&self, token_hash: &str) -> String {
        format!("{}session:{token_hash}", self.prefix)
    }

    fn user_key(&self, user_id: Uuid) -> String {
        format!("{}user:{user_id}", self.prefix)
    }
}

fn backend_error<E>(_: E) -> AuthError {
    AuthError::Session
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn create(
        &self,
        token_hash: &str,
        record: SessionRecord,
        idle_ttl: Duration,
    ) -> Result<(), AuthError> {
        let mut conn = self.conn.clone();
        let now = Utc::now().timestamp();
        // The key never outlives the absolute cap.
        let ttl = (idle_ttl.as_secs() as i64).min(record.absolute_expiry - now);
        if ttl <= 0 {
            return Ok(());
        }

        let value = serde_json::to_string(&record).map_err(backend_error)?;
        let session_key = self.session_key(token_hash);
        let user_key = self.user_key(record.user_id);

        let _: () = conn
            .set_ex(&session_key, value, ttl as u64)
            .await
            .map_err(backend_error)?;
        let _: i64 = conn
            .sadd(&user_key, token_hash)
            .await
            .map_err(backend_error)?;
        // Keep the per-user index from living forever.
        let _: bool = conn
            .expire(&user_key, record.absolute_expiry - now)
            .await
            .map_err(backend_error)?;
        Ok(())
    }

    async fn get(&self, token_hash: &str) -> Result<Option<SessionRecord>, AuthError> {
        let mut conn = self.conn.clone();
        let session_key = self.session_key(token_hash);
        let value: Option<String> = conn.get(&session_key).await.map_err(backend_error)?;
        let Some(value) = value else {
            return Ok(None);
        };
        let record: SessionRecord = serde_json::from_str(&value).map_err(backend_error)?;
        if record.absolute_expiry <= Utc::now().timestamp() {
            let _: i64 = conn.del(&session_key).await.map_err(backend_error)?;
            return Ok(None);
        }
        Ok(Some(record))
    }

    async fn touch(&self, token_hash: &str, idle_ttl: Duration) -> Result<(), AuthError> {
        let mut conn = self.conn.clone();
        let session_key = self.session_key(token_hash);
        let value: Option<String> = conn.get(&session_key).await.map_err(backend_error)?;
        let Some(value) = value else {
            return Ok(());
        };
        let record: SessionRecord = serde_json::from_str(&value).map_err(backend_error)?;
        let ttl = (idle_ttl.as_secs() as i64).min(record.absolute_expiry - Utc::now().timestamp());
        if ttl <= 0 {
            let _: i64 = conn.del(&session_key).await.map_err(backend_error)?;
            return Ok(());
        }
        let _: bool = conn
            .expire(&session_key, ttl)
            .await
            .map_err(backend_error)?;
        Ok(())
    }

    async fn delete(&self, token_hash: &str) -> Result<(), AuthError> {
        let mut conn = self.conn.clone();
        let session_key = self.session_key(token_hash);
        // Read first so the per-user index can be cleaned up too.
        let value: Option<String> = conn.get(&session_key).await.map_err(backend_error)?;
        let _: i64 = conn.del(&session_key).await.map_err(backend_error)?;
        if let Some(value) = value
            && let Ok(record) = serde_json::from_str::<SessionRecord>(&value)
        {
            let _: i64 = conn
                .srem(self.user_key(record.user_id), token_hash)
                .await
                .map_err(backend_error)?;
        }
        Ok(())
    }

    async fn delete_for_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        let mut conn = self.conn.clone();
        let user_key = self.user_key(user_id);
        let hashes: Vec<String> = conn.smembers(&user_key).await.map_err(backend_error)?;
        for hash in &hashes {
            let _: i64 = conn
                .del(self.session_key(hash))
                .await
                .map_err(backend_error)?;
        }
        let _: i64 = conn.del(&user_key).await.map_err(backend_error)?;
        Ok(())
    }
}
