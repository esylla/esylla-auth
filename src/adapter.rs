//! Lifecycle hooks for injecting host logic into the auth flow without rewriting
//! the built-in handlers.

use async_trait::async_trait;
use axum::http::HeaderMap;

use crate::error::AuthError;
use crate::store::User;

/// Request metadata passed to adapter hooks. Exposes the request headers so host
/// logic can read a forwarded IP, user-agent, or anything else it needs — the
/// framework does not interpret them.
#[derive(Clone, Default)]
pub struct RequestContext {
    headers: HeaderMap,
}

impl RequestContext {
    pub fn new(headers: HeaderMap) -> Self {
        Self { headers }
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Convenience for a single header value as a string.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

/// Hooks a host can override to run its own logic at key points. Every method
/// defaults to a no-op, so a host implements only what it needs.
#[async_trait]
pub trait AccountAdapter: Send + Sync {
    /// Canonicalize an email before it is stored or looked up, so case/whitespace
    /// variants resolve to one account. Override for provider-specific rules (e.g.
    /// Gmail dot/plus handling). Default: trim + lowercase.
    fn normalize_email(&self, email: &str) -> String {
        email.trim().to_lowercase()
    }

    /// Gate signups — return an error to refuse (default: allowed).
    async fn is_open_for_signup(&self, _ctx: &RequestContext) -> Result<(), AuthError> {
        Ok(())
    }

    /// Runs after a new account is created.
    async fn on_signed_up(&self, _user: &User, _ctx: &RequestContext) -> Result<(), AuthError> {
        Ok(())
    }

    /// Runs after a successful password login.
    async fn on_logged_in(&self, _user: &User, _ctx: &RequestContext) -> Result<(), AuthError> {
        Ok(())
    }
}

pub(crate) struct NoopAdapter;

#[async_trait]
impl AccountAdapter for NoopAdapter {}
