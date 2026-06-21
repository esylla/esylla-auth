//! Login, logout, and session resolution.

use std::sync::LazyLock;

use super::AuthServices;
use crate::adapter::RequestContext;
use crate::crypto::password;
use crate::error::AuthError;
use crate::store::User;

/// A real Argon2 hash to verify against when the account is missing or has no
/// password, so a failed login costs the same time either way (no enumeration).
static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| password::hash_password("esylla-auth-timing-dummy").expect("dummy hash"));

impl AuthServices {
    /// Authenticate by email + password and open a session, returning the raw
    /// session token for the caller to set as a cookie.
    #[tracing::instrument(skip_all)]
    pub async fn login(
        &self,
        email: &str,
        password_plain: &str,
        ctx: &RequestContext,
    ) -> Result<String, AuthError> {
        let email = self.adapter.normalize_email(email);
        let user = self.users.find_by_email(&email).await?;

        match user.as_ref().and_then(|u| u.password_hash.as_deref()) {
            Some(hash) => password::verify_password(password_plain, hash)?,
            None => {
                // Unknown account or OAuth-only: spend the same effort, then fail.
                let _ = password::verify_password(password_plain, &DUMMY_HASH);
                return Err(AuthError::InvalidCredentials);
            }
        }

        // Password is correct; only now may we reveal verification state.
        let user = user.expect("user present when hash matched");
        if !user.email_verified {
            return Err(AuthError::EmailNotVerified);
        }
        let session = self.session.issue(user.id).await?;
        self.adapter.on_logged_in(&user, ctx).await?;
        tracing::info!(user_id = %user.id, "user logged in");
        Ok(session)
    }

    /// End the session identified by the raw token.
    pub async fn logout(&self, raw_token: &str) -> Result<(), AuthError> {
        self.session.revoke(raw_token).await
    }

    /// Resolve the user behind a session token, refreshing its idle window.
    pub async fn authenticate(&self, raw_token: &str) -> Result<Option<User>, AuthError> {
        let Some(user_id) = self.session.resolve(raw_token).await? else {
            return Ok(None);
        };
        self.users.find_by_id(user_id).await
    }
}
