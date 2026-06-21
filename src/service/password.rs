//! Password reset (forgot → reset) and authenticated change.

use uuid::Uuid;

use super::{AuthServices, PURPOSE_PASSWORD_RESET};
use crate::crypto::password;
use crate::error::AuthError;
use crate::store::one_time_token;

impl AuthServices {
    /// Begin a password reset. Always succeeds — it never reveals whether the
    /// email is registered — sending a reset mail only when it is.
    #[tracing::instrument(skip_all)]
    pub async fn forgot_password(&self, email: &str) -> Result<(), AuthError> {
        let email = self.adapter.normalize_email(email);
        if let Some(user) = self.users.find_by_email(&email).await? {
            let raw = one_time_token::issue(
                &self.db,
                user.id,
                PURPOSE_PASSWORD_RESET,
                self.config.password_reset_ttl,
            )
            .await?;
            self.mailer.send_password_reset_email(&email, &raw).await?;
        }
        Ok(())
    }

    /// Complete a reset with the one-time token. Invalidates all of the user's
    /// sessions and does not log them in.
    #[tracing::instrument(skip_all)]
    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<(), AuthError> {
        let user_id = one_time_token::consume(&self.db, token, PURPOSE_PASSWORD_RESET).await?;
        let hash = password::hash_password(new_password)?;
        self.users.set_password(user_id, &hash).await?;
        self.session.revoke_user(user_id).await?;
        tracing::info!(user_id = %user_id, "password reset");
        Ok(())
    }

    /// Change the password of an authenticated user after re-checking the current
    /// one. Invalidates all existing sessions.
    #[tracing::instrument(skip_all)]
    pub async fn change_password(
        &self,
        user_id: Uuid,
        current: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        let user = self
            .users
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::Unauthenticated)?;
        let hash = user
            .password_hash
            .as_deref()
            .ok_or(AuthError::InvalidCredentials)?;
        password::verify_password(current, hash)?;

        let new_hash = password::hash_password(new_password)?;
        self.users.set_password(user_id, &new_hash).await?;
        self.session.revoke_user(user_id).await?;
        tracing::info!(user_id = %user_id, "password changed");
        Ok(())
    }
}
