//! Signup and email verification. A signup is held as a pending registration
//! until the email is verified; only then is the account created — so an
//! unverified email never reserves an account.

use sea_orm::SqlErr;

use super::AuthServices;
use crate::adapter::RequestContext;
use crate::crypto::password;
use crate::error::AuthError;
use crate::store::pending_registration;

impl AuthServices {
    /// Begin a signup: hold the credentials as a pending registration and email a
    /// verification token. Enumeration-safe — the same success whether or not the
    /// email is already taken.
    #[tracing::instrument(skip_all)]
    pub async fn signup(
        &self,
        email: &str,
        password_plain: &str,
        ctx: &RequestContext,
    ) -> Result<(), AuthError> {
        self.adapter.is_open_for_signup(ctx).await?;
        let email = self.adapter.normalize_email(email);

        // Hash on every call so the work is the same whether or not the email is
        // already registered.
        let hash = password::hash_password(password_plain)?;

        // An existing account already owns this email: reveal nothing.
        if self.users.find_by_email(&email).await?.is_some() {
            return Ok(());
        }

        let raw = pending_registration::upsert(
            &self.db,
            &email,
            &hash,
            self.config.email_verification_ttl,
        )
        .await?;
        self.mailer.send_verification_email(&email, &raw).await?;
        Ok(())
    }

    /// Verify a pending signup and create the account, already verified.
    #[tracing::instrument(skip_all)]
    pub async fn verify_email(&self, token: &str, ctx: &RequestContext) -> Result<(), AuthError> {
        let pending = pending_registration::consume(&self.db, token).await?;

        // Create the account already verified in a single write — no separate
        // mark step that could fail and leave a permanently unverifiable account.
        let user = match self
            .users
            .create(&pending.email, Some(pending.password_hash), true)
            .await
        {
            Ok(user) => user,
            // A concurrent verification already created the account.
            Err(AuthError::Database(ref err))
                if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) =>
            {
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        self.adapter.on_signed_up(&user, ctx).await?;
        tracing::info!(user_id = %user.id, "account created via verification");
        Ok(())
    }
}
