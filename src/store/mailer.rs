//! The outbound-email seam. The implementation owns the message content — link
//! format, subject, body, templating, language — so the rest of the crate only
//! decides *when* a mail is sent and with which token. The `smtp` feature ships a
//! default [`SmtpMailer`](crate::store::SmtpMailer) (lettre + minijinja).

use async_trait::async_trait;

use crate::error::AuthError;

#[async_trait]
pub trait Mailer: Send + Sync {
    /// Deliver an email-verification message carrying the raw token. The
    /// implementation turns the token into a link and renders the body.
    async fn send_verification_email(&self, to: &str, token: &str) -> Result<(), AuthError>;

    /// Deliver a password-reset message carrying the raw token.
    async fn send_password_reset_email(&self, to: &str, token: &str) -> Result<(), AuthError>;
}
