//! Default SMTP mailer: lettre delivers, minijinja renders the (overridable)
//! HTML templates. Available with the `smtp` feature. A host wanting a non-SMTP
//! transport (e.g. a transactional API) implements [`Mailer`] directly instead.

use async_trait::async_trait;
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use minijinja::{Environment, context};

use crate::error::AuthError;
use crate::store::Mailer;

/// Connection and content settings for [`SmtpMailer`].
#[derive(Clone, Debug)]
pub struct SmtpConfig {
    pub relay: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    /// Sender mailbox, e.g. `"Acme <no-reply@acme.com>"`.
    pub from: String,
    /// Verification link; `{token}` is substituted with the raw token.
    pub verification_url: String,
    /// Reset link; `{token}` is substituted with the raw token.
    pub reset_url: String,
}

const VERIFICATION: &str = "verification";
const RESET: &str = "reset";

const DEFAULT_VERIFICATION_HTML: &str =
    "<p>Confirm your email address by visiting <a href=\"{{ url }}\">{{ url }}</a>.</p>";
const DEFAULT_RESET_HTML: &str =
    "<p>Reset your password by visiting <a href=\"{{ url }}\">{{ url }}</a>.</p>";

pub struct SmtpMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    templates: Environment<'static>,
    verification_url: String,
    reset_url: String,
    verification_subject: String,
    reset_subject: String,
}

impl SmtpMailer {
    /// Build over a TLS SMTP relay using the default templates and subjects.
    pub fn new(config: SmtpConfig) -> Result<Self, AuthError> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.relay)
            .map_err(|_| AuthError::Mailer)?
            .port(config.port)
            .credentials(Credentials::new(config.username, config.password))
            .build();
        let from = config.from.parse().map_err(|_| AuthError::Mailer)?;

        let mut templates = Environment::new();
        templates
            .add_template(VERIFICATION, DEFAULT_VERIFICATION_HTML)
            .map_err(|_| AuthError::Mailer)?;
        templates
            .add_template(RESET, DEFAULT_RESET_HTML)
            .map_err(|_| AuthError::Mailer)?;

        Ok(Self {
            transport,
            from,
            templates,
            verification_url: config.verification_url,
            reset_url: config.reset_url,
            verification_subject: "Verify your email".to_owned(),
            reset_subject: "Reset your password".to_owned(),
        })
    }

    /// Override the HTML templates. Each is a minijinja template receiving a
    /// `url` variable (the verification/reset link with the token substituted).
    pub fn with_templates(
        mut self,
        verification_html: &str,
        reset_html: &str,
    ) -> Result<Self, AuthError> {
        let mut templates = Environment::new();
        templates
            .add_template_owned(VERIFICATION, verification_html.to_owned())
            .map_err(|_| AuthError::Mailer)?;
        templates
            .add_template_owned(RESET, reset_html.to_owned())
            .map_err(|_| AuthError::Mailer)?;
        self.templates = templates;
        Ok(self)
    }

    /// Override the subject lines.
    pub fn with_subjects(mut self, verification: &str, reset: &str) -> Self {
        self.verification_subject = verification.to_owned();
        self.reset_subject = reset.to_owned();
        self
    }

    async fn deliver(
        &self,
        to: &str,
        subject: &str,
        template: &str,
        url: String,
    ) -> Result<(), AuthError> {
        let body = self
            .templates
            .get_template(template)
            .map_err(|_| AuthError::Mailer)?
            .render(context! { url })
            .map_err(|_| AuthError::Mailer)?;
        let recipient: Mailbox = to.parse().map_err(|_| AuthError::Mailer)?;
        let email = Message::builder()
            .from(self.from.clone())
            .to(recipient)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body)
            .map_err(|_| AuthError::Mailer)?;
        self.transport.send(email).await.map_err(|_| AuthError::Mailer)?;
        Ok(())
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send_verification_email(&self, to: &str, token: &str) -> Result<(), AuthError> {
        let url = self.verification_url.replace("{token}", token);
        self.deliver(to, &self.verification_subject, VERIFICATION, url)
            .await
    }

    async fn send_password_reset_email(&self, to: &str, token: &str) -> Result<(), AuthError> {
        let url = self.reset_url.replace("{token}", token);
        self.deliver(to, &self.reset_subject, RESET, url).await
    }
}
