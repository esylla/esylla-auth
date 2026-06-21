//! OAuth authorize/callback orchestration. Available with the `oauth` feature.

use std::sync::Arc;

use sea_orm::SqlErr;
use uuid::Uuid;

use super::AuthServices;
use crate::error::AuthError;
use crate::oauth::{self, GitHub, OAuthProvider, Oidc};

const GOOGLE_ISSUER: &str = "https://accounts.google.com";

impl AuthServices {
    /// Resolve a provider by name: a host-registered custom provider wins,
    /// otherwise a built-in is constructed from config.
    fn provider(&self, name: &str) -> Result<Arc<dyn OAuthProvider>, AuthError> {
        if let Some(provider) = self.oauth_providers.get(name) {
            return Ok(provider.clone());
        }

        let configured = &self.config.oauth;
        let provider: Option<Arc<dyn OAuthProvider>> = match name {
            "github" => configured
                .github
                .clone()
                .map(|config| Arc::new(GitHub::new(config)) as Arc<dyn OAuthProvider>),
            "google" => configured.google.clone().map(|config| {
                let issuer = config
                    .issuer
                    .clone()
                    .unwrap_or_else(|| GOOGLE_ISSUER.to_owned());
                Arc::new(Oidc::new("google", issuer, config)) as Arc<dyn OAuthProvider>
            }),
            // Microsoft is tenant-scoped, so the issuer must be configured
            // (e.g. https://login.microsoftonline.com/<tenant>/v2.0).
            "microsoft" => configured
                .microsoft
                .clone()
                .and_then(|config| config.issuer.clone().map(|issuer| (config, issuer)))
                .map(|(config, issuer)| {
                    Arc::new(Oidc::new("microsoft", issuer, config)) as Arc<dyn OAuthProvider>
                }),
            _ => None,
        };
        provider.ok_or(AuthError::OAuthProviderUnconfigured)
    }

    /// Begin an OAuth flow. Returns the provider authorization URL and the CSRF
    /// `state` (the caller stores it in a browser cookie to bind the flow); the
    /// PKCE verifier and nonce are persisted server-side for the callback.
    #[tracing::instrument(skip_all, fields(provider = provider_name))]
    pub async fn oauth_authorize(
        &self,
        provider_name: &str,
    ) -> Result<(String, String), AuthError> {
        let provider = self.provider(provider_name)?;
        let request = provider.begin().await?;
        oauth::issue(
            &self.db,
            &request.state,
            provider.name(),
            &request.pkce_verifier,
            request.nonce.as_deref(),
            self.config.oauth_state_ttl,
        )
        .await?;
        Ok((request.url, request.state))
    }

    /// Complete an OAuth flow: verify the state, exchange the code, resolve or
    /// provision the account, and open a session. Returns the raw session token.
    ///
    /// `cookie_state` is the state value the browser sent back from the cookie set
    /// at authorize; it must match the `state` query parameter, binding the
    /// callback to the browser that started the flow (login-CSRF defense).
    #[tracing::instrument(skip_all, fields(provider = provider_name))]
    pub async fn oauth_callback(
        &self,
        provider_name: &str,
        code: &str,
        state: &str,
        cookie_state: Option<&str>,
    ) -> Result<String, AuthError> {
        // The flow must be completed by the browser that began it.
        if cookie_state != Some(state) {
            return Err(AuthError::OAuth);
        }

        let stored = oauth::consume(&self.db, state).await?;
        if stored.provider != provider_name {
            return Err(AuthError::OAuth);
        }

        let provider = self.provider(provider_name)?;
        let identity = provider
            .complete(code.to_owned(), stored.pkce_verifier, stored.nonce)
            .await?;

        let user_id =
            match oauth::connection::find_user(&self.db, &identity.provider, &identity.account_id)
                .await?
            {
                Some(user_id) => user_id,
                None => {
                    // First time with this provider account: link to an existing user
                    // by the provider-verified email, or provision a new one.
                    let email = identity.email.as_deref().ok_or(AuthError::OAuth)?;
                    let email = self.adapter.normalize_email(email);
                    let user_id = match self.users.find_by_email(&email).await? {
                        Some(user) => {
                            // Only link into a local account that has itself verified
                            // this email. Auto-linking into an unverified account would
                            // let a squatter who pre-registered the address capture the
                            // OAuth login (account takeover).
                            if !user.email_verified {
                                return Err(AuthError::EmailTaken);
                            }
                            user.id
                        }
                        None => self.provision_oauth_user(&email).await?,
                    };
                    match oauth::connection::link(
                        &self.db,
                        user_id,
                        &identity.provider,
                        &identity.account_id,
                    )
                    .await
                    {
                        Ok(()) => user_id,
                        // A concurrent callback already linked this provider account;
                        // resolve to whoever won the race.
                        Err(AuthError::Database(ref err))
                            if matches!(
                                err.sql_err(),
                                Some(SqlErr::UniqueConstraintViolation(_))
                            ) =>
                        {
                            oauth::connection::find_user(
                                &self.db,
                                &identity.provider,
                                &identity.account_id,
                            )
                            .await?
                            .ok_or(AuthError::OAuth)?
                        }
                        Err(err) => return Err(err),
                    }
                }
            };

        let session = self.session.issue(user_id).await?;
        tracing::info!(user_id = %user_id, "user logged in via oauth");
        Ok(session)
    }

    async fn provision_oauth_user(&self, email: &str) -> Result<Uuid, AuthError> {
        // OAuth accounts have no password; the provider already verified the email,
        // so create the user verified in one write.
        let user = self.users.create(email, None, true).await?;
        Ok(user.id)
    }
}
