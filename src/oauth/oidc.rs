//! Generic OpenID Connect provider, usable with any OIDC issuer (Google,
//! Microsoft, GitLab, Okta, …). The `openidconnect` crate validates the ID token
//! (signature via JWKS, issuer, audience, expiry) and the nonce.

use async_trait::async_trait;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};

use oauth2_reqwest::ReqwestClient;

use super::provider::{AuthorizationRequest, OAuthProvider, ProviderIdentity, http_client};
use crate::config::OAuthProviderConfig;
use crate::error::AuthError;

pub struct Oidc {
    name: &'static str,
    issuer: String,
    config: OAuthProviderConfig,
}

impl Oidc {
    pub fn new(name: &'static str, issuer: impl Into<String>, config: OAuthProviderConfig) -> Self {
        Self {
            name,
            issuer: issuer.into(),
            config,
        }
    }

    async fn discover(&self, http: &ReqwestClient) -> Result<CoreProviderMetadata, AuthError> {
        // Require HTTPS so a misconfigured issuer can't be pointed at an internal
        // or plaintext endpoint (SSRF / metadata spoofing).
        if !self.issuer.starts_with("https://") {
            return Err(AuthError::OAuth);
        }
        let issuer = IssuerUrl::new(self.issuer.clone()).map_err(|_| AuthError::OAuth)?;
        CoreProviderMetadata::discover_async(issuer, http)
            .await
            .map_err(|_| AuthError::OAuth)
    }

    fn build_client(
        &self,
        metadata: CoreProviderMetadata,
    ) -> Result<
        CoreClient<
            openidconnect::EndpointSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointNotSet,
            openidconnect::EndpointMaybeSet,
            openidconnect::EndpointMaybeSet,
        >,
        AuthError,
    > {
        Ok(CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(self.config.redirect_uri.clone()).map_err(|_| AuthError::OAuth)?,
        ))
    }
}

#[async_trait]
impl OAuthProvider for Oidc {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn begin(&self) -> Result<AuthorizationRequest, AuthError> {
        let http = ReqwestClient::from(http_client()?);
        let metadata = self.discover(&http).await?;
        let client = self.build_client(metadata)?;

        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, csrf, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_owned()))
            .add_scope(Scope::new("email".to_owned()))
            .set_pkce_challenge(challenge)
            .url();

        Ok(AuthorizationRequest {
            url: url.to_string(),
            state: csrf.secret().clone(),
            pkce_verifier: verifier.secret().clone(),
            nonce: Some(nonce.secret().clone()),
        })
    }

    async fn complete(
        &self,
        code: String,
        pkce_verifier: String,
        nonce: Option<String>,
    ) -> Result<ProviderIdentity, AuthError> {
        let http = ReqwestClient::from(http_client()?);
        let metadata = self.discover(&http).await?;
        let client = self.build_client(metadata)?;

        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| AuthError::OAuth)?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&http)
            .await
            .map_err(|_| AuthError::OAuth)?;

        let id_token = token.id_token().ok_or(AuthError::OAuth)?;
        let nonce = nonce.ok_or(AuthError::OAuth)?;
        let claims = id_token
            .claims(&client.id_token_verifier(), &Nonce::new(nonce))
            .map_err(|_| AuthError::OAuth)?;

        // Only trust the email if the provider asserts it is verified.
        let email = match claims.email_verified() {
            Some(true) => claims.email().map(|email| email.as_str().to_owned()),
            _ => None,
        };

        Ok(ProviderIdentity {
            provider: self.name.to_owned(),
            account_id: claims.subject().as_str().to_owned(),
            email,
        })
    }
}
