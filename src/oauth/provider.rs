//! Provider abstraction. The trait deals only in plain strings so each provider
//! keeps its `oauth2`/`openidconnect` machinery internal; a host can add its own
//! provider by implementing this trait.

use async_trait::async_trait;

use crate::error::AuthError;

/// The data a provider produces to start an authorization-code flow.
pub struct AuthorizationRequest {
    /// Where to send the user agent.
    pub url: String,
    /// Opaque CSRF state to persist (hashed) and re-check on callback.
    pub state: String,
    /// PKCE verifier to persist and present at token exchange.
    pub pkce_verifier: String,
    /// OIDC nonce to persist and verify in the ID token (None for plain OAuth2).
    pub nonce: Option<String>,
}

/// The verified identity a provider returns after the callback.
pub struct ProviderIdentity {
    pub provider: String,
    /// The provider's stable unique account id.
    pub account_id: String,
    pub email: Option<String>,
}

#[async_trait]
pub trait OAuthProvider: Send + Sync {
    fn name(&self) -> &'static str;

    /// Build the authorization URL and the secrets to persist for the callback.
    /// Async because OIDC providers discover their metadata over the network.
    async fn begin(&self) -> Result<AuthorizationRequest, AuthError>;

    /// Exchange the callback `code`, verify the response, and return the identity.
    async fn complete(
        &self,
        code: String,
        pkce_verifier: String,
        nonce: Option<String>,
    ) -> Result<ProviderIdentity, AuthError>;
}

/// A reqwest client that refuses redirects, as recommended by `oauth2` to avoid
/// SSRF during token exchange.
pub(crate) fn http_client() -> Result<reqwest::Client, AuthError> {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AuthError::OAuth)
}
