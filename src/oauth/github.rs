//! GitHub — plain OAuth2 (authorization-code + PKCE); identity is read from the
//! REST API since GitHub is not an OIDC provider.

use async_trait::async_trait;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::Deserialize;

use oauth2_reqwest::ReqwestClient;

use super::provider::{AuthorizationRequest, OAuthProvider, ProviderIdentity, http_client};
use crate::config::OAuthProviderConfig;
use crate::error::AuthError;

const AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";
const EMAILS_URL: &str = "https://api.github.com/user/emails";

pub struct GitHub {
    config: OAuthProviderConfig,
}

impl GitHub {
    pub fn new(config: OAuthProviderConfig) -> Self {
        Self { config }
    }

    fn client(
        &self,
    ) -> Result<
        BasicClient<
            oauth2::EndpointSet,
            oauth2::EndpointNotSet,
            oauth2::EndpointNotSet,
            oauth2::EndpointNotSet,
            oauth2::EndpointSet,
        >,
        AuthError,
    > {
        Ok(BasicClient::new(ClientId::new(self.config.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.config.client_secret.clone()))
            .set_auth_uri(AuthUrl::new(AUTHORIZE_URL.to_owned()).map_err(|_| AuthError::OAuth)?)
            .set_token_uri(TokenUrl::new(TOKEN_URL.to_owned()).map_err(|_| AuthError::OAuth)?)
            .set_redirect_uri(
                RedirectUrl::new(self.config.redirect_uri.clone()).map_err(|_| AuthError::OAuth)?,
            ))
    }
}

#[derive(Deserialize)]
struct GitHubUser {
    id: u64,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[async_trait]
impl OAuthProvider for GitHub {
    fn name(&self) -> &'static str {
        "github"
    }

    async fn begin(&self) -> Result<AuthorizationRequest, AuthError> {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, csrf) = self
            .client()?
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("read:user".to_owned()))
            .add_scope(Scope::new("user:email".to_owned()))
            .set_pkce_challenge(challenge)
            .url();

        Ok(AuthorizationRequest {
            url: url.to_string(),
            state: csrf.secret().clone(),
            pkce_verifier: verifier.secret().clone(),
            nonce: None,
        })
    }

    async fn complete(
        &self,
        code: String,
        pkce_verifier: String,
        _nonce: Option<String>,
    ) -> Result<ProviderIdentity, AuthError> {
        let http = http_client()?;
        let oauth_http = ReqwestClient::from(http.clone());
        let token = self
            .client()?
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&oauth_http)
            .await
            .map_err(|_| AuthError::OAuth)?;
        let access = token.access_token().secret();

        let user: GitHubUser = http
            .get(USER_URL)
            .bearer_auth(access)
            .header("User-Agent", "esylla-auth")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|_| AuthError::OAuth)?
            .json()
            .await
            .map_err(|_| AuthError::OAuth)?;

        let emails: Vec<GitHubEmail> = http
            .get(EMAILS_URL)
            .bearer_auth(access)
            .header("User-Agent", "esylla-auth")
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|_| AuthError::OAuth)?
            .json()
            .await
            .map_err(|_| AuthError::OAuth)?;

        let email = emails
            .into_iter()
            .find(|entry| entry.primary && entry.verified)
            .map(|entry| entry.email);

        Ok(ProviderIdentity {
            provider: "github".to_owned(),
            account_id: user.id.to_string(),
            email,
        })
    }
}
