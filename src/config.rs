//! Runtime configuration. The host constructs an [`AuthConfig`] and exposes it to
//! the module via the framework's state.

use std::time::Duration;

pub use axum_extra::extract::cookie::SameSite;

#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Sliding window: a session expires this long after its last use.
    pub session_idle_ttl: Duration,
    /// Hard cap on a session's lifetime regardless of activity.
    pub session_absolute_ttl: Duration,
    pub email_verification_ttl: Duration,
    pub password_reset_ttl: Duration,
    pub oauth_state_ttl: Duration,
    pub cookie: CookieConfig,
    pub oauth: OAuthConfig,
}

/// OAuth provider credentials. Each provider is configured only if present.
#[derive(Clone, Debug)]
pub struct OAuthConfig {
    pub google: Option<OAuthProviderConfig>,
    pub github: Option<OAuthProviderConfig>,
    pub microsoft: Option<OAuthProviderConfig>,
    /// Where to send the browser after a successful OAuth login.
    pub post_login_redirect: String,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            google: None,
            github: None,
            microsoft: None,
            post_login_redirect: "/".to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    /// Must match the provider's registered redirect URI exactly.
    pub redirect_uri: String,
    /// OIDC issuer URL. Optional for providers with a known default (Google);
    /// required for tenant-scoped providers (Microsoft). Ignored by GitHub.
    pub issuer: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CookieConfig {
    /// Base name; a `__Host-`/`__Secure-` prefix is added by [`CookieConfig::full_name`].
    pub name: String,
    /// Set only for cross-subdomain sessions; leaving it unset enables the
    /// stricter `__Host-` cookie prefix.
    pub domain: Option<String>,
    pub secure: bool,
    pub same_site: SameSite,
}

impl CookieConfig {
    /// The cookie name with the strongest applicable prefix: `__Host-` when the
    /// cookie is secure with no `Domain` (and host-only `Path=/`), `__Secure-`
    /// when merely secure, otherwise the bare name.
    pub fn full_name(&self) -> String {
        if self.secure && self.domain.is_none() {
            format!("__Host-{}", self.name)
        } else if self.secure {
            format!("__Secure-{}", self.name)
        } else {
            self.name.clone()
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            session_idle_ttl: Duration::from_secs(60 * 60 * 24 * 7),
            session_absolute_ttl: Duration::from_secs(60 * 60 * 24 * 30),
            email_verification_ttl: Duration::from_secs(60 * 60 * 24),
            password_reset_ttl: Duration::from_secs(60 * 15),
            oauth_state_ttl: Duration::from_secs(60 * 10),
            cookie: CookieConfig::default(),
            oauth: OAuthConfig::default(),
        }
    }
}

impl Default for CookieConfig {
    fn default() -> Self {
        CookieConfig {
            name: "session".to_string(),
            domain: None,
            secure: true,
            same_site: SameSite::Lax,
        }
    }
}
