//! Session and OAuth-state cookie handling.

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

use crate::config::CookieConfig;

const OAUTH_STATE: &str = "oauth_state";

/// Apply the same `__Host-`/`__Secure-` prefix rules as the session cookie to an
/// arbitrary base name.
fn prefixed(cfg: &CookieConfig, base: &str) -> String {
    if cfg.secure && cfg.domain.is_none() {
        format!("__Host-{base}")
    } else if cfg.secure {
        format!("__Secure-{base}")
    } else {
        base.to_owned()
    }
}

fn base_cookie(cfg: &CookieConfig, value: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(cfg.full_name(), value);
    cookie.set_http_only(true);
    cookie.set_secure(cfg.secure);
    cookie.set_same_site(cfg.same_site);
    cookie.set_path("/");
    if let Some(domain) = &cfg.domain {
        cookie.set_domain(domain.clone());
    }
    cookie
}

/// Attach the session cookie (a browser-session cookie — the server enforces the
/// idle/absolute TTLs).
pub(crate) fn set_session(jar: CookieJar, cfg: &CookieConfig, raw_token: String) -> CookieJar {
    jar.add(base_cookie(cfg, raw_token))
}

/// Expire the session cookie.
pub(crate) fn clear_session(jar: CookieJar, cfg: &CookieConfig) -> CookieJar {
    jar.remove(base_cookie(cfg, String::new()))
}

pub(crate) fn session_token(jar: &CookieJar, cfg: &CookieConfig) -> Option<String> {
    jar.get(&cfg.full_name()).map(|c| c.value().to_owned())
}

fn oauth_state_cookie(cfg: &CookieConfig, value: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(prefixed(cfg, OAUTH_STATE), value);
    cookie.set_http_only(true);
    cookie.set_secure(cfg.secure);
    // Lax so the cookie rides along on the provider's top-level redirect back.
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    if let Some(domain) = &cfg.domain {
        cookie.set_domain(domain.clone());
    }
    cookie
}

/// Bind the OAuth `state` to the initiating browser (defends against login-CSRF).
pub(crate) fn set_oauth_state(jar: CookieJar, cfg: &CookieConfig, state: String) -> CookieJar {
    jar.add(oauth_state_cookie(cfg, state))
}

pub(crate) fn oauth_state(jar: &CookieJar, cfg: &CookieConfig) -> Option<String> {
    jar.get(&prefixed(cfg, OAUTH_STATE)).map(|c| c.value().to_owned())
}

pub(crate) fn clear_oauth_state(jar: CookieJar, cfg: &CookieConfig) -> CookieJar {
    jar.remove(oauth_state_cookie(cfg, String::new()))
}
