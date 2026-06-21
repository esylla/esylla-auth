//! OAuth endpoints: redirect to the provider, then handle the callback. These are
//! browser navigations (the provider redirects back), so they reply with 303
//! redirects rather than JSON.

use axum::extract::{Path, Query, State};
use axum::response::Redirect;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use super::cookie;
use crate::error::AuthError;
use crate::service::AuthServices;

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

#[utoipa::path(
    get,
    path = "/oauth/{provider}/authorize",
    params(("provider" = String, Path, description = "Provider name, e.g. `google` or `github`")),
    responses((status = 303, description = "Redirect to the provider's consent screen")),
    tag = "auth"
)]
pub async fn authorize(
    State(services): State<AuthServices>,
    Path(provider): Path<String>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), AuthError> {
    let (url, state) = services.oauth_authorize(&provider).await?;
    let jar = cookie::set_oauth_state(jar, &services.config.cookie, state);
    Ok((jar, Redirect::to(&url)))
}

#[utoipa::path(
    get,
    path = "/oauth/{provider}/callback",
    params(
        ("provider" = String, Path, description = "Provider name"),
        ("code" = String, Query, description = "Authorization code from the provider"),
        ("state" = String, Query, description = "Opaque CSRF state issued at authorize")
    ),
    responses((status = 303, description = "Session cookie set; redirect to the app")),
    tag = "auth"
)]
pub async fn callback(
    State(services): State<AuthServices>,
    Path(provider): Path<String>,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Result<(CookieJar, Redirect), AuthError> {
    let cookie_state = cookie::oauth_state(&jar, &services.config.cookie);
    let session = services
        .oauth_callback(
            &provider,
            &query.code,
            &query.state,
            cookie_state.as_deref(),
        )
        .await?;
    let jar = cookie::clear_oauth_state(jar, &services.config.cookie);
    let jar = cookie::set_session(jar, &services.config.cookie, session);
    Ok((
        jar,
        Redirect::to(&services.config.oauth.post_login_redirect),
    ))
}
