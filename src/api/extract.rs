//! The authenticated-user extractor.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum_extra::extract::cookie::CookieJar;

use super::cookie;
use crate::error::AuthError;
use crate::service::AuthServices;
use crate::store::User;

/// Resolves the session cookie to the current [`User`]; rejects with
/// `401 Unauthorized` when absent or invalid.
pub struct CurrentUser(pub User);

impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
    AuthServices: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let services = AuthServices::from_ref(state);
        let jar = CookieJar::from_headers(&parts.headers);
        let token = cookie::session_token(&jar, &services.config.cookie)
            .ok_or(AuthError::Unauthenticated)?;
        let user = services
            .authenticate(&token)
            .await?
            .ok_or(AuthError::Unauthenticated)?;
        Ok(CurrentUser(user))
    }
}
