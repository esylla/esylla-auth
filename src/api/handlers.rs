use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum_extra::extract::cookie::CookieJar;
use esylla::ValidatedJson;

use super::cookie;
use super::extract::CurrentUser;
use crate::adapter::RequestContext;
use crate::dto::{
    ChangePasswordRequest, ForgotPasswordRequest, LoginRequest, ResetPasswordRequest,
    SignupRequest, TokenRequest,
};
use crate::error::AuthError;
use crate::service::AuthServices;

#[utoipa::path(post, path = "/auth/signup", request_body = SignupRequest,
    responses((status = 204, description = "Account created; verification email sent")))]
pub async fn signup(
    State(svc): State<AuthServices>,
    headers: HeaderMap,
    ValidatedJson(body): ValidatedJson<SignupRequest>,
) -> Result<StatusCode, AuthError> {
    svc.signup(&body.email, &body.password, &RequestContext::new(headers))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/auth/verify-email", request_body = TokenRequest,
    responses((status = 204, description = "Email verified")))]
pub async fn verify_email(
    State(svc): State<AuthServices>,
    headers: HeaderMap,
    ValidatedJson(body): ValidatedJson<TokenRequest>,
) -> Result<StatusCode, AuthError> {
    svc.verify_email(&body.token, &RequestContext::new(headers))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/auth/login", request_body = LoginRequest,
    responses((status = 204, description = "Logged in; session cookie set")))]
pub async fn login(
    State(svc): State<AuthServices>,
    headers: HeaderMap,
    jar: CookieJar,
    ValidatedJson(body): ValidatedJson<LoginRequest>,
) -> Result<(CookieJar, StatusCode), AuthError> {
    let raw = svc
        .login(&body.email, &body.password, &RequestContext::new(headers))
        .await?;
    let jar = cookie::set_session(jar, &svc.config.cookie, raw);
    Ok((jar, StatusCode::NO_CONTENT))
}

#[utoipa::path(post, path = "/auth/logout", responses((status = 204, description = "Logged out")))]
pub async fn logout(
    State(svc): State<AuthServices>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), AuthError> {
    if let Some(token) = cookie::session_token(&jar, &svc.config.cookie) {
        svc.logout(&token).await?;
    }
    let jar = cookie::clear_session(jar, &svc.config.cookie);
    Ok((jar, StatusCode::NO_CONTENT))
}

#[utoipa::path(post, path = "/auth/forgot-password", request_body = ForgotPasswordRequest,
    responses((status = 204, description = "Reset email sent if the account exists")))]
pub async fn forgot_password(
    State(svc): State<AuthServices>,
    ValidatedJson(body): ValidatedJson<ForgotPasswordRequest>,
) -> Result<StatusCode, AuthError> {
    svc.forgot_password(&body.email).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/auth/reset-password", request_body = ResetPasswordRequest,
    responses((status = 204, description = "Password reset")))]
pub async fn reset_password(
    State(svc): State<AuthServices>,
    ValidatedJson(body): ValidatedJson<ResetPasswordRequest>,
) -> Result<StatusCode, AuthError> {
    svc.reset_password(&body.token, &body.new_password).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(post, path = "/auth/change-password", request_body = ChangePasswordRequest,
    responses((status = 204, description = "Password changed")))]
pub async fn change_password(
    State(svc): State<AuthServices>,
    CurrentUser(user): CurrentUser,
    jar: CookieJar,
    ValidatedJson(body): ValidatedJson<ChangePasswordRequest>,
) -> Result<(CookieJar, StatusCode), AuthError> {
    svc.change_password(user.id, &body.current_password, &body.new_password)
        .await?;
    // A change revokes all of the user's sessions, including this one — clear the
    // now-dead cookie so the client logs in again.
    let jar = cookie::clear_session(jar, &svc.config.cookie);
    Ok((jar, StatusCode::NO_CONTENT))
}
