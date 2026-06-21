//! Errors returned by esylla-auth.

use esylla::EsyllaError;

#[derive(Debug, thiserror::Error, EsyllaError)]
pub enum AuthError {
    #[esylla(status = UNAUTHORIZED, code = "auth.invalid_credentials")]
    #[error("invalid credentials")]
    InvalidCredentials,

    #[esylla(status = UNAUTHORIZED, code = "auth.unauthenticated")]
    #[error("not authenticated")]
    Unauthenticated,

    #[esylla(status = FORBIDDEN, code = "auth.email_not_verified")]
    #[error("email not verified")]
    EmailNotVerified,

    #[esylla(status = CONFLICT, code = "auth.email_taken")]
    #[error("email already registered")]
    EmailTaken,

    #[esylla(status = BAD_REQUEST, code = "auth.invalid_token")]
    #[error("invalid or expired token")]
    InvalidToken,

    #[esylla(status = BAD_REQUEST, code = "auth.password_too_long")]
    #[error("password exceeds the maximum length")]
    PasswordTooLong,

    #[esylla(status = INTERNAL_SERVER_ERROR, code = "auth.hashing")]
    #[error("password hashing failed")]
    Hashing,

    #[esylla(status = INTERNAL_SERVER_ERROR, code = "auth.mailer")]
    #[error("failed to send email")]
    Mailer,

    #[esylla(status = INTERNAL_SERVER_ERROR, code = "auth.session")]
    #[error("session backend error")]
    Session,

    #[esylla(status = BAD_REQUEST, code = "auth.oauth")]
    #[error("oauth flow failed")]
    OAuth,

    #[esylla(status = BAD_REQUEST, code = "auth.oauth_provider_unconfigured")]
    #[error("oauth provider not configured")]
    OAuthProviderUnconfigured,

    #[esylla(status = INTERNAL_SERVER_ERROR, code = "auth.database")]
    #[error("database error")]
    Database(#[from] sea_orm::DbErr),
}
