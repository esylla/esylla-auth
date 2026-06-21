//! Customizing esylla-auth via an `AccountAdapter`: gate signups behind an invite
//! header and read request metadata (e.g. a forwarded IP) on login — without
//! touching the built-in handlers.
//!
//! Run: `cargo run --example customize`

use std::sync::Arc;

use async_trait::async_trait;
use axum::http::HeaderMap;
use esylla_auth::config::AuthConfig;
use esylla_auth::{AccountAdapter, AuthError, AuthServices, Mailer, RequestContext, User};
use sea_orm::{ConnectOptions, Database};

struct InviteOnly;

#[async_trait]
impl AccountAdapter for InviteOnly {
    async fn is_open_for_signup(&self, ctx: &RequestContext) -> Result<(), AuthError> {
        match ctx.header("x-invite") {
            Some("let-me-in") => Ok(()),
            _ => Err(AuthError::Unauthenticated),
        }
    }

    async fn on_logged_in(&self, user: &User, ctx: &RequestContext) -> Result<(), AuthError> {
        let ip = ctx.header("x-forwarded-for").unwrap_or("unknown");
        println!("[adapter] login user={} ip={ip}", user.id);
        Ok(())
    }
}

struct PrintMailer;

#[async_trait]
impl Mailer for PrintMailer {
    async fn send_verification_email(&self, to: &str, token: &str) -> Result<(), AuthError> {
        println!("[mail] verify {to}: token={token}");
        Ok(())
    }

    async fn send_password_reset_email(&self, to: &str, token: &str) -> Result<(), AuthError> {
        println!("[mail] reset {to}: token={token}");
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let mut opt = ConnectOptions::new("sqlite::memory:");
    opt.max_connections(1).min_connections(1);
    let db = Database::connect(opt).await.unwrap();
    esylla::run_migrations(&db, &esylla_auth::migration::migrations())
        .await
        .unwrap();

    let svc = AuthServices::new(db, Arc::new(PrintMailer), AuthConfig::default())
        .with_adapter(Arc::new(InviteOnly));

    // No invite header → the adapter refuses the signup.
    let refused = svc
        .signup("a@b.com", "longpassword", &RequestContext::default())
        .await;
    println!("signup without invite refused: {}", refused.is_err());

    // With the invite header → allowed.
    let mut headers = HeaderMap::new();
    headers.insert("x-invite", "let-me-in".parse().unwrap());
    svc.signup("a@b.com", "longpassword", &RequestContext::new(headers))
        .await
        .unwrap();
    println!("signup with invite: ok");
}
