//! The `JwtSessions` strategy: a login issues a stateless HS256 token that
//! `authenticate` verifies. Requires the `jwt` feature.
#![cfg(feature = "jwt")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{TestMailer, ctx};
use esylla_auth::config::AuthConfig;
use esylla_auth::{AuthServices, JwtSessions};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};

async fn setup() -> (AuthServices, TestMailer) {
    let mut opt = ConnectOptions::new("sqlite::memory:");
    opt.max_connections(1).min_connections(1);
    let db: DatabaseConnection = Database::connect(opt).await.unwrap();
    esylla::run_migrations(&db, &esylla_auth::migration::migrations())
        .await
        .unwrap();
    let mailer = TestMailer::default();
    let secret = [7u8; 32]; // test-only 256-bit secret
    let svc = AuthServices::new(db, Arc::new(mailer.clone()), AuthConfig::default())
        .with_session_strategy(Arc::new(JwtSessions::new(
            &secret,
            Duration::from_secs(900),
        )));
    (svc, mailer)
}

#[tokio::test]
async fn jwt_login_roundtrip() {
    let (svc, mail) = setup().await;

    svc.signup("a@b.com", "longpassword", &ctx()).await.unwrap();
    svc.verify_email(&mail.token(), &ctx()).await.unwrap();

    let token = svc.login("a@b.com", "longpassword", &ctx()).await.unwrap();
    // A JWT is three dot-separated parts (header.payload.signature).
    assert_eq!(token.matches('.').count(), 2);
    assert_eq!(
        svc.authenticate(&token).await.unwrap().unwrap().email,
        "a@b.com"
    );

    // A token that isn't a valid, correctly-signed JWT yields no session.
    assert!(svc.authenticate("not.a.jwt").await.unwrap().is_none());
}

#[tokio::test]
async fn jwt_rejects_foreign_secret() {
    let (svc, mail) = setup().await;
    svc.signup("a@b.com", "longpassword", &ctx()).await.unwrap();
    svc.verify_email(&mail.token(), &ctx()).await.unwrap();
    let token = svc.login("a@b.com", "longpassword", &ctx()).await.unwrap();

    // A verifier with a different secret must reject the token.
    let foreign = JwtSessions::new(&[9u8; 32], Duration::from_secs(900));
    assert!(
        esylla_auth::SessionStrategy::resolve(&foreign, &token)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
#[should_panic]
fn jwt_rejects_short_secret() {
    let _ = JwtSessions::new(&[0u8; 16], Duration::from_secs(900));
}
