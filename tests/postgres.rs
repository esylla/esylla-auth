//! The email/password vertical against a real Postgres started via testcontainers,
//! proving the migrations and queries work on the production database. Requires a
//! running Docker daemon.

mod common;

use std::sync::Arc;

use common::{TestMailer, ctx};
use esylla_auth::config::AuthConfig;
use esylla_auth::{AuthError, AuthServices};
use sea_orm::Database;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn email_password_vertical_on_postgres() {
    let container = Postgres::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let db = Database::connect(url).await.unwrap();
    esylla::run_migrations(&db, &esylla_auth::migration::migrations())
        .await
        .unwrap();

    let mailer = TestMailer::default();
    let svc = AuthServices::new(db, Arc::new(mailer.clone()), AuthConfig::default());

    svc.signup("a@b.com", "longpassword", &ctx()).await.unwrap();
    // No account exists until the email is verified.
    assert!(matches!(
        svc.login("a@b.com", "longpassword", &ctx()).await,
        Err(AuthError::InvalidCredentials)
    ));

    svc.verify_email(&mailer.token(), &ctx()).await.unwrap();
    let session = svc.login("a@b.com", "longpassword", &ctx()).await.unwrap();
    let user = svc
        .authenticate(&session)
        .await
        .unwrap()
        .expect("session valid");
    assert_eq!(user.email, "a@b.com");

    // Changing the password invalidates the existing session.
    svc.change_password(user.id, "longpassword", "newlongpassword")
        .await
        .unwrap();
    assert!(svc.authenticate(&session).await.unwrap().is_none());
    svc.login("a@b.com", "newlongpassword", &ctx())
        .await
        .unwrap();
}
