//! End-to-end tests for the email/password flow against in-memory SQLite, both at
//! the service layer and over HTTP (via `tower::oneshot`).

mod common;

use std::sync::Arc;

use common::{AppState, TestMailer, ctx};
use esylla_auth::config::AuthConfig;
use esylla_auth::{Auth, AuthError, AuthServices};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};

async fn setup() -> (AuthServices, TestMailer) {
    let mut opt = ConnectOptions::new("sqlite::memory:");
    opt.max_connections(1).min_connections(1);
    let db: DatabaseConnection = Database::connect(opt).await.unwrap();
    esylla::run_migrations(&db, &esylla_auth::migration::migrations())
        .await
        .unwrap();
    let mailer = TestMailer::default();
    let services = AuthServices::new(db, Arc::new(mailer.clone()), AuthConfig::default());
    (services, mailer)
}

#[tokio::test]
async fn signup_verify_login_logout() {
    let (svc, mail) = setup().await;

    svc.signup("a@b.com", "longpassword", &ctx()).await.unwrap();
    // Before verification no account exists yet, so login fails as unknown.
    assert!(matches!(
        svc.login("a@b.com", "longpassword", &ctx()).await,
        Err(AuthError::InvalidCredentials)
    ));

    svc.verify_email(&mail.token(), &ctx()).await.unwrap();
    let session = svc.login("a@b.com", "longpassword", &ctx()).await.unwrap();
    assert_eq!(
        svc.authenticate(&session).await.unwrap().unwrap().email,
        "a@b.com"
    );

    assert!(matches!(
        svc.login("a@b.com", "wrong", &ctx()).await,
        Err(AuthError::InvalidCredentials)
    ));

    svc.logout(&session).await.unwrap();
    assert!(svc.authenticate(&session).await.unwrap().is_none());
}

#[tokio::test]
async fn does_not_leak_account_existence() {
    let (svc, _mail) = setup().await;

    assert!(matches!(
        svc.login("nobody@x.com", "whatever", &ctx()).await,
        Err(AuthError::InvalidCredentials)
    ));
    svc.forgot_password("nobody@x.com").await.unwrap();
    svc.signup("dup@x.com", "longpassword", &ctx()).await.unwrap();
    svc.signup("dup@x.com", "longpassword", &ctx()).await.unwrap();
}

#[tokio::test]
async fn reset_invalidates_sessions() {
    let (svc, mail) = setup().await;

    svc.signup("c@d.com", "oldpassword", &ctx()).await.unwrap();
    svc.verify_email(&mail.token(), &ctx()).await.unwrap();
    let session = svc.login("c@d.com", "oldpassword", &ctx()).await.unwrap();

    svc.forgot_password("c@d.com").await.unwrap();
    svc.reset_password(&mail.token(), "newpassword")
        .await
        .unwrap();

    assert!(svc.authenticate(&session).await.unwrap().is_none());
    assert!(matches!(
        svc.login("c@d.com", "oldpassword", &ctx()).await,
        Err(AuthError::InvalidCredentials)
    ));
    svc.login("c@d.com", "newpassword", &ctx()).await.unwrap();
}

#[tokio::test]
async fn http_signup_endpoint() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let (svc, _mail) = setup().await;
    let app = esylla::Esylla::new(AppState { auth: svc })
        .module(Auth::new())
        .into_router();

    let response = app
        .oneshot(
            Request::post("/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"h@i.com","password":"longpassword"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let bad = app_with(&setup().await.0)
        .oneshot(
            Request::post("/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"email":"not-an-email","password":"short"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

fn app_with(svc: &AuthServices) -> axum::Router {
    esylla::Esylla::new(AppState { auth: svc.clone() })
        .module(Auth::new())
        .into_router()
}
