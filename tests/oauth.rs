//! OAuth orchestration tests using a mock `OAuthProvider`, so the authorize/
//! callback logic — browser-bound state, single-use consume, account linking,
//! provisioning, and session issuance — is exercised without contacting a real
//! provider. Requires the `oauth` feature.
#![cfg(feature = "oauth")]

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use common::{TestMailer, ctx};
use esylla_auth::config::AuthConfig;
use esylla_auth::oauth::{AuthorizationRequest, OAuthProvider, ProviderIdentity};
use esylla_auth::{AuthError, AuthServices};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};

/// Returns a fixed authorization request and identity, standing in for a real
/// provider's network exchange.
struct MockProvider {
    account_id: String,
    email: Option<String>,
}

#[async_trait]
impl OAuthProvider for MockProvider {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn begin(&self) -> Result<AuthorizationRequest, AuthError> {
        Ok(AuthorizationRequest {
            url: "https://provider.example/authorize".to_owned(),
            state: "test-state".to_owned(),
            pkce_verifier: "test-verifier".to_owned(),
            nonce: None,
        })
    }

    async fn complete(
        &self,
        _code: String,
        _pkce_verifier: String,
        _nonce: Option<String>,
    ) -> Result<ProviderIdentity, AuthError> {
        Ok(ProviderIdentity {
            provider: "mock".to_owned(),
            account_id: self.account_id.clone(),
            email: self.email.clone(),
        })
    }
}

async fn setup(provider: MockProvider) -> (AuthServices, TestMailer) {
    let mut opt = ConnectOptions::new("sqlite::memory:");
    opt.max_connections(1).min_connections(1);
    let db: DatabaseConnection = Database::connect(opt).await.unwrap();
    esylla::run_migrations(&db, &esylla_auth::migration::migrations())
        .await
        .unwrap();
    let mailer = TestMailer::default();
    let services = AuthServices::new(db, Arc::new(mailer.clone()), AuthConfig::default())
        .with_oauth_provider("mock", Arc::new(provider));
    (services, mailer)
}

#[tokio::test]
async fn provisions_then_links_same_account() {
    let (svc, _mail) = setup(MockProvider {
        account_id: "acct-1".to_owned(),
        email: Some("new@x.com".to_owned()),
    })
    .await;

    // First flow: provisions a new, verified account and a session.
    let (_url, state) = svc.oauth_authorize("mock").await.unwrap();
    let session = svc
        .oauth_callback("mock", "code", &state, Some(&state))
        .await
        .unwrap();
    let user = svc.authenticate(&session).await.unwrap().expect("session");
    assert_eq!(user.email, "new@x.com");

    // Second flow with the same provider account resolves the existing user.
    let (_url, state) = svc.oauth_authorize("mock").await.unwrap();
    let session = svc
        .oauth_callback("mock", "code", &state, Some(&state))
        .await
        .unwrap();
    let again = svc.authenticate(&session).await.unwrap().expect("session");
    assert_eq!(again.id, user.id);
}

#[tokio::test]
async fn rejects_state_not_bound_to_browser() {
    let (svc, _mail) = setup(MockProvider {
        account_id: "acct-1".to_owned(),
        email: Some("new@x.com".to_owned()),
    })
    .await;

    let (_url, state) = svc.oauth_authorize("mock").await.unwrap();
    // Cookie state missing or mismatched → login-CSRF defense rejects it.
    assert!(matches!(
        svc.oauth_callback("mock", "code", &state, None).await,
        Err(AuthError::OAuth)
    ));
    assert!(matches!(
        svc.oauth_callback("mock", "code", &state, Some("wrong"))
            .await,
        Err(AuthError::OAuth)
    ));
}

#[tokio::test]
async fn state_is_single_use() {
    let (svc, _mail) = setup(MockProvider {
        account_id: "acct-1".to_owned(),
        email: Some("new@x.com".to_owned()),
    })
    .await;

    let (_url, state) = svc.oauth_authorize("mock").await.unwrap();
    svc.oauth_callback("mock", "code", &state, Some(&state))
        .await
        .unwrap();
    // Replaying the same state fails — it was consumed (single-use).
    assert!(matches!(
        svc.oauth_callback("mock", "code", &state, Some(&state))
            .await,
        Err(AuthError::InvalidToken)
    ));
}

#[tokio::test]
async fn links_to_verified_local_account() {
    let (svc, mail) = setup(MockProvider {
        account_id: "acct-2".to_owned(),
        email: Some("shared@x.com".to_owned()),
    })
    .await;

    // A verified password account already owns the address.
    svc.signup("shared@x.com", "longpassword", &ctx())
        .await
        .unwrap();
    svc.verify_email(&mail.token(), &ctx()).await.unwrap();
    let local = svc
        .login("shared@x.com", "longpassword", &ctx())
        .await
        .unwrap();
    let local_user = svc.authenticate(&local).await.unwrap().unwrap();

    // OAuth with the same verified email links into that account.
    let (_url, state) = svc.oauth_authorize("mock").await.unwrap();
    let session = svc
        .oauth_callback("mock", "code", &state, Some(&state))
        .await
        .unwrap();
    let linked = svc.authenticate(&session).await.unwrap().unwrap();
    assert_eq!(linked.id, local_user.id);
}

#[tokio::test]
async fn cannot_provision_without_email() {
    let (svc, _mail) = setup(MockProvider {
        account_id: "acct-3".to_owned(),
        email: None,
    })
    .await;

    let (_url, state) = svc.oauth_authorize("mock").await.unwrap();
    assert!(matches!(
        svc.oauth_callback("mock", "code", &state, Some(&state))
            .await,
        Err(AuthError::OAuth)
    ));
}
