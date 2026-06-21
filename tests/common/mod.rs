//! Shared test helpers: a token-capturing mailer, a request context, and a host
//! state that exposes `AuthServices` via `FromRef`.
#![allow(dead_code)] // not every test binary uses every helper

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::extract::FromRef;
use esylla_auth::{AuthError, AuthServices, Mailer, RequestContext};

#[derive(Clone, Default)]
pub struct TestMailer {
    last_token: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl Mailer for TestMailer {
    async fn send_verification_email(&self, _to: &str, token: &str) -> Result<(), AuthError> {
        *self.last_token.lock().unwrap() = Some(token.to_owned());
        Ok(())
    }

    async fn send_password_reset_email(&self, _to: &str, token: &str) -> Result<(), AuthError> {
        *self.last_token.lock().unwrap() = Some(token.to_owned());
        Ok(())
    }
}

impl TestMailer {
    pub fn token(&self) -> String {
        self.last_token
            .lock()
            .unwrap()
            .clone()
            .expect("an email was sent")
    }
}

pub fn ctx() -> RequestContext {
    RequestContext::default()
}

#[derive(Clone)]
pub struct AppState {
    pub auth: AuthServices,
}

impl FromRef<AppState> for AuthServices {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}
