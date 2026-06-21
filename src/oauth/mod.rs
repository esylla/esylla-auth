//! OAuth (authorization-code + PKCE). Compiled only with the `oauth` feature.

pub(crate) mod connection;
mod github;
mod oidc;
mod provider;
mod state;

pub use github::GitHub;
pub use oidc::Oidc;
pub use provider::{AuthorizationRequest, OAuthProvider, ProviderIdentity};

pub(crate) use state::{consume, issue};
