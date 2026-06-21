//! esylla-auth — authentication for the esylla framework.
//!
//! Email/password, sessions, and OAuth, exposed as an `esylla::Module`. JSON only.
//! See `DESIGN.md` for scope, architecture, and the security baseline.

pub mod adapter;
pub mod api;
pub mod config;
pub mod crypto;
pub mod dto;
pub mod entity;
#[cfg(feature = "jwt")]
pub mod jwt;
pub mod migration;
#[cfg(feature = "oauth")]
pub mod oauth;
pub mod service;
pub mod session;
pub mod store;

mod error;
mod module;

pub use adapter::{AccountAdapter, RequestContext};
pub use api::{AuthRoute, CurrentUser};
pub use config::AuthConfig;
pub use error::AuthError;
#[cfg(feature = "jwt")]
pub use jwt::JwtSessions;
pub use module::Auth;
pub use service::AuthServices;
pub use session::{OpaqueSessions, SessionStrategy};
pub use store::{
    DbSessionStore, DbUserStore, Mailer, SessionRecord, SessionStore, User, UserStore,
};
#[cfg(feature = "smtp")]
pub use store::{SmtpConfig, SmtpMailer};
