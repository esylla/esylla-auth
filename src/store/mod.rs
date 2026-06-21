//! Persistence and delivery seams. A host can rely on the bundled defaults or
//! implement any of these traits to plug in its own backend.

pub mod db;
pub mod mailer;
pub(crate) mod one_time_token;
pub(crate) mod pending_registration;
#[cfg(feature = "redis")]
pub mod redis;
pub mod session;
#[cfg(feature = "smtp")]
pub mod smtp;
pub mod user;

pub use db::{DbSessionStore, DbUserStore};
pub use mailer::Mailer;
#[cfg(feature = "redis")]
pub use redis::RedisSessionStore;
pub use session::{SessionRecord, SessionStore};
#[cfg(feature = "smtp")]
pub use smtp::{SmtpConfig, SmtpMailer};
pub use user::{User, UserStore};
