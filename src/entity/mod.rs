//! Bundled sea-orm entities backing the default stores. A host that supplies its
//! own `UserStore`/`SessionStore` need not use these.

pub mod oauth_connection;
pub mod oauth_state;
pub mod one_time_token;
pub mod pending_registration;
pub mod session;
pub mod user;
