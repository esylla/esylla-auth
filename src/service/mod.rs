//! Business logic. [`AuthServices`] bundles the stores, mailer, database, and
//! config; the HTTP layer extracts it from app state and calls these methods.

use std::sync::Arc;

use sea_orm::DatabaseConnection;

use crate::adapter::{AccountAdapter, NoopAdapter};
use crate::config::AuthConfig;
use crate::session::{OpaqueSessions, SessionStrategy};
use crate::store::{DbSessionStore, DbUserStore, Mailer, SessionStore, UserStore};

mod login;
#[cfg(feature = "oauth")]
mod oauth;
mod password;
mod signup;

const PURPOSE_PASSWORD_RESET: &str = "password_reset";

#[derive(Clone)]
pub struct AuthServices {
    pub(crate) users: Arc<dyn UserStore>,
    pub(crate) session: Arc<dyn SessionStrategy>,
    pub(crate) mailer: Arc<dyn Mailer>,
    pub(crate) adapter: Arc<dyn AccountAdapter>,
    /// Host-registered custom OAuth providers, keyed by name. Built-in providers
    /// (google/github/microsoft) are resolved from config and need no registration.
    #[cfg(feature = "oauth")]
    pub(crate) oauth_providers:
        std::collections::HashMap<String, Arc<dyn crate::oauth::OAuthProvider>>,
    /// Backs the module's own tables (one-time tokens, OAuth connections).
    pub(crate) db: DatabaseConnection,
    pub(crate) config: AuthConfig,
}

impl AuthServices {
    /// Build with the default sea-orm-backed user and session stores and a no-op
    /// adapter.
    pub fn new(db: DatabaseConnection, mailer: Arc<dyn Mailer>, config: AuthConfig) -> Self {
        let session = Arc::new(OpaqueSessions::new(
            Arc::new(DbSessionStore::new(db.clone())),
            config.session_idle_ttl,
            config.session_absolute_ttl,
        ));
        Self {
            users: Arc::new(DbUserStore::new(db.clone())),
            session,
            mailer,
            adapter: Arc::new(NoopAdapter),
            #[cfg(feature = "oauth")]
            oauth_providers: std::collections::HashMap::new(),
            db,
            config,
        }
    }

    /// Register a custom OAuth provider under `name`, used by the
    /// `/oauth/{name}/...` routes. Overrides a built-in of the same name.
    #[cfg(feature = "oauth")]
    pub fn with_oauth_provider(
        mut self,
        name: impl Into<String>,
        provider: Arc<dyn crate::oauth::OAuthProvider>,
    ) -> Self {
        self.oauth_providers.insert(name.into(), provider);
        self
    }

    /// Install an [`AccountAdapter`] to hook signup/login with custom logic.
    pub fn with_adapter(mut self, adapter: Arc<dyn AccountAdapter>) -> Self {
        self.adapter = adapter;
        self
    }

    /// Swap in a custom user store (e.g. an existing `users` table).
    pub fn with_user_store(mut self, users: Arc<dyn UserStore>) -> Self {
        self.users = users;
        self
    }

    /// Swap in a custom opaque session store (e.g. Redis-backed). Keeps the
    /// opaque-session strategy; for a different strategy use
    /// [`with_session_strategy`](Self::with_session_strategy).
    pub fn with_session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.session = Arc::new(OpaqueSessions::new(
            store,
            self.config.session_idle_ttl,
            self.config.session_absolute_ttl,
        ));
        self
    }

    /// Swap the whole session strategy — e.g. stateless JWTs
    /// (`JwtSessions`, `jwt` feature) instead of opaque server-side sessions.
    pub fn with_session_strategy(mut self, session: Arc<dyn SessionStrategy>) -> Self {
        self.session = session;
        self
    }
}
