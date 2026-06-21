//! The user persistence seam.

use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthError;

/// The module's view of a user. The default [`UserStore`] maps the bundled `users`
/// entity onto this; a host can implement [`UserStore`] over its own table to use
/// an existing user model.
#[derive(Clone, Debug)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    /// `None` for accounts that can only authenticate via OAuth.
    pub password_hash: Option<String>,
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError>;

    /// Create a user. `password_hash` is `None` for OAuth-only accounts;
    /// `email_verified` records whether the address is already proven (OAuth, or a
    /// confirmed signup), letting the account be created verified in one write.
    async fn create(
        &self,
        email: &str,
        password_hash: Option<String>,
        email_verified: bool,
    ) -> Result<User, AuthError>;

    async fn set_password(&self, id: Uuid, password_hash: &str) -> Result<(), AuthError>;

    /// Mark an existing user's email verified. Implementations must be idempotent.
    async fn mark_email_verified(&self, id: Uuid) -> Result<(), AuthError>;
}
