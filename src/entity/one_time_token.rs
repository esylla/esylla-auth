use sea_orm::entity::prelude::*;

/// One-time tokens bound to an existing user (currently password reset; email
/// verification uses `auth_pending_registrations`). Stored as a SHA-256 hash,
/// single-use (deleted on redemption), and time-limited.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "auth_one_time_tokens")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub token_hash: String,
    pub user_id: Uuid,
    /// The token's purpose, e.g. `"password_reset"`. Kept generic for future flows.
    pub purpose: String,
    pub expires_at: DateTimeUtc,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
