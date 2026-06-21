use sea_orm::entity::prelude::*;

/// A signup awaiting email verification. The real `auth_users` row is created
/// only when the token is verified, so an unverified email never reserves an
/// account. Keyed by the SHA-256 hash of the verification token.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "auth_pending_registrations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub token_hash: String,
    pub email: String,
    pub password_hash: String,
    pub expires_at: DateTimeUtc,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
