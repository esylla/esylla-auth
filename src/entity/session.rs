use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "auth_sessions")]
pub struct Model {
    /// SHA-256 hash of the opaque session token; the raw token lives only in the
    /// client cookie.
    #[sea_orm(primary_key, auto_increment = false)]
    pub token_hash: String,
    pub user_id: Uuid,
    pub absolute_expiry: DateTimeUtc,
    /// Sliding expiry, advanced on each use.
    pub idle_expiry: DateTimeUtc,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
