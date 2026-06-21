use sea_orm::entity::prelude::*;

/// Short-lived OAuth authorization state, keyed by the SHA-256 hash of the opaque
/// `state` value. Holds the PKCE verifier and (for OIDC) the nonce until the
/// provider redirects back. Single-use and time-limited.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "auth_oauth_states")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub state_hash: String,
    pub provider: String,
    pub pkce_verifier: String,
    pub nonce: Option<String>,
    pub expires_at: DateTimeUtc,
    pub created_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
