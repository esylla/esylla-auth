//! Persistence for OAuth account links (`auth_oauth_connections`).

use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::entity::oauth_connection;
use crate::error::AuthError;

/// The user linked to a `(provider, account_id)`, if any.
pub(crate) async fn find_user<C: ConnectionTrait>(
    db: &C,
    provider: &str,
    account_id: &str,
) -> Result<Option<Uuid>, AuthError> {
    Ok(oauth_connection::Entity::find()
        .filter(oauth_connection::Column::Provider.eq(provider))
        .filter(oauth_connection::Column::ProviderAccountId.eq(account_id))
        .one(db)
        .await?
        .map(|model| model.user_id))
}

pub(crate) async fn link<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    provider: &str,
    account_id: &str,
) -> Result<(), AuthError> {
    oauth_connection::ActiveModel {
        id: Set(Uuid::now_v7()),
        user_id: Set(user_id),
        provider: Set(provider.to_owned()),
        provider_account_id: Set(account_id.to_owned()),
        created_at: Set(Utc::now()),
    }
    .insert(db)
    .await?;
    Ok(())
}
