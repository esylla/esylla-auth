//! Short-lived OAuth authorization state, stored hashed in `auth_oauth_states`.
//! Single-use: consumed (deleted) on callback.

use std::time::Duration;

use chrono::Utc;
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, Set};

use crate::crypto::token;
use crate::entity::oauth_state;
use crate::error::AuthError;

pub(crate) struct StoredState {
    pub provider: String,
    pub pkce_verifier: String,
    pub nonce: Option<String>,
}

pub(crate) async fn issue<C: ConnectionTrait>(
    db: &C,
    state: &str,
    provider: &str,
    pkce_verifier: &str,
    nonce: Option<&str>,
    ttl: Duration,
) -> Result<(), AuthError> {
    let expires_at =
        Utc::now() + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::zero());
    oauth_state::ActiveModel {
        state_hash: Set(token::hash(state)),
        provider: Set(provider.to_owned()),
        pkce_verifier: Set(pkce_verifier.to_owned()),
        nonce: Set(nonce.map(str::to_owned)),
        expires_at: Set(expires_at),
        created_at: Set(Utc::now()),
    }
    .insert(db)
    .await?;
    Ok(())
}

pub(crate) async fn consume<C: ConnectionTrait>(
    db: &C,
    state: &str,
) -> Result<StoredState, AuthError> {
    let hash = token::hash(state);
    let Some(model) = oauth_state::Entity::find_by_id(hash).one(db).await? else {
        return Err(AuthError::InvalidToken);
    };
    let deleted = oauth_state::Entity::delete_by_id(model.state_hash.clone())
        .exec(db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(AuthError::InvalidToken);
    }
    if model.expires_at <= Utc::now() {
        return Err(AuthError::InvalidToken);
    }
    Ok(StoredState {
        provider: model.provider,
        pkce_verifier: model.pkce_verifier,
        nonce: model.nonce,
    })
}
