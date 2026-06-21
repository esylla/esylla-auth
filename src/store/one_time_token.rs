//! Repository for one-time tokens (email verification, password reset). Stored
//! hashed in `auth_one_time_tokens`; single-use (deleted on lookup, valid or not).

use std::time::Duration;

use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, Set};
use uuid::Uuid;

use crate::crypto::token;
use crate::entity::one_time_token;
use crate::error::AuthError;

fn deadline(ttl: Duration) -> DateTime<Utc> {
    Utc::now() + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::zero())
}

/// Issue a token for `purpose`, returning the raw value to deliver to the user.
pub(crate) async fn issue<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    purpose: &str,
    ttl: Duration,
) -> Result<String, AuthError> {
    let raw = token::generate();
    one_time_token::ActiveModel {
        token_hash: Set(token::hash(&raw)),
        user_id: Set(user_id),
        purpose: Set(purpose.to_owned()),
        expires_at: Set(deadline(ttl)),
        created_at: Set(Utc::now()),
    }
    .insert(db)
    .await?;
    Ok(raw)
}

/// Redeem a token: returns the user id if it exists, matches `purpose`, and has
/// not expired. The row is always consumed, so it can never be replayed.
pub(crate) async fn consume<C: ConnectionTrait>(
    db: &C,
    raw: &str,
    purpose: &str,
) -> Result<Uuid, AuthError> {
    let hash = token::hash(raw);
    let Some(model) = one_time_token::Entity::find_by_id(hash).one(db).await? else {
        return Err(AuthError::InvalidToken);
    };
    // The delete is the atomic claim: if a concurrent caller already consumed the
    // row, we lost the race and must not honor the token.
    let deleted = one_time_token::Entity::delete_by_id(model.token_hash.clone())
        .exec(db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(AuthError::InvalidToken);
    }
    if model.purpose != purpose || model.expires_at <= Utc::now() {
        return Err(AuthError::InvalidToken);
    }
    Ok(model.user_id)
}
