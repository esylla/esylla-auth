//! Pending signups, stored until email verification creates the real account.
//! Keyed by the hashed verification token; single-use.

use std::time::Duration;

use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set};

use crate::crypto::token;
use crate::entity::pending_registration;
use crate::error::AuthError;

pub(crate) struct PendingRegistration {
    pub email: String,
    pub password_hash: String,
}

/// Replace any pending signup for this email and issue a fresh token, returning
/// the raw value to email. Replacing keeps only the latest token valid.
pub(crate) async fn upsert<C: ConnectionTrait>(
    db: &C,
    email: &str,
    password_hash: &str,
    ttl: Duration,
) -> Result<String, AuthError> {
    pending_registration::Entity::delete_many()
        .filter(pending_registration::Column::Email.eq(email))
        .exec(db)
        .await?;

    let raw = token::generate();
    let expires_at =
        Utc::now() + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::days(1));
    pending_registration::ActiveModel {
        token_hash: Set(token::hash(&raw)),
        email: Set(email.to_owned()),
        password_hash: Set(password_hash.to_owned()),
        expires_at: Set(expires_at),
        created_at: Set(Utc::now()),
    }
    .insert(db)
    .await?;
    Ok(raw)
}

/// Redeem a pending signup. The row is always consumed, so the token is single-use.
pub(crate) async fn consume<C: ConnectionTrait>(
    db: &C,
    raw: &str,
) -> Result<PendingRegistration, AuthError> {
    let hash = token::hash(raw);
    let Some(model) = pending_registration::Entity::find_by_id(hash)
        .one(db)
        .await?
    else {
        return Err(AuthError::InvalidToken);
    };
    let deleted = pending_registration::Entity::delete_by_id(model.token_hash.clone())
        .exec(db)
        .await?;
    if deleted.rows_affected == 0 {
        return Err(AuthError::InvalidToken);
    }
    if model.expires_at <= Utc::now() {
        return Err(AuthError::InvalidToken);
    }
    Ok(PendingRegistration {
        email: model.email,
        password_hash: model.password_hash,
    })
}
