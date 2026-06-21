//! Default sea-orm-backed implementations of [`UserStore`] and [`SessionStore`],
//! over the bundled `auth_users` / `auth_sessions` tables. A host can swap either
//! for its own backend.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::entity::{session, user};
use crate::error::AuthError;
use crate::store::{SessionRecord, SessionStore, User, UserStore};

fn to_user(model: user::Model) -> User {
    User {
        id: model.id,
        email: model.email,
        email_verified: model.email_verified_at.is_some(),
        password_hash: model.password_hash,
    }
}

fn idle_deadline(idle_ttl: Duration) -> DateTime<Utc> {
    let delta =
        chrono::Duration::from_std(idle_ttl).unwrap_or_else(|_| chrono::Duration::days(36_500));
    Utc::now() + delta
}

#[derive(Clone)]
pub struct DbUserStore {
    db: DatabaseConnection,
}

impl DbUserStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl UserStore for DbUserStore {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AuthError> {
        Ok(user::Entity::find_by_id(id)
            .one(&self.db)
            .await?
            .map(to_user))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AuthError> {
        Ok(user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(&self.db)
            .await?
            .map(to_user))
    }

    async fn create(
        &self,
        email: &str,
        password_hash: Option<String>,
        email_verified: bool,
    ) -> Result<User, AuthError> {
        let now = Utc::now();
        let model = user::ActiveModel {
            id: Set(Uuid::now_v7()),
            email: Set(email.to_owned()),
            email_verified_at: Set(email_verified.then_some(now)),
            password_hash: Set(password_hash),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&self.db)
        .await?;
        Ok(to_user(model))
    }

    async fn set_password(&self, id: Uuid, password_hash: &str) -> Result<(), AuthError> {
        user::ActiveModel {
            id: Set(id),
            password_hash: Set(Some(password_hash.to_owned())),
            updated_at: Set(Utc::now()),
            ..Default::default()
        }
        .update(&self.db)
        .await?;
        Ok(())
    }

    async fn mark_email_verified(&self, id: Uuid) -> Result<(), AuthError> {
        user::ActiveModel {
            id: Set(id),
            email_verified_at: Set(Some(Utc::now())),
            updated_at: Set(Utc::now()),
            ..Default::default()
        }
        .update(&self.db)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct DbSessionStore {
    db: DatabaseConnection,
}

impl DbSessionStore {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl SessionStore for DbSessionStore {
    async fn create(
        &self,
        token_hash: &str,
        record: SessionRecord,
        idle_ttl: Duration,
    ) -> Result<(), AuthError> {
        let absolute = DateTime::from_timestamp(record.absolute_expiry, 0).unwrap_or_else(Utc::now);
        let idle = idle_deadline(idle_ttl).min(absolute);
        session::ActiveModel {
            token_hash: Set(token_hash.to_owned()),
            user_id: Set(record.user_id),
            absolute_expiry: Set(absolute),
            idle_expiry: Set(idle),
            created_at: Set(Utc::now()),
        }
        .insert(&self.db)
        .await?;
        Ok(())
    }

    async fn get(&self, token_hash: &str) -> Result<Option<SessionRecord>, AuthError> {
        let Some(model) = session::Entity::find_by_id(token_hash.to_owned())
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };

        let now = Utc::now();
        if model.idle_expiry <= now || model.absolute_expiry <= now {
            let _ = session::Entity::delete_by_id(model.token_hash)
                .exec(&self.db)
                .await;
            return Ok(None);
        }

        Ok(Some(SessionRecord {
            user_id: model.user_id,
            absolute_expiry: model.absolute_expiry.timestamp(),
        }))
    }

    async fn touch(&self, token_hash: &str, idle_ttl: Duration) -> Result<(), AuthError> {
        let Some(model) = session::Entity::find_by_id(token_hash.to_owned())
            .one(&self.db)
            .await?
        else {
            return Ok(());
        };
        let new_idle = idle_deadline(idle_ttl).min(model.absolute_expiry);
        session::ActiveModel {
            token_hash: Set(model.token_hash),
            idle_expiry: Set(new_idle),
            ..Default::default()
        }
        .update(&self.db)
        .await?;
        Ok(())
    }

    async fn delete(&self, token_hash: &str) -> Result<(), AuthError> {
        session::Entity::delete_by_id(token_hash.to_owned())
            .exec(&self.db)
            .await?;
        Ok(())
    }

    async fn delete_for_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        session::Entity::delete_many()
            .filter(session::Column::UserId.eq(user_id))
            .exec(&self.db)
            .await?;
        Ok(())
    }
}
