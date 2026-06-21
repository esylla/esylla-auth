//! Replacing the built-in signup with one that also collects a `nickname`.
//!
//! Because the account is created only when the email is verified (pending
//! registration), the nickname is stashed at signup and turned into a profile row
//! by an `AccountAdapter::on_signed_up` hook once the account actually exists.
//!
//! Run: `cargo run --example custom_signup`

use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::{FromRef, State};
use axum::http::{Request, StatusCode};
use axum::routing::post;
use esylla::{Esylla, ValidatedJson};
use esylla_auth::{
    AccountAdapter, Auth, AuthConfig, AuthError, AuthRoute, AuthServices, Mailer, RequestContext,
    User,
};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ConnectOptions, Database, DatabaseConnection, EntityTrait, Set};
use sea_orm_migration::prelude::*;
use serde::Deserialize;
use tower::ServiceExt;
use validator::Validate;

// ── host tables: a profile per user, and a place to stash the nickname until the
//    account is verified ──
mod profile {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "profiles")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub user_id: Uuid,
        pub nickname: String,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

mod pending_nickname {
    use sea_orm::entity::prelude::*;
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "pending_nicknames")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub email: String,
        pub nickname: String,
    }
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}
    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(DeriveMigrationName)]
struct CreateHostTables;

#[async_trait]
impl MigrationTrait for CreateHostTables {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("profiles"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("user_id"))
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Alias::new("nickname")).string().not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("pending_nicknames"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("email"))
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Alias::new("nickname")).string().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

#[derive(Clone)]
struct AppState {
    auth: AuthServices,
    db: DatabaseConnection,
}

impl FromRef<AppState> for AuthServices {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

// ── the custom signup: email + password (for auth) plus a host-owned nickname ──
#[derive(Debug, Deserialize, Validate)]
struct SignupRequest {
    #[validate(email, length(max = 254))]
    email: String,
    #[validate(length(min = 8, max = 4096))]
    password: String,
    #[validate(length(min = 1, max = 40))]
    nickname: String,
}

async fn signup(
    State(state): State<AppState>,
    ValidatedJson(body): ValidatedJson<SignupRequest>,
) -> Result<StatusCode, AuthError> {
    // Normalize the email the same way auth does, so the stash key matches the
    // user's email when the profile is created.
    let email = body.email.trim().to_lowercase();

    // Stash the nickname until the account is verified into existence.
    pending_nickname::Entity::insert(pending_nickname::ActiveModel {
        email: Set(email.clone()),
        nickname: Set(body.nickname),
    })
    .on_conflict(
        OnConflict::column(pending_nickname::Column::Email)
            .update_column(pending_nickname::Column::Nickname)
            .to_owned(),
    )
    .exec(&state.db)
    .await?;

    // The auth part is unchanged — pending registration + verification email.
    state
        .auth
        .signup(&email, &body.password, &RequestContext::default())
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// When the account is finally created (on verification), build its profile from
// the stashed nickname.
struct ProfileAdapter {
    db: DatabaseConnection,
}

#[async_trait]
impl AccountAdapter for ProfileAdapter {
    async fn on_signed_up(&self, user: &User, _ctx: &RequestContext) -> Result<(), AuthError> {
        let nickname = pending_nickname::Entity::find_by_id(user.email.clone())
            .one(&self.db)
            .await?
            .map(|row| row.nickname)
            .unwrap_or_else(|| "anonymous".to_owned());

        profile::Entity::insert(profile::ActiveModel {
            user_id: Set(user.id),
            nickname: Set(nickname),
        })
        .exec(&self.db)
        .await?;

        let _ = pending_nickname::Entity::delete_by_id(user.email.clone())
            .exec(&self.db)
            .await;
        Ok(())
    }
}

#[derive(Clone, Default)]
struct CapturingMailer {
    token: Arc<std::sync::Mutex<Option<String>>>,
}

#[async_trait]
impl Mailer for CapturingMailer {
    async fn send_verification_email(&self, _to: &str, token: &str) -> Result<(), AuthError> {
        *self.token.lock().unwrap() = Some(token.to_owned());
        Ok(())
    }
    async fn send_password_reset_email(&self, _to: &str, _token: &str) -> Result<(), AuthError> {
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let mut options = ConnectOptions::new("sqlite::memory:");
    options.max_connections(1).min_connections(1);
    let db = Database::connect(options).await.unwrap();
    esylla::run_migrations(&db, &esylla_auth::migration::migrations())
        .await
        .unwrap();
    esylla::run_migrations(
        &db,
        &[Box::new(CreateHostTables) as Box<dyn MigrationTrait>],
    )
    .await
    .unwrap();

    let mailer = CapturingMailer::default();
    let auth = AuthServices::new(db.clone(), Arc::new(mailer.clone()), AuthConfig::default())
        .with_adapter(Arc::new(ProfileAdapter { db: db.clone() }));
    let state = AppState {
        auth: auth.clone(),
        db: db.clone(),
    };

    // Drop the built-in signup; mount our own at the same path.
    let app = Esylla::new(state.clone())
        .module(Auth::new().without(&[AuthRoute::Signup]))
        .into_router()
        .merge(
            Router::new()
                .route("/auth/signup", post(signup))
                .with_state(state),
        );

    // Sign up with a nickname.
    let response = app
        .oneshot(
            Request::post("/auth/signup")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"a@b.com","password":"longpassword","nickname":"Ace"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify the email → the account is created and `on_signed_up` writes the profile.
    let token = mailer.token.lock().unwrap().clone().unwrap();
    auth.verify_email(&token, &RequestContext::default())
        .await
        .unwrap();

    // The user now exists with a profile carrying the nickname.
    let user = auth
        .authenticate(
            &auth
                .login("a@b.com", "longpassword", &RequestContext::default())
                .await
                .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let nickname = profile::Entity::find_by_id(user.id)
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .nickname;
    println!("{} has nickname {nickname}", user.email); // a@b.com has nickname Ace
}
