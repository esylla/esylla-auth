//! Extending the auth user with host-owned data. esylla-auth owns identity; the
//! host keeps a `scores` table keyed by the auth user id and reads/writes it from
//! its own handler, authenticating with esylla-auth's `CurrentUser` extractor.
//!
//! Run: `cargo run --example with_score`

use std::sync::Arc;

use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::{FromRef, State};
use axum::http::{Request, StatusCode};
use axum::routing::get;
use esylla::Esylla;
use esylla_auth::{Auth, AuthConfig, AuthError, AuthServices, CurrentUser, Mailer};
use sea_orm::sea_query::OnConflict;
use sea_orm::{ConnectOptions, Database, DatabaseConnection, EntityTrait, Set};
use sea_orm_migration::prelude::*;
use tower::ServiceExt;

// ── the host's own table: one score row per auth user ──
mod score {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "scores")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub user_id: Uuid,
        pub score: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(DeriveMigrationName)]
struct CreateScores;

#[async_trait]
impl MigrationTrait for CreateScores {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("scores"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("user_id"))
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("score"))
                            .big_integer()
                            .not_null()
                            .default(0),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("scores"))
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(Clone)]
struct AppState {
    auth: AuthServices,
    db: DatabaseConnection,
}

// Auth handlers (and the `CurrentUser` extractor) pull `AuthServices` from state.
impl FromRef<AppState> for AuthServices {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

// ── host handlers: identity from esylla-auth, data from the host's own table ──

async fn read_score(State(state): State<AppState>, CurrentUser(user): CurrentUser) -> Json<i64> {
    let score = score::Entity::find_by_id(user.id)
        .one(&state.db)
        .await
        .unwrap()
        .map(|row| row.score)
        .unwrap_or(0);
    Json(score)
}

async fn add_point(State(state): State<AppState>, CurrentUser(user): CurrentUser) -> Json<i64> {
    let current = score::Entity::find_by_id(user.id)
        .one(&state.db)
        .await
        .unwrap()
        .map(|row| row.score)
        .unwrap_or(0);
    let next = current + 1;
    score::Entity::insert(score::ActiveModel {
        user_id: Set(user.id),
        score: Set(next),
    })
    .on_conflict(
        OnConflict::column(score::Column::UserId)
            .update_column(score::Column::Score)
            .to_owned(),
    )
    .exec(&state.db)
    .await
    .unwrap();
    Json(next)
}

// A mailer that captures the verification token so the example can complete signup.
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

    // The framework runs the auth module's migrations; the host runs its own.
    esylla::run_migrations(&db, &esylla_auth::migration::migrations())
        .await
        .unwrap();
    esylla::run_migrations(&db, &[Box::new(CreateScores) as Box<dyn MigrationTrait>])
        .await
        .unwrap();

    let mailer = CapturingMailer::default();
    let auth = AuthServices::new(db.clone(), Arc::new(mailer.clone()), AuthConfig::default());
    let state = AppState {
        auth: auth.clone(),
        db,
    };

    // Compose: the auth module + the host's own `/me/score` routes.
    let app = Esylla::new(state.clone())
        .module(Auth::new())
        .into_router()
        .merge(
            Router::new()
                .route("/me/score", get(read_score).post(add_point))
                .with_state(state),
        );

    // Provision a verified user and a session (using the public services).
    let ctx = Default::default();
    auth.signup("player@x.com", "longpassword", &ctx)
        .await
        .unwrap();
    let token = mailer.token.lock().unwrap().clone().unwrap();
    auth.verify_email(&token, &ctx).await.unwrap();
    let session = auth
        .login("player@x.com", "longpassword", &ctx)
        .await
        .unwrap();

    // The session cookie (default name + `__Host-` prefix for a secure cookie).
    let cookie = format!("__Host-session={session}");

    // Authenticated requests to the host's own endpoint, scored against the user.
    for _ in 0..3 {
        let response = app
            .clone()
            .oneshot(
                Request::post("/me/score")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let response = app
        .oneshot(
            Request::get("/me/score")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let score: i64 = serde_json::from_slice(&bytes).unwrap();
    println!("player@x.com score = {score}"); // 3
}
