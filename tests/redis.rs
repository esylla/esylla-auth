//! `RedisSessionStore` against a real Redis started via testcontainers: the user
//! and token tables stay in SQLite while sessions live in Redis, exercising
//! create/get/touch/delete and `delete_for_user`. Requires Docker and the `redis`
//! feature.
#![cfg(feature = "redis")]

mod common;

use std::sync::Arc;

use common::{TestMailer, ctx};
use esylla_auth::config::AuthConfig;
use esylla_auth::redis::Client;
use esylla_auth::redis::aio::ConnectionManager;
use esylla_auth::{AuthServices, RedisSessionStore};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use testcontainers_modules::redis::Redis;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

#[tokio::test]
async fn sessions_on_redis() {
    let mut opt = ConnectOptions::new("sqlite::memory:");
    opt.max_connections(1).min_connections(1);
    let db: DatabaseConnection = Database::connect(opt).await.unwrap();
    esylla::run_migrations(&db, &esylla_auth::migration::migrations())
        .await
        .unwrap();

    let container = Redis::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(6379).await.unwrap();
    let client = Client::open(format!("redis://127.0.0.1:{port}")).unwrap();
    let conn = ConnectionManager::new(client).await.unwrap();

    let mailer = TestMailer::default();
    let svc = AuthServices::new(db, Arc::new(mailer.clone()), AuthConfig::default())
        .with_session_store(Arc::new(RedisSessionStore::new(conn)));

    svc.signup("a@b.com", "longpassword", &ctx()).await.unwrap();
    svc.verify_email(&mailer.token(), &ctx()).await.unwrap();

    let session = svc.login("a@b.com", "longpassword", &ctx()).await.unwrap();
    assert_eq!(
        svc.authenticate(&session).await.unwrap().unwrap().email,
        "a@b.com"
    );

    // logout deletes the session
    svc.logout(&session).await.unwrap();
    assert!(svc.authenticate(&session).await.unwrap().is_none());

    // change_password revokes all of the user's sessions (delete_for_user)
    let session = svc.login("a@b.com", "longpassword", &ctx()).await.unwrap();
    let user = svc
        .authenticate(&session)
        .await
        .unwrap()
        .expect("session valid");
    svc.change_password(user.id, "longpassword", "newlongpassword")
        .await
        .unwrap();
    assert!(svc.authenticate(&session).await.unwrap().is_none());
}
