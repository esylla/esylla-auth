//! Schema migrations contributed by the auth module.

use sea_orm_migration::MigrationTrait;

mod m20260621_000001_create_auth_tables;
mod m20260621_000002_create_oauth_state;
mod m20260621_000003_create_pending_registration;

/// All migrations, in order. The module hands these to the framework's builder.
pub fn migrations() -> Vec<Box<dyn MigrationTrait>> {
    vec![
        Box::new(m20260621_000001_create_auth_tables::Migration),
        Box::new(m20260621_000002_create_oauth_state::Migration),
        Box::new(m20260621_000003_create_pending_registration::Migration),
    ]
}
