use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("auth_oauth_states"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("state_hash"))
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Alias::new("provider")).string().not_null())
                    .col(
                        ColumnDef::new(Alias::new("pkce_verifier"))
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Alias::new("nonce")).string().null())
                    .col(
                        ColumnDef::new(Alias::new("expires_at"))
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("created_at"))
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("auth_oauth_states"))
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}
