pub use sea_orm_migration::prelude::*;

mod m20230608_071249_init_db;
mod m20251017_074408_asset_update;
mod m20251105_132121_asset_update;
mod m20251215_124959_backup_info_update;
mod m20260414_134758_add_reserved_txo;
mod m20260415_000001_create_reuse_address_index_table;
mod m20260625_121819_incoming_rework;
mod m20260727_115821_add_bdk_tables;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    // Ignore bookkeeping from the retired external signer. Its integration and
    // table migration are removed; existing ordinary wallets must still upgrade.
    async fn get_migration_models<C>(
        db: &C,
    ) -> Result<Vec<sea_orm_migration::seaql_migrations::Model>, DbErr>
    where
        C: ConnectionTrait,
    {
        use sea_orm_migration::sea_orm::EntityTrait;
        Self::install(db).await?;
        let models = sea_orm_migration::seaql_migrations::Entity::find()
            .all(db)
            .await?;
        Ok(models
            .into_iter()
            .filter(|model| model.version != "m20260401_000001_create_mpc_address_table")
            .collect())
    }

    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230608_071249_init_db::Migration),
            Box::new(m20251017_074408_asset_update::Migration),
            Box::new(m20251105_132121_asset_update::Migration),
            Box::new(m20251215_124959_backup_info_update::Migration),
            Box::new(m20260414_134758_add_reserved_txo::Migration),
            Box::new(m20260625_121819_incoming_rework::Migration),
            Box::new(m20260727_115821_add_bdk_tables::Migration),
            Box::new(m20260415_000001_create_reuse_address_index_table::Migration),
        ]
    }
}
