use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // wallet-level data (descriptors and network); a single row pinned to ID 0, as in BDK
        manager
            .create_table(
                Table::create()
                    .table(BdkWallet::Table)
                    .if_not_exists()
                    .col(
                        integer(BdkWallet::Id)
                            .primary_key()
                            .check(Expr::col(BdkWallet::Id).eq(0)),
                    )
                    .col(string_null(BdkWallet::Descriptor))
                    .col(string_null(BdkWallet::ChangeDescriptor))
                    .col(string_null(BdkWallet::Network))
                    .to_owned(),
            )
            .await?;

        // locked outpoints
        manager
            .create_table(
                Table::create()
                    .table(BdkWalletLockedOutpoint::Table)
                    .if_not_exists()
                    .col(pk_auto(BdkWalletLockedOutpoint::Idx))
                    .col(string(BdkWalletLockedOutpoint::Txid))
                    .col(big_integer(BdkWalletLockedOutpoint::Vout))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                sea_query::Index::create()
                    .name("idx-bdkwalletlockedoutpoint-txid-vout")
                    .table(BdkWalletLockedOutpoint::Table)
                    .col(BdkWalletLockedOutpoint::Txid)
                    .col(BdkWalletLockedOutpoint::Vout)
                    .unique()
                    .clone(),
            )
            .await?;

        // local chain blocks
        manager
            .create_table(
                Table::create()
                    .table(BdkBlock::Table)
                    .if_not_exists()
                    .col(pk_auto(BdkBlock::Idx))
                    .col(big_integer(BdkBlock::BlockHeight))
                    .col(string(BdkBlock::BlockHash))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                sea_query::Index::create()
                    .name("idx-bdkblock-blockheight")
                    .table(BdkBlock::Table)
                    .col(BdkBlock::BlockHeight)
                    .unique()
                    .clone(),
            )
            .await?;

        // full transactions and their seen/evicted timestamps
        manager
            .create_table(
                Table::create()
                    .table(BdkTx::Table)
                    .if_not_exists()
                    .col(pk_auto(BdkTx::Idx))
                    .col(string(BdkTx::Txid))
                    .col(binary_null(BdkTx::RawTx))
                    .col(string_null(BdkTx::FirstSeen))
                    .col(string_null(BdkTx::LastSeen))
                    .col(string_null(BdkTx::LastEvicted))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                sea_query::Index::create()
                    .name("idx-bdktx-txid")
                    .table(BdkTx::Table)
                    .col(BdkTx::Txid)
                    .unique()
                    .clone(),
            )
            .await?;

        // floating txouts
        manager
            .create_table(
                Table::create()
                    .table(BdkTxout::Table)
                    .if_not_exists()
                    .col(pk_auto(BdkTxout::Idx))
                    .col(string(BdkTxout::Txid))
                    .col(big_integer(BdkTxout::Vout))
                    .col(string(BdkTxout::Value))
                    .col(binary(BdkTxout::Script))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                sea_query::Index::create()
                    .name("idx-bdktxout-txid-vout")
                    .table(BdkTxout::Table)
                    .col(BdkTxout::Txid)
                    .col(BdkTxout::Vout)
                    .unique()
                    .clone(),
            )
            .await?;

        // anchors (transaction confirmations); references its transaction like BDK's own schema
        manager
            .create_table(
                Table::create()
                    .table(BdkAnchor::Table)
                    .if_not_exists()
                    .col(pk_auto(BdkAnchor::Idx))
                    .col(string(BdkAnchor::Txid))
                    .col(big_integer(BdkAnchor::BlockHeight))
                    .col(string(BdkAnchor::BlockHash))
                    .col(string(BdkAnchor::ConfirmationTime))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-bdkanchor-bdktx")
                            .from(BdkAnchor::Table, BdkAnchor::Txid)
                            .to(BdkTx::Table, BdkTx::Txid)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                sea_query::Index::create()
                    .name("idx-bdkanchor-txid-blockheight-blockhash")
                    .table(BdkAnchor::Table)
                    .col(BdkAnchor::Txid)
                    .col(BdkAnchor::BlockHeight)
                    .col(BdkAnchor::BlockHash)
                    .unique()
                    .clone(),
            )
            .await?;

        // last revealed index per descriptor
        manager
            .create_table(
                Table::create()
                    .table(BdkDescriptorLastRevealed::Table)
                    .if_not_exists()
                    .col(pk_auto(BdkDescriptorLastRevealed::Idx))
                    .col(string(BdkDescriptorLastRevealed::DescriptorId))
                    .col(big_integer(BdkDescriptorLastRevealed::LastRevealed))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                sea_query::Index::create()
                    .name("idx-bdkdescriptorlastrevealed-descriptorid")
                    .table(BdkDescriptorLastRevealed::Table)
                    .col(BdkDescriptorLastRevealed::DescriptorId)
                    .unique()
                    .clone(),
            )
            .await?;

        // bdk_chain also has a table for the derived SPK cache, which is left out: it is only
        // written when the wallet is built with `use_spk_cache`, which rgb-lib never enables

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(BdkDescriptorLastRevealed::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(BdkAnchor::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(BdkTxout::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(BdkTx::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(BdkBlock::Table).to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(BdkWalletLockedOutpoint::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(BdkWallet::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum BdkWallet {
    Table,
    Id,
    Descriptor,
    ChangeDescriptor,
    Network,
}

#[derive(DeriveIden)]
enum BdkWalletLockedOutpoint {
    Table,
    Idx,
    Txid,
    Vout,
}

#[derive(DeriveIden)]
enum BdkBlock {
    Table,
    Idx,
    BlockHeight,
    BlockHash,
}

#[derive(DeriveIden)]
enum BdkTx {
    Table,
    Idx,
    Txid,
    RawTx,
    FirstSeen,
    LastSeen,
    LastEvicted,
}

#[derive(DeriveIden)]
enum BdkTxout {
    Table,
    Idx,
    Txid,
    Vout,
    Value,
    Script,
}

#[derive(DeriveIden)]
enum BdkAnchor {
    Table,
    Idx,
    Txid,
    BlockHeight,
    BlockHash,
    ConfirmationTime,
}

#[derive(DeriveIden)]
enum BdkDescriptorLastRevealed {
    Table,
    Idx,
    DescriptorId,
    LastRevealed,
}
