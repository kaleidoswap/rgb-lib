use super::*;
use crate::wallet::vss::{PendingAutoBackup, VssBackupClient, VssBackupConfig};
use bdk_wallet::bitcoin::secp256k1::SecretKey;

fn local_wallet(reuse: bool) -> (tempfile::TempDir, Wallet, crate::keys::Keys) {
    let dir = tempfile::tempdir().unwrap();
    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::Taproot);
    let mut data = get_test_wallet_data(dir.path().to_str().unwrap());
    data.reuse_addresses = reuse;
    let wallet = Wallet::new(data, SinglesigKeys::from_keys(&keys, None)).unwrap();
    (dir, wallet, keys)
}

fn config() -> VssBackupConfig {
    VssBackupConfig::new(
        "http://127.0.0.1:1/vss".into(),
        "offline".into(),
        SecretKey::from_slice(&[1; 32]).unwrap(),
    )
}

#[test]
fn sqlite_snapshot_preserves_committed_bdk_and_pinned_addresses() {
    let (_dir, mut wallet, keys) = local_wallet(true);
    let initial = wallet.get_address().unwrap();
    let rotated = wallet.rotate_address(KeychainKind::Internal).unwrap();
    assert_ne!(initial, rotated);
    assert_eq!(wallet.get_address().unwrap(), rotated);
    let (bytes, timestamp) = wallet.create_vss_snapshot().unwrap();
    assert!(timestamp > 0);
    // Taking a snapshot alone never marks the live wallet as backed up.
    assert!(wallet.backup_info().unwrap());
    let restored_dir = tempfile::tempdir().unwrap();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    let names: Vec<_> = (0..archive.len())
        .map(|i| archive.by_index(i).unwrap().name().to_string())
        .collect();
    assert!(names.iter().any(|n| n.ends_with("/rgb_lib_db")));
    assert!(
        names
            .iter()
            .all(|n| !n.ends_with("-wal") && !n.ends_with("-shm"))
    );
    assert!(names.iter().any(|n| n.ends_with("/wallet_manifest.json")));
    archive.extract(restored_dir.path()).unwrap();
    let mut restored = Wallet::load(
        restored_dir.path().to_str().unwrap(),
        &keys.master_fingerprint,
        Some(keys.mnemonic),
    )
    .unwrap();
    assert!(restored.get_wallet_data().reuse_addresses);
    assert!(!restored.backup_info().unwrap());
    assert_eq!(restored.get_address().unwrap(), rotated);
    assert_eq!(
        restored.rotate_address(KeychainKind::Internal).unwrap(),
        wallet.rotate_address(KeychainKind::Internal).unwrap()
    );
}

#[test]
fn completed_snapshot_never_marks_a_later_operation_backed_up() {
    let (_dir, mut wallet, _) = local_wallet(false);
    wallet.get_address().unwrap();
    let (_, timestamp) = wallet.create_vss_snapshot().unwrap();
    wallet.get_address().unwrap();
    wallet
        .database()
        .mark_vss_snapshot_backed_up(timestamp)
        .unwrap();
    assert!(wallet.backup_info().unwrap());
    let txn = wallet.database().begin_transaction().unwrap();
    let info = txn.get_backup_info().unwrap().unwrap();
    assert_eq!(info.last_backup_timestamp, timestamp.to_string());
    txn.commit().unwrap();
    // An older upload completing out of order cannot regress backup progress.
    wallet
        .database()
        .mark_vss_snapshot_backed_up(timestamp - 1)
        .unwrap();
    let txn = wallet.database().begin_transaction().unwrap();
    assert_eq!(
        txn.get_backup_info()
            .unwrap()
            .unwrap()
            .last_backup_timestamp,
        timestamp.to_string()
    );
    txn.commit().unwrap();
}

#[test]
fn plaintext_configuration_and_upload_are_rejected_before_network_access() {
    let (_dir, mut wallet, _) = local_wallet(false);
    let config = config().with_encryption(false).with_auto_backup(true);
    assert!(matches!(
        wallet.configure_vss_backup(config.clone()),
        Err(Error::VssEncryptionRequired)
    ));
    assert!(wallet.vss_client().is_none());
    let client = VssBackupClient::new(config).unwrap();
    assert!(matches!(
        client.handle().block_on(client.upload_backup(vec![])),
        Err(Error::VssEncryptionRequired)
    ));
    assert!(matches!(
        client.handle().block_on(wallet.vss_backup(&client)),
        Err(Error::VssEncryptionRequired)
    ));
}

#[test]
fn auto_backup_queue_retains_the_latest_snapshot_and_ignores_stale_workers() {
    let (_dir, wallet, _) = local_wallet(false);
    let client = VssBackupClient::new(config()).unwrap();
    let snapshot = |timestamp| PendingAutoBackup {
        data: vec![timestamp as u8],
        timestamp,
        database: Arc::clone(wallet.database_arc()),
    };
    let first = client.queue_auto_backup(snapshot(1)).unwrap();
    assert_eq!(client.next_auto_backup(first).unwrap().timestamp, 1);
    assert!(client.queue_auto_backup(snapshot(2)).is_none());
    assert!(client.queue_auto_backup(snapshot(3)).is_none());
    assert_eq!(client.next_auto_backup(first).unwrap().timestamp, 3);
    assert!(client.next_auto_backup(first).is_none());
    let second = client.queue_auto_backup(snapshot(4)).unwrap();
    client.finish_auto_backup(first);
    assert_eq!(client.next_auto_backup(second).unwrap().timestamp, 4);
    client.finish_auto_backup(second);
    assert!(
        client
            .last_auto_backup_error()
            .unwrap()
            .contains("interrupted")
    );
    assert!(client.queue_auto_backup(snapshot(5)).is_some());
}
