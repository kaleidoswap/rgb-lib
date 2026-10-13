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
        wallet_dir: wallet.get_wallet_dir(),
        logger: wallet.logger().clone(),
        timestamp,
        database: Arc::clone(wallet.database_arc()),
        completions: vec![],
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

#[test]
fn snapshots_wait_for_rgb_writers_and_capture_matching_files_and_database() {
    let (_dir, wallet, _keys) = local_wallet(false);
    let marker = wallet.get_wallet_dir().join("rgb/state-marker");
    std::fs::write(&marker, b"before").unwrap();
    let runtime = crate::utils::load_rgb_runtime(wallet.get_wallet_dir()).unwrap();
    std::thread::scope(|scope| {
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let database = Arc::clone(wallet.database_arc());
        let wallet_dir = wallet.get_wallet_dir();
        let logger = wallet.logger().clone();
        scope.spawn(move || {
            started_tx.send(()).unwrap();
            done_tx
                .send(crate::wallet::backup::snapshot_wallet_dir(
                    &wallet_dir,
                    &database,
                    &logger,
                ))
                .unwrap();
        });
        started_rx.recv().unwrap();
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_millis(150))
                .is_err(),
            "snapshot must not read files while the runtime writer owns them"
        );
        std::fs::write(&marker, b"after").unwrap();
        let txn = wallet.database().begin_transaction().unwrap();
        wallet.update_backup_info(&txn, false).unwrap();
        let expected = txn
            .get_backup_info()
            .unwrap()
            .unwrap()
            .last_operation_timestamp;
        txn.commit().unwrap();
        drop(runtime);
        let (bytes, timestamp) = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap()
            .unwrap();
        assert_eq!(timestamp.to_string(), expected);
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
        let file = format!(
            "{}/rgb/state-marker",
            wallet
                .get_wallet_dir()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
        );
        let mut value = String::new();
        use std::io::Read;
        archive
            .by_name(&file)
            .unwrap()
            .read_to_string(&mut value)
            .unwrap();
        assert_eq!(value, "after");
    });
}

#[test]
fn snapshots_reject_reentrant_capture_and_exclude_transient_runtime_locks() {
    let (_dir, wallet, keys) = local_wallet(false);
    let runtime = crate::utils::load_rgb_runtime(wallet.get_wallet_dir()).unwrap();
    assert!(
        matches!(wallet.create_vss_snapshot(), Err(Error::Internal { details }) if details == "cannot snapshot an active RGB runtime")
    );
    drop(runtime);
    let (bytes, _) = wallet.create_vss_snapshot().unwrap();
    let restored_dir = tempfile::tempdir().unwrap();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).unwrap();
    for i in 0..archive.len() {
        assert!(
            !archive
                .by_index(i)
                .unwrap()
                .name()
                .ends_with("rgb_runtime.lock")
        );
    }
    archive.extract(restored_dir.path()).unwrap();
    Wallet::load(
        restored_dir.path().to_str().unwrap(),
        &keys.master_fingerprint,
        Some(keys.mnemonic),
    )
    .unwrap();
}

#[test]
fn queued_auto_backups_do_not_build_intermediate_snapshots() {
    let (_dir, mut wallet, _) = local_wallet(false);
    wallet.get_address().unwrap();
    let client = Arc::new(VssBackupClient::new(config().with_auto_backup(true)).unwrap());
    let generation = client
        .queue_auto_backup(PendingAutoBackup {
            wallet_dir: wallet.get_wallet_dir(),
            logger: wallet.logger().clone(),
            timestamp: 0,
            database: Arc::clone(wallet.database_arc()),
            completions: vec![],
        })
        .unwrap();
    let _in_flight = client.next_auto_backup(generation).unwrap();
    wallet.set_vss_client(Some(Arc::clone(&client)));
    let runtime = crate::utils::load_rgb_runtime(wallet.get_wallet_dir()).unwrap();
    // Capturing here would fail because this thread owns an active runtime.
    // A busy worker must receive only a lightweight request, with no copy/ZIP.
    wallet.trigger_auto_backup();
    wallet.trigger_auto_backup();
    assert!(client.last_auto_backup_error().is_none());
    let latest = client.next_auto_backup(generation).unwrap();
    assert!(latest.timestamp > 0);
    assert_eq!(latest.wallet_dir, wallet.get_wallet_dir());
    drop(runtime);
    assert!(client.next_auto_backup(generation).is_none());
}

#[test]
fn failed_publication_does_not_acknowledge_new_wallet_operations() {
    use crate::wallet::vss::publication_tests::{Failure, MockVss};
    let (_dir, mut wallet, _) = local_wallet(false);
    let server = MockVss::new();
    wallet.get_address().unwrap();
    server
        .client
        .handle()
        .block_on(wallet.vss_backup(&server.client))
        .unwrap();
    assert!(!wallet.backup_info().unwrap());
    let baseline = server
        .client
        .handle()
        .block_on(server.client.download_backup())
        .unwrap();
    wallet.get_address().unwrap();
    server.state.lock().unwrap().failure = Some(Failure::Publish);
    assert!(
        server
            .client
            .handle()
            .block_on(wallet.vss_backup(&server.client))
            .is_err()
    );
    assert!(wallet.backup_info().unwrap());
    assert_eq!(
        server
            .client
            .handle()
            .block_on(server.client.download_backup())
            .unwrap(),
        baseline
    );
    server.state.lock().unwrap().failure = None;
    server
        .client
        .handle()
        .block_on(wallet.vss_backup(&server.client))
        .unwrap();
    assert!(!wallet.backup_info().unwrap());
}

#[test]
fn restore_removes_stale_runtime_locks_from_legacy_backups() {
    use crate::wallet::vss::{
        BackupManifest, VssEncryptionMetadata, encrypt_data, publication_tests::MockVss,
        restore_from_vss,
    };
    use std::io::Write;
    let (_dir, mut wallet, keys) = local_wallet(true);
    let address = wallet.get_address().unwrap();
    let (bytes, _) = wallet.create_vss_snapshot().unwrap();
    let mut zip = zip::ZipWriter::new_append(std::io::Cursor::new(bytes)).unwrap();
    zip.start_file(
        format!("{}/rgb_runtime.lock", keys.master_fingerprint),
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zip.write_all(b"").unwrap();
    let bytes = zip.finish().unwrap().into_inner();
    let server = MockVss::new();
    let metadata = VssEncryptionMetadata::new();
    let data = encrypt_data(&bytes, &server.config.signing_key, &metadata, None).unwrap();
    let manifest = BackupManifest {
        chunk_count: 1,
        total_size: data.len(),
        encrypted: true,
        version: 1,
        generation: None,
    };
    {
        let mut state = server.state.lock().unwrap();
        state.seed("backup/manifest", serde_json::to_vec(&manifest).unwrap());
        state.seed("backup/data", data);
        state.seed("backup/metadata", serde_json::to_vec(&metadata).unwrap());
        state.seed(
            "backup/fingerprint",
            keys.master_fingerprint.clone().into_bytes(),
        );
    }
    let restored_dir = tempfile::tempdir().unwrap();
    let restored = server
        .client
        .handle()
        .block_on(restore_from_vss(
            server.config.clone(),
            restored_dir.path().to_str().unwrap(),
        ))
        .unwrap();
    assert!(!restored.join("rgb_runtime.lock").exists());
    let mut loaded = Wallet::load(
        restored_dir.path().to_str().unwrap(),
        &keys.master_fingerprint,
        Some(keys.mnemonic),
    )
    .unwrap();
    assert_eq!(loaded.get_address().unwrap(), address);
}

#[test]
fn restore_uses_the_fingerprint_from_its_captured_generation() {
    use crate::wallet::vss::{publication_tests::MockVss, restore_from_vss};
    let (_dir_a, mut wallet_a, keys_a) = local_wallet(false);
    let (_dir_b, mut wallet_b, _keys_b) = local_wallet(false);
    wallet_a.get_address().unwrap();
    wallet_b.get_address().unwrap();
    let server = MockVss::new();
    server
        .client
        .handle()
        .block_on(wallet_a.vss_backup(&server.client))
        .unwrap();
    let a = server.state.lock().unwrap().objects["backup/manifest"]
        .value
        .clone();
    server
        .client
        .handle()
        .block_on(wallet_b.vss_backup(&server.client))
        .unwrap();
    let b = server.state.lock().unwrap().objects["backup/manifest"]
        .value
        .clone();
    {
        let mut state = server.state.lock().unwrap();
        state.seed("backup/manifest", a);
        state.switch_on_read = Some(b);
    }
    let target = tempfile::tempdir().unwrap();
    let restored = server
        .client
        .handle()
        .block_on(restore_from_vss(
            server.config.clone(),
            target.path().to_str().unwrap(),
        ))
        .unwrap();
    assert_eq!(
        restored.file_name().unwrap().to_str().unwrap(),
        keys_a.master_fingerprint
    );
    Wallet::load(
        target.path().to_str().unwrap(),
        &keys_a.master_fingerprint,
        Some(keys_a.mnemonic),
    )
    .unwrap();
}

#[test]
fn coalesced_requests_preserve_all_blocking_callers_and_release_them_on_completion() {
    let (_dir, wallet, _) = local_wallet(false);
    let client = Arc::new(VssBackupClient::new(config()).unwrap());
    let (first_tx, first_rx) = std::sync::mpsc::channel();
    let (second_tx, second_rx) = std::sync::mpsc::channel();
    let request = |timestamp, completion| PendingAutoBackup {
        wallet_dir: wallet.get_wallet_dir(),
        logger: wallet.logger().clone(),
        timestamp,
        database: Arc::clone(wallet.database_arc()),
        completions: vec![completion],
    };
    let generation = client.queue_auto_backup(request(1, first_tx)).unwrap();
    assert!(client.queue_auto_backup(request(2, second_tx)).is_none());
    assert!(matches!(
        first_rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert!(matches!(
        second_rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    let latest = client.next_auto_backup(generation).unwrap();
    assert_eq!(latest.timestamp, 2);
    assert_eq!(latest.completions.len(), 2);
    for completion in latest.completions {
        completion.send(()).unwrap();
    }
    client.wait_auto_backup(Some(first_rx));
    client.wait_auto_backup(Some(second_rx));
    assert!(client.last_auto_backup_error().is_none());
    assert!(client.next_auto_backup(generation).is_none());
}
