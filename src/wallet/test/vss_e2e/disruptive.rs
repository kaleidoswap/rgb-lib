use super::*;

use crate::wallet::test::utils::vss::{
    VssServerRestartGuard, dir_has_any_subdir, generate_signing_key_and_store_id, start_vss_server,
    stop_vss_server, tokio_runtime, vss_server_url, wait_tcp_up_http_url,
};

use crate::wallet::test::utils::vss::VssBackupDeleteGuard;

use crate::wallet::vss::{VssBackupClient, VssBackupConfig, restore_from_vss};

// Block 4 / Scenario 4.2:
// VSS server unavailable -> vss_backup/restore_from_vss must fail cleanly.
#[cfg(feature = "electrum")]
#[test]
#[serial]
#[ignore = "Disruptive (stops VSS docker service); run manually."]
fn scenario_4_2_vss_unavailable_backup_and_restore_fail_cleanly() {
    initialize();

    let vss_url = vss_server_url();
    let rt = tokio_runtime();

    let (mut wallet_a, online_a) = get_funded_noutxo_wallet!();

    // Ensure wallet has a non-trivial on-chain state (funded address already exists via helper).
    let _ = wallet_a
        .get_btc_balance(Some(online_a), false)
        .expect("get_btc_balance");

    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_neg_vss_down");
    let config = VssBackupConfig::new(vss_url.clone(), store_id, signing_key);
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    let client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");

    // Establish a baseline backup while VSS is up.
    let _baseline = rt
        .block_on(wallet_a.vss_backup(&client))
        .expect("baseline vss_backup");
    assert!(
        !wallet_a.backup_info().expect("backup_info"),
        "precondition: backup_info=false immediately after successful baseline VSS backup"
    );

    // Make a state change after baseline backup so backup_info becomes true deterministically.
    let _ = wallet_a.get_address().expect("get_address");
    let backup_required_before = wallet_a.backup_info().expect("backup_info");
    assert!(
        backup_required_before,
        "precondition: expected backup_info=true after a state change following baseline backup"
    );

    // Stop VSS server and ensure it is restarted even on panic (fallback only).
    let mut restart_guard = VssServerRestartGuard::new();
    stop_vss_server().expect("stop_vss_server");

    let mut backup_info_bug: Option<String> = None;

    // vss_backup must fail, and must not mark wallet as backed up.
    let err = match rt.block_on(wallet_a.vss_backup(&client)) {
        Ok(v) => panic!("Expected vss_backup to fail, but it succeeded: {v}"),
        Err(e) => e,
    };
    match &err {
        Error::VssError { .. } => {}
        other => panic!("Expected VssError from vss_backup, got: {other:?}"),
    }

    let backup_required_after = wallet_a.backup_info().expect("backup_info");
    if backup_required_after != backup_required_before {
        // Known bug: failed vss_backup may incorrectly clear backup_info.
        backup_info_bug = Some(format!(
            "BUG: backup_info changed after failed vss_backup: before={backup_required_before}, after={backup_required_after}"
        ));
    }

    // restore_from_vss must fail and must not extract any wallet data.
    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();
    let err = match rt.block_on(restore_from_vss(config, restore_root)) {
        Ok(p) => panic!(
            "Expected restore_from_vss to fail with VSS down, but it succeeded: {}",
            p.display()
        ),
        Err(e) => e,
    };
    match &err {
        Error::VssError { .. } | Error::VssBackupNotFound | Error::VssAuth { .. } => {}
        other => panic!("Expected VSS-related error from restore, got: {other:?}"),
    }
    assert!(
        !dir_has_any_subdir(std::path::Path::new(restore_root)),
        "restore root must not contain any subdirectories on failure (only log files are expected)"
    );

    // Bring VSS back.
    start_vss_server().expect("start_vss_server");
    restart_guard.mark_restarted();
    wait_tcp_up_http_url(&vss_url, Duration::from_secs(30)).expect("wait VSS up");

    if let Some(msg) = backup_info_bug {
        panic!("{msg}");
    }

    rt.block_on(client.delete_backup()).ok();
    cleanup.disarm();
}
