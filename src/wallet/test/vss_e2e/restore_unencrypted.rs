use crate::wallet::test::utils::vss::{
    generate_signing_key_and_store_id, seed_legacy_plaintext_backup, tokio_runtime, vss_server_url,
};
use crate::wallet::vss::{VssBackupClient, VssBackupConfig, restore_from_vss};

// A historical sanitized plaintext store remains readable. New library uploads
// cannot create this format; fixtures seed the raw VSS protocol directly.
#[test]
fn legacy_plaintext_restore_preserves_rgb_files_without_bdk_or_manifest() {
    use std::io::Write;
    let rt = tokio_runtime();
    let url = vss_server_url();
    let (key, store) = generate_signing_key_and_store_id("legacy_plaintext_restore");
    let mut bytes = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut bytes);
        let options = zip::write::SimpleFileOptions::default();
        zip.add_directory("a1b2c3d4/", options).unwrap();
        for (path, contents) in [
            ("a1b2c3d4/rgb_lib_db", b"historical RGB database".as_slice()),
            ("a1b2c3d4/assets/asset.dat", b"historical asset".as_slice()),
            ("a1b2c3d4/bdk_db", b"historical BDK store".as_slice()),
            (
                "a1b2c3d4/wallet_manifest.json",
                b"private descriptors".as_slice(),
            ),
        ] {
            zip.start_file(path, options).unwrap();
            zip.write_all(contents).unwrap();
        }
        zip.finish().unwrap();
    }
    rt.block_on(seed_legacy_plaintext_backup(
        &url,
        &store,
        key,
        bytes.into_inner(),
    ));
    let config = VssBackupConfig::new(url, store, key).with_encryption(false);
    let client = VssBackupClient::new(config.clone()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let restored = rt
        .block_on(restore_from_vss(config, dir.path().to_str().unwrap()))
        .unwrap();
    assert_eq!(restored.file_name().unwrap(), "a1b2c3d4");
    assert_eq!(
        std::fs::read(restored.join("rgb_lib_db")).unwrap(),
        b"historical RGB database"
    );
    assert_eq!(
        std::fs::read(restored.join("assets/asset.dat")).unwrap(),
        b"historical asset"
    );
    assert!(!restored.join("bdk_db").exists());
    assert!(!restored.join("wallet_manifest.json").exists());
    rt.block_on(client.delete_backup()).unwrap();
}
