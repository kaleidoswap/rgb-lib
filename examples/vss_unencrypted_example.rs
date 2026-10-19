//! New VSS uploads require encryption. Legacy plaintext backups remain readable.
//! Run with `cargo run --example vss_unencrypted_example --features vss`.
use bdk_wallet::bitcoin::secp256k1::{Secp256k1, rand::rngs::OsRng};
use rgb_lib::{
    Error,
    wallet::vss::{VssBackupClient, VssBackupConfig},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (key, _) = Secp256k1::new().generate_keypair(&mut OsRng);
    let config = VssBackupConfig::new("http://localhost:8081/vss".into(), "example".into(), key)
        .with_encryption(false);
    let client = VssBackupClient::new(config)?;
    assert!(matches!(
        client.upload_backup(vec![]).await,
        Err(Error::VssEncryptionRequired)
    ));
    println!("Plaintext uploads are rejected. Use encryption for every new backup.");
    // For an existing legacy store, use its original signing key and store ID with
    // restore_from_vss(config, target_dir). Download detects the stored format.
    Ok(())
}
