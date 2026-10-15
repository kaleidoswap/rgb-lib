//! VSS (Versioned Storage Service) backup module
//!
//! This module provides cloud backup functionality using VSS servers.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bdk_wallet::bitcoin::secp256k1::SecretKey;
// Note: this is the RustCrypto crate (XChaCha20). The similarly named
// `chacha20-poly1305` (rust-bitcoin, stateless-only) is a transitive dep
// of vss-client-ng via bitreq — they are not interchangeable.
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, aead::Aead};
use hkdf::Hkdf;

use serde::{Deserialize, Serialize};
use sha2::Sha256;
use slog::{Logger, debug, info};
use time::OffsetDateTime;
use vss_client::client::VssClient;
use vss_client::error::VssError;
use vss_client::headers::sigs_auth::SigsAuthProvider;
use vss_client::types::{GetObjectRequest, KeyValue, ListKeyVersionsRequest, PutObjectRequest};
use vss_client::util::retry::{
    ExponentialBackoffRetryPolicy, MaxAttemptsRetryPolicy, MaxTotalDelayRetryPolicy, RetryPolicy,
};
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;

use crate::error::{Error, InternalError};
use crate::utils::LOG_FILE;
use crate::utils::setup_logger;
use crate::wallet::backup::stream_be32_nonce;
#[cfg(test)]
use crate::wallet::core::WALLET_MANIFEST_FILE;

/// Whether auto-backup uploads block the calling operation or run asynchronously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VssBackupMode {
    /// Upload runs on a spawned tokio task (fire-and-forget). Default.
    #[default]
    Async,
    /// Upload blocks the calling operation until the backup is persisted.
    Blocking,
}

/// Type alias for our retry policy
type VssRetryPolicy =
    MaxTotalDelayRetryPolicy<MaxAttemptsRetryPolicy<ExponentialBackoffRetryPolicy<VssError>>>;

// Encryption constants (matching backup.rs)
const BACKUP_BUFFER_LEN_ENCRYPT: usize = 239;
const BACKUP_BUFFER_LEN_DECRYPT: usize = BACKUP_BUFFER_LEN_ENCRYPT + 16;
const BACKUP_KEY_LENGTH: usize = 32;
const BACKUP_NONCE_LENGTH: usize = 19;
const VSS_BACKUP_VERSION: u8 = 1;
const VSS_MANIFEST_VERSION: u8 = 2;
const BACKUP_GENERATION_PREFIX: &str = "backup/generations/";

/// Default chunk size for large backups
/// Kept under the upstream vss-client-ng 10-second HTTP timeout
/// so that each chunk PUT completes reliably
pub(crate) const VSS_CHUNK_SIZE: usize = 1024 * 1024; // 1MB

/// Key prefix for backup data
const BACKUP_KEY_DATA: &str = "backup/data";
/// Key prefix for backup metadata (encryption params)
const BACKUP_KEY_METADATA: &str = "backup/metadata";
/// Key prefix for backup manifest (chunk info)
const BACKUP_KEY_MANIFEST: &str = "backup/manifest";
/// Key prefix for backup chunks
const BACKUP_KEY_CHUNK_PREFIX: &str = "backup/chunk/";
/// Key for storing wallet fingerprint separately
const BACKUP_KEY_FINGERPRINT: &str = "backup/fingerprint";
/// Generic directory name used in sanitized (plaintext) backups
const SANITIZED_DIR_NAME: &str = "wallet";
/// Marker dropped in a restored wallet dir until its first successful
/// consistency check, so a failure there can be attributed to the restore.
pub(crate) const VSS_RESTORE_MARKER: &str = ".vss_restored";
/// BDK database filename
#[cfg(test)]
const BDK_DB_NAME: &str = "bdk_db";
/// BDK watch-only database filename
#[cfg(test)]
const BDK_DB_WO_NAME: &str = "bdk_db_watch_only";

/// Salt length for HKDF key derivation (32 bytes, hex-encoded = 64 chars)
const BACKUP_SALT_LENGTH: usize = 32;

/// Encryption metadata stored alongside encrypted backups
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VssEncryptionMetadata {
    /// Salt used for HKDF key derivation (hex encoded)
    pub salt: String,
    /// Nonce used for encryption
    pub nonce: String,
    /// Version of the encryption format
    pub version: u8,
}

impl Default for VssEncryptionMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl VssEncryptionMetadata {
    /// Create new encryption metadata with random salt and nonce
    pub fn new() -> Self {
        let salt: [u8; BACKUP_SALT_LENGTH] = rand::random();
        let nonce: [u8; BACKUP_NONCE_LENGTH] = rand::random();

        Self {
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            version: VSS_BACKUP_VERSION,
        }
    }

    fn nonce_bytes(&self) -> Result<[u8; BACKUP_NONCE_LENGTH], Error> {
        let bytes = hex::decode(&self.nonce).map_err(|e| Error::Internal {
            details: format!("Invalid nonce hex: {e}"),
        })?;
        bytes.as_slice().try_into().map_err(|_| Error::Internal {
            details: "Invalid nonce length".to_string(),
        })
    }
}

/// Configuration for VSS backup service
#[derive(Clone)]
pub struct VssBackupConfig {
    /// VSS server URL
    pub(crate) server_url: String,
    /// Store ID (namespace for this wallet's data)
    pub(crate) store_id: String,
    /// Private key for signing requests and deriving encryption key
    pub(crate) signing_key: SecretKey,
    /// Whether to encrypt data before uploading (default: true)
    pub(crate) encryption_enabled: bool,
    /// Whether to automatically back up after state-changing operations (default: false)
    pub(crate) auto_backup: bool,
    /// Whether auto-backup uploads block the caller or run asynchronously (default: Async)
    pub(crate) backup_mode: VssBackupMode,
}

impl VssBackupConfig {
    /// Create a new VSS backup configuration
    ///
    /// Encryption is enabled by default. The encryption key is derived from the
    /// signing key using HKDF-SHA256, so no separate password is needed.
    pub fn new(server_url: String, store_id: String, signing_key: SecretKey) -> Self {
        Self {
            server_url,
            store_id,
            signing_key,
            encryption_enabled: true,
            auto_backup: false,
            backup_mode: VssBackupMode::default(),
        }
    }

    /// Select encrypted uploads (required) or legacy plaintext restore support.
    ///
    /// Disabling encryption rejects uploads and wallet backup configuration.
    pub fn with_encryption(mut self, enabled: bool) -> Self {
        self.encryption_enabled = enabled;
        self
    }

    /// Enable or disable automatic backups after state-changing operations
    pub fn with_auto_backup(mut self, enabled: bool) -> Self {
        self.auto_backup = enabled;
        self
    }

    /// Set the auto-backup mode (Async or Blocking)
    pub fn with_backup_mode(mut self, mode: VssBackupMode) -> Self {
        self.backup_mode = mode;
        self
    }
}

/// Backup manifest for tracking chunked backups
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupManifest {
    /// Number of chunks
    pub chunk_count: usize,
    /// Total size in bytes
    pub total_size: usize,
    /// Whether the backup is encrypted
    pub encrypted: bool,
    /// Backup version
    pub version: u8,
    /// Immutable upload generation. Absent in legacy version-1 backups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
}

impl BackupManifest {
    pub(crate) fn chunk_key(&self, index: usize) -> String {
        match &self.generation {
            Some(generation) => format!("{BACKUP_GENERATION_PREFIX}{generation}/chunk/{index}"),
            None if self.chunk_count == 1 => BACKUP_KEY_DATA.to_string(),
            None => format!("{BACKUP_KEY_CHUNK_PREFIX}{index}"),
        }
    }

    pub(crate) fn metadata_key(&self) -> String {
        self.generation.as_ref().map_or_else(
            || BACKUP_KEY_METADATA.to_string(),
            |generation| format!("{BACKUP_GENERATION_PREFIX}{generation}/metadata"),
        )
    }

    pub(crate) fn fingerprint_key(&self) -> String {
        self.generation.as_ref().map_or_else(
            || BACKUP_KEY_FINGERPRINT.to_string(),
            |generation| format!("{BACKUP_GENERATION_PREFIX}{generation}/fingerprint"),
        )
    }

    fn validate(&self) -> Result<(), Error> {
        let valid_generation = match (self.version, &self.generation) {
            (VSS_BACKUP_VERSION, None) => true,
            (VSS_MANIFEST_VERSION, Some(generation)) => {
                generation.len() == 64 && generation.bytes().all(|b| b.is_ascii_hexdigit())
            }
            _ => false,
        };
        if !valid_generation || self.chunk_count == 0 {
            return Err(Error::Internal {
                details: "invalid or unsupported VSS backup manifest".to_string(),
            });
        }
        Ok(())
    }
}

pub(crate) struct PendingAutoBackup {
    pub(crate) wallet_dir: PathBuf,
    pub(crate) logger: Logger,
    pub(crate) timestamp: i128,
    pub(crate) database: Arc<crate::database::RgbLibDatabase>,
    pub(crate) completions: Vec<std::sync::mpsc::Sender<()>>,
}

#[derive(Default)]
struct AutoBackupState {
    generation: u64,
    running: bool,
    pending: Option<PendingAutoBackup>,
}

/// VSS backup client wrapper
pub struct VssBackupClient {
    client: VssClient<VssRetryPolicy>,
    store_id: String,
    encryption_enabled: bool,
    signing_key: SecretKey,
    auto_backup: bool,
    backup_mode: VssBackupMode,
    runtime: Option<tokio::runtime::Runtime>,
    last_auto_backup_error: std::sync::Mutex<Option<String>>,
    auto_backup_state: std::sync::Mutex<AutoBackupState>,
}

impl Drop for VssBackupClient {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

impl VssBackupClient {
    /// Create a new VSS backup client
    pub fn new(config: VssBackupConfig) -> Result<Self, Error> {
        let auth_provider = SigsAuthProvider::new(config.signing_key, HashMap::new());

        let retry_policy = ExponentialBackoffRetryPolicy::new(Duration::from_millis(100))
            .with_max_attempts(3)
            .with_max_total_delay(Duration::from_secs(5));

        let client =
            VssClient::new_with_headers(config.server_url, retry_policy, Arc::new(auth_provider));

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|e| Error::Internal {
                details: format!("Failed to create tokio runtime: {e}"),
            })?;

        Ok(Self {
            client,
            store_id: config.store_id,
            encryption_enabled: config.encryption_enabled,
            signing_key: config.signing_key,
            auto_backup: config.auto_backup,
            backup_mode: config.backup_mode,
            runtime: Some(runtime),
            last_auto_backup_error: std::sync::Mutex::new(None),
            auto_backup_state: std::sync::Mutex::new(AutoBackupState::default()),
        })
    }

    /// Queue the latest capture request while a prior upload is running.
    pub(crate) fn queue_auto_backup(&self, mut snapshot: PendingAutoBackup) -> Option<u64> {
        let mut state = self
            .auto_backup_state
            .lock()
            .expect("auto backup state lock");
        if let Some(mut previous) = state.pending.take() {
            snapshot.completions.append(&mut previous.completions);
        }
        state.pending = Some(snapshot);
        if state.running {
            return None;
        }
        state.running = true;
        state.generation = state.generation.wrapping_add(1);
        Some(state.generation)
    }

    pub(crate) fn next_auto_backup(&self, generation: u64) -> Option<PendingAutoBackup> {
        let mut state = self
            .auto_backup_state
            .lock()
            .expect("auto backup state lock");
        if state.generation != generation {
            return None;
        }
        let pending = state.pending.take();
        if pending.is_none() {
            state.running = false;
        }
        pending
    }

    pub(crate) fn finish_auto_backup(&self, generation: u64) {
        let mut state = self
            .auto_backup_state
            .lock()
            .expect("auto backup state lock");
        if state.generation == generation && state.running {
            state.running = false;
            state.pending = None;
            self.record_auto_backup_result(Some("auto backup task interrupted".to_string()));
        }
    }

    /// Error message of the most recent failed auto-backup, cleared on the
    /// next successful one. `None` when the last auto-backup succeeded or none
    /// ran yet.
    pub fn last_auto_backup_error(&self) -> Option<String> {
        self.last_auto_backup_error.lock().unwrap().clone()
    }

    pub(crate) fn record_auto_backup_result(&self, error: Option<String>) {
        *self.last_auto_backup_error.lock().unwrap() = error;
    }

    pub(crate) fn wait_auto_backup(&self, receiver: Option<std::sync::mpsc::Receiver<()>>) {
        if let Some(receiver) = receiver
            && receiver.recv().is_err()
        {
            self.record_auto_backup_result(Some("auto backup task interrupted".to_string()));
        }
    }

    /// Get a handle to the client's tokio runtime
    pub fn handle(&self) -> &tokio::runtime::Handle {
        self.runtime
            .as_ref()
            .expect("runtime not available")
            .handle()
    }

    /// Upload backup data to VSS server
    ///
    /// If encryption is enabled, data will be encrypted before upload.
    /// The encryption key is derived from the signing key using HKDF-SHA256.
    ///
    /// New backups require encryption and preserve the complete wallet state.
    /// Encryption-disabled clients remain usable for restoring legacy backups.
    ///
    /// Returns the version number of the uploaded backup.
    pub async fn upload_backup(&self, data: Vec<u8>) -> Result<i64, Error> {
        if !self.encryption_enabled {
            return Err(Error::VssEncryptionRequired);
        }
        let fingerprint = get_fingerprint_from_zip_bytes(&data)?;
        // Pin the publication version before staging. A slow upload cannot
        // replace a newer backup committed by another client in the meantime.
        let manifest_version = self
            .get_current_version(BACKUP_KEY_MANIFEST)
            .await?
            .unwrap_or(0);
        let legacy_metadata_version = self
            .get_current_version(BACKUP_KEY_METADATA)
            .await?
            .unwrap_or(0);
        let legacy_fingerprint_version = self
            .get_current_version(BACKUP_KEY_FINGERPRINT)
            .await?
            .unwrap_or(0);
        let metadata = VssEncryptionMetadata::new();
        let upload_data = encrypt_data(&data, &self.signing_key, &metadata, None)?;
        drop(data);
        let generation = hex::encode(rand::random::<[u8; 32]>());
        let manifest = BackupManifest {
            chunk_count: upload_data.len().div_ceil(VSS_CHUNK_SIZE),
            total_size: upload_data.len(),
            encrypted: true,
            version: VSS_MANIFEST_VERSION,
            generation: Some(generation),
        };
        for (index, chunk) in upload_data.chunks(VSS_CHUNK_SIZE).enumerate() {
            self.client
                .put_object(&PutObjectRequest {
                    store_id: self.store_id.clone(),
                    global_version: None,
                    transaction_items: vec![KeyValue {
                        key: manifest.chunk_key(index),
                        version: 0,
                        value: chunk.to_vec(),
                    }],
                    delete_items: vec![],
                })
                .await
                .map_err(vss_error_to_rgb_error)?;
        }
        // The one mutable pointer and its generation-specific metadata become
        // visible atomically. Published generations are retained for readers
        // that fetched an earlier manifest; delete_backup removes all of them.
        self.client
            .put_object(&PutObjectRequest {
                store_id: self.store_id.clone(),
                global_version: None,
                transaction_items: vec![
                    KeyValue {
                        key: BACKUP_KEY_MANIFEST.to_string(),
                        version: manifest_version,
                        value: serde_json::to_vec(&manifest).map_err(InternalError::from)?,
                    },
                    KeyValue {
                        key: manifest.metadata_key(),
                        version: 0,
                        value: serde_json::to_vec(&metadata).map_err(InternalError::from)?,
                    },
                    KeyValue {
                        key: manifest.fingerprint_key(),
                        version: 0,
                        value: fingerprint.as_bytes().to_vec(),
                    },
                    // Old clients ignore unknown manifest fields and versions.
                    // Rotate their metadata too: they must fail to decrypt old
                    // data rather than silently restore an obsolete v1 backup.
                    KeyValue {
                        key: BACKUP_KEY_METADATA.to_string(),
                        version: legacy_metadata_version,
                        value: serde_json::to_vec(&metadata).map_err(InternalError::from)?,
                    },
                    KeyValue {
                        key: BACKUP_KEY_FINGERPRINT.to_string(),
                        version: legacy_fingerprint_version,
                        value: fingerprint.into_bytes(),
                    },
                ],
                delete_items: vec![],
            })
            .await
            .map_err(vss_error_to_rgb_error)?;
        Ok(manifest_version + 1)
    }

    /// Download backup data from VSS server
    ///
    /// If the backup was encrypted, it will be decrypted using a key derived from
    /// the signing key via HKDF-SHA256.
    pub async fn download_backup(&self) -> Result<Vec<u8>, Error> {
        let (_, data, _) = self.download_record().await?;
        Ok(data)
    }

    async fn download_record(&self) -> Result<(BackupManifest, Vec<u8>, String), Error> {
        for _ in 0..3 {
            let manifest = self.get_manifest().await?;
            let data = self.download_manifest(&manifest).await;
            let fingerprint = self.get_fingerprint(&manifest).await;
            // A v1 -> v2 upgrade rotates the old mutable metadata. If it
            // overlapped this read, retry the complete new generation instead
            // of mixing legacy bytes with the newly published metadata.
            if manifest.generation.is_none() && self.get_manifest().await?.generation.is_some() {
                continue;
            }
            return Ok((manifest, data?, fingerprint?));
        }
        Err(Error::VssVersionConflict {
            details: "backup changed repeatedly during restore".to_string(),
        })
    }

    async fn download_manifest(&self, manifest: &BackupManifest) -> Result<Vec<u8>, Error> {
        let mut data = Vec::with_capacity(manifest.total_size);
        for index in 0..manifest.chunk_count {
            let response = self
                .client
                .get_object(&GetObjectRequest {
                    store_id: self.store_id.clone(),
                    key: manifest.chunk_key(index),
                })
                .await
                .map_err(vss_error_to_rgb_error)?;
            let chunk = response.value.ok_or(Error::VssBackupNotFound)?;
            data.extend(chunk.value);
        }
        if manifest.encrypted {
            let metadata = self.get_encryption_metadata(manifest).await?;
            decrypt_data(&data, &self.signing_key, &metadata, None)
        } else {
            Ok(data)
        }
    }

    /// Get the backup manifest
    async fn get_manifest(&self) -> Result<BackupManifest, Error> {
        let request = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: BACKUP_KEY_MANIFEST.to_string(),
        };

        let response = self
            .client
            .get_object(&request)
            .await
            .map_err(vss_error_to_rgb_error)?;

        let manifest_bytes = response
            .value
            .map(|kv| kv.value)
            .ok_or(Error::VssBackupNotFound)?;

        let manifest: BackupManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| Error::Internal {
                details: format!("Failed to parse backup manifest: {e}"),
            })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Get the encryption metadata
    async fn get_encryption_metadata(
        &self,
        manifest: &BackupManifest,
    ) -> Result<VssEncryptionMetadata, Error> {
        let request = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: manifest.metadata_key(),
        };

        let response = self
            .client
            .get_object(&request)
            .await
            .map_err(vss_error_to_rgb_error)?;

        let metadata_bytes = response
            .value
            .map(|kv| kv.value)
            .ok_or(Error::VssBackupNotFound)?;

        serde_json::from_slice(&metadata_bytes).map_err(|e| Error::Internal {
            details: format!("Failed to parse encryption metadata: {e}"),
        })
    }

    /// Get the current version of a backup
    ///
    /// Returns `None` if no backup exists, otherwise returns the version number.
    pub async fn get_backup_version(&self) -> Result<Option<i64>, Error> {
        self.get_current_version(BACKUP_KEY_MANIFEST).await
    }

    /// Get the wallet fingerprint stored on the server
    async fn get_fingerprint(&self, manifest: &BackupManifest) -> Result<String, Error> {
        let request = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: manifest.fingerprint_key(),
        };

        let response = self
            .client
            .get_object(&request)
            .await
            .map_err(vss_error_to_rgb_error)?;

        let fingerprint_bytes = response
            .value
            .map(|kv| kv.value)
            .ok_or(Error::VssBackupNotFound)?;

        let fingerprint = String::from_utf8(fingerprint_bytes).map_err(|e| Error::Internal {
            details: format!("Invalid fingerprint encoding: {e}"),
        })?;
        validate_wallet_fingerprint(&fingerprint)?;
        Ok(fingerprint)
    }

    /// Get the current version of a key
    async fn get_current_version(&self, key: &str) -> Result<Option<i64>, Error> {
        let request = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: key.to_string(),
        };

        match self.client.get_object(&request).await {
            Ok(response) => Ok(response.value.map(|kv| kv.version)),
            Err(VssError::NoSuchKeyError(_)) => Ok(None),
            Err(e) => Err(vss_error_to_rgb_error(e)),
        }
    }

    /// Delete the backup from VSS server
    pub async fn delete_backup(&self) -> Result<(), Error> {
        // Include retained reader generations and abandoned partial uploads,
        // even when no manifest was ever published. Pin the store version so
        // a concurrent upload makes deletion fail atomically rather than
        // removing chunks that another writer is about to publish.
        let mut page_token = None;
        let mut global_version = None;
        let mut delete_items = Vec::new();
        loop {
            let page = self
                .client
                .list_key_versions(&ListKeyVersionsRequest {
                    store_id: self.store_id.clone(),
                    key_prefix: Some("backup/".to_string()),
                    page_size: Some(1000),
                    page_token: page_token.clone(),
                })
                .await
                .map_err(vss_error_to_rgb_error)?;
            if page_token.is_none() {
                global_version = page.global_version;
            }
            delete_items.extend(page.key_versions);
            page_token = page.next_page_token.filter(|token| !token.is_empty());
            if page_token.is_none() {
                break;
            }
        }
        if delete_items.is_empty() {
            return Ok(());
        }
        let global_version = global_version.ok_or_else(|| Error::Internal {
            details: "VSS server omitted the store version during backup deletion".to_string(),
        })?;
        self.client
            .put_object(&PutObjectRequest {
                store_id: self.store_id.clone(),
                global_version: Some(global_version),
                transaction_items: vec![],
                delete_items,
            })
            .await
            .map_err(vss_error_to_rgb_error)?;
        Ok(())
    }

    /// Check if encryption is enabled
    #[must_use]
    pub fn encryption_enabled(&self) -> bool {
        self.encryption_enabled
    }

    /// Check if auto-backup is enabled
    #[must_use]
    pub fn auto_backup(&self) -> bool {
        self.auto_backup
    }

    /// Get the configured backup mode
    #[must_use]
    pub fn backup_mode(&self) -> VssBackupMode {
        self.backup_mode
    }
}

/// Default HKDF info string used by rgb-lib's wallet backup encryption.
///
/// Downstream callers that re-use [`derive_encryption_key`] / [`encrypt_data`] /
/// [`decrypt_data`] for a different purpose (e.g. encrypting LDK KVStore
/// values rather than wallet zips) should pass their own domain-separation tag
/// via the `info` parameter so that the derived keys differ even when the
/// signing key and salt happen to match.
const HKDF_INFO: &[u8] = b"rgb-lib-vss-backup-encryption-v1";

/// Derive an encryption key from a signing key using HKDF-SHA256.
///
/// When `info` is `None`, rgb-lib's default domain-separation tag
/// (`b"rgb-lib-vss-backup-encryption-v1"`) is used — that's the right choice
/// when the caller is encrypting data that will round-trip through rgb-lib's
/// own backup helpers. Pass `Some(tag)` to supply a custom HKDF info string
/// when encrypting unrelated data (e.g. LDK channel-state values) so that the
/// derived key is distinct from rgb-lib's wallet-backup key for the same
/// signing key and metadata.
pub fn derive_encryption_key(
    signing_key: &SecretKey,
    metadata: &VssEncryptionMetadata,
    info: Option<&[u8]>,
) -> Result<Key, Error> {
    let salt_bytes = hex::decode(&metadata.salt).map_err(|e| Error::Internal {
        details: format!("Invalid salt hex: {e}"),
    })?;

    let hk = Hkdf::<Sha256>::new(Some(&salt_bytes), &signing_key.secret_bytes());

    let mut key_bytes = [0u8; BACKUP_KEY_LENGTH];
    hk.expand(info.unwrap_or(HKDF_INFO), &mut key_bytes)
        .map_err(|e| Error::Internal {
            details: format!("HKDF expansion failed: {e}"),
        })?;

    Ok(Key::from(key_bytes))
}

/// Encrypt data using XChaCha20-Poly1305 with a key derived from `signing_key`
/// via HKDF-SHA256 (see [`derive_encryption_key`] for the `info` parameter).
///
/// The same `signing_key`, `metadata`, and `info` must be passed to
/// [`decrypt_data`] for the round-trip to succeed.
pub fn encrypt_data(
    data: &[u8],
    signing_key: &SecretKey,
    metadata: &VssEncryptionMetadata,
    info: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let key = derive_encryption_key(signing_key, metadata, info)?;
    let aead = XChaCha20Poly1305::new(&key);
    let nonce_prefix = metadata.nonce_bytes()?;
    let mut position: u32 = 0;
    let mut encrypted = Vec::new();
    let mut buffer = [0u8; BACKUP_BUFFER_LEN_ENCRYPT];
    let mut reader = std::io::Cursor::new(data);

    loop {
        let read_count = reader.read(&mut buffer).map_err(|e| Error::Internal {
            details: format!("Failed to read data: {e}"),
        })?;
        let is_last = read_count != BACKUP_BUFFER_LEN_ENCRYPT;
        if !is_last && position == u32::MAX {
            return Err(Error::Internal {
                details: "data too large".to_string(),
            });
        }

        let nonce = stream_be32_nonce(&nonce_prefix, position, is_last);
        let ciphertext =
            aead.encrypt(&nonce, &buffer[..read_count])
                .map_err(|e| Error::Internal {
                    details: format!("Encryption error: {e}"),
                })?;
        encrypted.extend(ciphertext);

        if is_last {
            break;
        }
        position += 1;
    }

    Ok(encrypted)
}

/// Decrypt data using XChaCha20-Poly1305 with a key derived from `signing_key`
/// via HKDF-SHA256 (see [`derive_encryption_key`] for the `info` parameter).
///
/// The `signing_key`, `metadata`, and `info` must match what was passed to
/// [`encrypt_data`]; otherwise the AEAD authentication tag check fails and an
/// `Error::VssError` is returned.
pub fn decrypt_data(
    encrypted: &[u8],
    signing_key: &SecretKey,
    metadata: &VssEncryptionMetadata,
    info: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let key = derive_encryption_key(signing_key, metadata, info)?;
    let aead = XChaCha20Poly1305::new(&key);
    let nonce_prefix = metadata.nonce_bytes()?;
    let mut position: u32 = 0;
    let mut decrypted = Vec::new();
    let mut buffer = [0u8; BACKUP_BUFFER_LEN_DECRYPT];
    let mut reader = std::io::Cursor::new(encrypted);

    loop {
        let read_count = reader.read(&mut buffer).map_err(|e| Error::Internal {
            details: format!("Failed to read data: {e}"),
        })?;

        if read_count == BACKUP_BUFFER_LEN_DECRYPT {
            if position == u32::MAX {
                return Err(Error::Internal {
                    details: "data too large".to_string(),
                });
            }
            let nonce = stream_be32_nonce(&nonce_prefix, position, false);
            let cleartext =
                aead.decrypt(&nonce, buffer.as_slice())
                    .map_err(|_| Error::VssError {
                        details: "decryption failed: wrong signing key or corrupted data"
                            .to_string(),
                    })?;
            decrypted.extend(cleartext);
        } else if read_count == 0 {
            return Err(Error::VssError {
                details: "encrypted backup is missing its final authentication block".to_string(),
            });
        } else {
            let nonce = stream_be32_nonce(&nonce_prefix, position, true);
            let cleartext =
                aead.decrypt(&nonce, &buffer[..read_count])
                    .map_err(|_| Error::VssError {
                        details: "decryption failed: wrong signing key or corrupted data"
                            .to_string(),
                    })?;
            decrypted.extend(cleartext);
            break;
        }
        position += 1;
    }

    Ok(decrypted)
}

fn validate_wallet_fingerprint(fingerprint: &str) -> Result<(), Error> {
    if fingerprint.len() != 8 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::VssError {
            details: "invalid wallet fingerprint in backup".to_string(),
        });
    }
    Ok(())
}

/// Convert VSS error to RGB-lib error
fn vss_error_to_rgb_error(e: VssError) -> Error {
    match e {
        VssError::NoSuchKeyError(_) => Error::VssBackupNotFound,
        VssError::ConflictError(msg) => Error::VssVersionConflict { details: msg },
        VssError::AuthError(msg) => Error::VssAuth { details: msg },
        VssError::InternalServerError(msg) => Error::VssError {
            details: format!("Server error: {msg}"),
        },
        VssError::InvalidRequestError(msg) => Error::VssError {
            details: format!("Invalid request: {msg}"),
        },
        _ => Error::VssError {
            details: e.to_string(),
        },
    }
}

/// VSS backup info returned by `vss_backup_info()`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssBackupInfo {
    /// Whether a backup exists on the server
    pub backup_exists: bool,
    /// Server-side version of the backup
    pub server_version: Option<i64>,
    /// Whether the local wallet has changes since last backup
    pub backup_required: bool,
    /// Error of the most recent failed auto-backup, if the last one failed
    pub last_auto_backup_error: Option<String>,
}

/// Create a zip archive of a wallet directory in memory
fn zip_wallet_to_bytes(wallet_dir: &Path, logger: &Logger) -> Result<Vec<u8>, Error> {
    let mut buffer = std::io::Cursor::new(Vec::new());

    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);
        let mut file_buffer = [0u8; 4096];

        // Get the parent directory to preserve wallet fingerprint in zip
        let prefix = wallet_dir.parent().ok_or_else(|| Error::Internal {
            details: "Wallet directory has no parent".to_string(),
        })?;

        let entry_iterator = WalkDir::new(wallet_dir).into_iter().filter_map(|e| e.ok());

        for entry in entry_iterator {
            let path = entry.path();
            let name = path.strip_prefix(prefix).map_err(|e| Error::Internal {
                details: format!("Failed to strip prefix: {e}"),
            })?;
            let name_str = name.to_str().ok_or_else(|| Error::Internal {
                details: "Invalid path encoding".to_string(),
            })?;

            if path.is_file() {
                // Skip log file
                if path.ends_with(LOG_FILE) {
                    continue;
                }
                debug!(logger, "VSS backup: adding file {:?}", name);
                zip.start_file(name_str, options)
                    .map_err(|e| Error::Internal {
                        details: format!("Failed to add file to zip: {e}"),
                    })?;

                let mut f = fs::File::open(path)?;
                loop {
                    let read_count = f.read(&mut file_buffer)?;
                    if read_count != 0 {
                        zip.write_all(&file_buffer[..read_count])?;
                    } else {
                        break;
                    }
                }
            } else if !name.as_os_str().is_empty() {
                debug!(logger, "VSS backup: adding directory {:?}", name);
                zip.add_directory(name_str, options)
                    .map_err(|e| Error::Internal {
                        details: format!("Failed to add directory to zip: {e}"),
                    })?;
            }
        }

        zip.finish().map_err(|e| Error::Internal {
            details: format!("Failed to finalize zip: {e}"),
        })?;
    }

    Ok(buffer.into_inner())
}

/// Extract the wallet fingerprint from a zip archive
///
/// Wallet fingerprints are 4-byte BIP32 fingerprints displayed as 8 lowercase
/// hex characters (e.g., `"a1b2c3d4"`).
fn get_fingerprint_from_zip_bytes(data: &[u8]) -> Result<String, Error> {
    let reader = std::io::Cursor::new(data);
    let archive = zip::ZipArchive::new(reader).map_err(|e| Error::Internal {
        details: format!("Failed to read zip archive: {e}"),
    })?;

    let first_entry = archive.name_for_index(0).unwrap_or_default();
    let fingerprint = first_entry.trim_end_matches('/').to_string();

    // Validate: wallet fingerprints are 8 hex characters (4 bytes)
    if fingerprint.len() != 8 || hex::decode(&fingerprint).is_err() {
        return Err(Error::Internal {
            details: format!("Invalid wallet fingerprint in zip: '{fingerprint}'"),
        });
    }

    Ok(fingerprint)
}

/// Check if a zip entry path is a BDK database file (contains xpubs in descriptors)
///
/// Matches the `bdk_db`/`bdk_db_watch_only` stems and any recovery sidecar the store
/// leaves behind (`bdk_db.corrupt[.N]`, `bdk_db.recovering`, …): those copies hold full
/// descriptors and must never ride into a plaintext backup.
#[cfg(test)]
fn is_bdk_db_file(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let stem = filename.split('.').next().unwrap_or(filename);
    stem == BDK_DB_NAME || stem == BDK_DB_WO_NAME
}

/// Check if a zip entry path is the wallet manifest, or a temp copy orphaned by a crash
/// mid-write (contains xpubs and the fingerprint)
#[cfg(test)]
fn is_wallet_manifest_file(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    filename == WALLET_MANIFEST_FILE || filename == format!("{WALLET_MANIFEST_FILE}.tmp")
}

/// Sanitize a wallet zip for plaintext (unencrypted) backup
///
/// Removes sensitive data that should not be stored unencrypted:
/// - Replaces the master fingerprint directory name with a generic "wallet/" name
/// - Excludes BDK database files (bdk_db, bdk_db_watch_only) which contain xpubs
/// - Excludes the wallet manifest, which contains the xpubs and fingerprint in plaintext;
///   the first `Wallet::new` after restore rewrites it
///
/// Returns the sanitized zip bytes and the extracted fingerprint.
#[cfg(test)]
pub(crate) fn sanitize_zip_for_plaintext(data: &[u8]) -> Result<(Vec<u8>, String), Error> {
    let fingerprint = get_fingerprint_from_zip_bytes(data)?;

    let reader = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| Error::Internal {
        details: format!("Failed to read zip archive: {e}"),
    })?;

    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip_writer = zip::ZipWriter::new(&mut buffer);
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| Error::Internal {
                details: format!("Failed to read zip entry: {e}"),
            })?;

            // ZIP APPNOTE mandates '/' separators; a Windows-produced archive may carry
            // backslashes ("fp\bdk_db"), which the separator-naive predicates below would miss
            // and leak unredacted. Normalize once so every predicate sees canonical names.
            let original_name = file.name().replace('\\', "/");

            // Skip files carrying xpubs or the fingerprint in their contents
            if is_bdk_db_file(&original_name) || is_wallet_manifest_file(&original_name) {
                continue;
            }

            // Replace fingerprint with generic directory name
            let sanitized_name = original_name.replacen(&fingerprint, SANITIZED_DIR_NAME, 1);

            if file.is_dir() {
                zip_writer
                    .add_directory(&sanitized_name, options)
                    .map_err(|e| Error::Internal {
                        details: format!("Failed to add directory to sanitized zip: {e}"),
                    })?;
            } else {
                zip_writer
                    .start_file(&sanitized_name, options)
                    .map_err(|e| Error::Internal {
                        details: format!("Failed to add file to sanitized zip: {e}"),
                    })?;
                std::io::copy(&mut file, &mut zip_writer)?;
            }
        }

        zip_writer.finish().map_err(|e| Error::Internal {
            details: format!("Failed to finalize sanitized zip: {e}"),
        })?;
    }

    Ok((buffer.into_inner(), fingerprint))
}

/// Unzip wallet data to a target directory
fn unzip_wallet_from_bytes(data: &[u8], target_dir: &Path, logger: &Logger) -> Result<(), Error> {
    let reader = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| Error::Internal {
        details: format!("Failed to read zip archive: {e}"),
    })?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| Error::Internal {
            details: format!("Failed to read zip entry: {e}"),
        })?;

        let outpath = match file.enclosed_name() {
            Some(path) => target_dir.join(path),
            None => continue,
        };

        if file.name().ends_with('/') {
            debug!(logger, "VSS restore: creating directory {:?}", outpath);
            fs::create_dir_all(&outpath)?;
        } else {
            debug!(
                logger,
                "VSS restore: extracting file {:?} ({} bytes)",
                outpath,
                file.size()
            );
            if let Some(p) = outpath.parent()
                && !p.exists()
            {
                fs::create_dir_all(p)?;
            }
            let mut outfile = fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(())
}

/// Restore a wallet from VSS backup
///
/// Downloads the backup from the VSS server and extracts it to the target directory.
/// For encrypted backups, the fingerprint is embedded in the zip entry paths.
/// For plaintext backups, the fingerprint is fetched from a separate server key
/// and the sanitized "wallet/" directory is renamed to the actual fingerprint.
///
/// Returns the path to the restored wallet directory.
pub async fn restore_from_vss(config: VssBackupConfig, target_dir: &str) -> Result<PathBuf, Error> {
    fs::create_dir_all(target_dir)?;
    let log_dir = Path::new(target_dir);
    let log_name = format!("vss_restore_{}", OffsetDateTime::now_utc().unix_timestamp());
    let (logger, _logger_guard) = setup_logger(log_dir, Some(&log_name))?;

    info!(logger, "Starting VSS restore...");
    info!(logger, "Server URL: {}", config.server_url);
    info!(logger, "Store ID: {}", config.store_id);

    // Create VSS client and download backup
    let client = VssBackupClient::new(config)?;

    info!(logger, "Downloading backup from VSS server...");
    let (manifest, backup_data, fingerprint) = client.download_record().await?;
    info!(
        logger,
        "Downloaded {} bytes ({:.2} MB)",
        backup_data.len(),
        backup_data.len() as f64 / 1_000_000.0
    );

    info!(logger, "Wallet fingerprint: {}", fingerprint);

    let target_dir_path = PathBuf::from(target_dir);
    let wallet_dir = target_dir_path.join(&fingerprint);

    // Check if wallet already exists
    if wallet_dir.exists() {
        return Err(Error::WalletDirAlreadyExists {
            path: wallet_dir.to_string_lossy().to_string(),
        });
    }

    // Extract backup
    info!(logger, "Extracting backup to {:?}", target_dir_path);
    unzip_wallet_from_bytes(&backup_data, &target_dir_path, &logger)?;

    // For non-encrypted backups, the zip uses "wallet/" as the directory name
    // instead of the real fingerprint. Rename it back.
    if !manifest.encrypted {
        let sanitized_dir = target_dir_path.join(SANITIZED_DIR_NAME);
        if sanitized_dir.exists() {
            info!(
                logger,
                "Renaming sanitized directory {:?} to {:?}", sanitized_dir, wallet_dir
            );
            fs::rename(&sanitized_dir, &wallet_dir)?;
        }
    }

    // Old backups could contain a transient lock from the source process.
    // The target directory is newly extracted and has no live runtime owner.
    match fs::remove_file(wallet_dir.join(crate::utils::RGB_RUNTIME_LOCK_FILE)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    if let Err(e) = fs::write(wallet_dir.join(VSS_RESTORE_MARKER), b"") {
        info!(logger, "Could not write restore marker: {e}");
    }

    info!(logger, "VSS restore completed successfully");
    Ok(wallet_dir)
}

/// Create backup data from a wallet directory
///
/// This is a helper function used by Wallet::vss_backup()
pub fn create_backup_data(wallet_dir: &Path, logger: &Logger) -> Result<Vec<u8>, Error> {
    info!(logger, "Creating VSS backup data from {:?}", wallet_dir);
    let data = zip_wallet_to_bytes(wallet_dir, logger)?;
    info!(
        logger,
        "Backup data created: {} bytes ({:.2} MB)",
        data.len(),
        data.len() as f64 / 1_000_000.0
    );
    Ok(data)
}

#[cfg(test)]
pub(crate) mod publication_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::secp256k1::{Secp256k1, rand::rngs::OsRng};

    fn test_signing_key() -> SecretKey {
        let secp = Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut OsRng);
        sk
    }

    #[test]
    fn legacy_stream_ciphertext_remains_readable_and_truncation_fails() {
        // Generated by chacha20poly1305 0.10.1 EncryptorBE32 using two full
        // 239-byte blocks and its mandatory final empty authenticated block.
        let key = SecretKey::from_slice(&[1; 32]).unwrap();
        let metadata = VssEncryptionMetadata {
            salt: hex::encode([2; 32]),
            nonce: hex::encode([3; 19]),
            version: 1,
        };
        let encrypted = include_bytes!("test/fixtures/legacy-vss-v1.bin");
        assert_eq!(
            decrypt_data(encrypted, &key, &metadata, None).unwrap(),
            vec![42; 478]
        );
        assert_eq!(
            encrypt_data(&[42; 478], &key, &metadata, None).unwrap(),
            encrypted
        );
        assert!(decrypt_data(&encrypted[..encrypted.len() - 16], &key, &metadata, None).is_err());
        let mut invalid = metadata;
        invalid.nonce = "00".into();
        assert!(decrypt_data(encrypted, &key, &invalid, None).is_err());
    }

    #[test]
    fn restore_fingerprint_cannot_escape_the_target_directory() {
        assert!(validate_wallet_fingerprint("a1b2c3d4").is_ok());
        for invalid in [
            "",
            "wallet",
            "../other",
            "/tmp/abc",
            "abcdefgh",
            "012345678",
        ] {
            assert!(validate_wallet_fingerprint(invalid).is_err());
        }
    }

    #[test]
    fn test_backup_manifest_serialization() {
        let manifest = BackupManifest {
            chunk_count: 5,
            total_size: 20_000_000,
            encrypted: true,
            version: 1,
            generation: None,
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: BackupManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.chunk_count, 5);
        assert_eq!(parsed.total_size, 20_000_000);
        assert!(parsed.encrypted);
        assert_eq!(parsed.version, 1);
    }

    #[test]
    fn test_encryption_metadata_serialization() {
        let metadata = VssEncryptionMetadata::new();

        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: VssEncryptionMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, VSS_BACKUP_VERSION);
        assert_eq!(parsed.nonce.len(), BACKUP_NONCE_LENGTH * 2);
        assert!(!parsed.salt.is_empty());
        // Salt should be valid hex (64 chars for 32 bytes)
        assert_eq!(parsed.salt.len(), BACKUP_SALT_LENGTH * 2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original_data = b"Hello, this is test data for encryption!".to_vec();
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        // Encrypt
        let encrypted = encrypt_data(&original_data, &key, &metadata, None).unwrap();
        assert_ne!(encrypted, original_data);

        // Decrypt
        let decrypted = decrypt_data(&encrypted, &key, &metadata, None).unwrap();
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        // Test with data larger than buffer size
        let original_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let encrypted = encrypt_data(&original_data, &key, &metadata, None).unwrap();
        let decrypted = decrypt_data(&encrypted, &key, &metadata, None).unwrap();

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_wrong_key_fails() {
        let original_data = b"Secret data".to_vec();
        let correct_key = test_signing_key();
        let wrong_key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let encrypted = encrypt_data(&original_data, &correct_key, &metadata, None).unwrap();
        let result = decrypt_data(&encrypted, &wrong_key, &metadata, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let original_data: Vec<u8> = vec![];
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let encrypted = encrypt_data(&original_data, &key, &metadata, None).unwrap();
        let decrypted = decrypt_data(&encrypted, &key, &metadata, None).unwrap();

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_encrypt_decrypt_exact_buffer_size() {
        // Test with data exactly at buffer boundary
        let original_data: Vec<u8> = (0..BACKUP_BUFFER_LEN_ENCRYPT)
            .map(|i| (i % 256) as u8)
            .collect();
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let encrypted = encrypt_data(&original_data, &key, &metadata, None).unwrap();
        let decrypted = decrypt_data(&encrypted, &key, &metadata, None).unwrap();

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_encrypt_decrypt_multiple_buffer_sizes() {
        // Test with data that spans multiple buffer reads
        let original_data: Vec<u8> = (0..(BACKUP_BUFFER_LEN_ENCRYPT * 3 + 50))
            .map(|i| (i % 256) as u8)
            .collect();
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let encrypted = encrypt_data(&original_data, &key, &metadata, None).unwrap();
        let decrypted = decrypt_data(&encrypted, &key, &metadata, None).unwrap();

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_decrypt_corrupted_data_fails() {
        let original_data = b"Test data for corruption test".to_vec();
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let mut encrypted = encrypt_data(&original_data, &key, &metadata, None).unwrap();

        // Corrupt the encrypted data
        if !encrypted.is_empty() {
            let mid = encrypted.len() / 2;
            encrypted[mid] ^= 0xFF;
        }

        let result = decrypt_data(&encrypted, &key, &metadata, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_salts_produce_different_keys() {
        let key = test_signing_key();
        let metadata1 = VssEncryptionMetadata::new();
        let metadata2 = VssEncryptionMetadata::new();

        let derived1 = derive_encryption_key(&key, &metadata1, None).unwrap();
        let derived2 = derive_encryption_key(&key, &metadata2, None).unwrap();

        // Different random salts should produce different derived keys
        assert_ne!(derived1, derived2);
    }

    #[test]
    fn test_backup_manifest_chunk_calculation() {
        // Test that chunk count calculation is correct
        let small_size = VSS_CHUNK_SIZE - 1;
        let exact_size = VSS_CHUNK_SIZE;
        let large_size = VSS_CHUNK_SIZE * 2 + 100;

        assert_eq!(small_size.div_ceil(VSS_CHUNK_SIZE), 1);
        assert_eq!(exact_size.div_ceil(VSS_CHUNK_SIZE), 1);
        assert_eq!(large_size.div_ceil(VSS_CHUNK_SIZE), 3);
    }

    #[test]
    fn test_is_bdk_db_file() {
        assert!(is_bdk_db_file("bdk_db"));
        assert!(is_bdk_db_file("bdk_db_watch_only"));
        assert!(is_bdk_db_file("abc123/bdk_db"));
        assert!(is_bdk_db_file("abc123/bdk_db_watch_only"));
        assert!(is_bdk_db_file("some/deep/path/bdk_db"));

        // recovery sidecars carry full descriptors and must be excluded (HIGH-3)
        assert!(is_bdk_db_file("abc123/bdk_db.corrupt"));
        assert!(is_bdk_db_file("abc123/bdk_db.corrupt.1"));
        assert!(is_bdk_db_file("abc123/bdk_db.recovering"));
        assert!(is_bdk_db_file("abc123/bdk_db_watch_only.corrupt"));

        assert!(!is_bdk_db_file("bdk_db_other"));
        assert!(!is_bdk_db_file("not_bdk_db"));
        assert!(!is_bdk_db_file("abc123/some_file.txt"));
        assert!(!is_bdk_db_file(""));
    }

    /// Helper: create a test zip with a fingerprint directory structure
    fn create_test_zip(fingerprint: &str) -> Vec<u8> {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buffer);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

            // Add fingerprint directory
            zip.add_directory(format!("{fingerprint}/"), options)
                .unwrap();

            // Add a normal file
            zip.start_file(format!("{fingerprint}/some_file.txt"), options)
                .unwrap();
            zip.write_all(b"test content").unwrap();

            // Add bdk_db file
            zip.start_file(format!("{fingerprint}/bdk_db"), options)
                .unwrap();
            zip.write_all(b"xpub_sensitive_data").unwrap();

            // Add bdk_db_watch_only file
            zip.start_file(format!("{fingerprint}/bdk_db_watch_only"), options)
                .unwrap();
            zip.write_all(b"xpub_watch_only_data").unwrap();

            // Add a nested file
            zip.add_directory(format!("{fingerprint}/subdir/"), options)
                .unwrap();
            zip.start_file(format!("{fingerprint}/subdir/nested.dat"), options)
                .unwrap();
            zip.write_all(b"nested data").unwrap();

            // Add a wallet manifest with xpubs and the fingerprint
            zip.start_file(format!("{fingerprint}/{WALLET_MANIFEST_FILE}"), options)
                .unwrap();
            zip.write_all(
                format!(
                    r#"{{"account_xpub_vanilla":"tpubFakeVanilla","account_xpub_colored":"tpubFakeColored","master_fingerprint":"{fingerprint}"}}"#
                )
                .as_bytes(),
            )
            .unwrap();

            // Add an orphaned manifest temp file left by a crash mid-write
            zip.start_file(format!("{fingerprint}/{WALLET_MANIFEST_FILE}.tmp"), options)
                .unwrap();
            zip.write_all(br#"{"account_xpub_vanilla":"tpubFakeVanilla"}"#)
                .unwrap();

            zip.finish().unwrap();
        }
        buffer.into_inner()
    }

    #[test]
    fn test_sanitize_zip_for_plaintext() {
        let fingerprint = "a1b2c3d4";
        let zip_data = create_test_zip(fingerprint);

        let (sanitized, extracted_fp) = sanitize_zip_for_plaintext(&zip_data).unwrap();
        assert_eq!(extracted_fp, fingerprint);

        // Inspect sanitized zip
        let reader = std::io::Cursor::new(&sanitized);
        let mut archive = zip::ZipArchive::new(reader).unwrap();

        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();

        // Fingerprint should be replaced with "wallet"
        assert!(names.iter().any(|n| n.starts_with("wallet/")));
        assert!(!names.iter().any(|n| n.contains(fingerprint)));

        // BDK files should be excluded
        assert!(!names.iter().any(|n| n.ends_with("bdk_db")));
        assert!(!names.iter().any(|n| n.ends_with("bdk_db_watch_only")));

        // Normal files should be present
        assert!(names.contains(&"wallet/some_file.txt".to_string()));
        assert!(names.contains(&"wallet/subdir/nested.dat".to_string()));

        // Verify file content is preserved
        let mut some_file = archive.by_name("wallet/some_file.txt").unwrap();
        let mut content = String::new();
        some_file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "test content");
    }

    #[test]
    fn test_sanitize_zip_excludes_wallet_manifest() {
        let fingerprint = "a1b2c3d4";
        let zip_data = create_test_zip(fingerprint);

        let (sanitized, _) = sanitize_zip_for_plaintext(&zip_data).unwrap();

        let reader = std::io::Cursor::new(&sanitized);
        let mut archive = zip::ZipArchive::new(reader).unwrap();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            let filename = file.name().rsplit('/').next().unwrap().to_string();
            assert_ne!(filename, WALLET_MANIFEST_FILE);
            assert_ne!(filename, format!("{WALLET_MANIFEST_FILE}.tmp"));
            let mut content = Vec::new();
            file.read_to_end(&mut content).unwrap();
            let content = String::from_utf8_lossy(&content);
            assert!(!content.contains("tpubFakeVanilla"));
            assert!(!content.contains("tpubFakeColored"));
            assert!(!content.contains(fingerprint));
        }
    }

    #[test]
    fn test_get_fingerprint_from_zip_bytes() {
        let fingerprint = "deadbeef";
        let zip_data = create_test_zip(fingerprint);

        let extracted = get_fingerprint_from_zip_bytes(&zip_data).unwrap();
        assert_eq!(extracted, fingerprint);
    }

    /// Zip carrying a Windows backslash-separated bdk_db plus BDK recovery sidecars, all with
    /// full descriptors. Guards HIGH-4 (separator leak) end-to-end.
    fn create_test_zip_with_leaky_sidecars(fingerprint: &str) -> Vec<u8> {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buffer);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

            zip.add_directory(format!("{fingerprint}/"), options)
                .unwrap();
            zip.start_file(format!("{fingerprint}/some_file.txt"), options)
                .unwrap();
            zip.write_all(b"harmless").unwrap();

            // Windows-style backslash separator on the primary bdk_db
            zip.start_file(format!("{fingerprint}\\bdk_db"), options)
                .unwrap();
            zip.write_all(b"tpubLeakBackslash").unwrap();

            // recovery sidecars reached through a backslash-separated directory
            zip.start_file(format!("{fingerprint}\\bdk_db.corrupt"), options)
                .unwrap();
            zip.write_all(format!("tr([{fingerprint}/86'/1'/0']tpubLeakCorrupt/0/*)").as_bytes())
                .unwrap();
            zip.start_file(format!("{fingerprint}\\bdk_db.recovering"), options)
                .unwrap();
            zip.write_all(b"tpubLeakRecovering").unwrap();

            zip.finish().unwrap();
        }
        buffer.into_inner()
    }

    #[test]
    fn test_sanitize_zip_excludes_bdk_db_recovery_sidecars() {
        let fingerprint = "a1b2c3d4";
        let zip_data = create_test_zip_with_leaky_sidecars(fingerprint);

        let (sanitized, _) = sanitize_zip_for_plaintext(&zip_data).unwrap();

        let reader = std::io::Cursor::new(&sanitized);
        let mut archive = zip::ZipArchive::new(reader).unwrap();
        for i in 0..archive.len() {
            let mut file = archive.by_index(i).unwrap();
            let mut content = Vec::new();
            file.read_to_end(&mut content).unwrap();
            let content = String::from_utf8_lossy(&content);
            assert!(!content.contains("tpubLeakBackslash"));
            assert!(!content.contains("tpubLeakCorrupt"));
            assert!(!content.contains("tpubLeakRecovering"));
            assert!(!content.contains(fingerprint));
        }
    }
}
