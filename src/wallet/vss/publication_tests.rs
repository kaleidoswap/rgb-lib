use super::*;
use prost::Message;
use std::collections::BTreeMap;
use std::sync::Mutex;
use vss_client::types::{
    ErrorCode, ErrorResponse, GetObjectResponse, ListKeyVersionsResponse, PutObjectResponse,
};

#[derive(Clone, Copy)]
pub(crate) enum Failure {
    Chunk(usize),
    Publish,
}

#[derive(Default)]
pub(crate) struct Store {
    pub(crate) objects: BTreeMap<String, KeyValue>,
    pub(crate) version: i64,
    pub(crate) failure: Option<Failure>,
    pub(crate) advance_pointer_on_chunk: bool,
    pub(crate) switch_on_read: Option<Vec<u8>>,
}

impl Store {
    fn failure(&self, request: &PutObjectRequest) -> bool {
        request
            .transaction_items
            .iter()
            .any(|kv| match self.failure {
                Some(Failure::Chunk(index)) => kv.key.ends_with(&format!("/chunk/{index}")),
                Some(Failure::Publish) => kv.key == BACKUP_KEY_MANIFEST,
                None => false,
            })
    }
    fn conflict(&self, request: &PutObjectRequest) -> bool {
        request
            .global_version
            .is_some_and(|version| version != self.version)
            || request
                .transaction_items
                .iter()
                .any(|kv| self.objects.get(&kv.key).map_or(0, |v| v.version) != kv.version)
            || request
                .delete_items
                .iter()
                .any(|kv| self.objects.get(&kv.key).map(|v| v.version) != Some(kv.version))
    }
    pub(crate) fn seed(&mut self, key: &str, value: Vec<u8>) {
        let version = self.objects.get(key).map_or(1, |v| v.version + 1);
        self.objects.insert(
            key.to_string(),
            KeyValue {
                key: key.to_string(),
                version,
                value,
            },
        );
        self.version += 1;
    }
}

pub(crate) struct MockVss {
    _server: mockito::ServerGuard,
    _mocks: Vec<mockito::Mock>,
    pub(crate) state: Arc<Mutex<Store>>,
    pub(crate) client: Arc<VssBackupClient>,
    pub(crate) config: VssBackupConfig,
}

fn error(code: ErrorCode) -> Vec<u8> {
    ErrorResponse {
        error_code: code as i32,
        message: format!("injected {code:?}"),
    }
    .encode_to_vec()
}

impl MockVss {
    pub(crate) fn new() -> Self {
        let mut server = mockito::Server::new();
        let state = Arc::new(Mutex::new(Store::default()));
        let status = Arc::clone(&state);
        let body = Arc::clone(&state);
        let get = server
            .mock("POST", "/getObject")
            .with_status_code_from_request(move |req| {
                let req = GetObjectRequest::decode(req.body().unwrap().as_slice()).unwrap();
                if status.lock().unwrap().objects.contains_key(&req.key) {
                    200
                } else {
                    404
                }
            })
            .with_body_from_request(move |req| {
                let req = GetObjectRequest::decode(req.body().unwrap().as_slice()).unwrap();
                let mut state = body.lock().unwrap();
                if (req.key.contains("/chunk/") || req.key == BACKUP_KEY_DATA)
                    && let Some(manifest) = state.switch_on_read.take()
                {
                    state.seed(BACKUP_KEY_MANIFEST, manifest);
                }
                match state.objects.get(&req.key).cloned() {
                    Some(value) => GetObjectResponse { value: Some(value) }.encode_to_vec(),
                    None => error(ErrorCode::NoSuchKeyException),
                }
            })
            .create();
        let status = Arc::clone(&state);
        let body = Arc::clone(&state);
        let put = server
            .mock("POST", "/putObjects")
            .with_status_code_from_request(move |req| {
                let req = PutObjectRequest::decode(req.body().unwrap().as_slice()).unwrap();
                let state = status.lock().unwrap();
                if state.failure(&req) {
                    503
                } else if state.conflict(&req) {
                    409
                } else {
                    200
                }
            })
            .with_body_from_request(move |req| {
                let req = PutObjectRequest::decode(req.body().unwrap().as_slice()).unwrap();
                let mut state = body.lock().unwrap();
                if state.failure(&req) {
                    return error(ErrorCode::InternalServerException);
                }
                if state.conflict(&req) {
                    return error(ErrorCode::ConflictException);
                }
                for kv in req.transaction_items {
                    state.objects.insert(
                        kv.key.clone(),
                        KeyValue {
                            version: kv.version + 1,
                            ..kv
                        },
                    );
                }
                for kv in req.delete_items {
                    state.objects.remove(&kv.key);
                }
                state.version += 1;
                if state.advance_pointer_on_chunk && state.objects.contains_key(BACKUP_KEY_MANIFEST)
                {
                    state.advance_pointer_on_chunk = false;
                    let manifest = state.objects[BACKUP_KEY_MANIFEST].value.clone();
                    state.seed(BACKUP_KEY_MANIFEST, manifest);
                }
                PutObjectResponse {}.encode_to_vec()
            })
            .create();
        let body = Arc::clone(&state);
        let list = server
            .mock("POST", "/listKeyVersions")
            .with_body_from_request(move |req| {
                let req = ListKeyVersionsRequest::decode(req.body().unwrap().as_slice()).unwrap();
                let state = body.lock().unwrap();
                let offset = req
                    .page_token
                    .as_deref()
                    .unwrap_or("0")
                    .parse::<usize>()
                    .unwrap();
                let keys: Vec<_> = state
                    .objects
                    .values()
                    .filter(|v| v.key.starts_with(req.key_prefix.as_deref().unwrap_or("")))
                    .map(|v| KeyValue {
                        value: vec![],
                        ..v.clone()
                    })
                    .collect();
                // Force pagination even when the caller requests a large page.
                let end = (offset + 2).min(keys.len());
                ListKeyVersionsResponse {
                    key_versions: keys[offset..end].to_vec(),
                    next_page_token: (end < keys.len()).then(|| end.to_string()),
                    global_version: req.page_token.is_none().then_some(state.version),
                }
                .encode_to_vec()
            })
            .create();
        let config = VssBackupConfig::new(
            server.url(),
            "regression".to_string(),
            SecretKey::from_slice(&[1; 32]).unwrap(),
        );
        let client = Arc::new(VssBackupClient::new(config.clone()).unwrap());
        Self {
            _server: server,
            _mocks: vec![get, put, list],
            state,
            client,
            config,
        }
    }
    fn upload(&self, bytes: Vec<u8>) -> Result<i64, Error> {
        self.client
            .handle()
            .block_on(self.client.upload_backup(bytes))
    }
    fn download(&self) -> Result<Vec<u8>, Error> {
        self.client.handle().block_on(self.client.download_backup())
    }
    fn manifest(&self) -> KeyValue {
        self.state.lock().unwrap().objects[BACKUP_KEY_MANIFEST].clone()
    }
}

fn zip_payload(byte: u8, large: bool) -> Vec<u8> {
    let mut out = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut out);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.add_directory("a1b2c3d4/", options).unwrap();
        zip.start_file("a1b2c3d4/payload", options).unwrap();
        zip.write_all(&vec![byte; if large { VSS_CHUNK_SIZE * 2 } else { 64 }])
            .unwrap();
        zip.finish().unwrap();
    }
    out.into_inner()
}

#[test]
fn interrupted_chunked_replacement_preserves_baseline_and_retry() {
    let server = MockVss::new();
    let baseline = zip_payload(1, true);
    let replacement = zip_payload(2, true);
    let version = server.upload(baseline.clone()).unwrap();
    let old = server.state.lock().unwrap().objects.clone();
    let manifest: BackupManifest = serde_json::from_slice(&server.manifest().value).unwrap();
    assert!(manifest.chunk_count > 1);
    assert_eq!(server.download().unwrap(), baseline);
    server.state.lock().unwrap().failure = Some(Failure::Chunk(1));
    assert!(server.upload(replacement.clone()).is_err());
    let current = server.state.lock().unwrap().objects.clone();
    for (key, value) in old {
        assert_eq!(
            current[&key], value,
            "published object {key} was overwritten"
        );
    }
    assert_eq!(server.download().unwrap(), baseline);
    server.state.lock().unwrap().failure = None;
    assert_eq!(server.upload(replacement.clone()).unwrap(), version + 1);
    assert_eq!(server.download().unwrap(), replacement);
    assert_eq!(
        server
            .client
            .handle()
            .block_on(server.client.download_manifest(&manifest))
            .unwrap(),
        baseline
    );
}

#[test]
fn failed_manifest_publication_preserves_old_backup() {
    let server = MockVss::new();
    let baseline = zip_payload(3, true);
    server.upload(baseline.clone()).unwrap();
    let manifest = server.manifest();
    server.state.lock().unwrap().failure = Some(Failure::Publish);
    assert!(server.upload(zip_payload(4, false)).is_err());
    assert_eq!(server.manifest(), manifest);
    assert_eq!(server.download().unwrap(), baseline);
}

#[test]
fn readers_keep_data_and_metadata_from_their_captured_generation() {
    let server = MockVss::new();
    let small = zip_payload(5, false);
    let large = zip_payload(6, true);
    server.upload(small.clone()).unwrap();
    let a = server.manifest().value;
    server.upload(large.clone()).unwrap();
    let b = server.manifest().value;
    {
        let mut state = server.state.lock().unwrap();
        state.seed(BACKUP_KEY_MANIFEST, a.clone());
        state.switch_on_read = Some(b.clone());
    }
    assert_eq!(server.download().unwrap(), small);
    {
        let mut state = server.state.lock().unwrap();
        state.seed(BACKUP_KEY_MANIFEST, b);
        state.switch_on_read = Some(a);
    }
    assert_eq!(server.download().unwrap(), large);
}

#[test]
fn slow_upload_cannot_replace_a_concurrently_published_backup() {
    let server = MockVss::new();
    let baseline = zip_payload(7, false);
    server.upload(baseline.clone()).unwrap();
    server.state.lock().unwrap().advance_pointer_on_chunk = true;
    assert!(matches!(
        server.upload(zip_payload(8, true)),
        Err(Error::VssVersionConflict { .. })
    ));
    assert_eq!(server.download().unwrap(), baseline);
}

#[test]
fn deletion_cleans_all_generations_and_unpublished_chunks() {
    let server = MockVss::new();
    server.upload(zip_payload(9, true)).unwrap();
    server.upload(zip_payload(10, false)).unwrap();
    server.state.lock().unwrap().failure = Some(Failure::Chunk(1));
    assert!(server.upload(zip_payload(11, true)).is_err());
    {
        let mut state = server.state.lock().unwrap();
        state.failure = None;
        state.seed("unrelated/key", b"keep".to_vec());
    }
    server
        .client
        .handle()
        .block_on(server.client.delete_backup())
        .unwrap();
    assert_eq!(server.state.lock().unwrap().objects.len(), 1);
    assert_eq!(
        server.state.lock().unwrap().objects["unrelated/key"].value,
        b"keep"
    );
    // An interrupted first upload has no manifest, but deletion must clean it too.
    server.state.lock().unwrap().failure = Some(Failure::Chunk(1));
    assert!(server.upload(zip_payload(12, true)).is_err());
    server.state.lock().unwrap().failure = None;
    server
        .client
        .handle()
        .block_on(server.client.delete_backup())
        .unwrap();
    assert_eq!(server.state.lock().unwrap().objects.len(), 1);
}

#[test]
fn legacy_plaintext_and_encrypted_single_and_chunked_backups_remain_readable() {
    for (encrypted, large) in [(false, false), (true, false), (true, true)] {
        let server = MockVss::new();
        let bytes = zip_payload(13, large);
        let metadata = VssEncryptionMetadata::new();
        let data = if encrypted {
            encrypt_data(&bytes, &server.config.signing_key, &metadata, None).unwrap()
        } else {
            bytes.clone()
        };
        let manifest = BackupManifest {
            chunk_count: data.len().div_ceil(VSS_CHUNK_SIZE),
            total_size: data.len(),
            encrypted,
            version: 1,
            generation: None,
        };
        {
            let mut state = server.state.lock().unwrap();
            state.seed(BACKUP_KEY_MANIFEST, serde_json::to_vec(&manifest).unwrap());
            state.seed(BACKUP_KEY_METADATA, serde_json::to_vec(&metadata).unwrap());
            state.seed(BACKUP_KEY_FINGERPRINT, b"a1b2c3d4".to_vec());
            for (i, chunk) in data.chunks(VSS_CHUNK_SIZE).enumerate() {
                state.seed(&manifest.chunk_key(i), chunk.to_vec());
            }
        }
        assert_eq!(server.download().unwrap(), bytes);
        server.upload(zip_payload(14, !large)).unwrap();
        assert_eq!(server.download().unwrap(), zip_payload(14, !large));
    }
}

#[test]
fn malformed_or_unsupported_generation_manifests_are_rejected() {
    let server = MockVss::new();
    for (version, generation) in [
        (2, None),
        (1, Some("a".repeat(64))),
        (2, Some("../backup/data".to_string())),
        (3, Some("a".repeat(64))),
    ] {
        let manifest = BackupManifest {
            chunk_count: 1,
            total_size: 1,
            encrypted: true,
            version,
            generation,
        };
        server
            .state
            .lock()
            .unwrap()
            .seed(BACKUP_KEY_MANIFEST, serde_json::to_vec(&manifest).unwrap());
        assert!(
            matches!(server.download(), Err(Error::Internal { details }) if details == "invalid or unsupported VSS backup manifest")
        );
    }
}

#[test]
fn legacy_upgrade_does_not_allow_old_clients_to_restore_stale_ciphertext() {
    let server = MockVss::new();
    let baseline = zip_payload(15, false);
    let metadata = VssEncryptionMetadata::new();
    let encrypted = encrypt_data(&baseline, &server.config.signing_key, &metadata, None).unwrap();
    let legacy = BackupManifest {
        chunk_count: 1,
        total_size: encrypted.len(),
        encrypted: true,
        version: 1,
        generation: None,
    };
    {
        let mut state = server.state.lock().unwrap();
        state.seed(BACKUP_KEY_DATA, encrypted.clone());
        state.seed(BACKUP_KEY_METADATA, serde_json::to_vec(&metadata).unwrap());
        state.seed(BACKUP_KEY_FINGERPRINT, b"a1b2c3d4".to_vec());
        state.seed(BACKUP_KEY_MANIFEST, serde_json::to_vec(&legacy).unwrap());
    }
    let current = zip_payload(16, false);
    server.upload(current.clone()).unwrap();
    let published = server.manifest().value;
    let canonical_metadata: VssEncryptionMetadata =
        serde_json::from_slice(&server.state.lock().unwrap().objects[BACKUP_KEY_METADATA].value)
            .unwrap();
    // A version-1 client ignores generation and reads backup/data plus the
    // mutable metadata key. It must error, not successfully return the baseline.
    assert!(
        decrypt_data(
            &encrypted,
            &server.config.signing_key,
            &canonical_metadata,
            None
        )
        .is_err()
    );
    // A new client that captured the legacy manifest immediately before the
    // upgrade must retry the newly published generation coherently.
    {
        let mut state = server.state.lock().unwrap();
        state.seed(BACKUP_KEY_MANIFEST, serde_json::to_vec(&legacy).unwrap());
        state.switch_on_read = Some(published);
    }
    assert_eq!(server.download().unwrap(), current);
}
