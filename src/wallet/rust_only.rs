//! Rust-only functionality.
//!
//! This module defines additional utility methods that are not exposed via FFI.

use super::*;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use crate::utils::{recipient_id_from_script_buf, script_buf_from_recipient_id};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use crate::wallet::online::proxy_get_consignment;
use amplify::num::u5;
use bdk_wallet::bitcoin::Transaction;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use bdk_wallet::bitcoin::hashes::{Hash, sha256};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use rgbstd::AssignmentType;
use rgbstd::Operation as _;
use rgbstd::{
    containers::SealWitness,
    opret::OpretProof,
    rgbcore::commit_verify::{
        TryCommitVerify,
        mpc::{self, MPC_MINIMAL_DEPTH},
    },
};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use std::io::Write;

#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OPS_DIR: &str = "psbt_ops";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_META_FILE: &str = "meta.json";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_FOREIGN_INPUTS_FILE: &str = "foreign_inputs.json";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_COLORED_PSBT_FILE: &str = "colored.psbt";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_STAGED_PSBT_FILE: &str = "staged.psbt";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_STAGED_MANIFEST_FILE: &str = "staged.json";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_CONSIGNMENTS_DIR: &str = "consignments";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_CONSIGNMENT_FILE: &str = CONSIGNMENT_FILE;
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) const STASH_CONSUMED_FILE: &str = "stash_consumed";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const COLOR_PREPARE_FILE: &str = "color_prepare";

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn persist_stash_consumed_marker(path: &Path) -> Result<(), Error> {
    let file = fs::File::create(path)?;
    file.sync_all()?;
    fsync_parent_dir(path)
}

#[cfg(all(unix, any(feature = "electrum", feature = "esplora")))]
fn fsync_parent_dir(path: &Path) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(all(not(unix), any(feature = "electrum", feature = "esplora")))]
fn fsync_parent_dir(_path: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn persist_durable_replace(path: &Path, contents: impl AsRef<[u8]>) -> Result<(), Error> {
    let file_name = path.file_name().ok_or_else(|| Error::Internal {
        details: s!("invalid durable file path"),
    })?;
    let tmp = path.with_file_name(format!("{}.tmp", file_name.to_string_lossy()));
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(contents.as_ref())?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    fsync_parent_dir(path)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn persist_durable_create_dir(path: &Path) -> Result<(), Error> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        fs::File::open(path)?.sync_all()?;
    }
    fsync_parent_dir(path)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    sha256::Hash::hash(bytes.as_ref()).to_string()
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_META_SCHEMA_VERSION: u32 = 1;

/// Windows-safe path: `consignments/{sha256(asset_id)}/consignment_out` (`:` is invalid on Windows).
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn psbt_op_consignment_path(op_dir: &Path, asset_id: &str) -> PathBuf {
    let digest = sha256::Hash::hash(asset_id.as_bytes());
    op_dir
        .join(PSBT_OP_CONSIGNMENTS_DIR)
        .join(digest.to_string())
        .join(PSBT_OP_CONSIGNMENT_FILE)
}
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_ID_LEN: usize = 32;
/// Expiration applied by `psbt_op_prepare` when the caller gives none.
pub const PSBT_OP_DEFAULT_EXPIRATION_SECS: u64 = 24 * 60 * 60;

/// When a prepared PSBT operation may be failed by the expiry sweep.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtOpExpiry {
    /// [`PSBT_OP_DEFAULT_EXPIRATION_SECS`] from now.
    Default,
    /// At this unix timestamp.
    At(u64),
    /// Never: the caller broadcasts the transaction itself and applies or aborts the operation
    /// explicitly, so an operation whose transaction the indexer hasn't seen yet is never failed.
    Never,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl From<Option<u64>> for PsbtOpExpiry {
    fn from(expiration_timestamp: Option<u64>) -> Self {
        expiration_timestamp.map_or(Self::Default, Self::At)
    }
}

#[cfg(all(test, any(feature = "electrum", feature = "esplora")))]
thread_local! {
    pub(crate) static MOCK_FAIL_AFTER_STASH_CONSUME: std::cell::RefCell<bool> =
        const { std::cell::RefCell::new(false) };
    pub(crate) static MOCK_FAIL_AFTER_STOCK_PERSIST: std::cell::RefCell<bool> =
        const { std::cell::RefCell::new(false) };
    pub(crate) static MOCK_FAIL_AFTER_PSBT_OP_SQL_FAIL: std::cell::RefCell<bool> =
        const { std::cell::RefCell::new(false) };
}

/// RGB asset-specific information to color a transaction
#[derive(Debug, Clone)]
pub struct AssetColoringInfo {
    /// Map of vouts and asset amounts to color the transaction outputs
    pub output_map: HashMap<u32, u64>,
    /// Static blinding to keep the transaction construction deterministic
    pub static_blinding: Option<u64>,
}

/// RGB information to color a transaction
#[derive(Debug, Clone)]
pub struct ColoringInfo {
    /// Asset-specific information
    pub asset_info_map: HashMap<ContractId, AssetColoringInfo>,
    /// Static blinding to keep the transaction construction deterministic
    pub static_blinding: Option<u64>,
    /// Nonce for offchain TXs ordering
    pub nonce: Option<u64>,
}

/// Result of importing an RGB contract without receiving asset allocations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportAssetContractResult {
    /// Imported contract ID.
    pub asset_id: String,
    /// Whether the wallet's RGB stock and asset database both contained the contract before the
    /// call.
    pub already_imported: bool,
    /// Metadata derived from the validated contract.
    pub metadata: Metadata,
}

/// Map of contract ID and list of its beneficiaries
pub type AssetBeneficiariesMap = BTreeMap<ContractId, Vec<BuilderSeal<GraphSeal>>>;

/// Result of [`Wallet::color_psbt_and_prepare_consume`] / [`Wallet::color_psbt_for_outpoints_and_prepare_consume`].
#[derive(Debug)]
pub struct ColorPrepareResult {
    /// Per-asset consignments built from the fascia (before stash consume).
    pub transfers: Vec<RgbTransfer>,
    /// Fallible batch transfer created for recovery via `fail_transfers`.
    pub batch_transfer_idx: i32,
}

/// Status of a file-backed HTLC coloring operation.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PsbtOperationStatus {
    /// This wallet's transitions are staged on a PSBT other parties may still stage on, and its
    /// inputs are reserved; the RGB commitment is not final yet (see [`Wallet::psbt_op_stage`]).
    Staged,
    /// Colored PSBT + payloads on disk; RGB stash not updated.
    Prepared,
    /// Fascia consumed into the RGB stash after broadcast.
    Applied,
    /// Aborted before apply (never broadcast).
    Failed,
    /// Reconciled as settled against wallet/batch state.
    Settled,
}

/// Caller-reported / indexer-observed broadcast lifecycle for an HTLC operation.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PsbtBroadcastState {
    /// Caller has not reported a broadcast attempt.
    #[default]
    NotAttempted,
    /// Caller reported a broadcast attempt; indexer has not confirmed the tx.
    Attempted,
    /// Indexer has seen the witness tx.
    Observed,
    /// Broadcast was attempted and the indexer currently does not see the tx.
    Ambiguous,
}

/// Result of [`Wallet::psbt_op_prepare`].
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone)]
pub struct PsbtOpPrepareResult {
    /// Opaque operation ID (directory name under `psbt_ops/`).
    pub operation_id: String,
    /// Colored unsigned PSBT (caller signs and broadcasts).
    pub colored_psbt: String,
    /// Wallet-relative directory containing file-backed payloads.
    pub operation_dir: String,
    /// What the operation's RGB transitions assign, read back from the committed fascia.
    pub allocations: Vec<PsbtOpAllocation>,
}

/// Result of [`Wallet::psbt_op_stage`].
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone)]
pub struct PsbtOpStageResult {
    /// Opaque operation ID (directory name under `psbt_ops/`).
    pub operation_id: String,
    /// The PSBT with this wallet's transitions staged on it, for the next party to stage on or
    /// for the single party calling [`Wallet::psbt_op_finalize`].
    pub staged_psbt: String,
    /// Wallet-relative directory containing file-backed payloads.
    pub operation_dir: String,
    /// What this wallet's staged transitions assign, read back from the staged PSBT.
    pub allocations: Vec<PsbtOpAllocation>,
}

/// One assignment a PSBT operation's RGB transitions make, read back from its committed fascia
/// (not from the [`ColoringInfo`] the operation was prepared with).
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PsbtOpAllocation {
    /// Contract the assignment belongs to, in its canonical spelling.
    pub asset_id: String,
    /// Output of the witness transaction the assignment is sealed to; `None` when the seal is
    /// concealed or points to another transaction.
    pub vout: Option<u32>,
    /// The assigned state.
    pub assignment: Assignment,
}

/// A consignment fetched from a proxy, before any validation.
///
/// **Unchecked:** `txid` and `vout` are what the proxy reported. Pass it to
/// [`Wallet::accept_transfer_pinned`], which pins the witness output before accepting.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone)]
pub struct FetchedConsignment {
    /// The consignment.
    pub consignment: RgbTransfer,
    /// Witness transaction ID reported by the proxy.
    pub txid: String,
    /// Witness output reported by the proxy.
    pub vout: u32,
}

/// Result of [`Wallet::accept_transfer_pinned`].
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone)]
pub struct AcceptedTransfer {
    /// The accepted consignment.
    pub consignment: RgbTransfer,
    /// Assignments received on the pinned witness output.
    pub assignments: Vec<Assignment>,
    /// The pinned witness output.
    pub outpoint: Outpoint,
}

/// Fetch an RGB consignment by recipient_id (proxy lookup key), without a wallet: what
/// [`Wallet::fetch_consignment_by_recipient_id_unchecked`] does, so it can run off the thread
/// that owns the wallet.
///
/// **Unchecked:** `txid` and `vout` come from the proxy and are **not** validated here. Accept
/// the result with [`Wallet::accept_transfer_pinned`], which pins the witness output first.
///
/// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn fetch_consignment_by_recipient_id_unchecked(
    recipient_id: String,
    consignment_endpoint: &str,
) -> Result<FetchedConsignment, Error> {
    let proxy_url = TransportEndpoint::new(consignment_endpoint.to_string())?.endpoint;
    let consignment_res = proxy_get_consignment(
        &proxy_url,
        &recipient_id,
        &Logger::root(slog::Discard, o!()),
    )?;
    let vout = consignment_res.vout.ok_or_else(|| Error::Internal {
        details: s!("missing vout in consignment response"),
    })?;
    let consignment_bytes = general_purpose::STANDARD
        .decode(consignment_res.consignment)
        .map_err(InternalError::from)?;
    let consignment = RgbTransfer::load(&consignment_bytes[..]).map_err(InternalError::from)?;
    Ok(FetchedConsignment {
        consignment,
        txid: consignment_res.txid,
        vout,
    })
}

/// What `fascia`'s transitions assign. Every owned-state type the wallet's schemas define is
/// reported; any other is an error rather than left out.
#[cfg(any(feature = "electrum", feature = "esplora"))]
fn fascia_allocations(fascia: &Fascia) -> Result<Vec<PsbtOpAllocation>, Error> {
    bundle_allocations(fascia.bundles().iter())
}

/// What `bundles`' transitions assign, as [`fascia_allocations`] reports it.
#[cfg(any(feature = "electrum", feature = "esplora"))]
fn bundle_allocations<'a>(
    bundles: impl IntoIterator<Item = (&'a ContractId, &'a rgbstd::TransitionBundle)>,
) -> Result<Vec<PsbtOpAllocation>, Error> {
    fn witness_vout(seal: Option<GraphSeal>) -> Option<u32> {
        seal.filter(|seal| seal.txid == TxPtr::WitnessTx)
            .map(|seal| seal.vout.into_u32())
    }
    let mut allocations = vec![];
    for (contract_id, bundle) in bundles {
        let asset_id = contract_id.to_string();
        let unknown = |ass_type: &AssignmentType| Error::Inconsistency {
            details: format!("fascia for {asset_id} assigns unknown owned state {ass_type}"),
        };
        for KnownTransition { transition, .. } in bundle.known_transitions.iter() {
            for (ass_type, typed_assigns) in transition.assignments.iter() {
                let mut found = vec![];
                for assign in typed_assigns.as_fungible() {
                    let amount = assign.as_revealed_state().as_u64();
                    let assignment =
                        Assignment::fungible(*ass_type, amount).ok_or_else(|| unknown(ass_type))?;
                    found.push((witness_vout(assign.revealed_seal()), assignment));
                }
                for assign in typed_assigns.as_structured() {
                    found.push((
                        witness_vout(assign.revealed_seal()),
                        Assignment::NonFungible,
                    ));
                }
                for assign in typed_assigns.as_declarative() {
                    if *ass_type != OS_LINK {
                        return Err(unknown(ass_type));
                    }
                    found.push((witness_vout(assign.revealed_seal()), Assignment::LinkRight));
                }
                allocations.extend(
                    found
                        .into_iter()
                        .map(|(vout, assignment)| PsbtOpAllocation {
                            asset_id: asset_id.clone(),
                            vout,
                            assignment,
                        }),
                );
            }
        }
    }
    allocations.sort();
    Ok(allocations)
}

/// Recovered HTLC operation (lookup after a lost `psbt_op_prepare` response).
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone)]
pub struct PsbtOperation {
    /// Opaque operation ID (directory name under `psbt_ops/`).
    pub operation_id: String,
    /// Colored unsigned PSBT; for an operation staged and never completed, the staged PSBT.
    pub colored_psbt: String,
    /// Wallet-relative directory containing file-backed payloads.
    pub operation_dir: String,
    /// High-level operation status.
    pub status: PsbtOperationStatus,
    /// Broadcast lifecycle.
    pub broadcast: PsbtBroadcastState,
    /// Witness txid committed at prepare; for an operation staged and never completed, the txid
    /// of the staged PSBT, which changes once the commitment is finalized.
    pub txid: String,
    /// What the operation's RGB transitions assign, read back from the committed fascia (from
    /// the staged PSBT for an operation staged and never completed).
    pub allocations: Vec<PsbtOpAllocation>,
}

/// Caller intent for HTLC / special accept paths.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedTransfer {
    /// Expected contract / asset ID
    pub asset_id: String,
    /// Expected RGB schema
    pub asset_schema: AssetSchema,
    /// Expected assignment type and amount (`Any` is rejected)
    pub assignment: Assignment,
}

/// Hashes binding an operation's payload files to its manifest. `fascia` and `colored_psbt` are
/// set once the commitment is final (by `psbt_op_prepare` or `psbt_op_complete`); `staged` is
/// set for an operation created by `psbt_op_stage` and kept after it completes.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PsbtOpPayloadHashes {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fascia: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    colored_psbt: Option<String>,
    foreign_inputs: String,
    consignments: BTreeMap<String, String>,
    txid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    batch_transfer_idx: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    staged: Option<PsbtOpStagedHashes>,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PsbtOpStagedHashes {
    psbt: String,
    manifest: String,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl PsbtOpPayloadHashes {
    fn new(
        fascia: &[u8],
        colored_psbt: &[u8],
        foreign_inputs: &[u8],
        consignments: BTreeMap<String, String>,
        txid: &str,
        batch_transfer_idx: Option<i32>,
    ) -> Self {
        Self {
            fascia: Some(sha256_hex(fascia)),
            colored_psbt: Some(sha256_hex(colored_psbt)),
            foreign_inputs: sha256_hex(foreign_inputs),
            consignments,
            txid: sha256_hex(txid.as_bytes()),
            batch_transfer_idx: batch_transfer_idx.map(psbt_op_batch_identity_hash),
            staged: None,
        }
    }

    fn new_staged(
        staged_psbt: &[u8],
        manifest: &[u8],
        foreign_inputs: &[u8],
        staged_txid: &str,
    ) -> Self {
        Self {
            fascia: None,
            colored_psbt: None,
            foreign_inputs: sha256_hex(foreign_inputs),
            consignments: BTreeMap::new(),
            txid: sha256_hex(staged_txid.as_bytes()),
            batch_transfer_idx: None,
            staged: Some(PsbtOpStagedHashes {
                psbt: sha256_hex(staged_psbt),
                manifest: sha256_hex(manifest),
            }),
        }
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn psbt_op_batch_identity_hash(batch_transfer_idx: i32) -> String {
    sha256_hex(batch_transfer_idx.to_string().as_bytes())
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PsbtOpMeta {
    schema_version: u32,
    operation_id: String,
    status: PsbtOperationStatus,
    txid: String,
    created_at: i64,
    batch_transfer_idx: Option<i32>,
    #[serde(default)]
    broadcast: PsbtBroadcastState,
    hashes: PsbtOpPayloadHashes,
    /// Write-ahead record of a Staged operation's `psbt_op_complete`: the final witness txid
    /// whose batch transfer replaces the staged one. Set before that SQL commit, cleared when
    /// the operation is published as Prepared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completing_txid: Option<String>,
}

/// What `psbt_op_stage` needs to rebuild after a restart: the coloring request, the inputs it
/// reserved and the batch transfer parameters. The staged transitions live in `staged.psbt`.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PsbtOpStagedManifest {
    input_outpoints: Vec<Outpoint>,
    assets: BTreeMap<String, PsbtOpStagedAssetColoring>,
    static_blinding: Option<u64>,
    nonce: Option<u64>,
    min_confirmations: u8,
    expiration_timestamp: Option<u64>,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PsbtOpStagedAssetColoring {
    /// Keyed by final vout, as [`Wallet::psbt_op_stage`] takes it.
    output_map: BTreeMap<u32, u64>,
    static_blinding: Option<u64>,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl PsbtOpStagedManifest {
    fn new(
        coloring_info: &ColoringInfo,
        input_outpoints: &HashSet<OutPoint>,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
    ) -> Self {
        let mut inputs: Vec<OutPoint> = input_outpoints.iter().copied().collect();
        inputs.sort();
        Self {
            input_outpoints: inputs.into_iter().map(Outpoint::from).collect(),
            assets: coloring_info
                .asset_info_map
                .iter()
                .map(|(contract_id, info)| {
                    (
                        contract_id.to_string(),
                        PsbtOpStagedAssetColoring {
                            output_map: info.output_map.iter().map(|(k, v)| (*k, *v)).collect(),
                            static_blinding: info.static_blinding,
                        },
                    )
                })
                .collect(),
            static_blinding: coloring_info.static_blinding,
            nonce: coloring_info.nonce,
            min_confirmations,
            expiration_timestamp,
        }
    }

    fn coloring_info(&self) -> Result<ColoringInfo, Error> {
        let mut asset_info_map = HashMap::new();
        for (asset_id, info) in &self.assets {
            let contract_id = ContractId::from_str(asset_id).map_err(|e| Error::Inconsistency {
                details: format!("staged manifest has an invalid asset ID {asset_id}: {e}"),
            })?;
            asset_info_map.insert(
                contract_id,
                AssetColoringInfo {
                    output_map: info.output_map.iter().map(|(k, v)| (*k, *v)).collect(),
                    static_blinding: info.static_blinding,
                },
            );
        }
        Ok(ColoringInfo {
            asset_info_map,
            static_blinding: self.static_blinding,
            nonce: self.nonce,
        })
    }

    fn inputs(&self) -> Result<HashSet<OutPoint>, Error> {
        self.input_outpoints
            .iter()
            .map(OutPoint::try_from)
            .collect::<Result<_, _>>()
    }
}

/// Check `finalized` is the transaction `staged` was built on with only the RGB commitment
/// filled in: same version, lock time and inputs (in order), and the same outputs except for the
/// OP_RETURN commitment host, which must stay an OP_RETURN at the same index. Returns that index.
#[cfg(any(feature = "electrum", feature = "esplora"))]
fn psbt_op_check_finalized_tx(
    staged: &Transaction,
    finalized: &Transaction,
) -> Result<usize, Error> {
    let invalid = |details: String| Error::InvalidColoringInfo {
        details: format!("finalized PSBT does not match the staged one: {details}"),
    };
    let opret_idx = staged
        .output
        .iter()
        .position(|o| o.script_pubkey.is_op_return())
        .ok_or_else(|| Error::Inconsistency {
            details: s!("staged PSBT has no OP_RETURN output"),
        })?;
    if staged.version != finalized.version || staged.lock_time != finalized.lock_time {
        return Err(invalid(s!("version or lock time changed")));
    }
    if staged.input.len() != finalized.input.len()
        || staged
            .input
            .iter()
            .zip(&finalized.input)
            .any(|(s, f)| s.previous_output != f.previous_output || s.sequence != f.sequence)
    {
        return Err(invalid(s!("inputs changed")));
    }
    if staged.output.len() != finalized.output.len() {
        return Err(invalid(s!("outputs added or removed")));
    }
    for (vout, (s, f)) in staged.output.iter().zip(&finalized.output).enumerate() {
        let script_ok = if vout == opret_idx {
            f.script_pubkey.is_op_return()
        } else {
            s.script_pubkey == f.script_pubkey
        };
        if s.value != f.value || !script_ok {
            return Err(invalid(format!("output {vout} changed")));
        }
    }
    Ok(opret_idx)
}

/// Whether an output of `psbt` already carries MPC messages, i.e. the RGB commitment was
/// finalized. `mpc_message_map` returns an empty map for outputs without any, so `is_ok` alone
/// is true for every PSBT.
#[cfg(any(feature = "electrum", feature = "esplora"))]
fn psbt_rgb_commitment_finalized(psbt: &Psbt) -> bool {
    psbt.outputs
        .iter()
        .any(|o| o.mpc_message_map().is_ok_and(|m| !m.is_empty()))
}

/// Rebuild the MPC tree committed by the OP_RETURN at `opret_idx` of `psbt` and check the output
/// script carries exactly that commitment and that every `expected` message is in the tree.
#[cfg(any(feature = "electrum", feature = "esplora"))]
fn psbt_op_check_commitment(
    psbt: &Psbt,
    opret_idx: usize,
    expected: &BTreeMap<mpc::ProtocolId, mpc::Message>,
) -> Result<mpc::MerkleTree, Error> {
    let invalid = |details: String| Error::InvalidColoringInfo {
        details: format!("finalized PSBT {details}"),
    };
    let output = psbt
        .outputs
        .get(opret_idx)
        .ok_or_else(|| invalid(s!("has no map for its OP_RETURN output")))?;
    let messages = output.mpc_message_map().map_err(|e| {
        invalid(format!(
            "has no RGB commitment on its OP_RETURN output: {e}"
        ))
    })?;
    if expected
        .iter()
        .any(|(protocol_id, message)| messages.get(protocol_id) != Some(message))
    {
        return Err(invalid(s!(
            "does not commit this wallet's staged transitions"
        )));
    }
    let source = mpc::MultiSource {
        min_depth: output
            .mpc_min_tree_depth()
            .map(u5::with)
            .unwrap_or(MPC_MINIMAL_DEPTH),
        messages,
        static_entropy: output.mpc_entropy(),
    };
    let merkle_tree = mpc::MerkleTree::try_commit(&source)
        .map_err(|e| invalid(format!("has an invalid RGB MPC tree: {e}")))?;
    let expected_script = ScriptBuf::new_op_return(merkle_tree.commit_id().to_byte_array());
    if psbt.unsigned_tx.output[opret_idx].script_pubkey != expected_script {
        return Err(invalid(s!(
            "OP_RETURN output does not carry its RGB commitment"
        )));
    }
    Ok(merkle_tree)
}

/// Verify `finalized` commits the bundles `staged` carries for `contracts` unchanged, on the same
/// transaction, and build the fascia of those bundles alone: the other parties' contracts may be
/// unknown to this wallet's stash, which `psbt_op_apply` consumes the fascia into.
#[cfg(any(feature = "electrum", feature = "esplora"))]
fn psbt_op_finalized_fascia(
    staged: &Psbt,
    finalized: &Psbt,
    contracts: &BTreeSet<ContractId>,
) -> Result<Fascia, Error> {
    let opret_idx = psbt_op_check_finalized_tx(&staged.unsigned_tx, &finalized.unsigned_tx)?;
    let staged_bundles = staged.rgb_bundles().map_err(InternalError::from)?;
    let committed_bundles = finalized
        .rgb_bundles()
        .map_err(|e| Error::InvalidColoringInfo {
            details: format!("finalized PSBT has invalid RGB data: {e}"),
        })?;
    let mut bundles = BTreeMap::new();
    let mut expected = BTreeMap::new();
    for contract_id in contracts {
        let staged_bundle =
            staged_bundles
                .get(contract_id)
                .ok_or_else(|| Error::Inconsistency {
                    details: format!("staged PSBT has no bundle for contract {contract_id}"),
                })?;
        if committed_bundles.get(contract_id) != Some(staged_bundle) {
            return Err(Error::InvalidColoringInfo {
                details: format!(
                    "finalized PSBT does not carry this wallet's staged transitions for {contract_id} unchanged"
                ),
            });
        }
        expected.insert(
            mpc::ProtocolId::from(*contract_id),
            mpc::Message::from(staged_bundle.bundle_id()),
        );
        bundles.insert(*contract_id, staged_bundle.clone());
    }
    let merkle_tree = psbt_op_check_commitment(finalized, opret_idx, &expected)?;
    let bundles = Confined::try_from(bundles).map_err(|_| Error::Inconsistency {
        details: s!("staged operation has no contract"),
    })?;
    let seal_witness = SealWitness::new(
        PubWitness::with(finalized.unsigned_tx.clone()),
        mpc::MerkleBlock::from(merkle_tree),
        OpretProof::default().into(),
    );
    Ok(Fascia::new(seal_witness, bundles))
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ForeignInputEntry {
    asset_id: String,
    outpoint: Outpoint,
    assignments: Vec<Assignment>,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
type SpentByContract = HashMap<ContractId, HashMap<OutPoint, Vec<Assignment>>>;

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ForeignInputsFile {
    entries: Vec<ForeignInputEntry>,
}

fn psbt_has_input_signatures(psbt: &Psbt) -> bool {
    psbt.inputs.iter().any(|input| {
        !input.partial_sigs.is_empty()
            || input.tap_key_sig.is_some()
            || !input.tap_script_sigs.is_empty()
            || input.final_script_sig.is_some()
            || input.final_script_witness.is_some()
    })
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn pin_witness_output_to_recipient_id(
    resolver: &AnyResolver,
    indexer: &Indexer,
    chain_net: ChainNet,
    witness_recipient_id: &str,
    txid: &str,
    vout: u32,
    min_confirmations: u8,
) -> Result<(), Error> {
    let xchainnet_beneficiary = XChainNet::<Beneficiary>::from_str(witness_recipient_id)
        .map_err(|_| Error::InvalidRecipientID)?;
    if xchainnet_beneficiary.chain_network() != chain_net {
        return Err(Error::InvalidRecipientNetwork);
    }
    let expected_script = match xchainnet_beneficiary.into_inner() {
        Beneficiary::WitnessVout(pay_2_vout, _) => pay_2_vout.to_script(),
        Beneficiary::BlindedSeal(_) => return Err(Error::InvalidRecipientID),
    };
    let witness_id = RgbTxid::from_str(txid).map_err(|_| Error::InvalidTxid)?;
    let status = resolver
        .resolve_witness(witness_id)
        .map_err(|e| Error::Network {
            details: e.to_string(),
        })?;
    let (tx, witness_ord) = match status {
        WitnessStatus::Resolved(tx, ord) => (tx, ord),
        _ => {
            return Err(Error::Network {
                details: s!("witness transaction not found on indexer"),
            });
        }
    };
    let Some(output) = tx.output.get(vout as usize) else {
        return Err(Error::WitnessOutputMismatch {
            details: format!("witness vout {vout} out of range for transaction"),
        });
    };
    if output.script_pubkey != expected_script {
        return Err(Error::WitnessOutputMismatch {
            details: s!("witness output script does not match witness_recipient_id"),
        });
    }

    match witness_ord {
        WitnessOrd::Ignored | WitnessOrd::Archived => {
            return Err(Error::WitnessOutputMismatch {
                details: format!(
                    "witness TX {txid} has non-spendable WitnessOrd status ({witness_ord})"
                ),
            });
        }
        WitnessOrd::Tentative | WitnessOrd::Mined(_) => {}
    }

    if min_confirmations == 0 {
        return Ok(());
    }

    let WitnessOrd::Mined(pos) = witness_ord else {
        return Err(Error::InsufficientConfirmations {
            needed: min_confirmations,
            got: 0,
        });
    };

    let tip_height = indexer.get_latest_block_height()?;
    let tx_height = pos.height().get();
    let confirmations = u64::from(tip_height.saturating_sub(tx_height)) + 1;
    if confirmations < min_confirmations as u64 {
        return Err(Error::InsufficientConfirmations {
            needed: min_confirmations,
            got: confirmations,
        });
    }
    Ok(())
}

fn rebuild_psbt_preserving_maps(
    psbt: &Psbt,
    mut unsigned_tx: Transaction,
    opreturn_first: bool,
) -> Result<Psbt, Error> {
    for txin in &mut unsigned_tx.input {
        txin.script_sig = ScriptBuf::new();
        txin.witness.clear();
    }
    let mut rebuilt = Psbt::from_unsigned_tx(unsigned_tx).map_err(|e| Error::Internal {
        details: format!("Failed to create PSBT: {e}"),
    })?;
    rebuilt.version = psbt.version;
    rebuilt.xpub = psbt.xpub.clone();
    rebuilt.proprietary = psbt.proprietary.clone();
    rebuilt.unknown = psbt.unknown.clone();
    for (rebuilt_input, input) in rebuilt.inputs.iter_mut().zip(psbt.inputs.iter()) {
        *rebuilt_input = input.clone();
    }
    if opreturn_first {
        for (rebuilt_output, output) in rebuilt.outputs.iter_mut().skip(1).zip(psbt.outputs.iter())
        {
            *rebuilt_output = output.clone();
        }
    } else {
        for (rebuilt_output, output) in rebuilt.outputs.iter_mut().zip(psbt.outputs.iter()) {
            *rebuilt_output = output.clone();
        }
    }
    Ok(rebuilt)
}

/// Indexer protocol
#[derive(Debug, Clone)]
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub enum IndexerProtocol {
    /// An indexer implementing the electrum protocol
    Electrum,
    /// An indexer implementing the esplora protocol
    Esplora,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl fmt::Display for IndexerProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Return the indexer protocol for the provided URL.
/// An error is raised if the provided indexer URL is invalid or if the service is for the wrong
/// network or doesn't have the required functionality.
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn check_indexer_url(
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<IndexerProtocol, Error> {
    let (indexer, _) = get_indexer_and_resolver(indexer_url, bitcoin_network)?;
    let indexer_protocol = match indexer {
        #[cfg(feature = "electrum")]
        Indexer::Electrum(_) => IndexerProtocol::Electrum,
        #[cfg(feature = "esplora")]
        Indexer::Esplora(_) => IndexerProtocol::Esplora,
    };

    Ok(indexer_protocol)
}

/// Return an [`AnyResolver`] for the provided indexer URL, auto-detecting the protocol
/// (Electrum or Esplora).
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn get_resolver(
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<AnyResolver, Error> {
    let (_, resolver) = get_indexer_and_resolver(indexer_url, bitcoin_network)?;
    Ok(resolver)
}

/// Check whether the provided URL points to a valid proxy.
/// An error is raised if the provided proxy URL is invalid or if the service is running an
/// unsupported protocol version.
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn check_proxy_url(proxy_url: &str) -> Result<(), Error> {
    check_proxy(proxy_url)
}

/// Validate a consignment using the witness bundled in the consignment (offchain).
/// This works before the witness transaction is broadcast, unlike [`get_resolver`]-based
/// validation which requires the TX to be in the indexer.
///
/// The `txid` is the witness transaction ID (from consignment.post params).
/// The `indexer_url` is used as fallback when the witness is not found in the consignment.
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn validate_consignment_offchain(
    file_path: &str,
    txid: &str,
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<ValidateConsignmentResult, Error> {
    use rgbstd::validation::ValidationError;

    let consignment = RgbTransfer::load_file(file_path).map_err(|e| Error::Internal {
        details: format!("Failed to load consignment: {e}"),
    })?;

    let witness_id = RgbTxid::from_str(txid).map_err(|_| Error::InvalidTxid)?;
    let chain_net: ChainNet = bitcoin_network.into();
    let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
    let trusted_typesystem = asset_schema.types();

    let fallback_resolver = get_resolver(indexer_url, bitcoin_network)?;

    let resolver = crate::utils::OffchainResolver {
        witness_id,
        consignment: &consignment,
        fallback: &fallback_resolver,
    };

    let validation_config = ValidationConfig {
        chain_net,
        trusted_typesystem,
        ..Default::default()
    };

    match consignment.clone().validate(&resolver, &validation_config) {
        Ok(valid_consignment) => {
            let status = valid_consignment.validation_status();
            Ok(ValidateConsignmentResult {
                valid: true,
                warnings: Some(
                    status
                        .warnings
                        .iter()
                        .map(|w| w.to_string())
                        .collect::<Vec<_>>(),
                ),
                error: None,
                details: None,
            })
        }
        Err(ValidationError::InvalidConsignment(failure)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("invalid".to_string()),
            details: Some(failure.to_string()),
        }),
        Err(ValidationError::ResolverError(e)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("resolver".to_string()),
            details: Some(e.to_string()),
        }),
    }
}

/// Result of consignment validation (offchain or indexer-based).
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone)]
pub struct ValidateConsignmentResult {
    /// Whether the consignment is valid.
    pub valid: bool,
    /// Warnings from validation (when valid).
    pub warnings: Option<Vec<String>>,
    /// Error type when invalid ("invalid" or "resolver").
    pub error: Option<String>,
    /// Error details when invalid.
    pub details: Option<String>,
}

/// Validate a consignment using the indexer only (witness TX must be visible to the indexer).
///
/// For transfers where the witness is not on-chain yet, use [`validate_consignment_offchain`].
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn validate_consignment(
    file_path: &str,
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<ValidateConsignmentResult, Error> {
    use rgbstd::validation::ValidationError;

    let consignment = RgbTransfer::load_file(file_path).map_err(|e| Error::Internal {
        details: format!("Failed to load consignment: {e}"),
    })?;

    let chain_net: ChainNet = bitcoin_network.into();
    let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
    let trusted_typesystem = asset_schema.types();

    let resolver = get_resolver(indexer_url, bitcoin_network)?;

    let validation_config = ValidationConfig {
        chain_net,
        trusted_typesystem,
        ..Default::default()
    };

    match consignment.clone().validate(&resolver, &validation_config) {
        Ok(valid_consignment) => {
            let status = valid_consignment.validation_status();
            Ok(ValidateConsignmentResult {
                valid: true,
                warnings: Some(
                    status
                        .warnings
                        .iter()
                        .map(|w| w.to_string())
                        .collect::<Vec<_>>(),
                ),
                error: None,
                details: None,
            })
        }
        Err(ValidationError::InvalidConsignment(failure)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("invalid".to_string()),
            details: Some(failure.to_string()),
        }),
        Err(ValidationError::ResolverError(e)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("resolver".to_string()),
            details: Some(e.to_string()),
        }),
    }
}

/// Rust-only APIs of the wallet.
impl Wallet {
    /// Export an RGB contract known to this wallet.
    ///
    /// The returned consignment contains the public contract definition and genesis metadata, but
    /// no transfer or allocation state. It can be distributed as public contract metadata and
    /// imported with [`import_asset_contract`](Wallet::import_asset_contract).
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed,
    /// use it only if you know what you're doing</div>
    pub fn export_asset_contract(&self, asset_id: String) -> Result<RgbContract, Error> {
        let contract_id = ContractId::from_str(&asset_id).map_err(|error| Error::Internal {
            details: format!("invalid asset ID: {error}"),
        })?;
        self.rgb_runtime()?
            .export_contract(contract_id)
            .map_err(Error::from)
    }

    /// Validate and import an RGB contract without importing any asset allocations.
    ///
    /// This registers the contract and its metadata in the wallet. It does not transfer ownership
    /// and the imported asset therefore starts with a zero balance. Re-importing a fully persisted
    /// contract is idempotent and returns the existing metadata. If an earlier import was
    /// interrupted between its RGB stock and database writes, retrying repairs the partial state.
    ///
    /// Contract attachments are not embedded in a contract consignment. Contracts declaring
    /// attachments must be imported through a flow that supplies and verifies those files.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed,
    /// use it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn import_asset_contract(
        &self,
        contract: RgbContract,
    ) -> Result<ImportAssetContractResult, Error> {
        let contract_id = contract.contract_id();
        let asset_id = contract_id.to_string();

        let asset_schema: AssetSchema = contract.schema_id().try_into()?;
        self.check_schema_support(&asset_schema)?;
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem: asset_schema.types(),
            ..Default::default()
        };
        let valid_contract = contract
            .validate(&DumbResolver, &validation_config)
            .map_err(|_| Error::InvalidConsignment)?;

        // The RGB runtime lock serializes the stock and database state transition. Persisting the
        // stock before committing the database makes every interrupted state repairable on retry.
        let mut runtime = self.rgb_runtime()?;
        let contract_in_stock = runtime.export_contract(contract_id).is_ok();
        let txn = self.database().begin_transaction()?;
        let asset_in_database = txn.get_asset(asset_id.clone())?.is_some();
        let already_imported = contract_in_stock && asset_in_database;

        if already_imported {
            drop(txn);
            drop(runtime);
            return Ok(ImportAssetContractResult {
                asset_id: asset_id.clone(),
                already_imported: true,
                metadata: self.get_asset_metadata(asset_id)?,
            });
        }

        if !asset_in_database
            && !self
                .extract_attachments(&valid_contract, asset_schema)
                .is_empty()
        {
            return Err(Error::InvalidAttachments {
                details: "contract import requires the declared attachment files".to_string(),
            });
        }

        if !contract_in_stock {
            runtime.require_explicit_persistence();
            runtime.import_contract(valid_contract.clone(), &DumbResolver)?;
        }

        if !asset_in_database {
            self.save_new_asset_internal(
                &txn,
                &runtime,
                contract_id,
                asset_schema,
                valid_contract,
                None,
            )?;
        }
        self.update_backup_info(&txn, false)?;
        if !contract_in_stock {
            runtime.persist()?;
        }
        txn.commit()?;
        drop(runtime);
        self.trigger_auto_backup();

        Ok(ImportAssetContractResult {
            asset_id: asset_id.clone(),
            already_imported,
            metadata: self.get_asset_metadata(asset_id)?,
        })
    }

    /// Color a PSBT.
    ///
    /// With P2TR, OP_RETURN is at vout 0 and `output_map` keys are pre-OP_RETURN indices. Signed
    /// inputs are rejected.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn color_psbt(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        let prev_outputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect::<HashSet<OutPoint>>();
        self.color_psbt_with_prevouts(psbt, coloring_info, prev_outputs, false)
    }

    /// Ensure the PSBT can be colored: reject signed inputs, insert OP_RETURN if missing.
    ///
    /// Returns whether `output_map` keys should be +1-shifted ([`Self::color_psbt`] legacy
    /// `OpretFirst` rule): `true` when any output is P2TR and OP_RETURN is (or will be) at
    /// vout 0. With P2TR, a pre-existing OP_RETURN at index > 0 is rejected so +1 cannot
    /// silently mis-seal. [`Self::color_psbt_for_outpoints`] ignores this flag.
    ///
    /// Uses `unsigned_tx` directly (no `extract_tx`): fee-rate guards are irrelevant to RGB
    /// commitment layout, and HTLC PSBTs may trip `AbsurdFeeRate` without being invalid to color.
    fn prepare_psbt_for_coloring(&self, psbt: &mut Psbt) -> Result<bool, Error> {
        if psbt_has_input_signatures(psbt) {
            return Err(Error::InvalidColoringInfo {
                details: s!(
                    "cannot color a signed PSBT: RGB commitment rewrites the OP_RETURN output"
                ),
            });
        }
        let opreturn_first = psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr());
        match psbt
            .unsigned_tx
            .output
            .iter()
            .position(|o| o.script_pubkey.is_op_return())
        {
            None => {
                let mut transaction = psbt.unsigned_tx.clone();
                let opreturn_output = TxOut {
                    value: BdkAmount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return([]),
                };
                if opreturn_first {
                    transaction.output.insert(0, opreturn_output);
                } else {
                    transaction.output.push(opreturn_output);
                }
                *psbt = rebuild_psbt_preserving_maps(psbt, transaction, opreturn_first)?;
            }
            Some(0) => {}
            // +1 assumes OP_RETURN at / inserted at vout 0; otherwise seals shift with no insert.
            Some(_) if opreturn_first => {
                return Err(Error::InvalidColoringInfo {
                    details: s!("OP_RETURN must be the first PSBT output"),
                });
            }
            Some(_) => {}
        }

        Ok(opreturn_first)
    }

    fn color_psbt_with_prevouts(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        prev_outputs: HashSet<OutPoint>,
        require_full_allocation: bool,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        info!(self.logger(), "Coloring PSBT...");
        let shift_output_map_for_opreturn_first = self.prepare_psbt_for_coloring(psbt)?;
        let runtime = self.rgb_runtime()?;
        self.color_psbt_with_prevouts_runtime(
            &runtime,
            psbt,
            coloring_info,
            prev_outputs,
            require_full_allocation,
            shift_output_map_for_opreturn_first,
        )
    }

    fn color_psbt_with_prevouts_runtime(
        &self,
        runtime: &RgbRuntime,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        prev_outputs: HashSet<OutPoint>,
        require_full_allocation: bool,
        shift_output_map_for_opreturn_first: bool,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        let static_blinding = coloring_info.static_blinding;
        let asset_beneficiaries = self.color_psbt_stage_runtime(
            runtime,
            psbt,
            coloring_info,
            prev_outputs,
            require_full_allocation,
            shift_output_map_for_opreturn_first,
        )?;
        let fascia = self.color_psbt_finalize(psbt, static_blinding)?;
        info!(self.logger(), "Color PSBT completed");
        Ok((fascia, asset_beneficiaries))
    }

    fn color_psbt_stage_runtime(
        &self,
        runtime: &RgbRuntime,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        prev_outputs: HashSet<OutPoint>,
        require_full_allocation: bool,
        shift_output_map_for_opreturn_first: bool,
    ) -> Result<AssetBeneficiariesMap, Error> {
        let mut all_transitions: HashMap<ContractId, Transition> = HashMap::new();
        let mut asset_beneficiaries: AssetBeneficiariesMap = bmap![];
        let assignment_name = FieldName::from(RGB_STATE_ASSET_OWNER);

        for (contract_id, asset_coloring_info) in coloring_info.asset_info_map.clone() {
            let schema = AssetSchema::get_from_contract_id(contract_id, runtime)?;

            let mut asset_transition_builder =
                runtime.transition_builder(contract_id, "transfer")?;

            let mut asset_available_amt: u64 = 0;
            let mut uda_state = None;
            for (_, opout_state_map) in
                runtime.contract_assignments_for(contract_id, prev_outputs.iter().copied())?
            {
                for (opout, state) in opout_state_map {
                    // Only the asset-owner assignment is re-assigned below, so a right on a spent
                    // input would be destroyed. An inflation right is `Amount` state too, so it
                    // would additionally be counted as spendable fungible value by the accounting
                    // right after this, making the full-allocation check reject honest callers.
                    if require_full_allocation && opout.ty != OS_ASSET {
                        let right = if opout.ty == OS_INFLATION {
                            "an inflation right"
                        } else if opout.ty == OS_LINK {
                            "a link right"
                        } else {
                            "a non-asset assignment"
                        };
                        return Err(Error::InvalidColoringInfo {
                            details: format!(
                                "a PSBT input carries {right} for contract {contract_id}, which this method cannot re-assign"
                            ),
                        });
                    }
                    if let AllocatedState::Amount(amt) = &state {
                        asset_available_amt = asset_available_amt
                            .checked_add(amt.as_u64())
                            .expect("total available asset amount cannot exceed u64::MAX");
                    } else if let AllocatedState::Data(_) = &state {
                        asset_available_amt = 1;
                        // there can be only a single state when contract is UDA
                        uda_state = Some(state.clone());
                    }
                    asset_transition_builder = asset_transition_builder.add_input(opout, state)?;
                }
            }

            let mut beneficiaries = vec![];
            let mut output_seals: Vec<(BuilderSeal<GraphSeal>, u64)> = vec![];
            let mut sending_amt: u64 = 0;
            // walk vouts in ascending order: iterating the HashMap directly would let the reported
            // validation error and the beneficiary ordering vary between otherwise identical calls
            for (mut vout, amount) in BTreeMap::from_iter(asset_coloring_info.output_map) {
                if amount == 0 {
                    continue;
                }
                if shift_output_map_for_opreturn_first {
                    vout = vout
                        .checked_add(1)
                        .ok_or_else(|| Error::InvalidColoringInfo {
                            details: s!("vout in output_map is too large"),
                        })?;
                }
                sending_amt =
                    sending_amt
                        .checked_add(amount)
                        .ok_or_else(|| Error::InvalidColoringInfo {
                            details: s!("total amount in output_map exceeds u64::MAX"),
                        })?;
                if vout as usize >= psbt.unsigned_tx.output.len() {
                    return Err(Error::InvalidColoringInfo {
                        details: s!("invalid vout in output_map, does not exist in the given PSBT"),
                    });
                }
                if psbt.unsigned_tx.output[vout as usize]
                    .script_pubkey
                    .is_op_return()
                {
                    return Err(Error::InvalidColoringInfo {
                        details: format!("output_map vout {vout} points to the OP_RETURN output"),
                    });
                }
                let graph_seal = if let Some(blinding) = asset_coloring_info.static_blinding {
                    GraphSeal::with_blinded_vout(vout, blinding)
                } else {
                    GraphSeal::new_random_vout(vout)
                };
                let seal = BuilderSeal::Revealed(graph_seal);
                beneficiaries.push(seal);
                output_seals.push((seal, amount));
            }
            if sending_amt > asset_available_amt {
                return Err(Error::InvalidColoringInfo {
                    details: format!(
                        "total amount in output_map ({sending_amt}) greater than available ({asset_available_amt})"
                    ),
                });
            }
            if require_full_allocation && sending_amt < asset_available_amt {
                return Err(Error::InvalidColoringInfo {
                    details: format!(
                        "total amount in output_map ({sending_amt}) less than available ({asset_available_amt}); full allocation required"
                    ),
                });
            }

            for (seal, amount) in output_seals {
                match schema {
                    AssetSchema::Nia | AssetSchema::Cfa | AssetSchema::Ifa => {
                        asset_transition_builder = asset_transition_builder.add_fungible_state(
                            assignment_name.clone(),
                            seal,
                            amount,
                        )?;
                    }
                    AssetSchema::Uda => {
                        let Some(AllocatedState::Data(state)) = uda_state.clone() else {
                            return Err(Error::InvalidColoringInfo {
                                details: format!(
                                    "UDA contract {contract_id} has no token assignment on the selected inputs"
                                ),
                            });
                        };
                        asset_transition_builder = asset_transition_builder
                            .add_data(assignment_name.clone(), seal, Allocation::from(state))
                            .map_err(Error::from)?;
                    }
                }
            }

            if let Some(nonce) = coloring_info.nonce {
                asset_transition_builder = asset_transition_builder.set_nonce(nonce);
            }

            let transition = asset_transition_builder.complete_transition()?;
            all_transitions.insert(contract_id, transition);
            asset_beneficiaries.insert(contract_id, beneficiaries);
        }

        for (contract_id, transition) in all_transitions {
            for opout in transition.inputs() {
                psbt.set_rgb_contract_consumer(contract_id, opout, transition.id())
                    .map_err(InternalError::from)?;
            }
            psbt.push_rgb_transition(transition)
                .map_err(InternalError::from)?;
        }

        info!(self.logger(), "Stage RGB coloring completed");
        Ok(asset_beneficiaries)
    }

    /// Finalize the RGB commitment on a PSBT that has had one or more contracts staged via
    /// [`Wallet::color_psbt_stage`]. Must be called exactly once per swap PSBT, after all staging
    /// is complete.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn color_psbt_finalize(
        &self,
        psbt: &mut Psbt,
        static_blinding: Option<u64>,
    ) -> Result<Fascia, Error> {
        info!(self.logger(), "Finalizing RGB commitment on PSBT...");
        let opreturn_index = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey.is_op_return())
            .ok_or_else(|| Error::InvalidColoringInfo {
                details: s!("PSBT has no OP_RETURN output to host the RGB commitment"),
            })?
            .0;
        let opreturn_output = psbt.outputs.get_mut(opreturn_index).unwrap();
        opreturn_output.set_opret_host();
        if let Some(blinding) = static_blinding {
            opreturn_output
                .set_mpc_entropy(blinding)
                .map_err(InternalError::from)?;
        }

        psbt.set_rgb_close_method(CloseMethod::OpretFirst);
        psbt.set_as_unmodifiable();
        let fascia = psbt.rgb_commit().map_err(InternalError::from)?;

        info!(self.logger(), "Finalize RGB commitment completed");
        Ok(fascia)
    }

    /// Reconstruct an RGB fascia from a PSBT whose RGB commitment has already been finalized.
    ///
    /// This is used by high-level interactive flows where one party receives a PSBT after the
    /// counterparty has finalized the MPC commitment. It keeps the raw fascia internal to Rust while
    /// still allowing the wallet to consume the RGB transition data.
    pub(crate) fn fascia_from_finalized_psbt(&self, psbt: &Psbt) -> Result<Fascia, Error> {
        let bundles = psbt.rgb_bundles().map_err(InternalError::from)?;
        let output = psbt
            .outputs
            .iter()
            .find(|output| output.mpc_message_map().is_ok())
            .ok_or_else(|| Error::InvalidColoringInfo {
                details: s!("PSBT has no RGB MPC message host"),
            })?;
        let messages = output.mpc_message_map().map_err(InternalError::from)?;
        let min_depth = output
            .mpc_min_tree_depth()
            .map(u5::with)
            .unwrap_or(MPC_MINIMAL_DEPTH);
        let source = mpc::MultiSource {
            min_depth,
            messages,
            static_entropy: output.mpc_entropy(),
        };
        let merkle_tree =
            mpc::MerkleTree::try_commit(&source).map_err(|e| Error::InvalidColoringInfo {
                details: format!("failed to reconstruct RGB MPC proof: {e}"),
            })?;
        let merkle_block = mpc::MerkleBlock::from(merkle_tree);
        let bundles = Confined::try_from(bundles).map_err(|_| Error::InvalidColoringInfo {
            details: s!("PSBT has no RGB bundles"),
        })?;
        let seal_witness = SealWitness::new(
            PubWitness::with(psbt.unsigned_tx.clone()),
            merkle_block,
            OpretProof::default().into(),
        );
        Ok(Fascia::new(seal_witness, bundles))
    }

    /// Validate a counterparty's colored HTLC spend without reserving inputs or
    /// consuming its transitions. The wallet must already know the lock's RGB history.
    /// Only one contract/transition, consuming all state on `locked_outpoint`
    /// and assigning exactly `amount` to `payment_vout`, is accepted.
    /// Bitcoin prevout identity, fee policy and signing authorization are the caller's job.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn validate_htlc_spend(
        &self,
        psbt: &Psbt,
        contract_id: ContractId,
        locked_outpoint: OutPoint,
        amount: u64,
        payment_vout: u32,
        indexer_url: &str,
    ) -> Result<Vec<PsbtOpAllocation>, Error> {
        let invalid = |details: &str| Error::InvalidColoringInfo {
            details: details.to_owned(),
        };
        if psbt.unsigned_tx.output.get(payment_vout as usize).is_none()
            || psbt
                .unsigned_tx
                .input
                .iter()
                .filter(|i| i.previous_output == locked_outpoint)
                .count()
                != 1
        {
            return Err(invalid(
                "HTLC spend must contain the pinned input and payment output",
            ));
        }
        let fascia = self.fascia_from_finalized_psbt(psbt)?;
        let bundles: Vec<_> = fascia.bundles().iter().collect();
        if bundles.len() != 1
            || *bundles[0].0 != contract_id
            || bundles[0].1.known_transitions.len() != 1
        {
            return Err(invalid(
                "HTLC spend must contain exactly one known contract transition",
            ));
        }
        let allocations = fascia_allocations(&fascia)?;
        if allocations
            != vec![PsbtOpAllocation {
                asset_id: contract_id.to_string(),
                vout: Some(payment_vout),
                assignment: Assignment::Fungible(amount),
            }]
        {
            return Err(invalid(
                "HTLC spend does not preserve the exact allocation at the payment output",
            ));
        }
        let runtime = self.rgb_runtime()?;
        let other_inputs: Vec<_> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|i| i.previous_output)
            .filter(|outpoint| *outpoint != locked_outpoint)
            .collect();
        if !runtime.contracts_assigning(other_inputs)?.is_empty()
            || runtime.contracts_assigning([locked_outpoint])? != BTreeSet::from([contract_id])
        {
            return Err(invalid(
                "HTLC spend would leave another known RGB allocation uncolored",
            ));
        }
        let mut expected = BTreeSet::new();
        for (_, states) in runtime.contract_assignments_for(contract_id, [locked_outpoint])? {
            expected.extend(states.keys().copied());
        }
        let bundle = bundles[0].1;
        let consumed: BTreeSet<_> = bundle.known_transitions[0]
            .transition
            .inputs
            .iter()
            .copied()
            .collect();
        let mapped: BTreeSet<_> = bundle.input_map.keys().copied().collect();
        if expected.is_empty() || consumed != expected || mapped != expected {
            return Err(invalid(
                "HTLC transition must consume precisely the pinned lock's known RGB state",
            ));
        }
        let witness_id = fascia.witness_id();
        let consignment = runtime.transfer_from_fascia(
            contract_id,
            vec![ExplicitSeal::with(witness_id, payment_vout)],
            Vec::new(),
            &fascia,
        )?;
        let fallback = get_resolver(indexer_url, self.bitcoin_network())?;
        let resolver = crate::utils::OffchainResolver {
            witness_id,
            consignment: &consignment,
            fallback: &fallback,
        };
        let schema: AssetSchema = consignment.schema_id().try_into()?;
        let config = ValidationConfig {
            chain_net: self.bitcoin_network().into(),
            trusted_typesystem: schema.types(),
            ..Default::default()
        };
        consignment
            .clone()
            .validate(&resolver, &config)
            .map_err(|e| match e {
                ValidationError::ResolverError(e) => Error::Network {
                    details: e.to_string(),
                },
                ValidationError::InvalidConsignment(e) => Error::InvalidColoringInfo {
                    details: format!("invalid HTLC spend proof: {e}"),
                },
            })?;
        Ok(allocations)
    }

    /// Stage RGB coloring information onto a PSBT without finalizing the MPC commitment.
    ///
    /// Multiple parties may each call this method on the same PSBT (each for their own contracts),
    /// in which case [`Wallet::color_psbt_finalize`] must be invoked once after all staging is
    /// complete to produce the [`Fascia`]. `output_map` indexing follows [`Self::color_psbt`].
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn color_psbt_stage(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
    ) -> Result<AssetBeneficiariesMap, Error> {
        info!(self.logger(), "Staging RGB coloring onto PSBT...");
        let prev_outputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect::<HashSet<OutPoint>>();
        let shift_output_map_for_opreturn_first = self.prepare_psbt_for_coloring(psbt)?;
        let runtime = self.rgb_runtime()?;
        self.color_psbt_stage_runtime(
            &runtime,
            psbt,
            coloring_info,
            prev_outputs,
            false,
            shift_output_map_for_opreturn_first,
        )
    }

    /// Stage coloring spending only `prev_outputs`, requiring every allocation they carry to be
    /// reassigned (no implicit burn).
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn color_psbt_stage_for_inputs(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        prev_outputs: HashSet<OutPoint>,
    ) -> Result<AssetBeneficiariesMap, Error> {
        let runtime = self.rgb_runtime()?;
        self.reject_uncolored_input_contracts(&runtime, &prev_outputs, &coloring_info)?;
        let shift_output_map_for_opreturn_first = self.prepare_psbt_for_coloring(psbt)?;
        self.color_psbt_stage_runtime(
            &runtime,
            psbt,
            coloring_info,
            prev_outputs,
            true,
            shift_output_map_for_opreturn_first,
        )
    }

    /// Record a colored PSBT as an Initiated batch inside `txn` without touching the stash. The
    /// fascia is applied later by [`Self::consume_transfer_fascia`], once the TX is known.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn prepare_consume_txn(
        &self,
        txn: &DbTxn,
        psbt: &Psbt,
        fascia: &Fascia,
        coloring_info: &ColoringInfo,
        prev_outputs: &HashSet<OutPoint>,
        shift_output_map_for_opreturn_first: bool,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
    ) -> Result<i32, Error> {
        let runtime = self.rgb_runtime()?;
        let mut spent: SpentByContract = HashMap::new();
        for contract_id in coloring_info.asset_info_map.keys() {
            let by_outpoint = spent.entry(*contract_id).or_default();
            for (explicit_seal, opout_state_map) in
                runtime.contract_assignments_for(*contract_id, prev_outputs.iter().copied())?
            {
                for (opout, state) in opout_state_map {
                    by_outpoint
                        .entry(explicit_seal.to_outpoint())
                        .or_default()
                        .push(Assignment::from_opout_and_state(opout, &state));
                }
            }
        }
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        self.write_color_prepare_files(psbt, &txid, fascia, true)?;
        self.persist_color_prepare_batch_txn(
            txn,
            psbt,
            &txid,
            &spent,
            coloring_info,
            shift_output_map_for_opreturn_first,
            min_confirmations,
            expiration_timestamp,
            &runtime,
        )
    }

    /// Color a PSBT, build consignments, and register a fallible batch transfer.
    ///
    /// `output_map` indexing follows [`Self::color_psbt`] (legacy P2TR / `OpretFirst` +1 shift).
    ///
    /// Consignments are built from the fascia **before** any stash update. The fascia is saved
    /// under the wallet transfer dir and a [`TransferStatus::Initiated`] batch is written so
    /// [`crate::wallet::Wallet::fail_transfers`] can roll back if the tx is never broadcast.
    /// Call [`Self::consume_transfer_fascia`] with [`ColorPrepareResult::batch_transfer_idx`]
    /// **after** broadcast (the indexer must see the tx) to apply the fascia to the RGB stash.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn color_psbt_and_prepare_consume(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
    ) -> Result<ColorPrepareResult, Error> {
        info!(self.logger(), "Coloring PSBT and preparing consume...");
        let prev_outputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect::<HashSet<OutPoint>>();
        let mut runtime = self.rgb_runtime()?;
        // checked before `prepare_psbt_for_coloring`, which would otherwise insert an OP_RETURN
        // into the caller's PSBT on the way to failing
        self.reject_uncolored_input_contracts(&runtime, &prev_outputs, &coloring_info)?;
        let shift_output_map_for_opreturn_first = self.prepare_psbt_for_coloring(psbt)?;
        let (fascia, asset_beneficiaries) = self.color_psbt_with_prevouts_runtime(
            &runtime,
            psbt,
            coloring_info.clone(),
            prev_outputs.clone(),
            true,
            shift_output_map_for_opreturn_first,
        )?;
        let result = self.prepare_color_and_transfer_runtime(
            &mut runtime,
            psbt,
            fascia,
            asset_beneficiaries,
            &prev_outputs,
            &coloring_info,
            shift_output_map_for_opreturn_first,
            min_confirmations,
            expiration_timestamp,
        )?;
        info!(self.logger(), "Color PSBT prepare-consume completed");
        Ok(result)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn prepare_color_psbt_for_outpoints(
        &self,
        psbt: &mut Psbt,
        coloring_info: &ColoringInfo,
        input_outpoints: Vec<OutPoint>,
        omitted_own_only: bool,
    ) -> Result<(RgbRuntime, HashSet<OutPoint>), Error> {
        let override_set: HashSet<OutPoint> = input_outpoints.into_iter().collect();
        if override_set.is_empty() {
            return Err(Error::InvalidColoringInfo {
                details: s!("input_outpoints is empty"),
            });
        }
        let psbt_inputs: HashSet<OutPoint> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect();
        if !override_set.is_subset(&psbt_inputs) {
            return Err(Error::InvalidColoringInfo {
                details: s!("input_outpoints must be a subset of PSBT inputs"),
            });
        }
        let runtime = self.rgb_runtime()?;
        self.validate_color_psbt_for_outpoints_inputs(
            &runtime,
            psbt,
            &override_set,
            &psbt_inputs,
            coloring_info,
            omitted_own_only,
        )?;
        // Signed-PSBT check; OP_RETURN is already required. Ignore the legacy P2TR shift flag —
        // this API always uses final vout indices.
        let _ = self.prepare_psbt_for_coloring(psbt)?;
        Ok((runtime, override_set))
    }

    /// Color a PSBT using a provided set of input outpoints.
    ///
    /// `input_outpoints` must be a non-empty subset of the PSBT inputs. Any PSBT input that
    /// still carries RGB allocations is rejected: omitted inputs must not carry allocations,
    /// and included inputs must have every allocated contract listed in `coloring_info`.
    ///
    /// The PSBT must already contain an OP_RETURN output. If any output is P2TR (RGB
    /// `OpretFirst`), that OP_RETURN must be output 0 so the fascia commitment precedes taproot
    /// outputs. This entry point is meant for externally constructed (HTLC) transactions whose
    /// output layout must not be rewritten.
    ///
    /// # `output_map` index convention (differs from [`Self::color_psbt`])
    ///
    /// Keys are always **final PSBT vout indices**. This method never inserts outputs and never
    /// shifts keys. Do **not** pass the pre-OP_RETURN indices used by [`Self::color_psbt`] when
    /// that method applies the P2TR / `OpretFirst` +1 shift — using the wrong base silently seals
    /// the wrong output.
    ///
    /// Coloring must happen **before** any input is signed (same rule as [`Self::color_psbt`]).
    ///
    /// Every contract listed in `coloring_info` must allocate the full available amount from the
    /// selected inputs; under-allocation is rejected (no implicit burn).
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn color_psbt_for_outpoints(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        info!(self.logger(), "Coloring PSBT...");
        let (runtime, override_set) =
            self.prepare_color_psbt_for_outpoints(psbt, &coloring_info, input_outpoints, false)?;
        let result = self.color_psbt_with_prevouts_runtime(
            &runtime,
            psbt,
            coloring_info,
            override_set,
            true,
            false,
        );
        info!(self.logger(), "Color PSBT completed");
        result
    }

    /// Refuse to spend inputs carrying allocations for contracts absent from `coloring_info`.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn reject_uncolored_input_contracts(
        &self,
        runtime: &RgbRuntime,
        inputs: &HashSet<OutPoint>,
        coloring_info: &ColoringInfo,
    ) -> Result<(), Error> {
        let colored_contracts: BTreeSet<ContractId> =
            coloring_info.asset_info_map.keys().copied().collect();
        let assigning = runtime.contracts_assigning(inputs.iter().copied())?;
        let uncolored: Vec<ContractId> =
            assigning.difference(&colored_contracts).copied().collect();
        if !uncolored.is_empty() {
            let contracts = uncolored
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::InvalidColoringInfo {
                details: format!(
                    "PSBT inputs carry RGB allocations for contracts not listed in coloring_info: {contracts}"
                ),
            });
        }
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn validate_color_psbt_for_outpoints_inputs(
        &self,
        runtime: &RgbRuntime,
        psbt: &Psbt,
        override_set: &HashSet<OutPoint>,
        psbt_inputs: &HashSet<OutPoint>,
        coloring_info: &ColoringInfo,
        omitted_own_only: bool,
    ) -> Result<(), Error> {
        let mut omitted: Vec<OutPoint> = psbt_inputs.difference(override_set).copied().collect();
        if omitted_own_only {
            // other parties' inputs may legitimately carry their own allocations, which this
            // wallet may know (e.g. after importing their history); only this wallet's coins
            // must never be spent with their allocations left uncolored
            let txn = self.database().begin_transaction()?;
            let mut own = Vec::new();
            for outpoint in omitted {
                if txn.get_txo(&outpoint.into())?.is_some() {
                    own.push(outpoint);
                }
            }
            omitted = own;
        }
        if !omitted.is_empty() {
            let assigning = runtime.contracts_assigning(omitted)?;
            if !assigning.is_empty() {
                let contracts = assigning
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(Error::InvalidColoringInfo {
                    details: format!(
                        "PSBT inputs omitted from input_outpoints carry RGB allocations for {contracts}"
                    ),
                });
            }
        }
        self.reject_uncolored_input_contracts(runtime, override_set, coloring_info)?;
        let outputs = &psbt.unsigned_tx.output;
        let has_p2tr = outputs.iter().any(|o| o.script_pubkey.is_p2tr());
        match outputs.iter().position(|o| o.script_pubkey.is_op_return()) {
            None => {
                return Err(Error::InvalidColoringInfo {
                    details: s!("PSBT must include an OP_RETURN output"),
                });
            }
            Some(0) => {}
            Some(_) if has_p2tr => {
                return Err(Error::InvalidColoringInfo {
                    details: s!("OP_RETURN must be the first PSBT output"),
                });
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Color a PSBT for explicit input outpoints, build consignments, register a fallible batch.
    ///
    /// Same recovery model as [`Self::color_psbt_and_prepare_consume`]: stash is updated only by
    /// [`Self::consume_transfer_fascia`] after broadcast; use `fail_transfers` if the tx is dropped.
    /// `min_confirmations` and `expiration_timestamp` have the same meaning as there.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn color_psbt_for_outpoints_and_prepare_consume(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
    ) -> Result<ColorPrepareResult, Error> {
        info!(self.logger(), "Coloring PSBT and preparing consume...");
        let (mut runtime, override_set) =
            self.prepare_color_psbt_for_outpoints(psbt, &coloring_info, input_outpoints, false)?;
        let (fascia, asset_beneficiaries) = self.color_psbt_with_prevouts_runtime(
            &runtime,
            psbt,
            coloring_info.clone(),
            override_set.clone(),
            true,
            false,
        )?;
        let result = self.prepare_color_and_transfer_runtime(
            &mut runtime,
            psbt,
            fascia,
            asset_beneficiaries,
            &override_set,
            &coloring_info,
            false,
            min_confirmations,
            expiration_timestamp,
        )?;
        info!(self.logger(), "Color PSBT prepare-consume completed");
        Ok(result)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn mark_psbt_inputs_spent(&self, txn: &DbTxn, psbt: &Psbt) -> Result<(), Error> {
        for input in &psbt.unsigned_tx.input {
            let outpoint = Outpoint {
                txid: input.previous_output.txid.to_string(),
                vout: input.previous_output.vout,
            };
            if let Some(db_txo) = txn.get_txo(&outpoint)? {
                let mut db_txo: DbTxoActMod = db_txo.into();
                db_txo.spent = ActiveValue::Set(true);
                txn.update_txo(db_txo)?;
            }
        }
        Ok(())
    }

    /// Apply a fascia previously prepared by [`Self::color_psbt_and_prepare_consume`] (or the outpoints
    /// variant) into the RGB stash after the Bitcoin tx has been broadcast.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn consume_transfer_fascia(
        &mut self,
        online: Online,
        batch_transfer_idx: i32,
    ) -> Result<(), Error> {
        info!(
            self.logger(),
            "Consuming transfer fascia for batch {batch_transfer_idx}..."
        );
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let db_data = txn.get_db_data(false)?;
        let batch_transfer =
            txn.get_batch_transfer_or_fail(batch_transfer_idx, &db_data.batch_transfers)?;
        if batch_transfer.status != TransferStatus::Initiated {
            return Err(Error::Internal {
                details: format!(
                    "batch transfer {batch_transfer_idx} is {:?}, expected Initiated",
                    batch_transfer.status
                ),
            });
        }
        let txid = batch_transfer
            .txid
            .as_ref()
            .ok_or_else(|| Error::Internal {
                details: s!("color-prepare batch transfer is missing txid"),
            })?;
        let transfer_dir = self.get_transfer_dir(txid);
        if !transfer_dir.join(COLOR_PREPARE_FILE).exists() {
            return Err(Error::Internal {
                details: format!(
                    "batch transfer {batch_transfer_idx} was not created by color_psbt_*_and_prepare_consume"
                ),
            });
        }
        let fascia_str = fs::read_to_string(transfer_dir.join(FASCIA_FILE))?;
        let fascia: Fascia = serde_json::from_str(&fascia_str).map_err(InternalError::from)?;
        let psbt_path = transfer_dir.join(UNSIGNED_PSBT_FILE);
        if !psbt_path.exists() {
            return Err(Error::Inconsistency {
                details: format!(
                    "unsigned PSBT missing for batch {batch_transfer_idx}; treating as operation corruption"
                ),
            });
        }
        let psbt =
            Psbt::from_str(&fs::read_to_string(&psbt_path)?).map_err(|e| Error::Inconsistency {
                details: format!("unsigned PSBT unreadable for batch {batch_transfer_idx}: {e}"),
            })?;
        let stash_marker = transfer_dir.join(STASH_CONSUMED_FILE);
        if !stash_marker.exists() {
            if self.indexer().get_tx_confirmations(txid)?.is_none() {
                return Err(Error::Internal {
                    details: format!(
                        "witness tx {txid} is not known to the indexer; broadcast it before consume_transfer_fascia"
                    ),
                });
            }
            self.consume_fascia_persist_then_mark(fascia, &[&stash_marker])?;
            #[cfg(test)]
            if MOCK_FAIL_AFTER_STASH_CONSUME.with(|f| f.replace(false)) {
                return Err(Error::Internal {
                    details: s!("mock failure after stash consume"),
                });
            }
        }
        self.update_db_colored_txos_from_bdk(&txn, false)?;
        self.mark_psbt_inputs_spent(&txn, &psbt)?;
        let mut updated: DbBatchTransferActMod = batch_transfer.into();
        updated.status = ActiveValue::Set(TransferStatus::WaitingConfirmations);
        txn.update_batch_transfer(&mut updated)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        let _ = fs::remove_file(&stash_marker);
        self.trigger_auto_backup();
        info!(self.logger(), "Consume transfer fascia completed");
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_ops_root(&self) -> PathBuf {
        self.wallet_dir().join(PSBT_OPS_DIR)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn validate_psbt_op_id(operation_id: &str) -> Result<(), Error> {
        let valid = operation_id.len() == PSBT_OP_ID_LEN
            && operation_id
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !valid {
            return Err(Error::PsbtOperationNotFound {
                operation_id: operation_id.to_string(),
            });
        }
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_dir(&self, operation_id: &str) -> Result<PathBuf, Error> {
        Self::validate_psbt_op_id(operation_id)?;
        Ok(self.psbt_ops_root().join(operation_id))
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_read_meta(&self, operation_id: &str) -> Result<PsbtOpMeta, Error> {
        let path = self.psbt_op_dir(operation_id)?.join(PSBT_OP_META_FILE);
        if !path.exists() {
            return Err(Error::PsbtOperationNotFound {
                operation_id: operation_id.to_string(),
            });
        }
        let raw = fs::read_to_string(&path)?;
        let meta: PsbtOpMeta = serde_json::from_str(&raw).map_err(|e| Error::Inconsistency {
            details: format!("HTLC operation {operation_id} has invalid meta.json: {e}"),
        })?;
        if meta.operation_id != operation_id {
            return Err(Error::Internal {
                details: format!(
                    "HTLC meta operation_id '{}' does not match requested '{}'",
                    meta.operation_id, operation_id
                ),
            });
        }
        if meta.schema_version != PSBT_OP_META_SCHEMA_VERSION {
            return Err(Error::Inconsistency {
                details: format!(
                    "HTLC operation {operation_id} has unsupported schema version {}",
                    meta.schema_version
                ),
            });
        }
        Ok(meta)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_write_meta(&self, operation_id: &str, meta: &PsbtOpMeta) -> Result<(), Error> {
        Self::validate_psbt_op_id(operation_id)?;
        if meta.operation_id != operation_id {
            return Err(Error::Internal {
                details: format!(
                    "HTLC meta operation_id '{}' does not match requested '{}'",
                    meta.operation_id, operation_id
                ),
            });
        }
        let path = self.psbt_op_dir(operation_id)?.join(PSBT_OP_META_FILE);
        let raw = serde_json::to_string_pretty(meta).map_err(InternalError::from)?;
        persist_durable_replace(&path, raw)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_set_batch_identity(
        meta: &mut PsbtOpMeta,
        batch_transfer_idx: i32,
    ) -> Result<(), Error> {
        let expected = psbt_op_batch_identity_hash(batch_transfer_idx);
        match &meta.hashes.batch_transfer_idx {
            Some(hash) if hash == &expected => {}
            Some(_) => {
                return Err(Error::Inconsistency {
                    details: format!(
                        "HTLC operation {} batch identity does not match the manifest",
                        meta.operation_id
                    ),
                });
            }
            None => meta.hashes.batch_transfer_idx = Some(expected),
        }
        meta.batch_transfer_idx = Some(batch_transfer_idx);
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_bind_batch_identity(
        &self,
        operation_id: &str,
        meta: &mut PsbtOpMeta,
        batch_transfer_idx: i32,
    ) -> Result<(), Error> {
        let already_bound = meta.batch_transfer_idx == Some(batch_transfer_idx)
            && meta.hashes.batch_transfer_idx.is_some();
        Self::psbt_op_set_batch_identity(meta, batch_transfer_idx)?;
        if already_bound {
            return Ok(());
        }
        self.psbt_op_write_meta(operation_id, meta)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_require_file_hash(
        operation_id: &str,
        label: &str,
        path: &Path,
        expected: &str,
    ) -> Result<Vec<u8>, Error> {
        let bytes = fs::read(path).map_err(|e| Error::Inconsistency {
            details: format!("HTLC operation {operation_id} missing required {label}: {e}"),
        })?;
        let actual = sha256_hex(&bytes);
        if actual != expected {
            return Err(Error::Inconsistency {
                details: format!("HTLC operation {operation_id} {label} hash mismatch"),
            });
        }
        Ok(bytes)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_verify_committed_payloads(
        &self,
        meta: &PsbtOpMeta,
    ) -> Result<(Psbt, Fascia), Error> {
        let operation_id = &meta.operation_id;
        if sha256_hex(meta.txid.as_bytes()) != meta.hashes.txid {
            return Err(Error::Inconsistency {
                details: format!("HTLC operation {operation_id} txid is not bound by the manifest"),
            });
        }
        if let Some(idx) = meta.batch_transfer_idx {
            match &meta.hashes.batch_transfer_idx {
                Some(hash) if hash == &psbt_op_batch_identity_hash(idx) => {}
                _ => {
                    return Err(Error::Inconsistency {
                        details: format!(
                            "HTLC operation {operation_id} batch identity is not bound by the manifest"
                        ),
                    });
                }
            }
        }

        let (Some(fascia_hash), Some(colored_psbt_hash)) =
            (&meta.hashes.fascia, &meta.hashes.colored_psbt)
        else {
            return Err(Error::Inconsistency {
                details: format!(
                    "HTLC operation {operation_id} has no committed payloads: it was staged and never completed"
                ),
            });
        };
        let op_dir = self.psbt_op_dir(operation_id)?;
        let fascia_bytes = Self::psbt_op_require_file_hash(
            operation_id,
            "fascia",
            &op_dir.join(FASCIA_FILE),
            fascia_hash,
        )?;
        let psbt_bytes = Self::psbt_op_require_file_hash(
            operation_id,
            "colored PSBT",
            &op_dir.join(PSBT_OP_COLORED_PSBT_FILE),
            colored_psbt_hash,
        )?;
        Self::psbt_op_require_file_hash(
            operation_id,
            "foreign inputs",
            &op_dir.join(PSBT_OP_FOREIGN_INPUTS_FILE),
            &meta.hashes.foreign_inputs,
        )?;
        for (asset_id, expected) in &meta.hashes.consignments {
            Self::psbt_op_require_file_hash(
                operation_id,
                &format!("consignment {asset_id}"),
                &psbt_op_consignment_path(&op_dir, asset_id),
                expected,
            )?;
        }

        let colored_psbt = String::from_utf8(psbt_bytes).map_err(|_| Error::Inconsistency {
            details: format!("HTLC operation {operation_id} colored PSBT is not valid UTF-8"),
        })?;
        let psbt = Psbt::from_str(&colored_psbt)?;
        let psbt_txid = psbt.unsigned_tx.compute_txid().to_string();
        if psbt_txid != meta.txid {
            return Err(Error::Inconsistency {
                details: format!(
                    "HTLC operation {operation_id} colored PSBT txid {psbt_txid} does not match manifest {}",
                    meta.txid
                ),
            });
        }
        let fascia_str = String::from_utf8(fascia_bytes).map_err(|_| Error::Inconsistency {
            details: format!("HTLC operation {operation_id} fascia is not valid UTF-8"),
        })?;
        let fascia: Fascia = serde_json::from_str(&fascia_str).map_err(InternalError::from)?;
        Ok((psbt, fascia))
    }

    /// Consume fascia, persist stock while the runtime lock is held, then fsync the marker.
    /// Always consumes (rgb-ops merge-reveals on retry): a witness stored by an incoming accept
    /// of the same tx is not a sign that this fascia's bundles are in the stash.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn consume_fascia_persist_then_mark(
        &self,
        fascia: Fascia,
        markers: &[&Path],
    ) -> Result<(), Error> {
        // consume overwrites the stored witness ord: never downgrade a Mined one to Tentative
        let witness_ord = match self
            .blockchain_resolver()
            .resolve_witness(fascia.witness_id())
            .map_err(|e| Error::Network {
                details: e.to_string(),
            })? {
            WitnessStatus::Resolved(_, ord) => ord,
            _ => {
                return Err(Error::Network {
                    details: s!("witness transaction not found on indexer"),
                });
            }
        };
        let mut runtime = self.rgb_runtime()?;
        runtime.require_explicit_persistence();
        runtime.consume_fascia(fascia, Some(witness_ord))?;
        runtime.persist()?;
        #[cfg(test)]
        if MOCK_FAIL_AFTER_STOCK_PERSIST.with(|f| f.replace(false)) {
            return Err(Error::Internal {
                details: s!("mock failure after stock persist before marker"),
            });
        }
        for marker in markers {
            persist_stash_consumed_marker(marker)?;
        }
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_scan(&self) -> Result<Vec<PsbtOpMeta>, Error> {
        let root = self.psbt_ops_root();
        if !root.exists() {
            return Ok(vec![]);
        }
        let mut ops = vec![];
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if Self::validate_psbt_op_id(&name).is_err() {
                continue;
            }
            match self.psbt_op_read_meta(&name) {
                Ok(meta) => ops.push(meta),
                // Meta is written before the SQL batch: a recognized dir without meta.json is an
                // unpublished prepare, not a committed operation.
                Err(Error::PsbtOperationNotFound { .. }) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(ops)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_from_meta(&self, meta: &PsbtOpMeta) -> Result<PsbtOperation, Error> {
        let (psbt, allocations) = if Self::psbt_op_never_completed(meta) {
            let (psbt, manifest, _) = self.psbt_op_verify_staged_payloads(meta)?;
            let allocations = Self::psbt_op_staged_allocations(&psbt, &manifest)?;
            (psbt, allocations)
        } else {
            let (psbt, fascia) = self.psbt_op_verify_committed_payloads(meta)?;
            (psbt, fascia_allocations(&fascia)?)
        };
        Ok(PsbtOperation {
            operation_id: meta.operation_id.clone(),
            colored_psbt: psbt.to_string(),
            operation_dir: Self::psbt_op_relative_dir(&meta.operation_id),
            status: meta.status,
            broadcast: meta.broadcast,
            txid: meta.txid.clone(),
            allocations,
        })
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_relative_dir(operation_id: &str) -> String {
        PathBuf::from(PSBT_OPS_DIR)
            .join(operation_id)
            .to_string_lossy()
            .into_owned()
    }

    /// Whether `meta` belongs to an operation `psbt_op_stage` created and `psbt_op_complete` never
    /// committed, so that its only PSBT is the staged one.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_never_completed(meta: &PsbtOpMeta) -> bool {
        meta.hashes.staged.is_some() && meta.hashes.colored_psbt.is_none()
    }

    /// Load and hash-check the payloads `psbt_op_stage` wrote: the staged PSBT, the staged
    /// manifest and the raw foreign inputs file.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_verify_staged_payloads(
        &self,
        meta: &PsbtOpMeta,
    ) -> Result<(Psbt, PsbtOpStagedManifest, Vec<u8>), Error> {
        let operation_id = &meta.operation_id;
        let staged =
            meta.hashes
                .staged
                .as_ref()
                .ok_or_else(|| Error::InvalidPsbtOperationStatus {
                    details: format!("operation {operation_id} was not created by psbt_op_stage"),
                })?;
        let op_dir = self.psbt_op_dir(operation_id)?;
        let psbt_bytes = Self::psbt_op_require_file_hash(
            operation_id,
            "staged PSBT",
            &op_dir.join(PSBT_OP_STAGED_PSBT_FILE),
            &staged.psbt,
        )?;
        let manifest_bytes = Self::psbt_op_require_file_hash(
            operation_id,
            "staged manifest",
            &op_dir.join(PSBT_OP_STAGED_MANIFEST_FILE),
            &staged.manifest,
        )?;
        let foreign_inputs = Self::psbt_op_require_file_hash(
            operation_id,
            "foreign inputs",
            &op_dir.join(PSBT_OP_FOREIGN_INPUTS_FILE),
            &meta.hashes.foreign_inputs,
        )?;
        let staged_psbt = String::from_utf8(psbt_bytes).map_err(|_| Error::Inconsistency {
            details: format!("HTLC operation {operation_id} staged PSBT is not valid UTF-8"),
        })?;
        let psbt = Psbt::from_str(&staged_psbt)?;
        // once completed, the manifest txid is the final one, which the staged PSBT predates
        if Self::psbt_op_never_completed(meta) {
            if sha256_hex(meta.txid.as_bytes()) != meta.hashes.txid {
                return Err(Error::Inconsistency {
                    details: format!(
                        "HTLC operation {operation_id} txid is not bound by the manifest"
                    ),
                });
            }
            let psbt_txid = psbt.unsigned_tx.compute_txid().to_string();
            if psbt_txid != meta.txid {
                return Err(Error::Inconsistency {
                    details: format!(
                        "HTLC operation {operation_id} staged PSBT txid {psbt_txid} does not match manifest {}",
                        meta.txid
                    ),
                });
            }
        }
        let manifest: PsbtOpStagedManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| Error::Inconsistency {
                details: format!(
                    "HTLC operation {operation_id} has an invalid staged manifest: {e}"
                ),
            })?;
        Ok((psbt, manifest, foreign_inputs))
    }

    /// What the bundles this wallet staged assign, read back from the staged PSBT.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_staged_allocations(
        psbt: &Psbt,
        manifest: &PsbtOpStagedManifest,
    ) -> Result<Vec<PsbtOpAllocation>, Error> {
        let contracts = manifest
            .coloring_info()?
            .asset_info_map
            .into_keys()
            .collect();
        let bundles = Self::psbt_op_own_bundles(psbt, &contracts)?;
        bundle_allocations(bundles.iter())
    }

    /// The bundles `psbt` carries for `contracts`, all of which must be there.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_own_bundles(
        psbt: &Psbt,
        contracts: &BTreeSet<ContractId>,
    ) -> Result<BTreeMap<ContractId, rgbstd::TransitionBundle>, Error> {
        let mut bundles = psbt.rgb_bundles().map_err(InternalError::from)?;
        bundles.retain(|contract_id, _| contracts.contains(contract_id));
        if bundles.len() != contracts.len() {
            return Err(Error::Inconsistency {
                details: s!("staged PSBT lacks a bundle for a staged contract"),
            });
        }
        Ok(bundles)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_resolve_batch_idx(&self, meta: &PsbtOpMeta) -> Result<Option<i32>, Error> {
        if let Some(idx) = meta.batch_transfer_idx {
            return Ok(Some(idx));
        }
        let txn = self.database().begin_transaction()?;
        let outgoing: Vec<_> = txn
            .iter_batch_transfers()?
            .into_iter()
            .filter(|b| b.txid.as_deref() == Some(meta.txid.as_str()) && !b.incoming)
            .collect();
        let live: Vec<_> = outgoing
            .iter()
            .filter(|b| b.status != TransferStatus::Failed)
            .collect();
        match (live.as_slice(), outgoing.as_slice()) {
            ([b], _) => Ok(Some(b.idx)),
            ([], [b]) => Ok(Some(b.idx)),
            _ => Ok(None),
        }
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn new_psbt_op_id() -> String {
        format!(
            "{:016x}{:016x}",
            rand::rng().random::<u64>(),
            rand::rng().random::<u64>()
        )
    }

    /// Color an HTLC (or other external) PSBT for explicit input outpoints, write file-backed
    /// payloads under `psbt_ops/{operation_id}/`, and persist SQL accounting for colored contracts.
    /// `expiration_timestamp` defaults to [`PSBT_OP_DEFAULT_EXPIRATION_SECS`] from now; see
    /// [`Self::psbt_op_prepare_with_expiry`] to disable expiry.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_op_prepare(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
    ) -> Result<PsbtOpPrepareResult, Error> {
        self.psbt_op_prepare_with_expiry(
            psbt,
            coloring_info,
            input_outpoints,
            min_confirmations,
            expiration_timestamp.into(),
        )
    }

    /// [`Self::psbt_op_prepare`] with an explicit [`PsbtOpExpiry`].
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_op_prepare_with_expiry(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
        min_confirmations: u8,
        expiry: PsbtOpExpiry,
    ) -> Result<PsbtOpPrepareResult, Error> {
        info!(self.logger(), "Preparing HTLC color operation...");
        let expiration_timestamp = Self::psbt_op_expiration_timestamp(expiry);
        let (runtime, override_set) =
            self.prepare_color_psbt_for_outpoints(psbt, &coloring_info, input_outpoints, false)?;
        let (fascia, asset_beneficiaries) = self.color_psbt_with_prevouts_runtime(
            &runtime,
            psbt,
            coloring_info.clone(),
            override_set.clone(),
            true,
            false,
        )?;

        let witness_txid = psbt.get_txid();
        let mut transfers = vec![];
        let spent = Self::psbt_op_spent_by_contract(
            &runtime,
            asset_beneficiaries.keys().copied(),
            &override_set,
        )?;

        for (contract_id, beneficiaries) in &asset_beneficiaries {
            let mut beneficiaries_witness = vec![];
            let mut beneficiaries_blinded = vec![];
            for builder_seal in beneficiaries {
                match builder_seal {
                    BuilderSeal::Revealed(seal) => {
                        let explicit_seal = ExplicitSeal::with(witness_txid, seal.vout);
                        beneficiaries_witness.push(explicit_seal);
                    }
                    BuilderSeal::Concealed(secret_seal) => {
                        beneficiaries_blinded.push(*secret_seal);
                    }
                };
            }
            transfers.push(runtime.transfer_from_fascia(
                *contract_id,
                beneficiaries_witness,
                beneficiaries_blinded,
                &fascia,
            )?);
        }

        let txid = psbt.unsigned_tx.compute_txid().to_string();
        let allocations = fascia_allocations(&fascia)?;
        let foreign_inputs = self.collect_foreign_input_entries(&spent)?;

        let operation_id = Self::new_psbt_op_id();
        let op_dir = self.psbt_op_dir(&operation_id)?;
        persist_durable_create_dir(&op_dir.join(PSBT_OP_CONSIGNMENTS_DIR))?;

        let serialized_fascia = serde_json::to_string(&fascia).map_err(InternalError::from)?;
        let colored_psbt = psbt.to_string();
        let foreign_inputs_raw = serde_json::to_string_pretty(&ForeignInputsFile {
            entries: foreign_inputs,
        })
        .map_err(InternalError::from)?;

        persist_durable_replace(&op_dir.join(FASCIA_FILE), &serialized_fascia)?;
        persist_durable_replace(&op_dir.join(PSBT_OP_COLORED_PSBT_FILE), &colored_psbt)?;
        let consignment_hashes = Self::psbt_op_persist_consignments(&op_dir, &transfers)?;

        persist_durable_replace(
            &op_dir.join(PSBT_OP_FOREIGN_INPUTS_FILE),
            &foreign_inputs_raw,
        )?;

        let mut meta = PsbtOpMeta {
            schema_version: PSBT_OP_META_SCHEMA_VERSION,
            operation_id: operation_id.clone(),
            status: PsbtOperationStatus::Prepared,
            txid: txid.clone(),
            created_at: now().unix_timestamp(),
            batch_transfer_idx: None,
            broadcast: PsbtBroadcastState::NotAttempted,
            hashes: PsbtOpPayloadHashes::new(
                serialized_fascia.as_bytes(),
                colored_psbt.as_bytes(),
                foreign_inputs_raw.as_bytes(),
                consignment_hashes,
                &txid,
                None,
            ),
            completing_txid: None,
        };
        self.psbt_op_write_meta(&operation_id, &meta)?;

        let batch_transfer_idx = match self.persist_color_prepare_batch(
            psbt,
            &txid,
            &spent,
            &fascia,
            &coloring_info,
            false,
            min_confirmations,
            expiration_timestamp,
            false,
            &runtime,
        ) {
            Ok(idx) => idx,
            Err(e) => {
                let _ = fs::remove_dir_all(&op_dir);
                return Err(e);
            }
        };
        drop(runtime);

        self.psbt_op_bind_batch_identity(&operation_id, &mut meta, batch_transfer_idx)?;
        self.trigger_auto_backup();

        info!(
            self.logger(),
            "HTLC prepare completed (operation_id={operation_id})"
        );
        Ok(PsbtOpPrepareResult {
            operation_dir: Self::psbt_op_relative_dir(&operation_id),
            operation_id,
            colored_psbt: psbt.to_string(),
            allocations,
        })
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_expiration_timestamp(expiry: PsbtOpExpiry) -> Option<u64> {
        match expiry {
            PsbtOpExpiry::Default => {
                Some(now().unix_timestamp() as u64 + PSBT_OP_DEFAULT_EXPIRATION_SECS)
            }
            PsbtOpExpiry::At(timestamp) => Some(timestamp),
            PsbtOpExpiry::Never => None,
        }
    }

    /// The known allocations of `contracts` that spending `inputs` consumes.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_spent_by_contract(
        runtime: &RgbRuntime,
        contracts: impl IntoIterator<Item = ContractId>,
        inputs: &HashSet<OutPoint>,
    ) -> Result<SpentByContract, Error> {
        let mut spent: SpentByContract = HashMap::new();
        for contract_id in contracts {
            let by_outpoint = spent.entry(contract_id).or_default();
            for (explicit_seal, opout_state_map) in
                runtime.contract_assignments_for(contract_id, inputs.iter().copied())?
            {
                let outpoint = explicit_seal.to_outpoint();
                for (opout, state) in opout_state_map {
                    by_outpoint
                        .entry(outpoint)
                        .or_default()
                        .push(Assignment::from_opout_and_state(opout, &state));
                }
            }
        }
        Ok(spent)
    }

    /// Durably write one consignment per transfer under `op_dir`, returning their hashes.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_persist_consignments(
        op_dir: &Path,
        transfers: &[RgbTransfer],
    ) -> Result<BTreeMap<String, String>, Error> {
        let mut consignment_hashes = BTreeMap::new();
        for transfer in transfers {
            let asset_id = transfer.contract_id().to_string();
            let path = psbt_op_consignment_path(op_dir, &asset_id);
            if let Some(parent) = path.parent() {
                persist_durable_create_dir(parent)?;
            }
            let mut consignment_bytes = Vec::new();
            transfer.save(&mut consignment_bytes)?;
            persist_durable_replace(&path, &consignment_bytes)?;
            consignment_hashes.insert(asset_id, sha256_hex(&consignment_bytes));
        }
        Ok(consignment_hashes)
    }

    /// The live (not Failed) outgoing batch transfer recorded for `txid`, if any.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_live_outgoing_batch(&self, txid: &str) -> Result<Option<DbBatchTransfer>, Error> {
        let txn = self.database().begin_transaction()?;
        Ok(txn
            .get_batch_transfers_by_txid(txid)?
            .into_iter()
            .find(|b| !b.incoming && b.status != TransferStatus::Failed))
    }

    /// Stage this wallet's RGB transitions on a PSBT other parties also stage on, reserve its
    /// inputs and journal the operation as [`PsbtOperationStatus::Staged`].
    ///
    /// This is the durable form of [`Self::color_psbt_stage`] for a transaction several wallets
    /// color together (e.g. an RGB-for-RGB swap built outside rgb-lib):
    /// 1. each party calls `psbt_op_stage` on the same PSBT, in turn, for its own contracts;
    /// 2. exactly one party calls [`Self::psbt_op_finalize`] on the result;
    /// 3. each party calls [`Self::psbt_op_complete`] with the finalized PSBT, which checks its
    ///    staged transitions are committed unchanged and moves the operation to
    ///    [`PsbtOperationStatus::Prepared`];
    /// 4. from there the operation is a prepared one: sign, [`Self::psbt_op_mark_broadcast`],
    ///    broadcast, [`Self::psbt_op_apply`], [`Self::psbt_op_reconcile`].
    ///
    /// [`Self::psbt_op_abort`] releases the inputs of a Staged operation. The journal under
    /// `psbt_ops/{operation_id}/` survives restarts between any of these steps.
    ///
    /// Each contract must be staged by exactly one party: a PSBT already carrying transitions
    /// for a contract in `coloring_info` is rejected, as is a PSBT whose commitment is final.
    ///
    /// # `output_map` index convention
    ///
    /// As for [`Self::psbt_op_prepare`] and [`Self::color_psbt_for_outpoints`], keys are **final
    /// PSBT vout indices**: the PSBT must already contain its OP_RETURN output (vout 0 when any
    /// output is P2TR), no output is ever inserted and keys are never shifted. This differs from
    /// [`Self::color_psbt_stage`], which follows [`Self::color_psbt`].
    ///
    /// `input_outpoints` and the full-allocation rule are as for [`Self::psbt_op_prepare`]. PSBT
    /// inputs outside `input_outpoints` belong to the other parties; only those that are this
    /// wallet's own coins must carry no allocations. Signing every input is still the caller's
    /// job.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_op_stage(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
        min_confirmations: u8,
        expiry: PsbtOpExpiry,
    ) -> Result<PsbtOpStageResult, Error> {
        info!(self.logger(), "Staging PSBT operation...");
        let expiration_timestamp = Self::psbt_op_expiration_timestamp(expiry);
        let contracts: BTreeSet<ContractId> =
            coloring_info.asset_info_map.keys().copied().collect();
        if contracts.is_empty() {
            return Err(Error::InvalidColoringInfo {
                details: s!("coloring_info lists no contract"),
            });
        }
        // checked before anything touches the caller's PSBT
        if psbt_rgb_commitment_finalized(psbt) {
            return Err(Error::InvalidColoringInfo {
                details: s!("the PSBT's RGB commitment is already finalized"),
            });
        }
        let already_staged = psbt
            .rgb_contract_ids()
            .map_err(|e| Error::InvalidColoringInfo {
                details: format!("PSBT has invalid RGB data: {e}"),
            })?;
        if let Some(contract_id) = already_staged.intersection(&contracts).next() {
            return Err(Error::InvalidColoringInfo {
                details: format!(
                    "PSBT already carries transitions for contract {contract_id}: each contract must be staged by exactly one party"
                ),
            });
        }
        let (runtime, override_set) =
            self.prepare_color_psbt_for_outpoints(psbt, &coloring_info, input_outpoints, true)?;
        self.color_psbt_stage_runtime(
            &runtime,
            psbt,
            coloring_info.clone(),
            override_set.clone(),
            true,
            false,
        )?;

        let txid = psbt.unsigned_tx.compute_txid().to_string();
        let spent =
            Self::psbt_op_spent_by_contract(&runtime, contracts.iter().copied(), &override_set)?;
        let foreign_inputs = self.collect_foreign_input_entries(&spent)?;
        let manifest = PsbtOpStagedManifest::new(
            &coloring_info,
            &override_set,
            min_confirmations,
            expiration_timestamp,
        );
        let allocations = Self::psbt_op_staged_allocations(psbt, &manifest)?;

        let operation_id = Self::new_psbt_op_id();
        let op_dir = self.psbt_op_dir(&operation_id)?;
        persist_durable_create_dir(&op_dir)?;
        let staged_psbt = psbt.to_string();
        let manifest_raw = serde_json::to_string_pretty(&manifest).map_err(InternalError::from)?;
        let foreign_inputs_raw = serde_json::to_string_pretty(&ForeignInputsFile {
            entries: foreign_inputs,
        })
        .map_err(InternalError::from)?;
        persist_durable_replace(&op_dir.join(PSBT_OP_STAGED_PSBT_FILE), &staged_psbt)?;
        persist_durable_replace(&op_dir.join(PSBT_OP_STAGED_MANIFEST_FILE), &manifest_raw)?;
        persist_durable_replace(
            &op_dir.join(PSBT_OP_FOREIGN_INPUTS_FILE),
            &foreign_inputs_raw,
        )?;

        let mut meta = PsbtOpMeta {
            schema_version: PSBT_OP_META_SCHEMA_VERSION,
            operation_id: operation_id.clone(),
            status: PsbtOperationStatus::Staged,
            txid: txid.clone(),
            created_at: now().unix_timestamp(),
            batch_transfer_idx: None,
            broadcast: PsbtBroadcastState::NotAttempted,
            hashes: PsbtOpPayloadHashes::new_staged(
                staged_psbt.as_bytes(),
                manifest_raw.as_bytes(),
                foreign_inputs_raw.as_bytes(),
                &txid,
            ),
            completing_txid: None,
        };
        self.psbt_op_write_meta(&operation_id, &meta)?;

        // reserve the inputs as psbt_op_prepare does, with an Initiated batch for the staged
        // txid; psbt_op_complete replaces it with the batch for the final txid
        let reserve = || -> Result<i32, Error> {
            let txn = self.database().begin_transaction()?;
            let batch_transfer_idx = self.persist_color_prepare_batch_txn(
                &txn,
                psbt,
                &txid,
                &spent,
                &coloring_info,
                false,
                min_confirmations,
                expiration_timestamp,
                &runtime,
            )?;
            self.update_backup_info(&txn, false)?;
            txn.commit()?;
            Ok(batch_transfer_idx)
        };
        let batch_transfer_idx = match reserve() {
            Ok(idx) => idx,
            Err(e) => {
                let _ = fs::remove_dir_all(&op_dir);
                return Err(e);
            }
        };
        drop(runtime);

        self.psbt_op_bind_batch_identity(&operation_id, &mut meta, batch_transfer_idx)?;
        self.trigger_auto_backup();

        info!(
            self.logger(),
            "Stage PSBT operation completed (operation_id={operation_id})"
        );
        Ok(PsbtOpStageResult {
            operation_dir: Self::psbt_op_relative_dir(&operation_id),
            operation_id,
            staged_psbt,
            allocations,
        })
    }

    /// Finalize the RGB commitment of a PSBT every party has staged on with
    /// [`Self::psbt_op_stage`]. Exactly one party calls this, once all staging is done, and hands
    /// the finalized PSBT to every party for [`Self::psbt_op_complete`].
    ///
    /// This journals nothing: each party's [`Self::psbt_op_complete`] checks the result against
    /// its own journal. `static_entropy` is the MPC entropy, as `static_blinding` is for
    /// [`Self::color_psbt_finalize`]. The returned fascia covers every party's contracts.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_op_finalize(
        &self,
        psbt: &mut Psbt,
        static_entropy: Option<u64>,
    ) -> Result<Fascia, Error> {
        if psbt_has_input_signatures(psbt) {
            return Err(Error::InvalidColoringInfo {
                details: s!(
                    "cannot finalize a signed PSBT: RGB commitment rewrites the OP_RETURN output"
                ),
            });
        }
        if psbt_rgb_commitment_finalized(psbt) {
            return Err(Error::InvalidColoringInfo {
                details: s!("the PSBT's RGB commitment is already finalized"),
            });
        }
        let staged = psbt
            .rgb_contract_ids()
            .map_err(|e| Error::InvalidColoringInfo {
                details: format!("PSBT has invalid RGB data: {e}"),
            })?;
        if staged.is_empty() {
            return Err(Error::InvalidColoringInfo {
                details: s!("PSBT has no staged RGB transitions"),
            });
        }
        // final-vout family: the OP_RETURN must already be there, never inserted here
        if !psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
        {
            return Err(Error::InvalidColoringInfo {
                details: s!("PSBT must include an OP_RETURN output"),
            });
        }
        self.color_psbt_finalize(psbt, static_entropy)
    }

    /// Complete a [`PsbtOperationStatus::Staged`] operation with the PSBT another party finalized
    /// via [`Self::psbt_op_finalize`], moving it to [`PsbtOperationStatus::Prepared`].
    ///
    /// The finalized PSBT is refused unless it is the staged transaction with only the RGB
    /// commitment filled in, carries this wallet's staged bundles unchanged, and its OP_RETURN
    /// commits to them. This wallet's consignments are then built and the input reservation
    /// moves to a batch transfer for the final txid, exactly as [`Self::psbt_op_prepare`] leaves
    /// it, so [`Self::psbt_op_mark_broadcast`], [`Self::psbt_op_apply`], [`Self::psbt_op_abort`]
    /// and [`Self::psbt_op_reconcile`] apply unchanged. Retrying with the same PSBT after a crash
    /// or a lost response is safe and returns the same result.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_op_complete(
        &self,
        operation_id: &str,
        finalized_psbt: &Psbt,
    ) -> Result<PsbtOpPrepareResult, Error> {
        info!(self.logger(), "Completing PSBT operation {operation_id}...");
        let mut meta = self.psbt_op_read_meta(operation_id)?;
        let final_txid = finalized_psbt.unsigned_tx.compute_txid().to_string();
        if meta.status != PsbtOperationStatus::Staged {
            if meta.hashes.staged.is_some()
                && meta.status != PsbtOperationStatus::Failed
                && meta.txid == final_txid
            {
                // an earlier call already completed it with this PSBT
                let op = self.psbt_op_from_meta(&meta)?;
                return Ok(PsbtOpPrepareResult {
                    operation_id: op.operation_id,
                    colored_psbt: op.colored_psbt,
                    operation_dir: op.operation_dir,
                    allocations: op.allocations,
                });
            }
            return Err(Error::InvalidPsbtOperationStatus {
                details: format!(
                    "operation {operation_id} is {:?}, expected Staged",
                    meta.status
                ),
            });
        }
        let (staged_psbt, manifest, foreign_inputs_raw) =
            self.psbt_op_verify_staged_payloads(&meta)?;
        let coloring_info = manifest.coloring_info()?;
        let contracts: BTreeSet<ContractId> =
            coloring_info.asset_info_map.keys().copied().collect();
        let fascia = psbt_op_finalized_fascia(&staged_psbt, finalized_psbt, &contracts)?;

        // a batch for the final txid only exists if an earlier call committed it and crashed
        // before publishing the operation as Prepared
        let completed_batch = match self.psbt_op_live_outgoing_batch(&final_txid)? {
            Some(batch) if meta.completing_txid.as_deref() == Some(final_txid.as_str()) => {
                Some(batch.idx)
            }
            Some(batch) => {
                return Err(Error::BatchTransferAlreadyExists {
                    txid: final_txid,
                    idx: batch.idx,
                });
            }
            None => {
                if let Some(other) = meta.completing_txid.as_deref()
                    && other != final_txid
                    && self.psbt_op_live_outgoing_batch(other)?.is_some()
                {
                    return Err(Error::InvalidPsbtOperationStatus {
                        details: format!(
                            "operation {operation_id} is already being completed with txid {other}"
                        ),
                    });
                }
                None
            }
        };
        let staged_batch_idx = self.psbt_op_resolve_batch_idx(&meta)?;
        if completed_batch.is_none() {
            match staged_batch_idx
                .map(|idx| self.psbt_op_batch_status(idx))
                .transpose()?
            {
                Some(Some(TransferStatus::Initiated)) => {}
                Some(Some(TransferStatus::Failed)) => {
                    self.psbt_op_journal_failed(&mut meta, staged_batch_idx)?;
                    return Err(Error::InvalidPsbtOperationStatus {
                        details: format!(
                            "operation {operation_id} batch transfer was failed (expired?); its inputs are no longer reserved"
                        ),
                    });
                }
                _ => {
                    return Err(Error::InvalidPsbtOperationStatus {
                        details: format!(
                            "operation {operation_id} has no Initiated batch transfer reserving its inputs; abort it"
                        ),
                    });
                }
            }
        }

        let runtime = self.rgb_runtime()?;
        let witness_txid = finalized_psbt.get_txid();
        let mut transfers = vec![];
        for (contract_id, info) in &coloring_info.asset_info_map {
            let mut vouts: Vec<u32> = info
                .output_map
                .iter()
                .filter(|(_, amount)| **amount > 0)
                .map(|(vout, _)| *vout)
                .collect();
            vouts.sort();
            let beneficiaries: Vec<_> = vouts
                .into_iter()
                .map(|vout| ExplicitSeal::with(witness_txid, vout))
                .collect();
            transfers.push(runtime.transfer_from_fascia(
                *contract_id,
                beneficiaries,
                vec![],
                &fascia,
            )?);
        }

        let op_dir = self.psbt_op_dir(operation_id)?;
        let serialized_fascia = serde_json::to_string(&fascia).map_err(InternalError::from)?;
        let colored_psbt = finalized_psbt.to_string();
        persist_durable_create_dir(&op_dir.join(PSBT_OP_CONSIGNMENTS_DIR))?;
        persist_durable_replace(&op_dir.join(FASCIA_FILE), &serialized_fascia)?;
        persist_durable_replace(&op_dir.join(PSBT_OP_COLORED_PSBT_FILE), &colored_psbt)?;
        let consignment_hashes = Self::psbt_op_persist_consignments(&op_dir, &transfers)?;
        self.write_color_prepare_files(finalized_psbt, &final_txid, &fascia, false)?;

        let batch_transfer_idx = match completed_batch {
            Some(idx) => idx,
            None => {
                if meta.completing_txid.as_deref() != Some(final_txid.as_str()) {
                    meta.completing_txid = Some(final_txid.clone());
                    self.psbt_op_write_meta(operation_id, &meta)?;
                }
                let spent = Self::psbt_op_spent_by_contract(
                    &runtime,
                    contracts.iter().copied(),
                    &manifest.inputs()?,
                )?;
                let txn = self.database().begin_transaction()?;
                // the new batch reserves the same inputs before the staged one is dropped, in
                // the same SQL transaction
                let idx = self.persist_color_prepare_batch_txn(
                    &txn,
                    finalized_psbt,
                    &final_txid,
                    &spent,
                    &coloring_info,
                    false,
                    manifest.min_confirmations,
                    manifest.expiration_timestamp,
                    &runtime,
                )?;
                if let Some(staged_idx) = staged_batch_idx {
                    let db_data = txn.get_db_data(false)?;
                    let staged_batch =
                        txn.get_batch_transfer_or_fail(staged_idx, &db_data.batch_transfers)?;
                    let asset_transfers =
                        staged_batch.get_asset_transfers(&db_data.asset_transfers);
                    self.delete_batch_transfer(
                        &txn,
                        &staged_batch,
                        &asset_transfers,
                        &db_data.colorings,
                        &db_data.txos,
                    )?;
                }
                self.update_backup_info(&txn, false)?;
                txn.commit()?;
                idx
            }
        };
        drop(runtime);

        let staged_hashes = meta.hashes.staged.take();
        meta.status = PsbtOperationStatus::Prepared;
        meta.txid = final_txid;
        meta.batch_transfer_idx = None;
        meta.completing_txid = None;
        meta.hashes = PsbtOpPayloadHashes::new(
            serialized_fascia.as_bytes(),
            colored_psbt.as_bytes(),
            &foreign_inputs_raw,
            consignment_hashes,
            &meta.txid,
            None,
        );
        meta.hashes.staged = staged_hashes;
        Self::psbt_op_set_batch_identity(&mut meta, batch_transfer_idx)?;
        self.psbt_op_write_meta(operation_id, &meta)?;
        self.trigger_auto_backup();

        info!(
            self.logger(),
            "Complete PSBT operation completed (operation_id={operation_id})"
        );
        Ok(PsbtOpPrepareResult {
            operation_id: operation_id.to_string(),
            colored_psbt,
            operation_dir: Self::psbt_op_relative_dir(operation_id),
            allocations: fascia_allocations(&fascia)?,
        })
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn collect_foreign_input_entries(
        &self,
        spent: &SpentByContract,
    ) -> Result<Vec<ForeignInputEntry>, Error> {
        let txn = self.database().begin_transaction()?;
        let mut foreign_inputs = Vec::new();
        for (contract_id, by_outpoint) in spent {
            for (outpoint, assignments) in by_outpoint {
                let outpoint_obj: Outpoint = (*outpoint).into();
                if txn.get_txo(&outpoint_obj)?.is_none() {
                    foreign_inputs.push(ForeignInputEntry {
                        asset_id: contract_id.to_string(),
                        outpoint: outpoint_obj,
                        assignments: assignments.clone(),
                    });
                }
            }
        }
        Ok(foreign_inputs)
    }

    /// Apply a prepared HTLC operation's fascia into the RGB stash after broadcast.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_op_apply(&mut self, online: Online, operation_id: &str) -> Result<(), Error> {
        info!(self.logger(), "Applying HTLC operation {operation_id}...");
        self.check_online(online)?;
        let mut meta = self.psbt_op_read_meta(operation_id)?;
        if meta.status != PsbtOperationStatus::Prepared {
            return Err(Error::InvalidPsbtOperationStatus {
                details: format!(
                    "operation {operation_id} is {:?}, expected Prepared",
                    meta.status
                ),
            });
        }

        let batch_transfer_idx = self.psbt_op_resolve_batch_idx(&meta)?.ok_or_else(|| {
            Error::Internal {
                details: format!(
                    "HTLC operation {operation_id} has no linked Initiated/WaitingConfirmations batch"
                ),
            }
        })?;
        self.psbt_op_bind_batch_identity(operation_id, &mut meta, batch_transfer_idx)?;
        let (psbt, fascia) = self.psbt_op_verify_committed_payloads(&meta)?;

        let op_dir = self.psbt_op_dir(operation_id)?;
        let stash_marker = op_dir.join(STASH_CONSUMED_FILE);
        let stash_consumed = stash_marker.exists();

        {
            let txn = self.database().begin_transaction()?;
            let db_data = txn.get_db_data(false)?;
            let batch_transfer =
                txn.get_batch_transfer_or_fail(batch_transfer_idx, &db_data.batch_transfers)?;
            match batch_transfer.status {
                TransferStatus::WaitingConfirmations | TransferStatus::Settled
                    if stash_consumed =>
                {
                    drop(txn);
                    meta.status = PsbtOperationStatus::Applied;
                    meta.batch_transfer_idx = Some(batch_transfer_idx);
                    self.psbt_op_write_meta(operation_id, &meta)?;
                    let _ = fs::remove_file(&stash_marker);
                    let _ = fs::remove_file(
                        self.get_transfer_dir(&meta.txid).join(STASH_CONSUMED_FILE),
                    );
                    self.trigger_auto_backup();
                    info!(
                        self.logger(),
                        "HTLC apply healed meta after prior SQL commit"
                    );
                    return Ok(());
                }
                TransferStatus::Initiated => {}
                other => {
                    return Err(Error::InvalidPsbtOperationStatus {
                        details: format!(
                            "HTLC batch transfer {batch_transfer_idx} is {other:?}, expected Initiated"
                        ),
                    });
                }
            }
        }

        if !stash_consumed {
            if self.indexer().get_tx_confirmations(&meta.txid)?.is_none() {
                return Err(Error::InvalidPsbtOperationStatus {
                    details: format!(
                        "witness tx {} is not known to the indexer; broadcast it before psbt_op_apply",
                        meta.txid
                    ),
                });
            }
            if meta.broadcast != PsbtBroadcastState::Observed {
                meta.broadcast = PsbtBroadcastState::Observed;
                self.psbt_op_write_meta(operation_id, &meta)?;
            }
            let transfer_marker = self.get_transfer_dir(&meta.txid).join(STASH_CONSUMED_FILE);
            self.consume_fascia_persist_then_mark(fascia, &[&stash_marker, &transfer_marker])?;
            #[cfg(test)]
            if MOCK_FAIL_AFTER_STASH_CONSUME.with(|f| f.replace(false)) {
                return Err(Error::Internal {
                    details: s!("mock failure after HTLC stash consume"),
                });
            }
        }

        let txn = self.database().begin_transaction()?;
        let db_data = txn.get_db_data(false)?;
        let batch_transfer =
            txn.get_batch_transfer_or_fail(batch_transfer_idx, &db_data.batch_transfers)?;
        match batch_transfer.status {
            TransferStatus::Initiated => {
                let mut updated: DbBatchTransferActMod = batch_transfer.into();
                updated.status = ActiveValue::Set(TransferStatus::WaitingConfirmations);
                txn.update_batch_transfer(&mut updated)?;
            }
            TransferStatus::WaitingConfirmations | TransferStatus::Settled => {}
            other => {
                return Err(Error::InvalidPsbtOperationStatus {
                    details: format!(
                        "HTLC batch transfer {batch_transfer_idx} is {other:?}, expected Initiated"
                    ),
                });
            }
        }
        self.update_db_colored_txos_from_bdk(&txn, false)?;
        self.mark_psbt_inputs_spent(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;

        meta.status = PsbtOperationStatus::Applied;
        meta.batch_transfer_idx = Some(batch_transfer_idx);
        self.psbt_op_write_meta(operation_id, &meta)?;
        let _ = fs::remove_file(&stash_marker);
        let _ = fs::remove_file(self.get_transfer_dir(&meta.txid).join(STASH_CONSUMED_FILE));
        self.trigger_auto_backup();
        info!(self.logger(), "HTLC apply completed");
        Ok(())
    }

    /// Abort a prepared HTLC operation whose witness TX did not reach the network.
    ///
    /// After a broadcast attempt rollback is refused until the batch transfer expires; past that
    /// the indexer decides, as for [`TransferStatus::WaitingBroadcast`].
    ///
    /// A [`PsbtOperationStatus::Staged`] operation is aborted the same way, releasing the inputs
    /// it reserved, unless one of this wallet's staged inputs is already spent (a transaction
    /// built from the staged PSBT may have been signed and broadcast without
    /// [`Self::psbt_op_complete`]).
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_op_abort(&mut self, online: Online, operation_id: &str) -> Result<(), Error> {
        info!(self.logger(), "Aborting HTLC operation {operation_id}...");
        self.check_online(online)?;
        let mut meta = self.psbt_op_read_meta(operation_id)?;
        let batch_transfer_idx = self.psbt_op_resolve_batch_idx(&meta)?;
        if meta.status == PsbtOperationStatus::Failed {
            if let Some(idx) = batch_transfer_idx {
                self.psbt_op_fail_batch_if_initiated(online, idx)?;
            }
            self.psbt_op_fail_completing_batch(online, &meta)?;
            self.psbt_op_backup_after_coherent_failure()?;
            info!(self.logger(), "HTLC abort completed");
            return Ok(());
        }
        if meta.status == PsbtOperationStatus::Staged {
            self.psbt_op_abort_staged(online, &mut meta, batch_transfer_idx)?;
            info!(self.logger(), "HTLC abort completed");
            return Ok(());
        }
        if meta.status != PsbtOperationStatus::Prepared {
            return Err(Error::InvalidPsbtOperationStatus {
                details: format!(
                    "operation {operation_id} is {:?}, expected Prepared",
                    meta.status
                ),
            });
        }
        if self
            .psbt_op_dir(operation_id)?
            .join(STASH_CONSUMED_FILE)
            .exists()
        {
            return Err(Error::InvalidPsbtOperationStatus {
                details: format!(
                    "operation {operation_id} already consumed its fascia into the RGB stash, \
                     it can only be completed with psbt_op_apply"
                ),
            });
        }

        if self.indexer().get_tx_confirmations(&meta.txid)?.is_some() {
            if meta.broadcast != PsbtBroadcastState::Observed {
                meta.broadcast = PsbtBroadcastState::Observed;
                self.psbt_op_write_meta(operation_id, &meta)?;
            }
            return Err(Error::InvalidPsbtOperationStatus {
                details: format!(
                    "witness tx {} is known to the indexer; refuse abort",
                    meta.txid
                ),
            });
        }
        if meta.broadcast != PsbtBroadcastState::NotAttempted {
            let expired = match batch_transfer_idx {
                Some(idx) => self.psbt_op_batch_expired(idx)?,
                None => true,
            };
            if !expired {
                if meta.broadcast == PsbtBroadcastState::Attempted {
                    meta.broadcast = PsbtBroadcastState::Ambiguous;
                    self.psbt_op_write_meta(operation_id, &meta)?;
                }
                return Err(Error::InvalidPsbtOperationStatus {
                    details: format!(
                        "operation {operation_id} broadcast is {:?}; automatic rollback is \
                         refused until the batch transfer expires",
                        meta.broadcast
                    ),
                });
            }
        }

        if let Some(idx) = batch_transfer_idx {
            self.psbt_op_fail_batch_if_initiated(online, idx)?;
        }
        #[cfg(test)]
        if MOCK_FAIL_AFTER_PSBT_OP_SQL_FAIL.with(|f| f.replace(false)) {
            return Err(Error::Internal {
                details: s!("mock failure after HTLC SQL fail"),
            });
        }
        self.psbt_op_journal_failed(&mut meta, batch_transfer_idx)?;
        self.psbt_op_backup_after_coherent_failure()?;
        info!(self.logger(), "HTLC abort completed");
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_abort_staged(
        &mut self,
        online: Online,
        meta: &mut PsbtOpMeta,
        batch_transfer_idx: Option<i32>,
    ) -> Result<(), Error> {
        let operation_id = meta.operation_id.clone();
        let (_, manifest, _) = self.psbt_op_verify_staged_payloads(meta)?;
        // the final txid is unknown until psbt_op_complete, so look at the inputs instead: once
        // one of this wallet's is spent, the transaction may carry the staged transitions
        let txn = self.database().begin_transaction()?;
        self.sync_if_requested(&txn, Some(online), false, KeychainKind::External)?;
        for outpoint in &manifest.input_outpoints {
            if txn.get_txo(outpoint)?.is_some()
                && self
                    .bdk_wallet()
                    .get_utxo(OutPoint::try_from(outpoint)?)
                    .is_none()
            {
                return Err(Error::InvalidPsbtOperationStatus {
                    details: format!(
                        "operation {operation_id} staged input {outpoint} is already spent; \
                         complete the operation with psbt_op_complete instead"
                    ),
                });
            }
        }
        txn.commit()?;
        if let Some(txid) = meta.completing_txid.as_deref()
            && self.indexer().get_tx_confirmations(txid)?.is_some()
        {
            return Err(Error::InvalidPsbtOperationStatus {
                details: format!("witness tx {txid} is known to the indexer; refuse abort"),
            });
        }
        if let Some(idx) = batch_transfer_idx {
            self.psbt_op_fail_batch_if_initiated(online, idx)?;
        }
        self.psbt_op_fail_completing_batch(online, meta)?;
        #[cfg(test)]
        if MOCK_FAIL_AFTER_PSBT_OP_SQL_FAIL.with(|f| f.replace(false)) {
            return Err(Error::Internal {
                details: s!("mock failure after HTLC SQL fail"),
            });
        }
        self.psbt_op_journal_failed(meta, batch_transfer_idx)?;
        self.psbt_op_backup_after_coherent_failure()
    }

    /// Fail the batch a crashed `psbt_op_complete` committed for a Staged operation, if any.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_fail_completing_batch(
        &mut self,
        online: Online,
        meta: &PsbtOpMeta,
    ) -> Result<(), Error> {
        let Some(txid) = meta.completing_txid.as_deref() else {
            return Ok(());
        };
        match self.psbt_op_live_outgoing_batch(txid)? {
            Some(batch) => self.psbt_op_fail_batch_if_initiated(online, batch.idx),
            None => Ok(()),
        }
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_journal_failed(
        &self,
        meta: &mut PsbtOpMeta,
        batch_transfer_idx: Option<i32>,
    ) -> Result<bool, Error> {
        if meta.status == PsbtOperationStatus::Failed
            && meta.batch_transfer_idx == batch_transfer_idx
        {
            return Ok(false);
        }
        if let Some(idx) = batch_transfer_idx {
            Self::psbt_op_set_batch_identity(meta, idx)?;
        }
        meta.status = PsbtOperationStatus::Failed;
        self.psbt_op_write_meta(&meta.operation_id, meta)?;
        Ok(true)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_batch(&self, batch_transfer_idx: i32) -> Result<Option<DbBatchTransfer>, Error> {
        let txn = self.database().begin_transaction()?;
        Ok(txn
            .iter_batch_transfers()?
            .into_iter()
            .find(|b| b.idx == batch_transfer_idx))
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_batch_status(
        &self,
        batch_transfer_idx: i32,
    ) -> Result<Option<TransferStatus>, Error> {
        Ok(self.psbt_op_batch(batch_transfer_idx)?.map(|b| b.status))
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_batch_expired(&self, batch_transfer_idx: i32) -> Result<bool, Error> {
        let now = now().unix_timestamp();
        Ok(self
            .psbt_op_batch(batch_transfer_idx)?
            .and_then(|b| b.expiration)
            .is_some_and(|expiration| expiration < now))
    }

    /// Align operation metas with batches `fail_transfers` marked Failed.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn psbt_op_heal_failed(&self) -> Result<bool, Error> {
        let mut healed = false;
        for mut meta in self.psbt_op_scan()? {
            if !matches!(
                meta.status,
                PsbtOperationStatus::Staged | PsbtOperationStatus::Prepared
            ) {
                continue;
            }
            let Some(idx) = self.psbt_op_resolve_batch_idx(&meta)? else {
                continue;
            };
            if self.psbt_op_batch_status(idx)? == Some(TransferStatus::Failed) {
                healed |= self.psbt_op_journal_failed(&mut meta, Some(idx))?;
            }
        }
        Ok(healed)
    }

    /// Whether a Prepared operation linked to this batch reported a broadcast attempt and the
    /// batch has not expired yet.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn psbt_op_has_live_broadcast(
        &self,
        batch_transfer: &DbBatchTransfer,
    ) -> Result<bool, Error> {
        let now = now().unix_timestamp();
        if batch_transfer
            .expiration
            .is_some_and(|expiration| expiration < now)
        {
            return Ok(false);
        }
        for meta in self.psbt_op_scan()? {
            if meta.status != PsbtOperationStatus::Prepared {
                continue;
            }
            if meta.broadcast == PsbtBroadcastState::NotAttempted {
                continue;
            }
            let linked = match meta.batch_transfer_idx {
                Some(idx) => idx == batch_transfer.idx,
                None => batch_transfer
                    .txid
                    .as_deref()
                    .is_some_and(|txid| meta.txid == txid),
            };
            if linked {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_backup_after_coherent_failure(&self) -> Result<(), Error> {
        let txn = self.database().begin_transaction()?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_fail_linked_batch(
        &mut self,
        online: Online,
        batch_transfer_idx: i32,
    ) -> Result<(), Error> {
        let outcome = self.fail_transfers_commit(online, Some(batch_transfer_idx), false, true)?;
        if outcome.cannot_fail {
            if outcome.transfers_changed {
                self.trigger_auto_backup();
            }
            return Err(Error::CannotFailBatchTransfer);
        }
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn psbt_op_fail_batch_if_initiated(
        &mut self,
        online: Online,
        batch_transfer_idx: i32,
    ) -> Result<(), Error> {
        match self.psbt_op_batch_status(batch_transfer_idx)? {
            Some(TransferStatus::Initiated) => {
                self.psbt_op_fail_linked_batch(online, batch_transfer_idx)
            }
            Some(TransferStatus::Failed) | None => Ok(()),
            Some(other) => Err(Error::InvalidPsbtOperationStatus {
                details: format!(
                    "HTLC batch transfer {batch_transfer_idx} is {other:?}, expected Initiated or Failed"
                ),
            }),
        }
    }

    /// Record that the caller attempted to broadcast the prepared witness tx. Idempotent;
    /// refused once the linked batch was rolled back.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_op_mark_broadcast(&self, operation_id: &str) -> Result<(), Error> {
        let mut meta = self.psbt_op_read_meta(operation_id)?;
        if meta.status != PsbtOperationStatus::Prepared {
            return Err(Error::InvalidPsbtOperationStatus {
                details: format!(
                    "operation {operation_id} is {:?}, expected Prepared",
                    meta.status
                ),
            });
        }
        if let Some(idx) = self.psbt_op_resolve_batch_idx(&meta)?
            && self.psbt_op_batch_status(idx)? == Some(TransferStatus::Failed)
        {
            return Err(Error::InvalidPsbtOperationStatus {
                details: format!(
                    "operation {operation_id} batch transfer {idx} is Failed; it cannot be broadcast"
                ),
            });
        }
        match meta.broadcast {
            PsbtBroadcastState::NotAttempted => {
                meta.broadcast = PsbtBroadcastState::Attempted;
                self.psbt_op_write_meta(operation_id, &meta)
            }
            PsbtBroadcastState::Attempted
            | PsbtBroadcastState::Ambiguous
            | PsbtBroadcastState::Observed => Ok(()),
        }
    }

    /// Find a committed HTLC operation by witness txid (lost `operation_id` / retry).
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_op_by_txid(&self, txid: &str) -> Result<PsbtOperation, Error> {
        let matches: Vec<PsbtOpMeta> = self
            .psbt_op_scan()?
            .into_iter()
            .filter(|meta| meta.txid == txid)
            .collect();
        if matches.is_empty() {
            return Err(Error::PsbtOperationNotFound {
                operation_id: txid.to_string(),
            });
        }
        let live: Vec<&PsbtOpMeta> = matches
            .iter()
            .filter(|meta| meta.status != PsbtOperationStatus::Failed)
            .collect();
        match (matches.as_slice(), live.as_slice()) {
            ([meta], _) => self.psbt_op_from_meta(meta),
            (_, [meta]) => self.psbt_op_from_meta(meta),
            _ => Err(Error::Internal {
                details: format!("multiple HTLC operations share txid {txid}"),
            }),
        }
    }

    /// List the HTLC operations whose colored PSBT spends `outpoint`, in any status, ordered by
    /// creation time (to the second).
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_ops_spending(&self, outpoint: Outpoint) -> Result<Vec<PsbtOperation>, Error> {
        let spent = OutPoint::try_from(&outpoint)?;
        let mut metas = self.psbt_op_scan()?;
        metas.sort_by(|a, b| (a.created_at, &a.operation_id).cmp(&(b.created_at, &b.operation_id)));
        let mut ops = vec![];
        for meta in metas {
            // Cheap filter on the PSBT alone; matches are fully verified below. An unreadable
            // PSBT is an error: skipping it could hide an operation spending `outpoint`.
            let file = if Self::psbt_op_never_completed(&meta) {
                PSBT_OP_STAGED_PSBT_FILE
            } else {
                PSBT_OP_COLORED_PSBT_FILE
            };
            let path = self.psbt_op_dir(&meta.operation_id)?.join(file);
            let psbt =
                Psbt::from_str(&fs::read_to_string(&path)?).map_err(|e| Error::Inconsistency {
                    details: format!(
                        "HTLC operation {} has an unreadable colored PSBT: {e}",
                        meta.operation_id
                    ),
                })?;
            if psbt
                .unsigned_tx
                .input
                .iter()
                .any(|i| i.previous_output == spent)
            {
                ops.push(self.psbt_op_from_meta(&meta)?);
            }
        }
        Ok(ops)
    }

    /// Hand the consignment an applied HTLC operation produced for `asset_id` to the wallet's
    /// pending receive it pays (e.g. the witness receive a claim spends to), as
    /// [`provide_out_of_band_consignment`](Wallet::provide_out_of_band_consignment) would.
    ///
    /// `asset_id` may be in any spelling rgb-lib parses. The operation must be applied: the
    /// consignment of an operation that may never confirm, or was aborted, is never handed over.
    /// As with `provide_out_of_band_consignment`, it is an error when no pending receive matches,
    /// including once the receive has already been handed the consignment.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_op_provide_receive_consignment(
        &mut self,
        online: Online,
        operation_id: &str,
        asset_id: &str,
    ) -> Result<RefreshResult, Error> {
        info!(
            self.logger(),
            "Providing HTLC operation {operation_id} consignment to its receive..."
        );
        self.check_online(online)?;
        let asset_id = ContractId::from_str(asset_id)
            .map_err(|_| Error::AssetNotFound {
                asset_id: asset_id.to_string(),
            })?
            .to_string();
        let meta = self.psbt_op_read_meta(operation_id)?;
        if !matches!(
            meta.status,
            PsbtOperationStatus::Applied | PsbtOperationStatus::Settled
        ) {
            return Err(Error::InvalidPsbtOperationStatus {
                details: format!(
                    "operation {operation_id} is {:?}, expected Applied or Settled",
                    meta.status
                ),
            });
        }
        self.psbt_op_verify_committed_payloads(&meta)?;
        if !meta.hashes.consignments.contains_key(&asset_id) {
            return Err(Error::CannotProvideOutOfBandConsignment {
                details: format!("operation {operation_id} has no consignment for {asset_id}"),
            });
        }
        let path = psbt_op_consignment_path(&self.psbt_op_dir(operation_id)?, &asset_id);
        let path = path
            .to_str()
            .ok_or_else(|| Error::Internal {
                details: s!("consignment path is not valid UTF-8"),
            })?
            .to_owned();
        let res = self.provide_out_of_band_consignment(online, path, vec![])?;
        info!(
            self.logger(),
            "Provide HTLC operation consignment completed"
        );
        Ok(res)
    }

    /// Read HTLC operation status; marks Settled when a linked batch has settled, and Failed when
    /// the batch of a Staged or Prepared operation was failed (e.g. by `fail_transfers`).
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn psbt_op_reconcile(&self, operation_id: &str) -> Result<PsbtOperationStatus, Error> {
        let mut meta = self.psbt_op_read_meta(operation_id)?;
        if let Some(batch_transfer_idx) = self.psbt_op_resolve_batch_idx(&meta)? {
            let txn = self.database().begin_transaction()?;
            let db_data = txn.get_db_data(false)?;
            if let Some(batch) = db_data
                .batch_transfers
                .iter()
                .find(|b| b.idx == batch_transfer_idx)
            {
                if matches!(
                    meta.status,
                    PsbtOperationStatus::Staged | PsbtOperationStatus::Prepared
                ) && batch.status == TransferStatus::Failed
                {
                    self.psbt_op_journal_failed(&mut meta, Some(batch_transfer_idx))?;
                } else if meta.status == PsbtOperationStatus::Applied
                    && batch.status == TransferStatus::Settled
                {
                    meta.status = PsbtOperationStatus::Settled;
                    self.psbt_op_write_meta(operation_id, &meta)?;
                }
            }
        }
        Ok(meta.status)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn prepare_color_and_transfer_runtime(
        &self,
        runtime: &mut RgbRuntime,
        psbt: &Psbt,
        fascia: Fascia,
        asset_beneficiaries: AssetBeneficiariesMap,
        prev_outputs: &HashSet<OutPoint>,
        coloring_info: &ColoringInfo,
        shift_output_map_for_opreturn_first: bool,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
    ) -> Result<ColorPrepareResult, Error> {
        let witness_txid = psbt.get_txid();
        let mut transfers = vec![];
        let mut spent: HashMap<ContractId, HashMap<OutPoint, Vec<Assignment>>> = HashMap::new();

        for (contract_id, beneficiaries) in &asset_beneficiaries {
            let mut by_outpoint: HashMap<OutPoint, Vec<Assignment>> = HashMap::new();
            for (explicit_seal, opout_state_map) in
                runtime.contract_assignments_for(*contract_id, prev_outputs.iter().copied())?
            {
                let outpoint = explicit_seal.to_outpoint();
                for (opout, state) in opout_state_map {
                    by_outpoint
                        .entry(outpoint)
                        .or_default()
                        .push(Assignment::from_opout_and_state(opout, &state));
                }
            }
            spent.insert(*contract_id, by_outpoint);

            let mut beneficiaries_witness = vec![];
            let mut beneficiaries_blinded = vec![];
            for builder_seal in beneficiaries {
                match builder_seal {
                    BuilderSeal::Revealed(seal) => {
                        let explicit_seal = ExplicitSeal::with(witness_txid, seal.vout);
                        beneficiaries_witness.push(explicit_seal);
                    }
                    BuilderSeal::Concealed(secret_seal) => {
                        beneficiaries_blinded.push(*secret_seal);
                    }
                };
            }
            transfers.push(runtime.transfer_from_fascia(
                *contract_id,
                beneficiaries_witness,
                beneficiaries_blinded,
                &fascia,
            )?);
        }

        let txid = psbt.unsigned_tx.compute_txid().to_string();
        let batch_transfer_idx = self.persist_color_prepare_batch(
            psbt,
            &txid,
            &spent,
            &fascia,
            coloring_info,
            shift_output_map_for_opreturn_first,
            min_confirmations,
            expiration_timestamp,
            true,
            runtime,
        )?;
        self.trigger_auto_backup();
        Ok(ColorPrepareResult {
            transfers,
            batch_transfer_idx,
        })
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn persist_color_prepare_batch(
        &self,
        psbt: &Psbt,
        txid: &str,
        spent: &HashMap<ContractId, HashMap<OutPoint, Vec<Assignment>>>,
        fascia: &Fascia,
        coloring_info: &ColoringInfo,
        shift_output_map_for_opreturn_first: bool,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
        allow_consume_transfer_fascia: bool,
        runtime: &RgbRuntime,
    ) -> Result<i32, Error> {
        self.write_color_prepare_files(psbt, txid, fascia, allow_consume_transfer_fascia)?;
        let txn = self.database().begin_transaction()?;
        let batch_transfer_idx = self.persist_color_prepare_batch_txn(
            &txn,
            psbt,
            txid,
            spent,
            coloring_info,
            shift_output_map_for_opreturn_first,
            min_confirmations,
            expiration_timestamp,
            runtime,
        )?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        Ok(batch_transfer_idx)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn write_color_prepare_files(
        &self,
        psbt: &Psbt,
        txid: &str,
        fascia: &Fascia,
        allow_consume_transfer_fascia: bool,
    ) -> Result<(), Error> {
        let transfer_dir = self.get_transfer_dir(txid);
        fs::create_dir_all(&transfer_dir)?;
        let fascia_path = transfer_dir.join(FASCIA_FILE);
        let serialized_fascia = serde_json::to_string(fascia).map_err(InternalError::from)?;
        fs::write(fascia_path, serialized_fascia)?;
        fs::write(transfer_dir.join(UNSIGNED_PSBT_FILE), psbt.to_string())?;
        if allow_consume_transfer_fascia {
            fs::write(transfer_dir.join(COLOR_PREPARE_FILE), b"")?;
        }
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn persist_color_prepare_batch_txn(
        &self,
        txn: &DbTxn,
        psbt: &Psbt,
        txid: &str,
        spent: &HashMap<ContractId, HashMap<OutPoint, Vec<Assignment>>>,
        coloring_info: &ColoringInfo,
        shift_output_map_for_opreturn_first: bool,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
        runtime: &RgbRuntime,
    ) -> Result<i32, Error> {
        let created_at = now().unix_timestamp();
        let bitcoin_network = self.bitcoin_network();
        let incoming_witness_scripts = Self::incoming_witness_receive_script_hexes(txn)?;
        if let Some(existing) =
            txn.get_batch_transfers_by_txid(txid)?
                .into_iter()
                .find(|batch_transfer| {
                    !batch_transfer.incoming
                        && matches!(
                            batch_transfer.status,
                            TransferStatus::Initiated
                                | TransferStatus::WaitingConfirmations
                                | TransferStatus::Settled
                        )
                })
        {
            return Err(Error::BatchTransferAlreadyExists {
                txid: txid.to_string(),
                idx: existing.idx,
            });
        }
        let batch_transfer = DbBatchTransferActMod {
            txid: ActiveValue::Set(Some(txid.to_string())),
            status: ActiveValue::Set(TransferStatus::Initiated),
            expiration: ActiveValue::Set(expiration_timestamp.map(|t| t as i64)),
            created_at: ActiveValue::Set(created_at),
            min_confirmations: ActiveValue::Set(min_confirmations),
            incoming: ActiveValue::Set(false),
            ..Default::default()
        };
        let batch_transfer_idx = txn.set_batch_transfer(batch_transfer)?;

        for (contract_id, by_outpoint) in spent {
            let asset_id = contract_id.to_string();
            let asset_schema = AssetSchema::get_from_contract_id(*contract_id, runtime)?;
            let asset_transfer = DbAssetTransferActMod {
                user_driven: ActiveValue::Set(true),
                batch_transfer_idx: ActiveValue::Set(batch_transfer_idx),
                asset_id: ActiveValue::Set(Some(asset_id)),
                ..Default::default()
            };
            let asset_transfer_idx = txn.set_asset_transfer(asset_transfer)?;

            for (outpoint, assignments) in by_outpoint {
                let outpoint: Outpoint = (*outpoint).into();
                let Some(txo) = txn.get_txo(&outpoint)? else {
                    continue;
                };
                let txo_idx = txo.idx;

                for assignment in assignments {
                    let db_coloring = DbColoringActMod {
                        txo_idx: ActiveValue::Set(txo_idx),
                        asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                        r#type: ActiveValue::Set(ColoringType::Input),
                        assignment: ActiveValue::Set(assignment.clone()),
                        ..Default::default()
                    };
                    txn.set_coloring(db_coloring)?;
                }
            }

            let mut external_destinations: Vec<(u32, u64, String)> = Vec::new();
            let mut change_destinations: Vec<(u32, u64, String)> = Vec::new();
            if let Some(asset_coloring) = coloring_info.asset_info_map.get(contract_id) {
                for (mut vout, amount) in BTreeMap::from_iter(asset_coloring.output_map.clone()) {
                    if amount == 0 {
                        continue;
                    }
                    if shift_output_map_for_opreturn_first {
                        vout += 1;
                    }
                    if vout as usize >= psbt.unsigned_tx.output.len() {
                        return Err(Error::InvalidColoringInfo {
                            details: s!(
                                "invalid vout in output_map, does not exist in the given PSBT"
                            ),
                        });
                    }
                    let txout = &psbt.unsigned_tx.output[vout as usize];
                    if txout.script_pubkey.is_op_return() {
                        return Err(Error::InvalidColoringInfo {
                            details: format!(
                                "output_map vout {vout} points to the OP_RETURN output"
                            ),
                        });
                    }
                    let recipient_id = recipient_id_from_script_buf(
                        txout.script_pubkey.clone(),
                        bitcoin_network,
                    )
                    .map_err(|_| Error::InvalidColoringInfo {
                        details: format!(
                            "output_map vout {vout} script is not a standard address payload"
                        ),
                    })?;
                    let output_assignment =
                        Self::assignment_for_coloring_output(asset_schema, amount);
                    let owned_by_witness_receive =
                        incoming_witness_scripts.contains(&txout.script_pubkey.to_hex_string());
                    // Skip Change when an open witness_receive already owns this script.
                    if self.bdk_wallet().is_mine(txout.script_pubkey.clone())
                        && !owned_by_witness_receive
                    {
                        let outpoint = Outpoint {
                            txid: txid.to_string(),
                            vout,
                        };
                        let txo_idx = match txn.get_txo(&outpoint)? {
                            Some(txo) => txo.idx,
                            None => {
                                let db_utxo = DbTxoActMod {
                                    txid: ActiveValue::Set(txid.to_string()),
                                    vout: ActiveValue::Set(vout),
                                    btc_amount: ActiveValue::Set(txout.value.to_sat().to_string()),
                                    spent: ActiveValue::Set(false),
                                    exists: ActiveValue::Set(false),
                                    pending_witness: ActiveValue::Set(false),
                                    ..Default::default()
                                };
                                txn.set_txo(db_utxo)?
                            }
                        };
                        let db_coloring = DbColoringActMod {
                            txo_idx: ActiveValue::Set(txo_idx),
                            asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                            r#type: ActiveValue::Set(ColoringType::Change),
                            assignment: ActiveValue::Set(output_assignment.clone()),
                            ..Default::default()
                        };
                        txn.set_coloring(db_coloring)?;
                        change_destinations.push((vout, amount, recipient_id));
                    } else {
                        external_destinations.push((vout, amount, recipient_id));
                    }
                }
            }

            let transfer_destinations = if !external_destinations.is_empty() {
                external_destinations
            } else {
                change_destinations
            };

            if transfer_destinations.is_empty() {
                let first_assignment = by_outpoint.values().flatten().next().cloned();
                txn.set_transfer(DbTransferActMod {
                    asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                    requested_assignment: ActiveValue::Set(first_assignment),
                    recipient_id: ActiveValue::Set(Some(format!("color:{txid}"))),
                    recipient_type: ActiveValue::Set(Some(RecipientTypeFull::Witness {
                        vout: None,
                        recipient_nonce: vec![],
                    })),
                    ..Default::default()
                })?;
            } else {
                for (vout, amount, recipient_id) in transfer_destinations {
                    let requested = Self::assignment_for_coloring_output(asset_schema, amount);
                    txn.set_transfer(DbTransferActMod {
                        asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                        requested_assignment: ActiveValue::Set(Some(requested)),
                        recipient_id: ActiveValue::Set(Some(recipient_id)),
                        recipient_type: ActiveValue::Set(Some(RecipientTypeFull::Witness {
                            vout: Some(vout),
                            recipient_nonce: vec![],
                        })),
                        ..Default::default()
                    })?;
                }
            }
        }

        Ok(batch_transfer_idx)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn assignment_for_coloring_output(asset_schema: AssetSchema, amount: u64) -> Assignment {
        match asset_schema {
            AssetSchema::Uda => Assignment::NonFungible,
            AssetSchema::Nia | AssetSchema::Cfa | AssetSchema::Ifa => Assignment::Fungible(amount),
        }
    }

    /// Scripts reserved by an open `witness_receive` (pending-script row or in-flight incoming
    /// witness invoice). Color-prepare must not project Change onto these outputs.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn incoming_witness_receive_script_hexes(txn: &DbTxn) -> Result<HashSet<String>, Error> {
        let mut scripts: HashSet<String> = txn
            .iter_pending_witness_scripts()?
            .into_iter()
            .map(|row| row.script)
            .collect();

        let batch_transfers = txn.iter_batch_transfers()?;
        let asset_transfers = txn.iter_asset_transfers()?;
        let transfers = txn.iter_transfers()?;
        let in_flight_incoming: HashSet<i32> = batch_transfers
            .iter()
            .filter(|bt| bt.incoming && !bt.status.settled() && !bt.status.failed())
            .map(|bt| bt.idx)
            .collect();
        let in_flight_asset: HashSet<i32> = asset_transfers
            .iter()
            .filter(|at| in_flight_incoming.contains(&at.batch_transfer_idx))
            .map(|at| at.idx)
            .collect();
        for transfer in &transfers {
            if !in_flight_asset.contains(&transfer.asset_transfer_idx) {
                continue;
            }
            if !matches!(
                transfer.recipient_type,
                Some(RecipientTypeFull::Witness { .. })
            ) {
                continue;
            }
            let Some(ref recipient_id) = transfer.recipient_id else {
                continue;
            };
            if let Ok(Some(script)) = script_buf_from_recipient_id(recipient_id.clone()) {
                scripts.insert(script.to_hex_string());
            }
        }
        Ok(scripts)
    }

    /// Inspect arbitrary outpoints for assignments of a given contract.
    ///
    /// Results are returned in the same order as `outpoints`, including duplicate entries.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    pub fn contract_assignments_for_outpoints(
        &self,
        contract_id: ContractId,
        outpoints: Vec<Outpoint>,
    ) -> Result<Vec<(Outpoint, Vec<Assignment>)>, Error> {
        let parsed: Vec<(Outpoint, OutPoint)> = outpoints
            .into_iter()
            .map(|outpoint| {
                let vout = outpoint.vout;
                let txid = crate::bitcoin::Txid::from_str(&outpoint.txid)
                    .map_err(|_| Error::InvalidTxid)?;
                Ok((outpoint, OutPoint { txid, vout }))
            })
            .collect::<Result<_, Error>>()?;

        let runtime = self.rgb_runtime()?;
        runtime.genesis(contract_id)?;
        let state = runtime
            .contract_assignments_for(contract_id, parsed.iter().map(|(_, outpoint)| *outpoint))?;

        let mut by_outpoint: HashMap<OutPoint, Vec<Assignment>> = HashMap::new();
        for (seal, opout_state_map) in state {
            let btc_outpoint = OutPoint {
                txid: crate::bitcoin::Txid::from_str(&seal.txid.to_string()).map_err(|_| {
                    Error::Internal {
                        details: s!("invalid seal txid in contract assignments"),
                    }
                })?,
                vout: seal.vout.into_u32(),
            };
            let assignments = by_outpoint.entry(btc_outpoint).or_default();
            for (opout, state) in opout_state_map {
                assignments.push(Assignment::from_opout_and_state(opout, &state));
            }
        }

        Ok(parsed
            .into_iter()
            .map(|(outpoint, btc_outpoint)| {
                let assignments = by_outpoint.get(&btc_outpoint).cloned().unwrap_or_default();
                (outpoint, assignments)
            })
            .collect())
    }

    /// Fetch an RGB consignment by recipient_id (proxy lookup key).
    ///
    /// **Unchecked:** the returned `txid` and `vout` come from the proxy and are **not**
    /// validated here. Prefer [`Self::fetch_and_accept_transfer_by_recipient_id`], which pins
    /// the witness output before accept. If you must use this with
    /// [`Self::accept_transfer_from_consignment_unchecked`], pin first: for witness recipient
    /// IDs, assert `output[vout].script_pubkey == script_buf_from_recipient_id(recipient_id)`.
    /// A malicious proxy can otherwise steer acceptance to an attacker-chosen witness.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn fetch_consignment_by_recipient_id_unchecked(
        &self,
        recipient_id: String,
        consignment_endpoint: &str,
    ) -> Result<(RgbTransfer, String, u32), Error> {
        let fetched =
            self::fetch_consignment_by_recipient_id_unchecked(recipient_id, consignment_endpoint)?;
        Ok((fetched.consignment, fetched.txid, fetched.vout))
    }

    /// Fetch a consignment by proxy key, pin the witness output to `witness_recipient_id`, and
    /// accept the transfer.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn fetch_and_accept_transfer_by_recipient_id(
        &mut self,
        online: Online,
        proxy_recipient_id: String,
        witness_recipient_id: String,
        consignment_endpoint: &str,
        blinding: u64,
        min_confirmations: u8,
        expected: ExpectedTransfer,
    ) -> Result<(RgbTransfer, Vec<Assignment>), Error> {
        self.check_online(online)?;
        let fetched = self::fetch_consignment_by_recipient_id_unchecked(
            proxy_recipient_id,
            consignment_endpoint,
        )?;
        let accepted = self.accept_transfer_pinned(
            online,
            fetched,
            witness_recipient_id,
            blinding,
            min_confirmations,
            expected,
        )?;
        Ok((accepted.consignment, accepted.assignments))
    }

    /// Accept a consignment fetched with [`fetch_consignment_by_recipient_id_unchecked`]: pin
    /// `output[vout]` of the witness transaction to `witness_recipient_id` with at least
    /// `min_confirmations`, check the transfer matches `expected`, and accept it.
    ///
    /// [`Self::fetch_and_accept_transfer_by_recipient_id`] is the fetch followed by this. Neither
    /// saves the asset: a wallet that never held it calls [`Self::save_new_asset`] before coloring
    /// a spend of the received allocation.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_transfer_pinned(
        &mut self,
        online: Online,
        fetched: FetchedConsignment,
        witness_recipient_id: String,
        blinding: u64,
        min_confirmations: u8,
        expected: ExpectedTransfer,
    ) -> Result<AcceptedTransfer, Error> {
        info!(self.logger(), "Accepting pinned transfer...");
        self.check_online(online)?;
        pin_witness_output_to_recipient_id(
            self.blockchain_resolver(),
            self.indexer(),
            self.chain_net(),
            &witness_recipient_id,
            &fetched.txid,
            fetched.vout,
            min_confirmations,
        )?;
        let outpoint = Outpoint {
            txid: fetched.txid.clone(),
            vout: fetched.vout,
        };
        let (consignment, assignments) = self.accept_transfer_from_consignment_unchecked(
            online,
            fetched.consignment,
            fetched.txid,
            fetched.vout,
            blinding,
            expected,
        )?;
        info!(self.logger(), "Accept pinned transfer completed");
        Ok(AcceptedTransfer {
            consignment,
            assignments,
            outpoint,
        })
    }

    /// Produce an [`RgbTransfer`] consignment for a single contract given its beneficiaries
    /// (typically obtained from a prior [`Wallet::color_psbt_stage`] call) and the witness
    /// transaction ID of the PSBT being colored, built from the colored PSBT's `fascia`.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn generate_transfer(
        &self,
        contract_id: ContractId,
        beneficiaries: Vec<BuilderSeal<GraphSeal>>,
        witness_txid: RgbTxid,
        fascia: &Fascia,
    ) -> Result<RgbTransfer, Error> {
        let runtime = self.rgb_runtime()?;
        let mut beneficiaries_witness = vec![];
        let mut beneficiaries_blinded = vec![];
        for builder_seal in beneficiaries {
            match builder_seal {
                BuilderSeal::Revealed(seal) => {
                    let explicit_seal = ExplicitSeal::with(witness_txid, seal.vout);
                    beneficiaries_witness.push(explicit_seal);
                }
                BuilderSeal::Concealed(secret_seal) => {
                    beneficiaries_blinded.push(secret_seal);
                }
            };
        }
        Ok(runtime.transfer_from_fascia(
            contract_id,
            beneficiaries_witness,
            beneficiaries_blinded,
            fascia,
        )?)
    }

    /// Create consignments for a PSBT created with the [`send_begin`](Wallet::send_begin) method.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn create_consignments(&self, psbt: String) -> Result<(), Error> {
        self.create_consignments_impl(psbt).map(|_| ())
    }

    /// Create consignments for a PSBT created with the [`send_begin`](Wallet::send_begin) method,
    /// returning the filesystem path of the consignment for the transferred asset.
    ///
    /// This requires the PSBT to send exactly one asset to a recipient; it returns an error
    /// otherwise, so a caller verifying the consignment before signing never verifies only a
    /// subset of a multi-recipient batch. This counts only recipient-directed transfers: other
    /// assets sharing the spent UTXOs may still move as change allocations back to the sender in
    /// the same transaction.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn create_consignments_return_path(&self, psbt: String) -> Result<String, Error> {
        let mut consignment_paths = self.create_consignments_impl(psbt)?;
        if consignment_paths.len() != 1 {
            return Err(Error::Internal {
                details: format!(
                    "expected exactly one asset transfer, found {}",
                    consignment_paths.len()
                ),
            });
        }
        Ok(consignment_paths.remove(0))
    }

    fn create_consignments_impl(&self, psbt: String) -> Result<Vec<String>, Error> {
        info!(self.logger(), "Creating consignments...");

        let psbt = Psbt::from_str(&psbt)?;
        let (txid, transfer_dir, info_contents, fascia) = self.get_transfer_end_data(&psbt)?;
        self.gen_consignments(&fascia, &info_contents.transfers, &transfer_dir)?;

        let consignment_paths = info_contents
            .transfers
            .keys()
            .map(|asset_id| {
                self.get_send_consignment_path(asset_id, &txid)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();

        info!(self.logger(), "Create consignments completed");
        Ok(consignment_paths)
    }

    /// Accept an RGB transfer using a consignment received out-of-band.
    ///
    /// Returns the consignment, the received assignments and the hex-encoded digests of the media
    /// attachments defined in the consignment.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_transfer_consignment(
        &mut self,
        online: Online,
        consignment_path: PathBuf,
        txid: String,
        vout: u32,
        blinding: u64,
    ) -> Result<(RgbTransfer, Vec<Assignment>, HashSet<String>), Error> {
        info!(self.logger(), "Accepting transfer consignment...");
        self.check_online(online)?;
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let consignment =
            RgbTransfer::load_file(&consignment_path).map_err(|_| Error::InvalidFilePath {
                file_path: consignment_path.to_string_lossy().to_string(),
            })?;

        self.accept_transfer_with_consignment(consignment, witness_id, vout, blinding, None)
    }

    /// Accept an RGB transfer using a TXID to retrieve its consignment from the proxy.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_transfer(
        &mut self,
        online: Online,
        txid: String,
        vout: u32,
        consignment_endpoint: &str,
        blinding: u64,
    ) -> Result<(RgbTransfer, Vec<Assignment>), Error> {
        info!(self.logger(), "Accepting transfer...");
        self.check_online(online)?;
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let proxy_url = TransportEndpoint::new(consignment_endpoint.to_string())?.endpoint;

        let consignment_res = self.get_consignment(&proxy_url, txid.clone())?;
        let consignment_bytes = general_purpose::STANDARD
            .decode(consignment_res.consignment)
            .map_err(InternalError::from)?;
        let consignment = RgbTransfer::load(&consignment_bytes[..]).map_err(InternalError::from)?;

        let (consignment, assignments, _media_digests) =
            self.accept_transfer_with_consignment(consignment, witness_id, vout, blinding, None)?;
        Ok((consignment, assignments))
    }

    /// Accept an RGB transfer from a pre-fetched consignment.
    ///
    /// **Unchecked:** `txid` and `vout` define the witness anchor used for validation but are
    /// not re-checked against a recipient ID or the blockchain. Prefer
    /// [`Self::fetch_and_accept_transfer_by_recipient_id`]. If composing manually, pin first
    /// (see [`Self::fetch_consignment_by_recipient_id_unchecked`]).
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_transfer_from_consignment_unchecked(
        &mut self,
        online: Online,
        consignment: RgbTransfer,
        txid: String,
        vout: u32,
        blinding: u64,
        expected: ExpectedTransfer,
    ) -> Result<(RgbTransfer, Vec<Assignment>), Error> {
        info!(self.logger(), "Accepting transfer...");
        self.check_online(online)?;
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let (consignment, assignments, _media_digests) = self.accept_transfer_with_consignment(
            consignment,
            witness_id,
            vout,
            blinding,
            Some(expected),
        )?;
        Ok((consignment, assignments))
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn accept_transfer_with_consignment(
        &mut self,
        consignment: RgbTransfer,
        witness_id: RgbTxid,
        vout: u32,
        blinding: u64,
        expected: Option<ExpectedTransfer>,
    ) -> Result<(RgbTransfer, Vec<Assignment>, HashSet<String>), Error> {
        let schema_id = consignment.schema_id().to_string();
        let asset_schema: AssetSchema = schema_id.try_into()?;
        self.check_schema_support(&asset_schema)?;
        debug!(
            self.logger(),
            "Got consignment for asset with {} schema", asset_schema
        );

        if let Some(ref expected) = expected {
            Self::validate_expected_transfer_intent(&consignment, &asset_schema, expected)?;
        }

        let mut runtime = self.rgb_runtime()?;

        let graph_seal = GraphSeal::with_blinded_vout(vout, blinding);
        runtime.store_secret_seal(graph_seal)?;

        let resolver = OffchainResolver {
            witness_id,
            consignment: &consignment,
            fallback: self.blockchain_resolver(),
        };

        debug!(self.logger(), "Validating consignment...");
        let trusted_typesystem = asset_schema.types();
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem,
            ..Default::default()
        };
        let valid_consignment = match consignment.clone().validate(&resolver, &validation_config) {
            Ok(consignment) => consignment,
            Err(ValidationError::InvalidConsignment(e)) => {
                error!(self.logger(), "Consignment is invalid: {}", e);
                return Err(Error::InvalidConsignment);
            }
            Err(ValidationError::ResolverError(e)) => {
                warn!(self.logger(), "Network error during consignment validation");
                return Err(Error::Network {
                    details: e.to_string(),
                });
            }
        };
        let validation_status = valid_consignment.validation_status();
        debug!(
            self.logger(),
            "Consignment validity: {:?}",
            validation_status.validity()
        );

        // The send path parks such transfers in WaitingSafeHeight; this API accepts straight into
        // the stash and has no batch to park, so refuse instead of accepting a reorgable history.
        if validation_status.validity() == Validity::Warnings {
            let unsafe_txids = Self::collect_unsafe_history_txids(
                &validation_status.warnings,
                &witness_id.to_string(),
            );
            if !unsafe_txids.is_empty() {
                warn!(
                    self.logger(),
                    "Unsafe history detected in consignment: {unsafe_txids:?}"
                );
                let mut txids: Vec<String> = unsafe_txids.into_iter().collect();
                txids.sort();
                return Err(Error::UnsafeTransferHistory {
                    details: format!("witness TXs not yet safe from reorgs: {}", txids.join(", ")),
                });
            }
        }

        let received_rgb_assignments =
            self.extract_received_assignments(&consignment, witness_id, Some(vout), None);
        let mut received: Vec<Assignment> = received_rgb_assignments.into_values().collect();
        received.sort();

        if let Some(ref expected) = expected {
            Self::validate_expected_transfer_assignments(&received, expected)?;
        }

        let valid_contract = valid_consignment.clone().into_valid_contract();
        let media_digests = self
            .extract_attachments(&valid_contract, asset_schema)
            .iter()
            .map(|a| hex::encode(a.digest))
            .collect::<HashSet<_>>();
        runtime.import_contract(valid_contract, self.blockchain_resolver())?;

        runtime.accept_transfer(valid_consignment, &resolver)?;

        info!(self.logger(), "Accept transfer completed");
        Ok((consignment, received, media_digests))
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn validate_expected_transfer_intent(
        consignment: &RgbTransfer,
        asset_schema: &AssetSchema,
        expected: &ExpectedTransfer,
    ) -> Result<(), Error> {
        if matches!(expected.assignment, Assignment::Any) {
            return Err(Error::InvalidAssignment);
        }
        let contract_id = consignment.contract_id().to_string();
        if contract_id != expected.asset_id {
            return Err(Error::UnexpectedTransfer {
                details: format!(
                    "contract id mismatch: got {contract_id}, expected {}",
                    expected.asset_id
                ),
            });
        }
        if asset_schema != &expected.asset_schema {
            return Err(Error::UnexpectedTransfer {
                details: format!(
                    "schema mismatch: got {asset_schema}, expected {}",
                    expected.asset_schema
                ),
            });
        }
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn validate_expected_transfer_assignments(
        received: &[Assignment],
        expected: &ExpectedTransfer,
    ) -> Result<(), Error> {
        if received.is_empty() {
            return Err(Error::UnexpectedTransfer {
                details: s!("no assignments for the given witness seal"),
            });
        }
        if received != [expected.assignment.clone()] {
            return Err(Error::UnexpectedTransfer {
                details: format!(
                    "assignment mismatch: got {received:?}, expected {:?}",
                    expected.assignment
                ),
            });
        }
        Ok(())
    }

    /// Consume an RGB fascia.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn consume_fascia(
        &self,
        fascia: Fascia,
        witness_ord: Option<WitnessOrd>,
    ) -> Result<(), Error> {
        info!(self.logger(), "Consuming fascia...");
        self.rgb_runtime()?
            .consume_fascia(fascia.clone(), witness_ord)?;
        info!(self.logger(), "Consume fascia completed");
        Ok(())
    }

    /// Get the height for a Bitcoin TX.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn get_tx_height(&self, online: Online, txid: String) -> Result<Option<u32>, Error> {
        info!(self.logger(), "Getting TX height...");
        self.check_online(online)?;
        let height = self.tx_height(txid)?;
        info!(self.logger(), "Get TX height completed");
        Ok(height)
    }

    /// Update RGB witnesses.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn update_witnesses(
        &self,
        online: Online,
        after_height: u32,
        force_witnesses: Vec<RgbTxid>,
    ) -> Result<UpdateRes, Error> {
        info!(self.logger(), "Updating witnesses...");
        self.check_online(online)?;
        let update_res = self.rgb_runtime()?.update_witnesses(
            self.blockchain_resolver(),
            after_height,
            force_witnesses,
        )?;
        info!(self.logger(), "Update witnesses completed");
        Ok(update_res)
    }

    /// Manually set the [`WitnessOrd`] of a witness TX.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn upsert_witness(
        &self,
        witness_id: RgbTxid,
        witness_ord: WitnessOrd,
    ) -> Result<(), Error> {
        let mut runtime = self.rgb_runtime()?;
        runtime.upsert_witness(witness_id, witness_ord)?;
        Ok(())
    }

    /// Extract the metadata of a new RGB asset and save the asset into the DB.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn save_new_asset(
        &self,
        online: Online,
        consignment: RgbTransfer,
        offchain_txid: String,
    ) -> Result<(), Error> {
        info!(self.logger(), "Saving new asset...");
        self.check_online(online)?;
        let contract_id = consignment.contract_id();
        let witness_id = RgbTxid::from_str(&offchain_txid).map_err(|_| Error::InvalidTxid)?;
        let resolver = OffchainResolver {
            witness_id,
            consignment: &consignment,
            fallback: self.blockchain_resolver(),
        };
        let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
        let trusted_typesystem = asset_schema.types();
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem,
            ..Default::default()
        };
        let valid_transfer = match consignment.clone().validate(&resolver, &validation_config) {
            Ok(consignment) => consignment,
            Err(ValidationError::InvalidConsignment(error)) => {
                error!(self.logger(), "Consignment is invalid: {}", error);
                return Err(Error::InvalidConsignment);
            }
            Err(ValidationError::ResolverError(error)) => {
                return Err(Error::Network {
                    details: error.to_string(),
                });
            }
        };
        let valid_contract = valid_transfer.clone().into_valid_contract();

        let runtime = self.rgb_runtime()?;
        let txn = self.database().begin_transaction()?;
        if txn.get_asset(contract_id.to_string())?.is_some() {
            // Metadata registration is idempotent only when the RGB stock agrees with the database.
            // A missing stock entry means the caller has not completed transfer acceptance.
            runtime.export_contract(contract_id)?;
            drop(txn);
            info!(self.logger(), "Save new asset completed");
            return Ok(());
        }
        self.save_new_asset_internal(
            &txn,
            &runtime,
            contract_id,
            asset_schema,
            valid_contract,
            Some(valid_transfer),
        )?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();

        info!(self.logger(), "Save new asset completed");
        Ok(())
    }

    /// List the Bitcoin unspents of the vanilla wallet, using BDK's objects, filtered by
    /// `min_confirmations`.
    ///
    /// <div class="warning">This method is meant for special usage, for most cases the method
    /// <code>list_unspents</code> is sufficient</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn list_unspents_vanilla(
        &mut self,
        online: Online,
        min_confirmations: u8,
        skip_sync: bool,
    ) -> Result<Vec<LocalOutput>, Error> {
        info!(self.logger(), "Listing unspents vanilla...");
        let txn = self.database().begin_transaction()?;
        self.sync_if_requested(&txn, Some(online), skip_sync, KeychainKind::Internal)?;
        txn.commit()?;

        let unspents = self.internal_unspents();

        let res = if min_confirmations > 0 {
            unspents
                .filter_map(|u| {
                    match self
                        .indexer()
                        .get_tx_confirmations(&u.outpoint.txid.to_string())
                    {
                        Ok(confirmations) => {
                            if let Some(confirmations) = confirmations
                                && confirmations >= min_confirmations as u64
                            {
                                return Some(Ok(u));
                            }
                            None
                        }
                        Err(e) => Some(Err(e)),
                    }
                })
                .collect::<Result<Vec<LocalOutput>, Error>>()
        } else {
            Ok(unspents.collect())
        };

        info!(self.logger(), "List unspents vanilla completed");
        res
    }

    /// Return whether the RGB asset with the provided ID is known to the wallet.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn is_asset_known(&self, contract_id: ContractId) -> Result<bool, Error> {
        let asset_id = contract_id.to_string();
        info!(
            self.logger(),
            "Checking if asset '{}' is known...", asset_id
        );
        let txn = self.database().begin_transaction()?;
        let known = txn.get_asset(asset_id)?.is_some();
        txn.commit()?;
        info!(self.logger(), "Check if asset is known completed");
        Ok(known)
    }

    /// List the media files for a given RGB asset.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn list_asset_media(&self, asset_id: String) -> Result<HashSet<Media>, Error> {
        info!(self.logger(), "Listing media for asset '{}'...", asset_id);
        let txn = self.database().begin_transaction()?;
        let asset = txn.check_asset_exists(asset_id)?;
        let token = match asset.schema {
            AssetSchema::Uda => self.get_asset_token(
                asset.idx,
                &txn.iter_media()?,
                &txn.iter_tokens()?,
                &txn.iter_token_medias()?,
            ),
            AssetSchema::Nia | AssetSchema::Cfa | AssetSchema::Ifa => None,
        };
        let medias = self.get_asset_medias(&txn, asset.media_idx, token)?;
        txn.commit()?;
        info!(self.logger(), "List asset media completed");
        Ok(medias)
    }

    /// Return the consignment file path for a send transfer of an asset.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn get_send_consignment_path(&self, asset_id: &str, transfer_id: &str) -> PathBuf {
        self.send_consignment_path(asset_id, transfer_id)
    }

    /// Complete the donation send operation by updating the DB only. This will also broadcast the
    /// transaction to update the DB with the new UTXOs and BDK.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn send_end_db_update_only(
        &mut self,
        online: Online,
        signed_psbt: String,
    ) -> Result<OperationResult, Error> {
        info!(self.logger(), "Sending (end) db update only...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;

        // this will also update the DB with the new UTXOs and BDK
        self.broadcast_psbt(&txn, &psbt)?;

        let (txid, _, info_contents, _) = self.get_transfer_end_data(&psbt)?;

        let batch_transfer_idx = self.update_or_save_transfers(
            &txn,
            txid.clone(),
            &info_contents,
            TransferStatus::WaitingConfirmations,
            true,
        )?;

        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();

        info!(self.logger(), "Send (end) db update only completed");
        Ok(OperationResult {
            txid,
            batch_transfer_idx,
            entropy: info_contents.entropy,
        })
    }
}

#[cfg(test)]
#[cfg(any(feature = "electrum", feature = "esplora"))]
mod tests {
    use super::*;

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn display_indexer_protocol() {
        assert_eq!(IndexerProtocol::Electrum.to_string(), "Electrum");
        assert_eq!(IndexerProtocol::Esplora.to_string(), "Esplora");
    }

    #[test]
    fn psbt_op_payload_hashes_bind_files_txid_and_batch() {
        let consignments = BTreeMap::from([(s!("rgb:asset"), sha256_hex(b"consignment"))]);
        let hashes = PsbtOpPayloadHashes::new(
            b"fascia",
            b"psbt",
            b"foreign_inputs",
            consignments,
            "txid-1",
            Some(7),
        );
        assert_eq!(hashes.fascia, Some(sha256_hex(b"fascia")));
        assert_eq!(hashes.colored_psbt, Some(sha256_hex(b"psbt")));
        assert_eq!(hashes.foreign_inputs, sha256_hex(b"foreign_inputs"));
        assert_eq!(hashes.txid, sha256_hex(b"txid-1"));
        assert_eq!(
            hashes.batch_transfer_idx,
            Some(psbt_op_batch_identity_hash(7))
        );
        assert_ne!(hashes.fascia, hashes.colored_psbt);
        assert_ne!(hashes.txid, psbt_op_batch_identity_hash(7));
    }

    const ASSET_1: &str = "rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E";
    const ASSET_2: &str = "rgb:4bBH~Lrb-rx8sB_n-WAJLPcn-X5tFL9q-dFDGbSz-8yApPws";
    const TXID_1: &str = "e5a3e577309df31bd606f48049049d2e1e02b048206ba232944fcc053a176ccb";
    const TXID_2: &str = "5ad4a4fcb7d76de88b7a0d79d0d20f0ec9f9bd77e25a2b03a0f1d68d5b0d2c11";

    fn staged_tx() -> Transaction {
        let input = |txid: &str, vout| bdk_wallet::bitcoin::TxIn {
            previous_output: OutPoint {
                txid: bdk_wallet::bitcoin::Txid::from_str(txid).unwrap(),
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: bdk_wallet::bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Default::default(),
        };
        let output = |sats, script: ScriptBuf| TxOut {
            value: BdkAmount::from_sat(sats),
            script_pubkey: script,
        };
        Transaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![input(TXID_1, 0), input(TXID_2, 1)],
            output: vec![
                output(0, ScriptBuf::new_op_return([])),
                output(
                    600,
                    ScriptBuf::from_bytes([&[0x00, 0x14][..], &[0x11; 20]].concat()),
                ),
                output(
                    700,
                    ScriptBuf::from_bytes([&[0x51, 0x20][..], &[0x22; 32]].concat()),
                ),
            ],
        }
    }

    #[test]
    fn psbt_op_finalized_tx_must_only_fill_the_commitment() {
        let staged = staged_tx();
        let mut finalized = staged.clone();
        finalized.output[0].script_pubkey = ScriptBuf::new_op_return([7u8; 32]);
        assert_eq!(psbt_op_check_finalized_tx(&staged, &finalized).unwrap(), 0);
        assert_eq!(psbt_op_check_finalized_tx(&staged, &staged).unwrap(), 0);

        let refused = |mutate: &dyn Fn(&mut Transaction)| {
            let mut tx = finalized.clone();
            mutate(&mut tx);
            matches!(
                psbt_op_check_finalized_tx(&staged, &tx),
                Err(Error::InvalidColoringInfo { .. })
            )
        };
        assert!(refused(&|tx| tx.input.swap(0, 1)));
        assert!(refused(&|tx| tx.input[1].previous_output.vout = 2));
        assert!(refused(&|tx| {
            tx.input[0].sequence = bdk_wallet::bitcoin::Sequence::MAX;
        }));
        assert!(refused(&|tx| {
            tx.input.pop();
        }));
        assert!(refused(&|tx| tx.output[1].value = BdkAmount::from_sat(601)));
        assert!(refused(&|tx| tx.output[1].script_pubkey = ScriptBuf::new()));
        assert!(refused(&|tx| tx.output[0].script_pubkey = ScriptBuf::new()));
        assert!(refused(&|tx| tx.output[0].value = BdkAmount::from_sat(1)));
        assert!(refused(&|tx| tx.output.swap(1, 2)));
        assert!(refused(&|tx| {
            tx.output.push(tx.output[1].clone());
        }));
        assert!(refused(&|tx| {
            tx.version = bdk_wallet::bitcoin::transaction::Version::ONE;
        }));
        assert!(refused(&|tx| {
            tx.lock_time = bdk_wallet::bitcoin::absolute::LockTime::from_consensus(1);
        }));

        let mut no_opret = staged.clone();
        no_opret.output.remove(0);
        assert!(matches!(
            psbt_op_check_finalized_tx(&no_opret, &no_opret),
            Err(Error::Inconsistency { .. })
        ));
    }

    /// Commit `messages` on the OP_RETURN (vout 0) of `staged_tx()` the way `rgb_commit` does.
    fn committed_psbt(messages: &[(mpc::ProtocolId, mpc::Message)]) -> Psbt {
        use psrgbt::DbcPsbtProof;
        let mut psbt = Psbt::from_unsigned_tx(staged_tx()).unwrap();
        let output = &mut psbt.outputs[0];
        output.set_opret_host();
        output.set_mpc_entropy(42).unwrap();
        for (protocol_id, message) in messages {
            output.set_mpc_message(*protocol_id, *message).unwrap();
        }
        OpretProof::dbc_commit(&mut psbt).unwrap();
        psbt
    }

    #[test]
    fn only_a_committed_psbt_counts_as_finalized() {
        // outputs without MPC messages still give an (empty) message map
        let unfinalized = Psbt::from_unsigned_tx(staged_tx()).unwrap();
        assert!(unfinalized.outputs[0].mpc_message_map().is_ok());
        assert!(!psbt_rgb_commitment_finalized(&unfinalized));
        let finalized = committed_psbt(&[(
            mpc::ProtocolId::from([1u8; 32]),
            mpc::Message::from([2u8; 32]),
        )]);
        assert!(psbt_rgb_commitment_finalized(&finalized));
    }

    #[test]
    fn psbt_op_commitment_check_binds_messages_and_op_return() {
        let ours = (
            mpc::ProtocolId::from([1u8; 32]),
            mpc::Message::from([2u8; 32]),
        );
        let theirs = (
            mpc::ProtocolId::from([3u8; 32]),
            mpc::Message::from([4u8; 32]),
        );
        let psbt = committed_psbt(&[ours, theirs]);
        let expected = BTreeMap::from([ours]);
        let tree = psbt_op_check_commitment(&psbt, 0, &expected).unwrap();
        assert_eq!(
            psbt.unsigned_tx.output[0].script_pubkey,
            ScriptBuf::new_op_return(tree.commit_id().to_byte_array())
        );

        // a changed message for this wallet's contract, or a missing one
        let altered = BTreeMap::from([(ours.0, mpc::Message::from([9u8; 32]))]);
        assert!(matches!(
            psbt_op_check_commitment(&psbt, 0, &altered),
            Err(Error::InvalidColoringInfo { .. })
        ));
        let dropped = committed_psbt(&[theirs]);
        assert!(matches!(
            psbt_op_check_commitment(&dropped, 0, &expected),
            Err(Error::InvalidColoringInfo { .. })
        ));

        // an OP_RETURN that does not carry the tree's commitment
        let mut tampered = psbt.clone();
        tampered.unsigned_tx.output[0].script_pubkey = ScriptBuf::new_op_return([5u8; 32]);
        assert!(matches!(
            psbt_op_check_commitment(&tampered, 0, &expected),
            Err(Error::InvalidColoringInfo { .. })
        ));

        // no commitment at all on that output
        assert!(matches!(
            psbt_op_check_commitment(&Psbt::from_unsigned_tx(staged_tx()).unwrap(), 0, &expected),
            Err(Error::InvalidColoringInfo { .. })
        ));
    }

    #[test]
    fn psbt_op_staged_manifest_round_trips_coloring_info() {
        let coloring_info = ColoringInfo {
            asset_info_map: HashMap::from([
                (
                    ContractId::from_str(ASSET_1).unwrap(),
                    AssetColoringInfo {
                        output_map: HashMap::from([(1, 40), (3, 0)]),
                        static_blinding: Some(7),
                    },
                ),
                (
                    ContractId::from_str(ASSET_2).unwrap(),
                    AssetColoringInfo {
                        output_map: HashMap::from([(2, 5)]),
                        static_blinding: None,
                    },
                ),
            ]),
            static_blinding: Some(11),
            nonce: Some(3),
        };
        let inputs = HashSet::from([
            OutPoint::from_str(&format!("{TXID_2}:1")).unwrap(),
            OutPoint::from_str(&format!("{TXID_1}:0")).unwrap(),
        ]);
        let manifest = PsbtOpStagedManifest::new(&coloring_info, &inputs, 2, Some(1_700_000_000));
        let raw = serde_json::to_string_pretty(&manifest).unwrap();
        let parsed: PsbtOpStagedManifest = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed, manifest);
        // deterministic bytes: the manifest hash must not depend on HashMap order
        assert_eq!(
            raw,
            serde_json::to_string_pretty(&PsbtOpStagedManifest::new(
                &coloring_info,
                &inputs,
                2,
                Some(1_700_000_000)
            ))
            .unwrap()
        );
        assert_eq!(parsed.inputs().unwrap(), inputs);
        assert_eq!(parsed.min_confirmations, 2);
        assert_eq!(parsed.expiration_timestamp, Some(1_700_000_000));

        let rebuilt = parsed.coloring_info().unwrap();
        assert_eq!(rebuilt.static_blinding, coloring_info.static_blinding);
        assert_eq!(rebuilt.nonce, coloring_info.nonce);
        assert_eq!(
            rebuilt.asset_info_map.len(),
            coloring_info.asset_info_map.len()
        );
        for (contract_id, info) in &coloring_info.asset_info_map {
            let got = &rebuilt.asset_info_map[contract_id];
            assert_eq!(got.output_map, info.output_map);
            assert_eq!(got.static_blinding, info.static_blinding);
        }

        let mut corrupt = parsed.clone();
        let entry = corrupt.assets.pop_first().unwrap().1;
        corrupt.assets.insert(s!("not-an-asset-id"), entry);
        assert!(matches!(
            corrupt.coloring_info(),
            Err(Error::Inconsistency { .. })
        ));
    }

    fn meta_json(status: &str, hashes: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "schema_version": PSBT_OP_META_SCHEMA_VERSION,
            "operation_id": "0123456789abcdef0123456789abcdef",
            "status": status,
            "txid": TXID_1,
            "created_at": 1,
            "batch_transfer_idx": 4,
            "broadcast": "not_attempted",
            "hashes": hashes,
        })
    }

    #[test]
    fn psbt_op_meta_reads_prepared_journals_and_round_trips_staged() {
        // a meta.json psbt_op_prepare wrote before Staged existed still parses unchanged
        let legacy = meta_json(
            "prepared",
            serde_json::json!({
                "fascia": "f",
                "colored_psbt": "c",
                "foreign_inputs": "i",
                "consignments": {"rgb:asset": "a"},
                "txid": "t",
                "batch_transfer_idx": "b",
            }),
        );
        let meta: PsbtOpMeta = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(meta.status, PsbtOperationStatus::Prepared);
        assert_eq!(meta.hashes.fascia.as_deref(), Some("f"));
        assert_eq!(meta.hashes.colored_psbt.as_deref(), Some("c"));
        assert!(meta.hashes.staged.is_none());
        assert!(meta.completing_txid.is_none());
        assert!(!Wallet::psbt_op_never_completed(&meta));
        // and is written back byte-for-byte in the same shape
        assert_eq!(serde_json::to_value(&meta).unwrap(), legacy);

        let staged = meta_json(
            "staged",
            serde_json::to_value(PsbtOpPayloadHashes::new_staged(
                b"psbt",
                b"manifest",
                b"in",
                TXID_1,
            ))
            .unwrap(),
        );
        let mut meta: PsbtOpMeta = serde_json::from_value(staged).unwrap();
        assert_eq!(meta.status, PsbtOperationStatus::Staged);
        assert!(meta.hashes.fascia.is_none());
        assert!(meta.hashes.colored_psbt.is_none());
        assert!(meta.hashes.consignments.is_empty());
        assert_eq!(
            meta.hashes.staged,
            Some(PsbtOpStagedHashes {
                psbt: sha256_hex(b"psbt"),
                manifest: sha256_hex(b"manifest"),
            })
        );
        assert!(Wallet::psbt_op_never_completed(&meta));

        meta.completing_txid = Some(TXID_2.to_string());
        let raw = serde_json::to_value(&meta).unwrap();
        assert_eq!(raw["completing_txid"], TXID_2);
        assert!(raw["hashes"].get("fascia").is_none());
        let back: PsbtOpMeta = serde_json::from_value(raw).unwrap();
        assert_eq!(back.completing_txid.as_deref(), Some(TXID_2));
        assert_eq!(back.hashes, meta.hashes);

        // completed: committed payloads bound, staged hashes kept for the audit trail
        let mut completed = back.clone();
        let staged_hashes = completed.hashes.staged.take();
        completed.hashes = PsbtOpPayloadHashes::new(
            b"fascia",
            b"colored",
            b"in",
            BTreeMap::new(),
            TXID_2,
            Some(4),
        );
        completed.hashes.staged = staged_hashes;
        assert!(!Wallet::psbt_op_never_completed(&completed));
    }
}
