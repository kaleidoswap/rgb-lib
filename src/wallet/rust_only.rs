//! Rust-only functionality.
//!
//! This module defines additional utility methods that are not exposed via FFI.
//!
//! It also includes the submarine / HTLC helpers (`color_psbt_for_outpoints*`,
//! `psbt_op_prepare` / `psbt_op_apply` / `psbt_op_abort` / `psbt_op_reconcile`) that operate on
//! escrow outpoints without treating them as wallet UTXOs.

use super::*;

#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OPS_DIR: &str = "psbt_ops";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_META_FILE: &str = "meta.json";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_FOREIGN_INPUTS_FILE: &str = "foreign_inputs.json";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_COLORED_PSBT_FILE: &str = "colored.psbt";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_CONSIGNMENTS_DIR: &str = "consignments";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_CONSIGNMENT_FILE: &str = CONSIGNMENT_FILE;
/// Marker left in the transfer dir once a prepared fascia has been consumed into the RGB stash,
/// until the related SQL update is committed.
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) const STASH_CONSUMED_FILE: &str = "stash_consumed";
/// Marker left in the transfer dir by the color-prepare flow, allowing
/// [`Wallet::consume_transfer_fascia`] on the related batch transfer.
#[cfg(any(feature = "electrum", feature = "esplora"))]
const COLOR_PREPARE_FILE: &str = "color_prepare";

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn persist_stash_consumed_marker(path: &Path) -> Result<(), Error> {
    let file = fs::File::create(path)?;
    file.sync_all()?;
    fsync_parent_dir(path)
}

#[cfg(all(unix, any(feature = "electrum", feature = "esplora")))]
fn fsync_parent_dir(_path: &Path) -> Result<(), Error> {
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
    <sha256::Hash as Sha256Hash>::hash(bytes.as_ref()).to_string()
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_META_SCHEMA_VERSION: u32 = 1;

/// Windows-safe path: `consignments/{sha256(asset_id)}/consignment_out` (`:` is invalid on Windows).
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn psbt_op_consignment_path(op_dir: &Path, asset_id: &str) -> PathBuf {
    let digest = <sha256::Hash as Sha256Hash>::hash(asset_id.as_bytes());
    op_dir
        .join(PSBT_OP_CONSIGNMENTS_DIR)
        .join(digest.to_string())
        .join(PSBT_OP_CONSIGNMENT_FILE)
}
#[cfg(any(feature = "electrum", feature = "esplora"))]
const PSBT_OP_ID_LEN: usize = 32;
/// Expiration applied by `psbt_op_prepare` when the caller gives none.
pub const PSBT_OP_DEFAULT_EXPIRATION_SECS: u64 = 24 * 60 * 60;

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

/// Map of contract ID and list of its beneficiaries
pub type AssetBeneficiariesMap = BTreeMap<ContractId, Vec<BuilderSeal<GraphSeal>>>;

/// Result of [`Wallet::color_psbt_and_prepare_consume`].
///
/// Consignments are ready to post, but the RGB stash is **not** updated until
/// [`Wallet::consume_transfer_fascia`] (after broadcast). While
/// [`ColorPrepareResult::batch_transfer_idx`] is [`TransferStatus::Initiated`] and its TX has
/// never been broadcast, `fail_transfers` can roll the DB reservation back.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug)]
pub struct ColorPrepareResult {
    /// Per-asset consignments before stash consumption.
    pub transfers: Vec<RgbTransfer>,
    /// Recoverable batch transfer.
    pub batch_transfer_idx: i32,
}

/// Status of a file-backed HTLC coloring operation.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PsbtOperationStatus {
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
}

/// Recovered HTLC operation (lookup after a lost `psbt_op_prepare` response).
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone)]
pub struct PsbtOperation {
    /// Opaque operation ID (directory name under `psbt_ops/`).
    pub operation_id: String,
    /// Colored unsigned PSBT.
    pub colored_psbt: String,
    /// Wallet-relative directory containing file-backed payloads.
    pub operation_dir: String,
    /// High-level operation status.
    pub status: PsbtOperationStatus,
    /// Broadcast lifecycle.
    pub broadcast: PsbtBroadcastState,
    /// Witness txid committed at prepare.
    pub txid: String,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PsbtOpPayloadHashes {
    fascia: String,
    colored_psbt: String,
    foreign_inputs: String,
    consignments: BTreeMap<String, String>,
    txid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    batch_transfer_idx: Option<String>,
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
            fascia: sha256_hex(fascia),
            colored_psbt: sha256_hex(colored_psbt),
            foreign_inputs: sha256_hex(foreign_inputs),
            consignments,
            txid: sha256_hex(txid.as_bytes()),
            batch_transfer_idx: batch_transfer_idx.map(psbt_op_batch_identity_hash),
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

fn rebuild_psbt_preserving_maps(
    psbt: &Psbt,
    mut unsigned_tx: BdkTransaction,
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

/// Rust-only APIs of the wallet.
impl Wallet {
    /// Color a PSBT.
    ///
    /// # `output_map` index convention
    ///
    /// Keys are PSBT output indices. When any output is P2TR (RGB `OpretFirst`), OP_RETURN is
    /// placed at vout 0 (inserted if missing) and keys are treated as **pre-OP_RETURN** indices:
    /// they are shifted by +1 internally. That applies even if OP_RETURN was already present at
    /// vout 0. With P2TR, a pre-existing OP_RETURN at index > 0 is rejected (would silently
    /// mis-seal under the +1 rule). With no P2TR, OP_RETURN is appended and keys are final.
    /// A key must not point to the OP_RETURN output.
    ///
    /// Coloring must happen **before** any input is signed. Partial signatures are rejected
    /// because embedding the RGB commitment rewrites the OP_RETURN output and invalidates existing
    /// sighashes.
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
    /// silently mis-seal.
    ///
    /// Uses `unsigned_tx` directly (no `extract_tx`): fee-rate guards are irrelevant to RGB
    /// commitment layout, and some PSBTs may trip `AbsurdFeeRate` without being invalid to color.
    pub(crate) fn prepare_psbt_for_coloring(&self, psbt: &mut Psbt) -> Result<bool, Error> {
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

    /// Build the RGB transitions for `coloring_info`, spending the allocations found on
    /// `prev_outputs`, and commit them to the PSBT's OP_RETURN output.
    ///
    /// The PSBT must already have gone through [`Self::prepare_psbt_for_coloring`], whose result
    /// is `shift_output_map_for_opreturn_first`. With `require_full_allocation`, the `output_map`
    /// of each contract must re-assign exactly the amount found on the inputs, and inputs carrying
    /// non-asset assignments (e.g. inflation rights) are rejected, since they would be destroyed.
    pub(crate) fn color_psbt_with_prevouts_runtime(
        &self,
        runtime: &RgbRuntime,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        prev_outputs: HashSet<OutPoint>,
        require_full_allocation: bool,
        shift_output_map_for_opreturn_first: bool,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        let mut all_transitions: HashMap<ContractId, Transition> = HashMap::new();
        let mut asset_beneficiaries: AssetBeneficiariesMap = bmap![];
        let assignment_name = FieldName::from(RGB_STATE_ASSET_OWNER);

        for (contract_id, asset_coloring_info) in coloring_info.asset_info_map.clone() {
            let schema = AssetSchema::get_from_contract_id(contract_id, runtime).map_err(|_| {
                Error::AssetNotFound {
                    asset_id: contract_id.to_string(),
                }
            })?;

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

        let opreturn_index = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey.is_op_return())
            .expect("psbt should have an op_return output")
            .0;
        let opreturn_output = psbt.outputs.get_mut(opreturn_index).unwrap();
        opreturn_output.set_opret_host();
        if let Some(blinding) = coloring_info.static_blinding {
            opreturn_output
                .set_mpc_entropy(blinding)
                .map_err(InternalError::from)?;
        }

        for (contract_id, transition) in all_transitions {
            for opout in transition.inputs() {
                psbt.set_rgb_contract_consumer(contract_id, opout, transition.id())
                    .map_err(InternalError::from)?;
            }
            psbt.push_rgb_transition(transition)
                .map_err(InternalError::from)?;
        }

        psbt.set_rgb_close_method(CloseMethod::OpretFirst);
        psbt.set_as_unmodifiable();
        let fascia = psbt.rgb_commit().map_err(InternalError::from)?;

        info!(self.logger(), "Color PSBT completed");
        Ok((fascia, asset_beneficiaries))
    }

    /// Color a PSBT, consume the RGB fascia and return the related consignment.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn color_psbt_and_consume(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
    ) -> Result<Vec<RgbTransfer>, Error> {
        info!(self.logger(), "Coloring PSBT and consuming...");
        let (fascia, asset_beneficiaries) = self.color_psbt(psbt, coloring_info.clone())?;

        let witness_txid = psbt.get_txid();

        let mut runtime = self.rgb_runtime()?;
        runtime.consume_fascia(fascia, None)?;

        let mut transfers = vec![];
        for (contract_id, beneficiaries) in asset_beneficiaries {
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
            transfers.push(runtime.transfer(
                contract_id,
                beneficiaries_witness,
                beneficiaries_blinded,
                Some(witness_txid),
            )?);
        }

        info!(self.logger(), "Color PSBT and consume completed");
        Ok(transfers)
    }

    /// Create consignments for a PSBT created with the [`send_begin`](Wallet::send_begin) method.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn create_consignments(&self, psbt: String) -> Result<(), Error> {
        info!(self.logger(), "Creating consignments...");

        let psbt = Psbt::from_str(&psbt)?;
        let (_, transfer_dir, info_contents, fascia) = self.get_transfer_end_data(&psbt)?;
        self.gen_consignments(&fascia, &info_contents.transfers, &transfer_dir)?;

        info!(self.logger(), "Create consignments completed");
        Ok(())
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

        let schema_id = consignment.schema_id().to_string();
        let asset_schema: AssetSchema = schema_id.try_into()?;
        self.check_schema_support(&asset_schema)?;
        debug!(
            self.logger(),
            "Got consignment for asset with {} schema", asset_schema
        );

        let mut runtime = self.rgb_runtime()?;

        let graph_seal = GraphSeal::with_blinded_vout(vout, blinding);
        runtime.store_secret_seal(graph_seal)?;

        let resolver = OffchainResolver {
            witness_id,
            consignment: &consignment,
            fallback: self.blockchain_resolver(),
        };

        debug!(self.logger(), "Validating consignment...");
        let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
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
        let validity = valid_consignment.validation_status().validity();
        debug!(self.logger(), "Consignment validity: {:?}", validity);

        let valid_contract = valid_consignment.clone().into_valid_contract();
        let media_digests = self
            .extract_attachments(&valid_contract, asset_schema)
            .iter()
            .map(|a| hex::encode(a.digest))
            .collect::<HashSet<_>>();
        runtime
            .import_contract(valid_contract, self.blockchain_resolver())
            .expect("failure importing validated contract");

        let received_rgb_assignments =
            self.extract_received_assignments(&consignment, witness_id, Some(vout), None);

        runtime.accept_transfer(valid_consignment, &resolver)?;

        info!(self.logger(), "Accept transfer completed");
        Ok((
            consignment,
            received_rgb_assignments.into_values().collect(),
            media_digests,
        ))
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
        let runtime = self.rgb_runtime()?;

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
        let valid_transfer = consignment
            .clone()
            .validate(&resolver, &validation_config)
            .expect("valid consignment");
        let valid_contract = valid_transfer.clone().into_valid_contract();

        let txn = self.database().begin_transaction()?;
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
        self.persist_and_commit(txn)?;

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
        self.persist_and_commit(txn)?;

        info!(self.logger(), "Send (end) db update only completed");
        Ok(OperationResult {
            txid,
            batch_transfer_idx,
            entropy: info_contents.entropy,
        })
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl Wallet {
    /// Color a PSBT and persist recovery data before broadcast and stash consumption.
    ///
    /// `output_map` indexing follows [`Self::color_psbt`] (legacy P2TR / `OpretFirst` +1 shift).
    /// Every allocation found on the PSBT inputs must be re-assigned: each contract with
    /// allocations on the inputs must be listed in `coloring_info`, its `output_map` must assign
    /// the full input amount, and inputs carrying non-asset rights are rejected.
    ///
    /// Consignments are built from the fascia **before** any stash update. The fascia and the
    /// unsigned PSBT are saved under the wallet transfer dir and a [`TransferStatus::Initiated`]
    /// outgoing batch transfer is written, so `fail_transfers` can roll it back as long as the TX
    /// has never been broadcast. Call [`Self::consume_transfer_fascia`] with
    /// [`ColorPrepareResult::batch_transfer_idx`] **after** broadcast to apply the fascia to the
    /// RGB stash.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
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
        runtime.persist()?;
        Ok(result)
    }

    /// Apply a fascia previously prepared by [`Self::color_psbt_and_prepare_consume`] into the RGB
    /// stash after the Bitcoin TX has been broadcast.
    ///
    /// The batch transfer must still be [`TransferStatus::Initiated`] and its TX must be known to
    /// the indexer. The batch transfer is then updated to
    /// [`TransferStatus::WaitingConfirmations`]. The stash update is made durable before the SQL
    /// commit (a `stash_consumed` marker is left in the transfer dir in between), so a call
    /// interrupted after the stash update can simply be retried.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
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
        info!(self.logger(), "Consume transfer fascia completed");
        Ok(())
    }

    /// Consume fascia, persist stock while the runtime lock is held, then fsync the markers.
    /// Always consumes (rgb-ops merge-reveals on retry): a witness stored by an incoming accept
    /// of the same tx is not a sign that this fascia's bundles are in the stash.
    pub(crate) fn consume_fascia_persist_then_mark(
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

    /// Reject coloring when the given inputs carry allocations for a contract not listed in
    /// `coloring_info`: no transition would re-assign them, so they would be destroyed.
    pub(crate) fn reject_uncolored_input_contracts(
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

    /// Mark the wallet TXOs spent by the PSBT inputs as spent.
    pub(crate) fn mark_psbt_inputs_spent(&self, txn: &DbTxn, psbt: &Psbt) -> Result<(), Error> {
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

    /// Build the consignments for a colored PSBT from its fascia (without consuming it) and
    /// register the related [`TransferStatus::Initiated`] outgoing batch transfer.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_color_and_transfer_runtime(
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
        Ok(ColorPrepareResult {
            transfers,
            batch_transfer_idx,
        })
    }

    /// Write the color-prepare recovery files (fascia, unsigned PSBT and, if
    /// `allow_consume_transfer_fascia`, the marker enabling [`Self::consume_transfer_fascia`])
    /// to the transfer dir of `txid`.
    pub(crate) fn write_color_prepare_files(
        &self,
        psbt: &Psbt,
        txid: &str,
        fascia: &Fascia,
        allow_consume_transfer_fascia: bool,
    ) -> Result<(), Error> {
        let transfer_dir = self.get_transfer_dir(txid);
        persist_durable_create_dir(&transfer_dir)?;
        let serialized_fascia = serde_json::to_string(fascia).map_err(InternalError::from)?;
        persist_durable_replace(&transfer_dir.join(FASCIA_FILE), serialized_fascia)?;
        persist_durable_replace(&transfer_dir.join(UNSIGNED_PSBT_FILE), psbt.to_string())?;
        if allow_consume_transfer_fascia {
            persist_durable_replace(&transfer_dir.join(COLOR_PREPARE_FILE), b"")?;
        }
        Ok(())
    }

    /// Write the color-prepare recovery files, then register the related
    /// [`TransferStatus::Initiated`] outgoing batch transfer in a new DB transaction.
    ///
    /// See [`Self::persist_color_prepare_batch_txn`] for the SQL side.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn persist_color_prepare_batch(
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
        txn.commit()?;
        Ok(batch_transfer_idx)
    }

    /// Register a [`TransferStatus::Initiated`] outgoing batch transfer for a colored PSBT inside
    /// the caller-provided DB transaction, which the caller has to commit.
    ///
    /// `spent` maps each colored contract to the assignments found on the PSBT inputs: they are
    /// saved as `Input` colorings of the wallet TXOs. Each `output_map` destination owned by the
    /// wallet (and not by an open witness receive) is saved as a `Change` coloring, and the
    /// transfers are saved for the external destinations (or for the change ones when there are
    /// no external destinations). The backup info is updated as well.
    ///
    /// Fails with [`Error::BatchTransferAlreadyExists`] if a live (initiated, waiting
    /// confirmations or settled) outgoing batch transfer already exists for `txid`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn persist_color_prepare_batch_txn(
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
                    let address_payload = AddressPayload::from_script(&txout.script_pubkey)
                        .map_err(|_| Error::InvalidColoringInfo {
                            details: format!(
                                "output_map vout {vout} script is not a standard address payload"
                            ),
                        })?;
                    let beneficiary =
                        Beneficiary::WitnessVout(Pay2Vout::new(address_payload), None);
                    let recipient_id =
                        XChainNet::with(bitcoin_network.into(), beneficiary).to_string();
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
                        })),
                        ..Default::default()
                    })?;
                }
            }
        }

        self.update_backup_info(txn, false)?;
        Ok(batch_transfer_idx)
    }

    /// Map a coloring `output_map` amount to the SQL [`Assignment`] for this schema.
    ///
    /// `output_map` only carries fungible amounts / UDA presence (1). Explicit inflation-right
    /// destinations are not expressible via this map.
    fn assignment_for_coloring_output(asset_schema: AssetSchema, amount: u64) -> Assignment {
        match asset_schema {
            AssetSchema::Uda => Assignment::NonFungible,
            AssetSchema::Nia | AssetSchema::Cfa | AssetSchema::Ifa => Assignment::Fungible(amount),
        }
    }

    /// Scripts that open incoming witness receives are waiting on (pending witness scripts and
    /// witness recipients of in-flight incoming transfers), hex-encoded.
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
}

/// Submarine / HTLC APIs of the wallet.
#[cfg(any(feature = "electrum", feature = "esplora"))]
impl Wallet {
    /// Shared setup for [`Self::color_psbt_for_outpoints`] and
    /// [`Self::color_psbt_for_outpoints_and_prepare_consume`]: empty/subset checks, validate allocations,
    /// prepare PSBT. Returns `(runtime, override_set)`.
    fn prepare_color_psbt_for_outpoints(
        &self,
        psbt: &mut Psbt,
        coloring_info: &ColoringInfo,
        input_outpoints: Vec<OutPoint>,
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
    pub fn color_psbt_for_outpoints(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        info!(self.logger(), "Coloring PSBT...");
        let (runtime, override_set) =
            self.prepare_color_psbt_for_outpoints(psbt, &coloring_info, input_outpoints)?;
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

    fn validate_color_psbt_for_outpoints_inputs(
        &self,
        runtime: &RgbRuntime,
        psbt: &Psbt,
        override_set: &HashSet<OutPoint>,
        psbt_inputs: &HashSet<OutPoint>,
        coloring_info: &ColoringInfo,
    ) -> Result<(), Error> {
        let omitted: Vec<OutPoint> = psbt_inputs.difference(override_set).copied().collect();
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

    /// Color a PSBT for explicit input outpoints, build consignments and register a fallible
    /// batch transfer.
    ///
    /// `output_map` keys are **final** PSBT vouts (same as [`Self::color_psbt_for_outpoints`]).
    /// Same recovery model as [`Self::color_psbt_and_prepare_consume`]: the RGB stash is updated
    /// only by [`Self::consume_transfer_fascia`] after broadcast; use `fail_transfers` if the TX is
    /// dropped.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
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
            self.prepare_color_psbt_for_outpoints(psbt, &coloring_info, input_outpoints)?;
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
        runtime.persist()?;
        Ok(result)
    }

    fn psbt_ops_root(&self) -> PathBuf {
        self.wallet_dir().join(PSBT_OPS_DIR)
    }

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

    fn psbt_op_dir(&self, operation_id: &str) -> Result<PathBuf, Error> {
        Self::validate_psbt_op_id(operation_id)?;
        Ok(self.psbt_ops_root().join(operation_id))
    }

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

        let op_dir = self.psbt_op_dir(operation_id)?;
        let fascia_bytes = Self::psbt_op_require_file_hash(
            operation_id,
            "fascia",
            &op_dir.join(FASCIA_FILE),
            &meta.hashes.fascia,
        )?;
        let psbt_bytes = Self::psbt_op_require_file_hash(
            operation_id,
            "colored PSBT",
            &op_dir.join(PSBT_OP_COLORED_PSBT_FILE),
            &meta.hashes.colored_psbt,
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

    fn psbt_op_from_meta(&self, meta: &PsbtOpMeta) -> Result<PsbtOperation, Error> {
        let (psbt, _) = self.psbt_op_verify_committed_payloads(meta)?;
        let operation_dir = PathBuf::from(PSBT_OPS_DIR)
            .join(&meta.operation_id)
            .to_string_lossy()
            .into_owned();
        Ok(PsbtOperation {
            operation_id: meta.operation_id.clone(),
            colored_psbt: psbt.to_string(),
            operation_dir,
            status: meta.status,
            broadcast: meta.broadcast,
            txid: meta.txid.clone(),
        })
    }

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

    fn new_psbt_op_id() -> String {
        format!(
            "{:016x}{:016x}",
            rand::rng().random::<u64>(),
            rand::rng().random::<u64>()
        )
    }

    /// Color an HTLC (or other external) PSBT for explicit input outpoints, write file-backed
    /// payloads under `psbt_ops/{operation_id}/`, and persist SQL accounting for colored contracts.
    /// `expiration_timestamp` defaults to [`PSBT_OP_DEFAULT_EXPIRATION_SECS`] from now.
    ///
    /// `output_map` keys are **final** PSBT vouts (same as [`Self::color_psbt_for_outpoints`]).
    /// Foreign escrow outpoints are listed in `foreign_inputs.json` (audit log for integrators; the
    /// library only checks its hash) and are **not** inserted as wallet TXOs / Input colorings.
    /// Wallet-owned destinations in `output_map` still get Change/Send rows so
    /// `get_asset_balance` / `list_unspents` stay consistent after claim.
    /// RGB stash is unchanged until [`Self::psbt_op_apply`].
    ///
    /// Other files under the op dir (`colored.psbt`, `consignments/{sha256(asset_id)}/...`) are
    /// artifacts for the caller; later HTLC methods verify every payload against the hashes bound
    /// in `meta.json` and read back only the fascia and the colored PSBT.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn psbt_op_prepare(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
    ) -> Result<PsbtOpPrepareResult, Error> {
        info!(self.logger(), "Preparing HTLC color operation...");
        let expiration_timestamp =
            Some(expiration_timestamp.unwrap_or_else(|| {
                now().unix_timestamp() as u64 + PSBT_OP_DEFAULT_EXPIRATION_SECS
            }));
        let (runtime, override_set) =
            self.prepare_color_psbt_for_outpoints(psbt, &coloring_info, input_outpoints)?;
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
        let mut spent: HashMap<ContractId, HashMap<OutPoint, Vec<Assignment>>> = HashMap::new();

        for (contract_id, beneficiaries) in &asset_beneficiaries {
            let mut by_outpoint: HashMap<OutPoint, Vec<Assignment>> = HashMap::new();
            for (explicit_seal, opout_state_map) in
                runtime.contract_assignments_for(*contract_id, override_set.iter().copied())?
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

        let mut consignment_hashes = BTreeMap::new();
        for transfer in &transfers {
            let asset_id = transfer.contract_id().to_string();
            let path = psbt_op_consignment_path(&op_dir, &asset_id);
            if let Some(parent) = path.parent() {
                persist_durable_create_dir(parent)?;
            }
            let mut consignment_bytes = Vec::new();
            transfer.save(&mut consignment_bytes)?;
            persist_durable_replace(&path, &consignment_bytes)?;
            consignment_hashes.insert(asset_id, sha256_hex(&consignment_bytes));
        }

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

        let operation_dir = PathBuf::from(PSBT_OPS_DIR)
            .join(&operation_id)
            .to_string_lossy()
            .into_owned();
        info!(
            self.logger(),
            "HTLC prepare completed (operation_id={operation_id})"
        );
        Ok(PsbtOpPrepareResult {
            operation_id,
            colored_psbt: psbt.to_string(),
            operation_dir,
        })
    }

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
    /// Order: validate linked batch (if any) → `consume_fascia` → SQL status → `meta.json`.
    /// Reordering cannot make stock+SQL crash-atomic; a durable journal is a follow-up. This
    /// order at least fails closed before mutating the stash when the batch is not `Initiated`.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
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
        info!(self.logger(), "HTLC apply completed");
        Ok(())
    }

    /// Abort a prepared HTLC operation whose witness TX did not reach the network.
    ///
    /// After a broadcast attempt rollback is refused until the batch transfer expires; past that
    /// the indexer decides, as for [`TransferStatus::WaitingBroadcast`].
    ///
    /// Rolls back a linked Initiated batch via `fail_transfers` when present.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn psbt_op_abort(&mut self, online: Online, operation_id: &str) -> Result<(), Error> {
        info!(self.logger(), "Aborting HTLC operation {operation_id}...");
        self.check_online(online)?;
        let mut meta = self.psbt_op_read_meta(operation_id)?;
        let batch_transfer_idx = self.psbt_op_resolve_batch_idx(&meta)?;
        if meta.status == PsbtOperationStatus::Failed {
            if let Some(idx) = batch_transfer_idx {
                self.psbt_op_fail_batch_if_initiated(online, idx)?;
            }
            self.psbt_op_backup_after_coherent_failure()?;
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

    fn psbt_op_batch(&self, batch_transfer_idx: i32) -> Result<Option<DbBatchTransfer>, Error> {
        let txn = self.database().begin_transaction()?;
        Ok(txn
            .iter_batch_transfers()?
            .into_iter()
            .find(|b| b.idx == batch_transfer_idx))
    }

    fn psbt_op_batch_status(
        &self,
        batch_transfer_idx: i32,
    ) -> Result<Option<TransferStatus>, Error> {
        Ok(self.psbt_op_batch(batch_transfer_idx)?.map(|b| b.status))
    }

    fn psbt_op_batch_expired(&self, batch_transfer_idx: i32) -> Result<bool, Error> {
        let now = now().unix_timestamp();
        Ok(self
            .psbt_op_batch(batch_transfer_idx)?
            .and_then(|b| b.expiration)
            .is_some_and(|expiration| expiration < now))
    }

    /// Align operation metas with batches `fail_transfers` marked Failed.
    pub(crate) fn psbt_op_heal_failed(&self) -> Result<bool, Error> {
        let mut healed = false;
        for mut meta in self.psbt_op_scan()? {
            if meta.status != PsbtOperationStatus::Prepared {
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

    fn psbt_op_backup_after_coherent_failure(&self) -> Result<(), Error> {
        let txn = self.database().begin_transaction()?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        Ok(())
    }

    fn psbt_op_fail_linked_batch(
        &mut self,
        online: Online,
        batch_transfer_idx: i32,
    ) -> Result<(), Error> {
        let outcome = self.fail_transfers_commit(online, Some(batch_transfer_idx), false, true)?;
        if outcome.cannot_fail {
            return Err(Error::CannotFailBatchTransfer);
        }
        Ok(())
    }

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

    /// Read HTLC operation status; marks Settled when a linked batch has settled.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
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
                if meta.status == PsbtOperationStatus::Prepared
                    && batch.status == TransferStatus::Failed
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

    use bdk_wallet::bitcoin::{
        Sequence, TxIn, Witness, absolute::LockTime, psbt::raw::ProprietaryKey,
        transaction::Version,
    };

    fn sentinel_key() -> ProprietaryKey {
        ProprietaryKey {
            prefix: b"rgb-lib-test".to_vec(),
            subtype: 0x7A,
            key: vec![0x01],
        }
    }

    fn unsigned_tx(n_outputs: u64) -> BdkTransaction {
        BdkTransaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: (0..n_outputs)
                .map(|i| TxOut {
                    value: BdkAmount::from_sat(1000 + i),
                    script_pubkey: ScriptBuf::new(),
                })
                .collect(),
        }
    }

    fn stamped_psbt(n_outputs: u64) -> Psbt {
        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx(n_outputs)).unwrap();
        let key = sentinel_key();
        psbt.proprietary.insert(key.clone(), vec![0xff]);
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: BdkAmount::from_sat(5000),
            script_pubkey: ScriptBuf::new(),
        });
        for (i, output) in psbt.outputs.iter_mut().enumerate() {
            output.proprietary.insert(key.clone(), vec![i as u8]);
        }
        psbt
    }

    fn opreturn_txout() -> TxOut {
        TxOut {
            value: BdkAmount::ZERO,
            script_pubkey: ScriptBuf::new_op_return([]),
        }
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
        assert_eq!(hashes.fascia, sha256_hex(b"fascia"));
        assert_eq!(hashes.colored_psbt, sha256_hex(b"psbt"));
        assert_eq!(hashes.foreign_inputs, sha256_hex(b"foreign_inputs"));
        assert_eq!(hashes.txid, sha256_hex(b"txid-1"));
        assert_eq!(
            hashes.batch_transfer_idx,
            Some(psbt_op_batch_identity_hash(7))
        );
        assert_ne!(hashes.fascia, hashes.colored_psbt);
        assert_ne!(hashes.txid, psbt_op_batch_identity_hash(7));
    }

    #[test]
    fn psbt_has_input_signatures_detects_finalized_inputs() {
        let psbt = stamped_psbt(2);
        assert!(!psbt_has_input_signatures(&psbt));

        let mut with_witness = psbt.clone();
        with_witness.inputs[0].final_script_witness = Some(Witness::from_slice(&[vec![1u8]]));
        assert!(psbt_has_input_signatures(&with_witness));

        let mut with_script_sig = psbt;
        with_script_sig.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x51]));
        assert!(psbt_has_input_signatures(&with_script_sig));
    }

    #[test]
    fn rebuild_psbt_preserving_maps_front_insert_shifts_output_maps() {
        let psbt = stamped_psbt(2);
        let mut tx = psbt.unsigned_tx.clone();
        tx.output.insert(0, opreturn_txout());
        let rebuilt = rebuild_psbt_preserving_maps(&psbt, tx, true).unwrap();

        let key = sentinel_key();
        assert_eq!(rebuilt.unsigned_tx.output.len(), 3);
        assert!(rebuilt.unsigned_tx.output[0].script_pubkey.is_op_return());
        assert!(!rebuilt.outputs[0].proprietary.contains_key(&key));
        assert_eq!(rebuilt.outputs[1].proprietary.get(&key), Some(&vec![0]));
        assert_eq!(rebuilt.outputs[2].proprietary.get(&key), Some(&vec![1]));
        assert_eq!(rebuilt.inputs, psbt.inputs);
        assert_eq!(rebuilt.proprietary, psbt.proprietary);
        assert_eq!(rebuilt.version, psbt.version);
    }

    #[test]
    fn rebuild_psbt_preserving_maps_append_keeps_output_maps() {
        let psbt = stamped_psbt(2);
        let mut tx = psbt.unsigned_tx.clone();
        tx.output.push(opreturn_txout());
        let rebuilt = rebuild_psbt_preserving_maps(&psbt, tx, false).unwrap();

        let key = sentinel_key();
        assert_eq!(rebuilt.unsigned_tx.output.len(), 3);
        assert!(rebuilt.unsigned_tx.output[2].script_pubkey.is_op_return());
        assert_eq!(rebuilt.outputs[0].proprietary.get(&key), Some(&vec![0]));
        assert_eq!(rebuilt.outputs[1].proprietary.get(&key), Some(&vec![1]));
        assert!(!rebuilt.outputs[2].proprietary.contains_key(&key));
        assert_eq!(rebuilt.inputs, psbt.inputs);
    }

    #[test]
    fn rebuild_psbt_preserving_maps_clears_input_scripts() {
        let psbt = stamped_psbt(1);
        let mut tx = psbt.unsigned_tx.clone();
        tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
        tx.input[0].witness = Witness::from_slice(&[vec![1u8]]);
        tx.output.push(opreturn_txout());
        let rebuilt = rebuild_psbt_preserving_maps(&psbt, tx, false).unwrap();
        assert!(rebuilt.unsigned_tx.input[0].script_sig.is_empty());
        assert!(rebuilt.unsigned_tx.input[0].witness.is_empty());
    }

    #[test]
    fn durable_file_helpers_create_and_replace() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("rgb-lib-durable-{}-{nanos}", std::process::id()));
        let dir = root.join("transfers").join("txid");
        persist_durable_create_dir(&dir).unwrap();
        assert!(dir.is_dir());

        let path = dir.join(FASCIA_FILE);
        persist_durable_replace(&path, b"first").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");
        persist_durable_replace(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert!(!dir.join(format!("{FASCIA_FILE}.tmp")).exists());

        let marker = dir.join(STASH_CONSUMED_FILE);
        persist_stash_consumed_marker(&marker).unwrap();
        assert!(marker.exists());

        fs::remove_dir_all(&root).unwrap();
    }
}
