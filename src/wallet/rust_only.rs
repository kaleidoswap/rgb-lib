//! Rust-only functionality.
//!
//! This module defines additional utility methods that are not exposed via FFI.

use super::*;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use amplify::num::u5;
use bdk_wallet::bitcoin::psbt::Output as PsbtOutput;
use rgbstd::TransitionBundle;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use rgbstd::{
    containers::SealWitness,
    opret::OpretProof,
    rgbcore::commit_verify::mpc::{self, MPC_MINIMAL_DEPTH},
};

/// Marker left in the transfer dir once a prepared fascia has been consumed into the RGB stash,
/// until the related SQL update is committed.
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) const STASH_CONSUMED_FILE: &str = "stash_consumed";
/// Marker left in the transfer dir by the color-prepare flow, allowing
/// [`Wallet::consume_transfer_fascia`] on the related batch transfer.
#[cfg(any(feature = "electrum", feature = "esplora"))]
const COLOR_PREPARE_FILE: &str = "color_prepare";

/// Maximum depth of an MPC tree built from, or committed into, a PSBT.
///
/// The depth comes from a proprietary PSBT key (or from protocol ID collisions) that whoever built
/// the PSBT controls, and building a tree of depth `d` walks and allocates `2^d` leaves: unchecked,
/// depths of 28-31 exhaust CPU or memory, and values above 31 panic in [`u5::with`]. RGB starts
/// from [`MPC_MINIMAL_DEPTH`] (3) and only goes deeper to place protocol IDs without collisions,
/// so a few contracts take a depth of 3-6; 16 (65536 leaves) leaves ample room while keeping the
/// tree cheap to build.
const MAX_PSBT_MPC_TREE_DEPTH: u8 = 16;

/// Maximum number of MPC messages (one per RGB contract) in a PSBT's MPC tree.
///
/// This keeps placing them cheap and, being the birthday bound of a tree at
/// [`MAX_PSBT_MPC_TREE_DEPTH`], lets them fit within it.
const MAX_PSBT_MPC_MESSAGES: usize = 1 << (MAX_PSBT_MPC_TREE_DEPTH / 2);

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

#[cfg(all(test, any(feature = "electrum", feature = "esplora")))]
thread_local! {
    pub(crate) static MOCK_FAIL_AFTER_STASH_CONSUME: std::cell::RefCell<bool> =
        const { std::cell::RefCell::new(false) };
    pub(crate) static MOCK_FAIL_AFTER_STOCK_PERSIST: std::cell::RefCell<bool> =
        const { std::cell::RefCell::new(false) };
}

/// RGB asset-specific information to color a transaction
#[derive(Debug, Clone)]
pub struct AssetColoringInfo {
    /// Map of vouts and asset amounts to color the transaction outputs.
    ///
    /// Keys are pre-OP_RETURN indices, shifted by +1 when the PSBT has a P2TR output (see
    /// [`Wallet::color_psbt`]). Every coloring method rejects a key that does not resolve to an
    /// existing, non-OP_RETURN output with a witness-seal script (P2PKH, P2SH, P2WPKH, P2WSH or
    /// P2TR), naming the convention it expected.
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

/// Resolve an `output_map` key to the vout of the (already OP_RETURN-prepared) PSBT it seals,
/// failing unless that output exists, is not the OP_RETURN commitment host and can carry a
/// witness seal (P2PKH, P2SH, P2WPKH, P2WSH or P2TR, the scripts a witness recipient can name).
///
/// Keys are pre-OP_RETURN indices: on a P2TR PSBT, where the OP_RETURN is vout 0, they are
/// shifted by +1 (`shift_output_map_for_opreturn_first`). A final vout passed by mistake is off by
/// one, so errors name the convention the key was read with.
fn output_map_seal_vout(
    psbt: &Psbt,
    key: u32,
    shift_output_map_for_opreturn_first: bool,
) -> Result<u32, Error> {
    let outputs = &psbt.unsigned_tx.output;
    let vout = if shift_output_map_for_opreturn_first {
        key.checked_add(1)
            .ok_or_else(|| Error::InvalidColoringInfo {
                details: s!("vout in output_map is too large"),
            })?
    } else {
        key
    };
    let convention = if shift_output_map_for_opreturn_first {
        "keys are pre-OP_RETURN indices: this PSBT has a P2TR output, so the OP_RETURN is vout 0 \
         and every key is shifted by +1; do not pass final vouts"
    } else {
        "keys are final vout indices (without a P2TR output both index conventions coincide)"
    };
    let Some(txout) = outputs.get(vout as usize) else {
        return Err(Error::InvalidColoringInfo {
            details: format!(
                "invalid vout in output_map, does not exist in the given PSBT: key {key} seals \
                 vout {vout} of {}; {convention}",
                outputs.len()
            ),
        });
    };
    if txout.script_pubkey.is_op_return() {
        return Err(Error::InvalidColoringInfo {
            details: format!(
                "output_map vout {vout} points to the OP_RETURN output (key {key}); {convention}"
            ),
        });
    }
    if AddressPayload::from_script(&txout.script_pubkey).is_err() {
        return Err(Error::InvalidColoringInfo {
            details: format!(
                "output_map vout {vout} script cannot carry an RGB witness seal (not P2PKH, P2SH, \
                 P2WPKH, P2WSH or P2TR) (key {key}); {convention}"
            ),
        });
    }
    Ok(vout)
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
    ///
    /// Each (shifted) key must resolve to an existing output that is not the OP_RETURN and has a
    /// witness-seal script (P2PKH, P2SH, P2WPKH, P2WSH or P2TR), otherwise
    /// [`Error::InvalidColoringInfo`] names the expected convention. These checks catch a final
    /// vout passed by mistake only when the shift lands on the end of the PSBT or on an output that
    /// cannot carry a seal; shifting onto another valid output cannot be told apart from a correct
    /// key.
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
    ///
    /// This is [`Self::color_psbt_stage_runtime`] followed by [`Self::color_psbt_finalize`] with
    /// the `coloring_info` static blinding as MPC entropy.
    pub(crate) fn color_psbt_with_prevouts_runtime(
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

    /// Build the RGB transitions for `coloring_info`, spending the allocations found on
    /// `prev_outputs`, and push them into the PSBT without committing them.
    ///
    /// Same preconditions and checks as [`Self::color_psbt_with_prevouts_runtime`]. The PSBT stays
    /// modifiable: further contracts can be staged on it (e.g. by a counterparty) before
    /// [`Self::color_psbt_finalize`] commits all of them at once.
    pub(crate) fn color_psbt_stage_runtime(
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
            for (key, amount) in BTreeMap::from_iter(asset_coloring_info.output_map) {
                if amount == 0 {
                    continue;
                }
                sending_amt =
                    sending_amt
                        .checked_add(amount)
                        .ok_or_else(|| Error::InvalidColoringInfo {
                            details: s!("total amount in output_map exceeds u64::MAX"),
                        })?;
                let vout = output_map_seal_vout(psbt, key, shift_output_map_for_opreturn_first)?;
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

    /// Stage RGB coloring information onto a PSBT without finalizing the MPC commitment.
    ///
    /// Multiple parties may each call this method on the same PSBT (each for their own contracts),
    /// in which case [`Self::color_psbt_finalize`] must be invoked once after all staging is
    /// complete to produce the [`Fascia`]. `output_map` indexing (pre-OP_RETURN), its checks and
    /// the signed-PSBT rejection follow [`Self::color_psbt`].
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

    /// Finalize the RGB commitment on a PSBT that has had one or more contracts staged via
    /// [`Self::color_psbt_stage`]: the first OP_RETURN output becomes the opret host (with
    /// `static_blinding` as MPC entropy, if given) and the PSBT is made unmodifiable. Must be
    /// called exactly once per PSBT, after all staging is complete.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn color_psbt_finalize(
        &self,
        psbt: &mut Psbt,
        static_blinding: Option<u64>,
    ) -> Result<Fascia, Error> {
        info!(self.logger(), "Finalizing RGB commitment on PSBT...");
        let fascia = commit_staged_psbt(psbt, static_blinding)?;
        info!(self.logger(), "Finalize RGB commitment completed");
        Ok(fascia)
    }

    /// Produce an [`RgbTransfer`] consignment for a single contract given its beneficiaries
    /// (typically obtained from a prior [`Self::color_psbt_stage`] call) and the witness
    /// transaction ID of the PSBT being colored, built from the colored PSBT's `fascia` without
    /// consuming it into the RGB stash.
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
                    beneficiaries_witness.push(ExplicitSeal::with(witness_txid, seal.vout));
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
    /// `output_map` indexing (pre-OP_RETURN, legacy P2TR / `OpretFirst` +1 shift) and its checks
    /// follow [`Self::color_psbt`]. Every allocation found on the PSBT inputs must be re-assigned: each contract with
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

    /// Stage coloring spending only `prev_outputs`, requiring every allocation they carry to be
    /// reassigned (no implicit burn): inputs carrying contracts absent from `coloring_info` or
    /// non-asset rights are rejected, as is an `output_map` that does not re-assign the full input
    /// amount of each contract.
    pub(crate) fn color_psbt_stage_for_inputs(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        prev_outputs: HashSet<OutPoint>,
    ) -> Result<AssetBeneficiariesMap, Error> {
        let runtime = self.rgb_runtime()?;
        // checked before `prepare_psbt_for_coloring`, which would otherwise insert an OP_RETURN
        // into the caller's PSBT on the way to failing
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

    /// Reconstruct an RGB fascia from a PSBT whose RGB commitment has already been finalized
    /// (e.g. by a counterparty, with [`Self::color_psbt_finalize`]).
    pub(crate) fn fascia_from_finalized_psbt(&self, psbt: &Psbt) -> Result<Fascia, Error> {
        fascia_from_committed_psbt(psbt)
    }

    /// Record a colored PSBT as a [`TransferStatus::Initiated`] outgoing batch inside `txn`
    /// without touching the RGB stash, writing the color-prepare recovery files first. The fascia
    /// is applied later by [`Self::consume_transfer_fascia`], once the TX is known.
    #[allow(clippy::too_many_arguments)]
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
        let mut spent: HashMap<ContractId, HashMap<OutPoint, Vec<Assignment>>> = HashMap::new();
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
                for (key, amount) in BTreeMap::from_iter(asset_coloring.output_map.clone()) {
                    if amount == 0 {
                        continue;
                    }
                    let vout =
                        output_map_seal_vout(psbt, key, shift_output_map_for_opreturn_first)?;
                    let txout = &psbt.unsigned_tx.output[vout as usize];
                    let address_payload = AddressPayload::from_script(&txout.script_pubkey)
                        .expect("checked by output_map_seal_vout");
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

/// Read the MPC minimum tree depth an untrusted PSBT output carries, within the allowed bounds.
fn psbt_mpc_min_depth(output: &PsbtOutput) -> Result<u5, Error> {
    let Some(depth) = output.mpc_min_tree_depth() else {
        return Ok(MPC_MINIMAL_DEPTH);
    };
    u5::try_from(depth)
        .ok()
        .filter(|d| d.to_u8() <= MAX_PSBT_MPC_TREE_DEPTH)
        .ok_or_else(|| Error::InvalidColoringInfo {
            details: format!(
                "PSBT MPC tree depth {depth} exceeds the maximum of {MAX_PSBT_MPC_TREE_DEPTH}"
            ),
        })
}

/// Build an MPC tree from untrusted PSBT data, refusing any tree too large to build cheaply.
///
/// The returned tree has not been walked yet: computing its commitment or block is bounded too.
fn bounded_mpc_tree(
    min_depth: u5,
    messages: mpc::MessageMap,
    static_entropy: Option<u64>,
) -> Result<mpc::MerkleTree, Error> {
    if messages.len() > MAX_PSBT_MPC_MESSAGES {
        return Err(Error::InvalidColoringInfo {
            details: format!(
                "PSBT has {} MPC messages, more than the maximum of {MAX_PSBT_MPC_MESSAGES}",
                messages.len()
            ),
        });
    }
    let source = mpc::MultiSource {
        min_depth,
        messages,
        static_entropy,
    };
    let merkle_tree =
        mpc::MerkleTree::try_commit(&source).map_err(|e| Error::InvalidColoringInfo {
            details: format!("failed to build RGB MPC tree: {e}"),
        })?;
    // placing the messages may have needed a deeper tree than the minimum
    let depth = merkle_tree.depth().to_u8();
    if depth > MAX_PSBT_MPC_TREE_DEPTH {
        return Err(Error::InvalidColoringInfo {
            details: format!(
                "PSBT MPC tree depth {depth} exceeds the maximum of {MAX_PSBT_MPC_TREE_DEPTH}"
            ),
        });
    }
    Ok(merkle_tree)
}

/// Check that `messages` commit every bundle, under its contract, by its bundle ID.
///
/// The bundles and the MPC messages are separate PSBT keys: without this, whoever finalizes a
/// PSBT can commit another bundle for a contract (e.g. one sending its inputs to them) while the
/// PSBT still shows the expected one.
fn check_bundles_committed<'a>(
    bundles: impl IntoIterator<Item = (&'a ContractId, &'a TransitionBundle)>,
    messages: &mpc::MessageMap,
) -> Result<(), Error> {
    for (contract_id, bundle) in bundles {
        if messages.get(&ProtocolId::from(*contract_id)) != Some(&Message::from(bundle.bundle_id()))
        {
            return Err(Error::InvalidColoringInfo {
                details: format!("PSBT MPC commitment does not commit the bundle of {contract_id}"),
            });
        }
    }
    Ok(())
}

/// Check that `rgb_commit` will build a bounded MPC tree for `psbt`, before it builds it unchecked.
///
/// `rgb_commit` writes the MPC messages to the first opret host and commits the first OP_RETURN
/// output's tree, so this replays that on the PSBT as staged, possibly by a counterparty.
fn check_psbt_mpc_commit_bounds(psbt: &Psbt, commit_idx: usize) -> Result<(), Error> {
    // only the committed output's key is read, but a stager has no reason to set one elsewhere
    for output in &psbt.outputs {
        psbt_mpc_min_depth(output)?;
    }
    // a close method set while staging is kept by `set_rgb_close_method` and picks the output
    if psbt.rgb_close_method().map_err(InternalError::from)? != Some(CloseMethod::OpretFirst) {
        return Err(Error::InvalidColoringInfo {
            details: s!("PSBT RGB close method must be opret"),
        });
    }
    let output = &psbt.outputs[commit_idx];
    let mut messages = output
        .mpc_message_map()
        .map_err(InternalError::from)?
        .release();
    if psbt.outputs.iter().position(|o| o.is_opret_host()) == Some(commit_idx) {
        let bundles = psbt.rgb_bundles().map_err(InternalError::from)?;
        for (contract_id, bundle) in bundles {
            messages.insert(
                ProtocolId::from(contract_id),
                Message::from(bundle.bundle_id()),
            );
        }
    }
    let messages = Confined::try_from(messages).map_err(|_| Error::InvalidColoringInfo {
        details: s!("PSBT has too many MPC messages"),
    })?;
    bounded_mpc_tree(psbt_mpc_min_depth(output)?, messages, output.mpc_entropy())?;
    Ok(())
}

/// Commit the RGB transitions staged on `psbt` in its first OP_RETURN output.
fn commit_staged_psbt(psbt: &mut Psbt, static_blinding: Option<u64>) -> Result<Fascia, Error> {
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
    check_psbt_mpc_commit_bounds(psbt, opreturn_index)?;
    let fascia = psbt.rgb_commit().map_err(InternalError::from)?;
    // the fascia's merkle block is built from the committed output's messages, so check these
    // carry every bundle: staging may have sent them to another output flagged as opret host
    let messages = psbt.outputs[opreturn_index]
        .mpc_message_map()
        .map_err(InternalError::from)?;
    check_bundles_committed(fascia.bundles().iter(), &messages)?;
    Ok(fascia)
}

/// Rebuild the fascia of a PSBT whose RGB commitment was finalized, possibly by a counterparty.
fn fascia_from_committed_psbt(psbt: &Psbt) -> Result<Fascia, Error> {
    let bundles = psbt.rgb_bundles().map_err(InternalError::from)?;
    // `rgb_commit` commits the MPC messages in the first OP_RETURN, which need not be vout 0.
    // Its opret host flag is removed on commit, and any other output has an empty (not
    // missing) message map, so look the output up by its script and check its commitment.
    let opret_idx = psbt
        .unsigned_tx
        .output
        .iter()
        .position(|o| o.script_pubkey.is_op_return())
        .ok_or_else(|| Error::InvalidColoringInfo {
            details: s!("PSBT has no OP_RETURN output hosting the RGB commitment"),
        })?;
    let output = psbt
        .outputs
        .get(opret_idx)
        .ok_or_else(|| Error::InvalidColoringInfo {
            details: s!("PSBT has no map for its OP_RETURN output"),
        })?;
    let messages = output.mpc_message_map().map_err(InternalError::from)?;
    if messages.is_empty() {
        return Err(Error::InvalidColoringInfo {
            details: s!("PSBT OP_RETURN output carries no RGB MPC messages"),
        });
    }
    check_bundles_committed(&bundles, &messages)?;
    let merkle_tree =
        bounded_mpc_tree(psbt_mpc_min_depth(output)?, messages, output.mpc_entropy())?;
    let expected_script = ScriptBuf::new_op_return(merkle_tree.commit_id().to_byte_array());
    if psbt.unsigned_tx.output[opret_idx].script_pubkey != expected_script {
        return Err(Error::InvalidColoringInfo {
            details: s!("PSBT OP_RETURN output does not carry its RGB MPC commitment"),
        });
    }
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

#[cfg(test)]
#[cfg(any(feature = "electrum", feature = "esplora"))]
mod tests {
    use super::*;
    use psrgbt::RgbPropKeyExt;

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

    /// A PSBT with an empty OP_RETURN host at vout 0 and one staged (placeholder) RGB transition.
    fn staged_psbt() -> Psbt {
        let tx = BdkTransaction {
            version: bdk_wallet::bitcoin::transaction::Version::TWO,
            lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
            input: vec![bdk_wallet::bitcoin::TxIn::default()],
            output: vec![
                TxOut {
                    value: BdkAmount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return([]),
                },
                TxOut {
                    value: BdkAmount::from_sat(1_000),
                    script_pubkey: ScriptBuf::new(),
                },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.push_rgb_transition(Transition::strict_dumb()).unwrap();
        psbt
    }

    /// Plant the MPC minimum tree depth key, as a counterparty controlling the PSBT can.
    fn set_mpc_min_depth(psbt: &mut Psbt, vout: usize, depth: u8) {
        psbt.outputs[vout]
            .proprietary
            .insert(ProprietaryKey::mpc_min_tree_depth(), vec![depth]);
    }

    /// A PSBT committed by an honest finalizer, whose depth key is then rewritten.
    fn committed_psbt_with_depth(depth: u8) -> Psbt {
        let mut psbt = staged_psbt();
        commit_staged_psbt(&mut psbt, Some(7)).unwrap();
        set_mpc_min_depth(&mut psbt, 0, depth);
        psbt
    }

    #[track_caller]
    fn assert_rejected<T>(result: Result<T, Error>, expected: &str) {
        match result {
            Err(Error::InvalidColoringInfo { details }) => {
                assert!(details.contains(expected), "unexpected error: {details}")
            }
            Err(e) => panic!("expected an error containing {expected:?}, got {e:?}"),
            Ok(_) => panic!("expected an error containing {expected:?}, got Ok"),
        }
    }

    #[test]
    fn fascia_rebuild_rejects_invalid_mpc_depth() {
        for depth in [32, 255] {
            let psbt = committed_psbt_with_depth(depth);
            assert_rejected(fascia_from_committed_psbt(&psbt), "MPC tree depth");
        }
    }

    #[test]
    fn fascia_rebuild_rejects_over_cap_mpc_depth() {
        // 31 would make the tree 2^31 leaves wide: this must fail fast instead of exhausting memory
        for depth in [MAX_PSBT_MPC_TREE_DEPTH + 1, 31] {
            let psbt = committed_psbt_with_depth(depth);
            assert_rejected(fascia_from_committed_psbt(&psbt), "MPC tree depth");
        }
    }

    #[test]
    fn commit_rejects_invalid_mpc_depth() {
        // the key is checked on every output, since the stager also controls the host flags
        for (vout, depth) in [(0, 32), (0, 255), (1, 32), (1, 255)] {
            let mut psbt = staged_psbt();
            set_mpc_min_depth(&mut psbt, vout, depth);
            assert_rejected(commit_staged_psbt(&mut psbt, Some(7)), "MPC tree depth");
        }
    }

    #[test]
    fn commit_rejects_over_cap_mpc_depth() {
        for depth in [MAX_PSBT_MPC_TREE_DEPTH + 1, 31] {
            let mut psbt = staged_psbt();
            set_mpc_min_depth(&mut psbt, 0, depth);
            assert_rejected(commit_staged_psbt(&mut psbt, Some(7)), "MPC tree depth");
        }
    }

    #[test]
    fn commit_rejects_too_many_mpc_messages() {
        let mut psbt = staged_psbt();
        for i in 0..MAX_PSBT_MPC_MESSAGES as u16 {
            let mut protocol_id = [0xffu8; 32];
            protocol_id[..2].copy_from_slice(&i.to_le_bytes());
            psbt.outputs[0]
                .set_mpc_message(
                    ProtocolId::copy_from_slice(&protocol_id).unwrap(),
                    Message::copy_from_slice(&[0u8; 32]).unwrap(),
                )
                .unwrap();
        }
        // with the staged transition's own message there is one too many
        assert_rejected(commit_staged_psbt(&mut psbt, Some(7)), "MPC messages");
    }

    #[test]
    fn commit_rejects_staged_close_method() {
        let mut psbt = staged_psbt();
        psbt.set_rgb_close_method(CloseMethod::TapretFirst);
        assert_rejected(commit_staged_psbt(&mut psbt, Some(7)), "close method");
    }

    #[test]
    fn fascia_rebuild_rejects_uncommitted_bundle() {
        let mut psbt = staged_psbt();
        let fascia = commit_staged_psbt(&mut psbt, Some(7)).unwrap();
        let contract_id = *fascia.bundles().keys().next().unwrap();
        let protocol_id = ProtocolId::from(contract_id);
        // commit another bundle ID for the contract, e.g. one moving its inputs to the attacker
        psbt.outputs[0]
            .proprietary
            .insert(ProprietaryKey::mpc_message(protocol_id), vec![0x42u8; 32]);
        let output = &psbt.outputs[0];
        let tree = bounded_mpc_tree(
            MPC_MINIMAL_DEPTH,
            output.mpc_message_map().unwrap(),
            output.mpc_entropy(),
        )
        .unwrap();
        psbt.unsigned_tx.output[0].script_pubkey =
            ScriptBuf::new_op_return(tree.commit_id().to_byte_array());
        assert_rejected(fascia_from_committed_psbt(&psbt), "does not commit");

        // without any message for the contract
        psbt.outputs[0]
            .proprietary
            .remove(&ProprietaryKey::mpc_message(protocol_id));
        let other_protocol_id = ProtocolId::copy_from_slice(&[0x11u8; 32]).unwrap();
        psbt.outputs[0].proprietary.insert(
            ProprietaryKey::mpc_message(other_protocol_id),
            vec![0x42u8; 32],
        );
        let output = &psbt.outputs[0];
        let tree = bounded_mpc_tree(
            MPC_MINIMAL_DEPTH,
            output.mpc_message_map().unwrap(),
            output.mpc_entropy(),
        )
        .unwrap();
        psbt.unsigned_tx.output[0].script_pubkey =
            ScriptBuf::new_op_return(tree.commit_id().to_byte_array());
        assert_rejected(fascia_from_committed_psbt(&psbt), "does not commit");
    }

    #[test]
    fn commit_rejects_bundles_left_off_the_commitment() {
        // the OP_RETURN is not the first output, and staging flagged an earlier one as opret
        // host: the bundles' messages would go there while the OP_RETURN commits none of them
        let mut psbt = staged_psbt();
        psbt.unsigned_tx.output.swap(0, 1);
        psbt.outputs[0].set_opret_host();
        assert_rejected(commit_staged_psbt(&mut psbt, Some(7)), "does not commit");
    }

    #[test]
    fn max_mpc_depth_commits_and_rebuilds() {
        let mut psbt = staged_psbt();
        set_mpc_min_depth(&mut psbt, 0, MAX_PSBT_MPC_TREE_DEPTH);
        let fascia = commit_staged_psbt(&mut psbt, Some(7)).unwrap();
        assert_eq!(
            fascia.seal_witness().merkle_block.width_limit(),
            1 << MAX_PSBT_MPC_TREE_DEPTH
        );
        let received = Psbt::from_str(&psbt.to_string()).unwrap();
        assert_eq!(fascia_from_committed_psbt(&received).unwrap(), fascia);
    }
}
