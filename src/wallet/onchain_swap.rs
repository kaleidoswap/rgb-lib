//! On-chain maker/taker swap APIs.
//!
//! This module keeps the RGB/PSBT internals behind wallet-level swap messages.

use super::*;

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use bdk_wallet::{
    KeychainKind, LocalOutput, SignOptions,
    bitcoin::{
        Amount as BdkAmount, OutPoint as BdkOutPoint, ScriptBuf, Sequence,
        Transaction as BitcoinTransaction, TxIn, TxOut, Witness, absolute::LockTime, psbt::Psbt,
        transaction::Version,
    },
};
use rand::distr::Alphanumeric;

use crate::utils::{hash_bytes_hex, now, parse_address_str, recipient_id_from_script_buf};

const DEFAULT_RGB_OUTPUT_SAT: u64 = 1_000;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum SwapDirection {
    RgbForBtc,
    BtcForRgb,
    RgbForRgb,
}

fn invalid_swap(details: impl Into<String>) -> Error {
    Error::InvalidDetails {
        details: details.into(),
    }
}

fn random_swap_id() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn random_blinding() -> u64 {
    rand::random::<u64>().max(1)
}

/// Derive a deterministic MPC entropy for a swap from its identifier. Both parties compute the
/// same value so the MPC commitment they each (re)produce is identical.
fn mpc_entropy_for_swap(swap_id: &str) -> u64 {
    let hash = hash_bytes_hex(swap_id.as_bytes());
    let mut bytes = [0u8; 8];
    let src = hash.as_bytes();
    let take = src.len().min(16);
    let hex_slice = &hash[..take];
    if let Ok(parsed) = u64::from_str_radix(hex_slice, 16) {
        return parsed.max(1);
    }
    bytes.copy_from_slice(&src[..8]);
    u64::from_be_bytes(bytes).max(1)
}

fn ensure_offer_not_expired(offer: &OnchainSwapOffer) -> Result<(), Error> {
    if let Some(expiration_timestamp) = offer.expiration_timestamp {
        let current_timestamp = u64::try_from(now().unix_timestamp()).unwrap_or_default();
        if expiration_timestamp <= current_timestamp {
            return Err(invalid_swap("swap offer expired"));
        }
    }
    Ok(())
}

fn validate_leg(leg: &OnchainSwapLeg) -> Result<(), Error> {
    if leg.amount == 0 {
        return Err(Error::InvalidAmountZero);
    }
    match leg.kind {
        OnchainSwapLegKind::Btc => {
            if leg.asset_id.is_some() {
                return Err(invalid_swap("BTC swap legs must not include an asset ID"));
            }
        }
        OnchainSwapLegKind::Rgb => {
            let asset_id = leg
                .asset_id
                .as_ref()
                .ok_or_else(|| invalid_swap("RGB swap legs require an asset ID"))?;
            ContractId::from_str(asset_id)
                .map_err(|e| invalid_swap(format!("invalid RGB asset ID: {e}")))?;
        }
    }
    Ok(())
}

fn validate_legs(
    gives: &OnchainSwapLeg,
    receives: &OnchainSwapLeg,
) -> Result<SwapDirection, Error> {
    validate_leg(gives)?;
    validate_leg(receives)?;
    if gives == receives {
        return Err(invalid_swap("swap legs cannot be identical"));
    }
    if matches!(gives.kind, OnchainSwapLegKind::Btc)
        && matches!(receives.kind, OnchainSwapLegKind::Btc)
    {
        return Err(invalid_swap("BTC-for-BTC swaps are not supported"));
    }
    if matches!(gives.kind, OnchainSwapLegKind::Rgb)
        && matches!(receives.kind, OnchainSwapLegKind::Rgb)
        && gives.asset_id == receives.asset_id
    {
        return Err(invalid_swap(
            "RGB-for-RGB swaps require different asset IDs",
        ));
    }
    Ok(match (gives.kind, receives.kind) {
        (OnchainSwapLegKind::Rgb, OnchainSwapLegKind::Btc) => SwapDirection::RgbForBtc,
        (OnchainSwapLegKind::Btc, OnchainSwapLegKind::Rgb) => SwapDirection::BtcForRgb,
        (OnchainSwapLegKind::Rgb, OnchainSwapLegKind::Rgb) => SwapDirection::RgbForRgb,
        (OnchainSwapLegKind::Btc, OnchainSwapLegKind::Btc) => unreachable!("BTC-for-BTC rejected"),
    })
}

fn parse_script(script_hex: &str) -> Result<ScriptBuf, Error> {
    ScriptBuf::from_hex(script_hex).map_err(|e| invalid_swap(format!("invalid script: {e}")))
}

fn swap_input_to_outpoint(input: &OnchainSwapInput) -> BdkOutPoint {
    BdkOutPoint::from(input.outpoint.clone())
}

fn input_txout(input: &OnchainSwapInput) -> Result<TxOut, Error> {
    Ok(TxOut {
        value: BdkAmount::from_sat(input.amount_sat),
        script_pubkey: parse_script(&input.script_pubkey_hex)?,
    })
}

fn build_swap_input(local_output: &LocalOutput) -> OnchainSwapInput {
    OnchainSwapInput {
        outpoint: local_output.outpoint.into(),
        amount_sat: local_output.txout.value.to_sat(),
        script_pubkey_hex: local_output.txout.script_pubkey.to_hex_string(),
    }
}

fn selected_inputs_total(inputs: &[OnchainSwapInput]) -> u64 {
    inputs.iter().map(|i| i.amount_sat).sum()
}

fn require_rgb_destination(
    leg: &OnchainSwapLeg,
    script_hex: &Option<String>,
    blinding: &Option<u64>,
) -> Result<(), Error> {
    if matches!(leg.kind, OnchainSwapLegKind::Rgb) && (script_hex.is_none() || blinding.is_none()) {
        return Err(invalid_swap("missing RGB receive data"));
    }
    Ok(())
}

fn consignment_dir(wallet: &Wallet, swap_id: &str) -> PathBuf {
    wallet.get_transfers_dir().join(format!("swap-{swap_id}"))
}

fn consignment_path(base_dir: &Path, asset_id: &str) -> PathBuf {
    let sanitized = asset_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let asset_id_hash = hash_bytes_hex(asset_id.as_bytes());
    base_dir.join(format!(
        "consignment-{sanitized}-{}.rgb",
        &asset_id_hash[..16]
    ))
}

fn proxy_transport_endpoint(proxy_url: &str) -> Result<String, Error> {
    if let Some(rest) = proxy_url.strip_prefix("http://") {
        Ok(format!("rpc://{rest}"))
    } else if let Some(rest) = proxy_url.strip_prefix("https://") {
        Ok(format!("rpcs://{rest}"))
    } else {
        RgbTransport::from_str(proxy_url)?;
        Ok(proxy_url.to_string())
    }
}

fn rgb_leg_coloring_info(
    leg: &OnchainSwapLeg,
    psbt: &Psbt,
    recipient_vout: u32,
    blinding: u64,
) -> Result<(ContractId, rust_only::ColoringInfo), Error> {
    let asset_id = leg.asset_id.clone().expect("RGB leg has asset ID");
    let contract_id = ContractId::from_str(&asset_id)
        .map_err(|e| invalid_swap(format!("invalid RGB asset ID: {e}")))?;
    let coloring_vout = if psbt
        .unsigned_tx
        .output
        .first()
        .is_some_and(|o| o.script_pubkey.is_op_return())
        && psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr())
    {
        recipient_vout
            .checked_sub(1)
            .ok_or_else(|| invalid_swap("invalid RGB recipient vout"))?
    } else {
        recipient_vout
    };
    let output_map = HashMap::from_iter([(coloring_vout, leg.amount)]);
    let coloring_info = rust_only::ColoringInfo {
        asset_info_map: HashMap::from_iter([(
            contract_id,
            rust_only::AssetColoringInfo {
                output_map,
                static_blinding: Some(blinding),
            },
        )]),
        static_blinding: Some(blinding),
        nonce: None,
    };
    Ok((contract_id, coloring_info))
}

/// Monolithic single-leg coloring. Used for RGB<->BTC swaps where only one party stages, finalizes,
/// consumes and emits the consignment in one go.
fn color_rgb_leg(
    txn: &DbTxn,
    wallet: &Wallet,
    psbt: &mut Psbt,
    leg: &OnchainSwapLeg,
    recipient_id: &str,
    recipient_vout: u32,
    blinding: u64,
    proxy_url: Option<&str>,
    swap_id: &str,
) -> Result<Vec<OnchainSwapConsignment>, Error> {
    if !matches!(leg.kind, OnchainSwapLegKind::Rgb) {
        return Ok(vec![]);
    }
    let asset_id = leg.asset_id.clone().expect("RGB leg has asset ID");
    let (_contract_id, coloring_info) = rgb_leg_coloring_info(leg, psbt, recipient_vout, blinding)?;
    let transfers = wallet.color_psbt_and_consume(psbt, coloring_info)?;
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    record_outgoing_rgb_swap(txn, &asset_id, &txid, psbt)?;
    emit_swap_consignments(
        wallet,
        transfers,
        proxy_url,
        swap_id,
        &txid,
        recipient_id,
        recipient_vout,
        blinding,
    )
}

/// Stage a single RGB leg onto the PSBT without finalizing the RGB commitment. Returns the
/// beneficiaries (a singleton map keyed by contract id) that the staging party keeps to later
/// generate their consignment.
fn stage_rgb_leg(
    wallet: &Wallet,
    psbt: &mut Psbt,
    leg: &OnchainSwapLeg,
    recipient_vout: u32,
    blinding: u64,
) -> Result<rust_only::AssetBeneficiariesMap, Error> {
    let (_contract_id, coloring_info) = rgb_leg_coloring_info(leg, psbt, recipient_vout, blinding)?;
    wallet.color_psbt_stage(psbt, coloring_info)
}

/// After finalize+consume, generate the consignment for a single-contract RGB leg and persist it
/// to disk plus optionally post it to the proxy server. Returns the resulting
/// [`OnchainSwapConsignment`] DTO(s).
fn emit_swap_consignments(
    wallet: &Wallet,
    transfers: Vec<RgbTransfer>,
    proxy_url: Option<&str>,
    swap_id: &str,
    txid: &str,
    recipient_id: &str,
    recipient_vout: u32,
    blinding: u64,
) -> Result<Vec<OnchainSwapConsignment>, Error> {
    let base_dir = consignment_dir(wallet, swap_id);
    fs::create_dir_all(&base_dir)?;
    let endpoint = proxy_url.map(proxy_transport_endpoint).transpose()?;

    let mut consignments = vec![];
    for transfer in transfers {
        let transfer_asset_id = transfer.contract_id().to_string();
        let schema_id = transfer.schema_id().to_string();
        let path = consignment_path(&base_dir, &transfer_asset_id);
        transfer.save_file(&path)?;
        if let Some(proxy_url) = proxy_url {
            wallet.post_consignment(
                proxy_url,
                recipient_id.to_string(),
                path.clone(),
                txid.to_string(),
                Some(recipient_vout),
            )?;
        }
        consignments.push(OnchainSwapConsignment {
            asset_id: transfer_asset_id,
            schema_id,
            path: path.to_string_lossy().to_string(),
            endpoint: endpoint.clone(),
            txid: txid.to_string(),
            vout: recipient_vout,
            blinding,
            recipient_id: recipient_id.to_string(),
        });
    }
    Ok(consignments)
}

fn record_outgoing_rgb_swap(
    txn: &DbTxn,
    asset_id: &str,
    txid: &str,
    psbt: &Psbt,
) -> Result<(), Error> {
    let db_data = txn.get_db_data(false)?;
    let input_outpoints = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|input| input.previous_output)
        .collect::<HashSet<_>>();

    let batch_transfer = DbBatchTransferActMod {
        txid: ActiveValue::Set(Some(txid.to_string())),
        status: ActiveValue::Set(TransferStatus::WaitingConfirmations),
        expiration: ActiveValue::Set(None),
        created_at: ActiveValue::Set(now().unix_timestamp()),
        min_confirmations: ActiveValue::Set(1),
        ..Default::default()
    };
    let batch_transfer_idx = txn.set_batch_transfer(batch_transfer)?;
    let asset_transfer = DbAssetTransferActMod {
        user_driven: ActiveValue::Set(true),
        batch_transfer_idx: ActiveValue::Set(batch_transfer_idx),
        asset_id: ActiveValue::Set(Some(asset_id.to_string())),
        ..Default::default()
    };
    let asset_transfer_idx = txn.set_asset_transfer(asset_transfer)?;

    for txo in db_data
        .txos
        .iter()
        .filter(|txo| input_outpoints.contains(&BdkOutPoint::from((*txo).clone())))
    {
        for coloring in db_data.colorings.iter().filter(|coloring| {
            coloring.txo_idx == txo.idx
                && coloring.incoming()
                && db_data.asset_transfers.iter().any(|asset_transfer| {
                    asset_transfer.idx == coloring.asset_transfer_idx
                        && asset_transfer.asset_id.as_deref() == Some(asset_id)
                })
                && db_data.batch_transfers.iter().any(|batch_transfer| {
                    db_data.asset_transfers.iter().any(|asset_transfer| {
                        asset_transfer.idx == coloring.asset_transfer_idx
                            && asset_transfer.batch_transfer_idx == batch_transfer.idx
                    }) && !batch_transfer.status.failed()
                })
        }) {
            let db_coloring = DbColoringActMod {
                txo_idx: ActiveValue::Set(txo.idx),
                asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                r#type: ActiveValue::Set(ColoringType::Input),
                assignment: ActiveValue::Set(coloring.assignment.clone()),
                ..Default::default()
            };
            txn.set_coloring(db_coloring)?;
        }
    }

    Ok(())
}

fn restore_input_metadata(psbt: &mut Psbt, inputs: &[OnchainSwapInput]) -> Result<(), Error> {
    for (idx, input) in inputs.iter().enumerate() {
        let psbt_input = psbt
            .inputs
            .get_mut(idx)
            .ok_or_else(|| invalid_swap("PSBT input metadata mismatch"))?;
        psbt_input.witness_utxo = Some(input_txout(input)?);
    }
    Ok(())
}

fn sign_swap_psbt(wallet: &Wallet, psbt: &mut Psbt) -> Result<(), Error> {
    let sign_options = SignOptions {
        trust_witness_utxo: true,
        ..Default::default()
    };
    wallet.sign_psbt_impl(psbt, Some(sign_options))
}

fn finalize_swap_psbt(wallet: &Wallet, psbt: &Psbt) -> Result<Option<String>, Error> {
    wallet
        .finalize_psbt(psbt.to_string(), Some(SignOptions::default()))
        .map(Some)
        .or(Ok(None))
}

fn validate_proposal_psbt(proposal: &OnchainSwapProposal, psbt: &Psbt) -> Result<(), Error> {
    let (expected_psbt, _, _) = build_psbt(proposal)?;
    let actual_tx = &psbt.unsigned_tx;
    let expected_tx = &expected_psbt.unsigned_tx;

    if actual_tx.version != expected_tx.version || actual_tx.lock_time != expected_tx.lock_time {
        return Err(invalid_swap("swap PSBT transaction header mismatch"));
    }
    if actual_tx.input != expected_tx.input {
        return Err(invalid_swap("swap PSBT inputs mismatch"));
    }
    if actual_tx.output.len() != expected_tx.output.len() {
        return Err(invalid_swap("swap PSBT output count mismatch"));
    }
    if actual_tx
        .output
        .first()
        .is_none_or(|o| o.value != BdkAmount::ZERO || !o.script_pubkey.is_op_return())
    {
        return Err(invalid_swap("swap PSBT missing RGB OP_RETURN host"));
    }
    for (idx, (actual, expected)) in actual_tx
        .output
        .iter()
        .zip(expected_tx.output.iter())
        .enumerate()
        .skip(1)
    {
        if actual != expected {
            return Err(invalid_swap(format!("swap PSBT output {idx} mismatch")));
        }
    }
    if proposal.txid != actual_tx.compute_txid().to_string() {
        return Err(invalid_swap("swap PSBT txid mismatch"));
    }
    Ok(())
}

fn side_btc_payment(leg: &OnchainSwapLeg) -> u64 {
    if matches!(leg.kind, OnchainSwapLegKind::Btc) {
        leg.amount
    } else {
        0
    }
}

fn side_rgb_output_cost(receives: &OnchainSwapLeg, rgb_output_sat: u64) -> u64 {
    if matches!(receives.kind, OnchainSwapLegKind::Rgb) {
        rgb_output_sat
    } else {
        0
    }
}

fn append_side_change(
    outputs: &mut Vec<TxOut>,
    inputs: &[OnchainSwapInput],
    gives: &OnchainSwapLeg,
    receives: &OnchainSwapLeg,
    rgb_output_sat: u64,
    fee_sat: u64,
    change_script_hex: &str,
) -> Result<(), Error> {
    let input_total = selected_inputs_total(inputs);
    let required = side_btc_payment(gives)
        .checked_add(side_rgb_output_cost(receives, rgb_output_sat))
        .and_then(|v| v.checked_add(fee_sat))
        .ok_or_else(|| invalid_swap("swap amounts overflow"))?;
    if input_total < required {
        return Err(Error::InsufficientBitcoins {
            needed: required,
            available: input_total,
        });
    }
    let change = input_total - required;
    if change > 0 {
        outputs.push(TxOut {
            value: BdkAmount::from_sat(change),
            script_pubkey: parse_script(change_script_hex)?,
        });
    }
    Ok(())
}

fn build_psbt(proposal: &OnchainSwapProposal) -> Result<(Psbt, Option<u32>, Option<u32>), Error> {
    let offer = &proposal.request.offer;
    let maker_inputs = &proposal.maker_inputs;
    let taker_inputs = &proposal.request.taker_inputs;
    let maker_gives = &offer.maker_gives;
    let maker_receives = &offer.maker_receives;
    let taker_gives = maker_receives;
    let taker_receives = maker_gives;

    let mut tx_inputs = vec![];
    for input in maker_inputs.iter().chain(taker_inputs.iter()) {
        tx_inputs.push(TxIn {
            previous_output: swap_input_to_outpoint(input),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }

    let mut outputs = vec![TxOut {
        value: BdkAmount::ZERO,
        script_pubkey: ScriptBuf::new_op_return([]),
    }];
    let mut maker_rgb_vout = None;
    let mut taker_rgb_vout = None;

    if matches!(maker_receives.kind, OnchainSwapLegKind::Btc) {
        let address = offer
            .maker_btc_address
            .as_ref()
            .ok_or_else(|| invalid_swap("missing maker BTC receive address"))?;
        outputs.push(TxOut {
            value: BdkAmount::from_sat(maker_receives.amount),
            script_pubkey: parse_address_str(address, offer.bitcoin_network)?.script_pubkey(),
        });
    }
    if matches!(taker_receives.kind, OnchainSwapLegKind::Btc) {
        let address = proposal
            .request
            .taker_btc_address
            .as_ref()
            .ok_or_else(|| invalid_swap("missing taker BTC receive address"))?;
        outputs.push(TxOut {
            value: BdkAmount::from_sat(taker_receives.amount),
            script_pubkey: parse_address_str(address, offer.bitcoin_network)?.script_pubkey(),
        });
    }
    if matches!(maker_receives.kind, OnchainSwapLegKind::Rgb) {
        maker_rgb_vout = Some(outputs.len() as u32);
        outputs.push(TxOut {
            value: BdkAmount::from_sat(offer.rgb_output_sat),
            script_pubkey: parse_script(
                offer
                    .maker_rgb_script_pubkey_hex
                    .as_ref()
                    .ok_or_else(|| invalid_swap("missing maker RGB receive script"))?,
            )?,
        });
    }
    if matches!(taker_receives.kind, OnchainSwapLegKind::Rgb) {
        taker_rgb_vout = Some(outputs.len() as u32);
        outputs.push(TxOut {
            value: BdkAmount::from_sat(offer.rgb_output_sat),
            script_pubkey: parse_script(
                proposal
                    .request
                    .taker_rgb_script_pubkey_hex
                    .as_ref()
                    .ok_or_else(|| invalid_swap("missing taker RGB receive script"))?,
            )?,
        });
    }

    append_side_change(
        &mut outputs,
        maker_inputs,
        maker_gives,
        maker_receives,
        offer.rgb_output_sat,
        0,
        &proposal.maker_change_script_pubkey_hex,
    )?;
    append_side_change(
        &mut outputs,
        taker_inputs,
        taker_gives,
        taker_receives,
        offer.rgb_output_sat,
        offer.network_fee_sat,
        &proposal.request.taker_change_script_pubkey_hex,
    )?;

    let mut psbt = Psbt::from_unsigned_tx(BitcoinTransaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: outputs,
    })
    .map_err(|e| Error::InvalidPsbt {
        details: e.to_string(),
    })?;
    let all_inputs = maker_inputs
        .iter()
        .chain(taker_inputs.iter())
        .cloned()
        .collect::<Vec<_>>();
    restore_input_metadata(&mut psbt, &all_inputs)?;
    Ok((psbt, maker_rgb_vout, taker_rgb_vout))
}

impl Wallet {
    /// Import the counterparty's contract definition from an issuance consignment file produced
    /// by `issue_asset_nia`/`issue_asset_cfa`/etc. on the other party's wallet. Used for
    /// RGB-for-RGB swaps so that both runtimes know all contracts referenced by the multi-contract
    /// fascia before `consume_fascia` runs.
    fn import_swap_contract(&self, txn: &DbTxn, contract_path_str: &str) -> Result<(), Error> {
        let contract_path = Path::new(contract_path_str);
        if !contract_path.exists() {
            return Err(invalid_swap(format!(
                "swap contract consignment not found at {}",
                contract_path.display()
            )));
        }
        let valid_contract =
            ValidContract::load_file(contract_path).map_err(InternalError::from)?;
        let contract_id = valid_contract.contract_id();
        let asset_id = contract_id.to_string();
        info!(
            self.logger(),
            "Importing swap contract {asset_id} from {}",
            contract_path.display()
        );
        let asset_schema: AssetSchema = valid_contract.schema_id().try_into()?;
        self.check_schema_support(&asset_schema)?;
        {
            let mut runtime = self.rgb_runtime()?;
            if runtime.contract_schema(contract_id).is_err() {
                runtime.import_contract(valid_contract.clone(), &DumbResolver)?;
            }
        } // drop runtime so subsequent rgb_runtime() / DB calls don't deadlock on the stash lock
        // Mirror the consignment under our own assets dir so subsequent local lookups find it.
        let local_path = self.get_wallet_dir().join(ASSETS_DIR).join(&asset_id);
        if !local_path.exists() {
            if let Some(parent) = local_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(contract_path, &local_path)?;
        }
        // Register the contract in the wallet database as a known asset so subsequent
        // accept_transfer / record_incoming_rgb_swap calls satisfy the FK constraint.
        if txn.get_asset(asset_id.clone())?.is_none() {
            let runtime = self.rgb_runtime()?;
            self.save_new_asset_internal(
                txn,
                &runtime,
                contract_id,
                asset_schema,
                valid_contract,
                None,
            )?;
        }
        Ok(())
    }

    fn ensure_swap_inputs_confirmed(
        &self,
        inputs: &[OnchainSwapInput],
        min_confirmations: u8,
    ) -> Result<(), Error> {
        if min_confirmations == 0 {
            return Ok(());
        }
        for input in inputs {
            let confirmations = self
                .indexer()
                .get_tx_confirmations(&input.outpoint.txid)?
                .unwrap_or_default();
            if confirmations < min_confirmations as u64 {
                return Err(invalid_swap(format!(
                    "swap input {} has {confirmations} confirmations, required {min_confirmations}",
                    input.outpoint
                )));
            }
        }
        Ok(())
    }

    fn accept_transfer_from_file(
        &mut self,
        txn: &DbTxn,
        consignment_path: &Path,
        txid: String,
        vout: u32,
        blinding: u64,
    ) -> Result<Vec<Assignment>, Error> {
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let consignment = RgbTransfer::load_file(consignment_path).map_err(InternalError::from)?;
        let contract_id = consignment.contract_id();
        let asset_id = contract_id.to_string();
        let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
        self.check_schema_support(&asset_schema)?;

        let mut runtime = self.rgb_runtime()?;
        let graph_seal = GraphSeal::with_blinded_vout(vout, blinding);
        runtime.store_secret_seal(graph_seal)?;

        let resolver = OffchainResolver {
            witness_id,
            consignment: &consignment,
            fallback: self.blockchain_resolver(),
        };
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem: asset_schema.types(),
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

        let valid_contract = valid_consignment.clone().into_valid_contract();
        runtime
            .import_contract(valid_contract.clone(), self.blockchain_resolver())
            .expect("failure importing validated contract");
        if txn.get_asset(asset_id.clone())?.is_none() {
            self.save_new_asset_internal(
                txn,
                &runtime,
                contract_id,
                asset_schema,
                valid_contract.clone(),
                Some(valid_consignment.clone()),
            )?;
        }
        let received_rgb_assignments =
            self.extract_received_assignments(&consignment, witness_id, Some(vout), None);
        runtime.accept_transfer(valid_consignment, &resolver)?;
        let assignments = received_rgb_assignments.into_values().collect::<Vec<_>>();
        drop(runtime);
        record_incoming_rgb_swap(txn, &asset_id, &txid, vout, &assignments)?;
        Ok(assignments)
    }

    /// Create a maker offer for an on-chain swap.
    pub fn create_swap_offer(
        &mut self,
        maker_gives: OnchainSwapLeg,
        maker_receives: OnchainSwapLeg,
        network_fee_sat: u64,
        expiration_timestamp: Option<u64>,
        proxy_url: Option<String>,
    ) -> Result<OnchainSwapOffer, Error> {
        info!(self.logger(), "Creating on-chain swap offer...");
        validate_legs(&maker_gives, &maker_receives)?;
        let (
            maker_btc_address,
            maker_rgb_recipient_id,
            maker_rgb_script_pubkey_hex,
            maker_rgb_blinding,
        ) = if matches!(maker_receives.kind, OnchainSwapLegKind::Btc) {
            (Some(self.get_address()?), None, None, None)
        } else {
            let script = self
                .get_new_addresses(KeychainKind::External, 1)?
                .script_pubkey();
            let blinding = random_blinding();
            (
                None,
                Some(recipient_id_from_script_buf(
                    script.clone(),
                    self.bitcoin_network(),
                )),
                Some(script.to_hex_string()),
                Some(blinding),
            )
        };
        let maker_send_contract_path = match &maker_gives {
            leg if matches!(leg.kind, OnchainSwapLegKind::Rgb) => {
                leg.asset_id.as_ref().map(|asset_id| {
                    self.get_wallet_dir()
                        .join(ASSETS_DIR)
                        .join(asset_id)
                        .to_string_lossy()
                        .to_string()
                })
            }
            _ => None,
        };
        Ok(OnchainSwapOffer {
            swap_id: random_swap_id(),
            maker_gives,
            maker_receives,
            bitcoin_network: self.bitcoin_network(),
            network_fee_sat,
            rgb_output_sat: DEFAULT_RGB_OUTPUT_SAT,
            expiration_timestamp,
            maker_btc_address,
            maker_rgb_recipient_id,
            maker_rgb_script_pubkey_hex,
            maker_rgb_blinding,
            proxy_url,
            maker_send_contract_path,
        })
    }

    /// Accept a maker offer and return the taker's request message.
    pub fn accept_swap_offer(
        &mut self,
        online: Online,
        offer: OnchainSwapOffer,
        min_confirmations: u8,
        skip_sync: bool,
    ) -> Result<OnchainSwapRequest, Error> {
        info!(self.logger(), "Accepting on-chain swap offer...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        validate_legs(&offer.maker_gives, &offer.maker_receives)?;
        ensure_offer_not_expired(&offer)?;
        if offer.bitcoin_network != self.bitcoin_network() {
            return Err(Error::BitcoinNetworkMismatch);
        }
        let taker_gives = offer.maker_receives.clone();
        let taker_receives = offer.maker_gives.clone();
        let taker_inputs = self.select_swap_inputs(
            &txn,
            online,
            &taker_gives,
            side_rgb_output_cost(&taker_receives, offer.rgb_output_sat)
                .checked_add(offer.network_fee_sat)
                .ok_or_else(|| invalid_swap("swap amounts overflow"))?,
            min_confirmations,
            skip_sync,
        )?;
        let (
            taker_btc_address,
            taker_rgb_recipient_id,
            taker_rgb_script_pubkey_hex,
            taker_rgb_blinding,
        ) = if matches!(taker_receives.kind, OnchainSwapLegKind::Btc) {
            (Some(self.get_address()?), None, None, None)
        } else {
            let script = self
                .get_new_addresses(KeychainKind::External, 1)?
                .script_pubkey();
            let blinding = random_blinding();
            (
                None,
                Some(recipient_id_from_script_buf(
                    script.clone(),
                    self.bitcoin_network(),
                )),
                Some(script.to_hex_string()),
                Some(blinding),
            )
        };
        let taker_change_script_pubkey_hex = self
            .get_new_addresses(KeychainKind::Internal, 1)?
            .script_pubkey()
            .to_hex_string();
        let taker_send_contract_path = match &taker_gives {
            leg if matches!(leg.kind, OnchainSwapLegKind::Rgb) => {
                leg.asset_id.as_ref().map(|asset_id| {
                    self.get_wallet_dir()
                        .join(ASSETS_DIR)
                        .join(asset_id)
                        .to_string_lossy()
                        .to_string()
                })
            }
            _ => None,
        };
        let request = OnchainSwapRequest {
            offer,
            taker_inputs,
            taker_btc_address,
            taker_rgb_recipient_id,
            taker_rgb_script_pubkey_hex,
            taker_rgb_blinding,
            taker_change_script_pubkey_hex,
            taker_send_contract_path,
        };
        txn.commit()?;
        Ok(request)
    }

    /// Accept a taker request and return the maker's PSBT proposal.
    pub fn accept_swap_request(
        &mut self,
        online: Online,
        request: OnchainSwapRequest,
        min_confirmations: u8,
        skip_sync: bool,
    ) -> Result<OnchainSwapProposal, Error> {
        info!(self.logger(), "Accepting on-chain swap request...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let offer = request.offer.clone();
        let direction = validate_legs(&offer.maker_gives, &offer.maker_receives)?;
        ensure_offer_not_expired(&offer)?;
        if offer.bitcoin_network != self.bitcoin_network() {
            return Err(Error::BitcoinNetworkMismatch);
        }
        require_rgb_destination(
            &offer.maker_gives,
            &request.taker_rgb_script_pubkey_hex,
            &request.taker_rgb_blinding,
        )?;
        require_rgb_destination(
            &offer.maker_receives,
            &offer.maker_rgb_script_pubkey_hex,
            &offer.maker_rgb_blinding,
        )?;
        let maker_inputs = self.select_swap_inputs(
            &txn,
            online,
            &offer.maker_gives,
            side_rgb_output_cost(&offer.maker_receives, offer.rgb_output_sat),
            min_confirmations,
            skip_sync,
        )?;
        let maker_change_script_pubkey_hex = self
            .get_new_addresses(KeychainKind::Internal, 1)?
            .script_pubkey()
            .to_hex_string();
        let mut proposal = OnchainSwapProposal {
            request,
            maker_inputs,
            maker_change_script_pubkey_hex,
            psbt: String::new(),
            txid: String::new(),
            consignments: vec![],
        };
        let (mut psbt, _maker_rgb_vout, taker_rgb_vout) = build_psbt(&proposal)?;
        let mut consignments = vec![];
        if matches!(offer.maker_gives.kind, OnchainSwapLegKind::Rgb) {
            let vout = taker_rgb_vout.ok_or_else(|| invalid_swap("missing taker RGB vout"))?;
            let blinding = proposal
                .request
                .taker_rgb_blinding
                .ok_or_else(|| invalid_swap("missing taker RGB blinding"))?;
            match direction {
                SwapDirection::RgbForBtc => {
                    // Single-RGB swap: maker stages, finalizes, consumes and emits the consignment
                    // here. The taker does not touch the RGB commitment.
                    let recipient_id = proposal
                        .request
                        .taker_rgb_recipient_id
                        .as_deref()
                        .ok_or_else(|| invalid_swap("missing taker RGB recipient ID"))?;
                    consignments = color_rgb_leg(
                        &txn,
                        self,
                        &mut psbt,
                        &offer.maker_gives,
                        recipient_id,
                        vout,
                        blinding,
                        offer.proxy_url.as_deref(),
                        &offer.swap_id,
                    )?;
                }
                SwapDirection::RgbForRgb => {
                    // Two-RGB swap: maker only stages here. Finalize + consume + consignment
                    // emission happen later (taker finalizes; maker resumes via
                    // `process_swap_completion`). The maker also imports the taker's contract so
                    // that `consume_fascia` in `process_swap_completion` recognizes it.
                    if let Some(taker_contract_path) =
                        proposal.request.taker_send_contract_path.as_deref()
                    {
                        self.import_swap_contract(&txn, taker_contract_path)?;
                    }
                    stage_rgb_leg(self, &mut psbt, &offer.maker_gives, vout, blinding)?;
                }
                SwapDirection::BtcForRgb => {
                    unreachable!("BTC-for-RGB cannot reach maker_gives==Rgb branch")
                }
            }
            let inputs = proposal
                .maker_inputs
                .iter()
                .chain(proposal.request.taker_inputs.iter())
                .cloned()
                .collect::<Vec<_>>();
            restore_input_metadata(&mut psbt, &inputs)?;
        }
        sign_swap_psbt(self, &mut psbt)?;
        proposal.txid = psbt.unsigned_tx.compute_txid().to_string();
        proposal.psbt = psbt.to_string();
        proposal.consignments = consignments;
        txn.commit()?;
        Ok(proposal)
    }

    /// Complete a maker proposal as the taker.
    pub fn complete_swap_proposal(
        &mut self,
        online: Online,
        proposal: OnchainSwapProposal,
        min_confirmations: u8,
        skip_sync: bool,
    ) -> Result<OnchainSwapCompletion, Error> {
        info!(self.logger(), "Completing on-chain swap proposal...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let offer = &proposal.request.offer;
        let direction = validate_legs(&offer.maker_gives, &offer.maker_receives)?;
        ensure_offer_not_expired(offer)?;
        if offer.bitcoin_network != self.bitcoin_network() {
            return Err(Error::BitcoinNetworkMismatch);
        }
        let mut psbt = Psbt::from_str(&proposal.psbt)?;
        validate_proposal_psbt(&proposal, &psbt)?;
        let mut consignments = proposal.consignments.clone();
        let mut fascia_json: Option<String> = None;
        let (_expected_psbt, maker_rgb_vout, taker_rgb_vout) = build_psbt(&proposal)?;
        let all_inputs = proposal
            .maker_inputs
            .iter()
            .chain(proposal.request.taker_inputs.iter())
            .cloned()
            .collect::<Vec<_>>();

        match direction {
            SwapDirection::BtcForRgb => {
                // Only the taker colors (and finalizes/consumes/emits) the maker_receives RGB leg.
                let vout = maker_rgb_vout.ok_or_else(|| invalid_swap("missing maker RGB vout"))?;
                let blinding = offer
                    .maker_rgb_blinding
                    .ok_or_else(|| invalid_swap("missing maker RGB blinding"))?;
                let recipient_id = offer
                    .maker_rgb_recipient_id
                    .as_deref()
                    .ok_or_else(|| invalid_swap("missing maker RGB recipient ID"))?;
                consignments.extend(color_rgb_leg(
                    &txn,
                    self,
                    &mut psbt,
                    &offer.maker_receives,
                    recipient_id,
                    vout,
                    blinding,
                    offer.proxy_url.as_deref(),
                    &offer.swap_id,
                )?);
                restore_input_metadata(&mut psbt, &all_inputs)?;
            }
            SwapDirection::RgbForBtc => {
                // Maker already colored maker_gives in `accept_swap_request`; the taker only signs.
            }
            SwapDirection::RgbForRgb => {
                // Maker has already staged maker_gives. The taker stages maker_receives, then
                // finalizes the commitment, consumes the fascia (for the leg it knows) and emits
                // the consignment for the maker_receives leg. The serialized fascia is returned in
                // the completion so the maker can do the same for the leg they sent.
                // First, import the maker's contract so `consume_fascia` recognises both legs.
                if let Some(maker_contract_path) = offer.maker_send_contract_path.as_deref() {
                    self.import_swap_contract(&txn, maker_contract_path)?;
                }
                let recv_vout =
                    maker_rgb_vout.ok_or_else(|| invalid_swap("missing maker RGB vout"))?;
                let recv_blinding = offer
                    .maker_rgb_blinding
                    .ok_or_else(|| invalid_swap("missing maker RGB blinding"))?;
                let taker_beneficiaries = stage_rgb_leg(
                    self,
                    &mut psbt,
                    &offer.maker_receives,
                    recv_vout,
                    recv_blinding,
                )?;
                // Pick a deterministic MPC entropy derived from the swap_id so both parties can
                // reproduce the same commitment independently.
                let mpc_entropy = mpc_entropy_for_swap(&offer.swap_id);
                let fascia = self.color_psbt_finalize(&mut psbt, Some(mpc_entropy))?;
                fascia_json = Some(serde_json::to_string(&fascia).map_err(InternalError::from)?);
                self.consume_fascia(fascia.clone(), None)?;
                let witness_txid = psbt.get_txid();
                let recv_asset_id = offer
                    .maker_receives
                    .asset_id
                    .clone()
                    .expect("RGB leg has asset ID");
                let recv_contract_id = ContractId::from_str(&recv_asset_id)
                    .map_err(|e| invalid_swap(format!("invalid RGB asset ID: {e}")))?;
                let beneficiaries = taker_beneficiaries
                    .get(&recv_contract_id)
                    .cloned()
                    .ok_or_else(|| invalid_swap("missing taker beneficiaries"))?;
                let transfer =
                    self.generate_transfer(recv_contract_id, beneficiaries, witness_txid)?;
                let txid_str = witness_txid.to_string();
                record_outgoing_rgb_swap(&txn, &recv_asset_id, &txid_str, &psbt)?;
                let recv_recipient_id = offer
                    .maker_rgb_recipient_id
                    .as_deref()
                    .ok_or_else(|| invalid_swap("missing maker RGB recipient ID"))?;
                consignments.extend(emit_swap_consignments(
                    self,
                    vec![transfer],
                    offer.proxy_url.as_deref(),
                    &offer.swap_id,
                    &txid_str,
                    recv_recipient_id,
                    recv_vout,
                    recv_blinding,
                )?);
                restore_input_metadata(&mut psbt, &all_inputs)?;
            }
        }
        let _ = taker_rgb_vout;
        self.sync_if_requested(&txn, Some(online), skip_sync, KeychainKind::Internal)?;
        self.sync_if_requested(&txn, Some(online), skip_sync, KeychainKind::External)?;
        self.ensure_swap_inputs_confirmed(&proposal.maker_inputs, min_confirmations)?;
        self.ensure_swap_inputs_confirmed(&proposal.request.taker_inputs, min_confirmations)?;
        sign_swap_psbt(self, &mut psbt)?;
        let finalized_psbt = finalize_swap_psbt(self, &psbt)?;
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        let completion = OnchainSwapCompletion {
            proposal,
            psbt: psbt.to_string(),
            finalized_psbt,
            txid,
            consignments,
            fascia_json,
        };
        txn.commit()?;
        Ok(completion)
    }

    /// After [`Wallet::complete_swap_proposal`] returns a completion, the maker calls this method
    /// to consume the RGB fascia and produce the consignment for the leg they are sending. This is
    /// only required for RGB-for-RGB swaps. For RGB-for-BTC the maker already produced the
    /// consignment in [`Wallet::accept_swap_request`]; for BTC-for-RGB the maker has nothing to
    /// emit. In all cases the returned completion is what should be forwarded to the receivers
    /// when they call [`Wallet::accept_swap_transfers`].
    pub fn process_swap_completion(
        &mut self,
        online: Online,
        completion: OnchainSwapCompletion,
    ) -> Result<OnchainSwapCompletion, Error> {
        info!(self.logger(), "Processing on-chain swap completion...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let offer = &completion.proposal.request.offer;
        let direction = validate_legs(&offer.maker_gives, &offer.maker_receives)?;
        if !matches!(direction, SwapDirection::RgbForRgb) {
            return Ok(completion);
        }
        let fascia_json = completion
            .fascia_json
            .as_ref()
            .ok_or_else(|| invalid_swap("missing fascia in completion"))?;
        let fascia: Fascia = serde_json::from_str(fascia_json).map_err(InternalError::from)?;
        self.consume_fascia(fascia, None)?;

        let psbt = Psbt::from_str(&completion.psbt)?;
        let witness_txid = psbt.get_txid();
        // Reconstruct the maker's beneficiaries from blinding+vout (the maker staged
        // maker_gives earlier with these parameters).
        let (_expected_psbt, _maker_rgb_vout, taker_rgb_vout) = build_psbt(&completion.proposal)?;
        let send_vout = taker_rgb_vout.ok_or_else(|| invalid_swap("missing taker RGB vout"))?;
        let send_blinding = completion
            .proposal
            .request
            .taker_rgb_blinding
            .ok_or_else(|| invalid_swap("missing taker RGB blinding"))?;
        let send_asset_id = offer
            .maker_gives
            .asset_id
            .clone()
            .expect("RGB leg has asset ID");
        let send_contract_id = ContractId::from_str(&send_asset_id)
            .map_err(|e| invalid_swap(format!("invalid RGB asset ID: {e}")))?;
        let beneficiaries = vec![BuilderSeal::Revealed(GraphSeal::with_blinded_vout(
            send_vout,
            send_blinding,
        ))];
        let transfer = self.generate_transfer(send_contract_id, beneficiaries, witness_txid)?;
        let txid_str = witness_txid.to_string();
        record_outgoing_rgb_swap(&txn, &send_asset_id, &txid_str, &psbt)?;
        let send_recipient_id = completion
            .proposal
            .request
            .taker_rgb_recipient_id
            .as_deref()
            .ok_or_else(|| invalid_swap("missing taker RGB recipient ID"))?;
        let mut consignments = completion.consignments.clone();
        consignments.extend(emit_swap_consignments(
            self,
            vec![transfer],
            offer.proxy_url.as_deref(),
            &offer.swap_id,
            &txid_str,
            send_recipient_id,
            send_vout,
            send_blinding,
        )?);
        let completion = OnchainSwapCompletion {
            consignments,
            ..completion
        };
        txn.commit()?;
        Ok(completion)
    }

    /// Accept RGB transfers received from a completed on-chain swap.
    pub fn accept_swap_transfers(
        &mut self,
        online: Online,
        completion: OnchainSwapCompletion,
        role: OnchainSwapRole,
        skip_sync: bool,
    ) -> Result<OnchainSwapReceiveResult, Error> {
        info!(self.logger(), "Accepting on-chain swap transfers...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        self.sync_if_requested(&txn, Some(online), skip_sync, KeychainKind::External)?;
        let offer = &completion.proposal.request.offer;
        let receives = match role {
            OnchainSwapRole::Maker => offer.maker_receives.clone(),
            OnchainSwapRole::Taker => offer.maker_gives.clone(),
        };
        if !matches!(receives.kind, OnchainSwapLegKind::Rgb) {
            let result = OnchainSwapReceiveResult {
                assignments: vec![],
            };
            txn.commit()?;
            return Ok(result);
        }
        let mut assignments = vec![];
        for consignment in completion
            .consignments
            .iter()
            .filter(|c| receives.asset_id.as_deref() == Some(c.asset_id.as_str()))
        {
            let local_path = self.fetch_swap_consignment_to_file(consignment)?;
            let mut accepted = self.accept_transfer_from_file(
                &txn,
                &local_path,
                consignment.txid.clone(),
                consignment.vout,
                consignment.blinding,
            )?;
            assignments.append(&mut accepted);
        }
        let result = OnchainSwapReceiveResult { assignments };
        txn.commit()?;
        Ok(result)
    }

    /// Resolve a swap consignment to a local file path: if a proxy endpoint is set, download the
    /// consignment from the proxy using its [`OnchainSwapConsignment::recipient_id`] (so multiple
    /// consignments sharing a witness transaction do not collide); otherwise return the local path
    /// that the sender wrote.
    fn fetch_swap_consignment_to_file(
        &self,
        consignment: &OnchainSwapConsignment,
    ) -> Result<PathBuf, Error> {
        if consignment.endpoint.is_none() {
            return Ok(PathBuf::from(&consignment.path));
        }
        let endpoint_str = consignment.endpoint.as_deref().unwrap();
        let transport = RgbTransport::from_str(endpoint_str)?;
        let proxy_url = TransportEndpoint::try_from(transport)?.endpoint;
        let proxy_client = ProxyClient::new(&proxy_url)?;
        let res = proxy_client.get_consignment(&consignment.recipient_id);
        if res.is_err() || res.as_ref().unwrap().result.as_ref().is_none() {
            // Fall back to the local file if the proxy lookup fails. This keeps the same-host case
            // working when the proxy is reachable but the consignment was never uploaded.
            return Ok(PathBuf::from(&consignment.path));
        }
        let consignment_res = res.unwrap().result.unwrap();
        let consignment_bytes = general_purpose::STANDARD
            .decode(consignment_res.consignment)
            .map_err(InternalError::from)?;
        let target_dir = self
            .get_wallet_dir()
            .join("swap-receive")
            .join(&consignment.recipient_id);
        fs::create_dir_all(&target_dir)?;
        let target_path = target_dir.join(format!("{}.rgb", consignment.asset_id));
        fs::write(&target_path, &consignment_bytes)?;
        Ok(target_path)
    }

    fn select_swap_inputs(
        &mut self,
        txn: &DbTxn,
        online: Online,
        gives: &OnchainSwapLeg,
        extra_sat: u64,
        min_confirmations: u8,
        skip_sync: bool,
    ) -> Result<Vec<OnchainSwapInput>, Error> {
        self.sync_if_requested(txn, Some(online), skip_sync, KeychainKind::Internal)?;
        self.sync_if_requested(txn, Some(online), skip_sync, KeychainKind::External)?;
        match gives.kind {
            OnchainSwapLegKind::Btc => self.select_btc_swap_inputs(
                online,
                gives
                    .amount
                    .checked_add(extra_sat)
                    .ok_or_else(|| invalid_swap("swap amounts overflow"))?,
                min_confirmations,
            ),
            OnchainSwapLegKind::Rgb => {
                let asset_id = gives.asset_id.clone().expect("RGB leg has asset ID");
                txn.check_asset_exists(asset_id.clone())?;
                let assignments = AssignmentsCollection {
                    fungible: gives.amount,
                    non_fungible: false,
                    inflation: 0,
                };
                let (_, _, input_unspents, _) = self.get_transfer_begin_data(txn, 1)?;
                let selected = self.select_rgb_inputs(asset_id, &assignments, input_unspents)?;
                let selected_outpoints = selected
                    .input_outpoints
                    .into_iter()
                    .map(BdkOutPoint::from)
                    .collect::<HashSet<_>>();
                let bdk_outputs = self.bdk_wallet().list_unspent().collect::<Vec<_>>();
                let mut swap_inputs = vec![];
                for output in bdk_outputs {
                    if selected_outpoints.contains(&output.outpoint) {
                        swap_inputs.push(build_swap_input(&output));
                    }
                }
                if swap_inputs.is_empty() {
                    return Err(invalid_swap("could not resolve selected RGB inputs"));
                }
                let total = selected_inputs_total(&swap_inputs);
                let needed = extra_sat;
                if total < needed {
                    return Err(Error::InsufficientBitcoins {
                        needed,
                        available: total,
                    });
                }
                self.ensure_swap_inputs_confirmed(&swap_inputs, min_confirmations)?;
                Ok(swap_inputs)
            }
        }
    }

    fn select_btc_swap_inputs(
        &mut self,
        online: Online,
        needed_sat: u64,
        min_confirmations: u8,
    ) -> Result<Vec<OnchainSwapInput>, Error> {
        let mut selected = vec![];
        let mut total = 0u64;
        for output in self
            .list_unspents_vanilla(online, min_confirmations, true)?
            .into_iter()
            .filter(|o| !o.is_spent)
        {
            total = total
                .checked_add(output.txout.value.to_sat())
                .ok_or_else(|| invalid_swap("swap amounts overflow"))?;
            selected.push(build_swap_input(&output));
            if total >= needed_sat {
                break;
            }
        }
        if total < needed_sat {
            return Err(Error::InsufficientBitcoins {
                needed: needed_sat,
                available: total,
            });
        }
        Ok(selected)
    }
}

fn record_incoming_rgb_swap(
    txn: &DbTxn,
    asset_id: &str,
    txid: &str,
    vout: u32,
    assignments: &[Assignment],
) -> Result<(), Error> {
    let batch_transfer = DbBatchTransferActMod {
        txid: ActiveValue::Set(Some(txid.to_string())),
        status: ActiveValue::Set(TransferStatus::WaitingConfirmations),
        expiration: ActiveValue::Set(None),
        created_at: ActiveValue::Set(now().unix_timestamp()),
        min_confirmations: ActiveValue::Set(1),
        ..Default::default()
    };
    let batch_transfer_idx = txn.set_batch_transfer(batch_transfer)?;
    let asset_transfer = DbAssetTransferActMod {
        user_driven: ActiveValue::Set(true),
        batch_transfer_idx: ActiveValue::Set(batch_transfer_idx),
        asset_id: ActiveValue::Set(Some(asset_id.to_string())),
        ..Default::default()
    };
    let asset_transfer_idx = txn.set_asset_transfer(asset_transfer)?;
    let db_txo = DbTxoActMod {
        txid: ActiveValue::Set(txid.to_string()),
        vout: ActiveValue::Set(vout),
        btc_amount: ActiveValue::Set(DEFAULT_RGB_OUTPUT_SAT.to_string()),
        spent: ActiveValue::Set(false),
        exists: ActiveValue::Set(false),
        pending_witness: ActiveValue::Set(true),
        ..Default::default()
    };
    // set_txo may return an invalid `last_insert_id` when the row already exists (e.g. it was
    // already populated by a chain sync after the swap tx was broadcast). Always look up the
    // actual row to get the real idx.
    let _ = txn.set_txo(db_txo)?;
    let txo_idx = txn
        .get_txo(&Outpoint {
            txid: txid.to_string(),
            vout,
        })?
        .map(|t| t.idx)
        .ok_or_else(|| invalid_swap("failed to locate swap output txo after insert"))?;

    for assignment in assignments {
        let db_coloring = DbColoringActMod {
            txo_idx: ActiveValue::Set(txo_idx),
            asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
            r#type: ActiveValue::Set(ColoringType::Receive),
            assignment: ActiveValue::Set(assignment.clone()),
            ..Default::default()
        };
        txn.set_coloring(db_coloring)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn btc(amount: u64) -> OnchainSwapLeg {
        OnchainSwapLeg {
            kind: OnchainSwapLegKind::Btc,
            asset_id: None,
            amount,
        }
    }

    fn rgb(asset_id: &str, amount: u64) -> OnchainSwapLeg {
        OnchainSwapLeg {
            kind: OnchainSwapLegKind::Rgb,
            asset_id: Some(asset_id.to_string()),
            amount,
        }
    }

    const ASSET_1: &str = "rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E";
    const ASSET_2: &str = "rgb:4bBH~Lrb-rx8sB_n-WAJLPcn-X5tFL9q-dFDGbSz-8yApPws";

    fn swap_input(txid: &str, vout: u32, amount_sat: u64) -> OnchainSwapInput {
        OnchainSwapInput {
            outpoint: Outpoint {
                txid: txid.to_string(),
                vout,
            },
            amount_sat,
            script_pubkey_hex: "51".to_string(),
        }
    }

    fn rgb_rgb_proposal() -> OnchainSwapProposal {
        let offer = OnchainSwapOffer {
            swap_id: "test-swap".to_string(),
            maker_gives: rgb(ASSET_1, 10),
            maker_receives: rgb(ASSET_2, 20),
            bitcoin_network: BitcoinNetwork::Regtest,
            network_fee_sat: 100,
            rgb_output_sat: DEFAULT_RGB_OUTPUT_SAT,
            expiration_timestamp: None,
            maker_btc_address: None,
            maker_rgb_recipient_id: Some("maker-rgb-recipient".to_string()),
            maker_rgb_script_pubkey_hex: Some("51".to_string()),
            maker_rgb_blinding: Some(1),
            proxy_url: None,
            maker_send_contract_path: None,
        };
        OnchainSwapProposal {
            request: OnchainSwapRequest {
                offer,
                taker_inputs: vec![swap_input(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                    0,
                    2_100,
                )],
                taker_btc_address: None,
                taker_rgb_recipient_id: Some("taker-rgb-recipient".to_string()),
                taker_rgb_script_pubkey_hex: Some("51".to_string()),
                taker_rgb_blinding: Some(2),
                taker_change_script_pubkey_hex: "51".to_string(),
                taker_send_contract_path: None,
            },
            maker_inputs: vec![swap_input(
                "2222222222222222222222222222222222222222222222222222222222222222",
                0,
                1_000,
            )],
            maker_change_script_pubkey_hex: "51".to_string(),
            psbt: String::new(),
            txid: String::new(),
            consignments: vec![],
        }
    }

    #[test]
    fn validates_supported_leg_pairs() {
        assert_eq!(
            validate_legs(&rgb(ASSET_1, 1), &btc(1_000)).unwrap(),
            SwapDirection::RgbForBtc
        );
        assert_eq!(
            validate_legs(&btc(1_000), &rgb(ASSET_1, 1)).unwrap(),
            SwapDirection::BtcForRgb
        );
        assert_eq!(
            validate_legs(&rgb(ASSET_1, 1), &rgb(ASSET_2, 1)).unwrap(),
            SwapDirection::RgbForRgb
        );
    }

    #[test]
    fn rejects_invalid_leg_pairs() {
        assert!(matches!(
            validate_legs(&btc(0), &rgb(ASSET_1, 1)),
            Err(Error::InvalidAmountZero)
        ));
        assert!(validate_legs(&btc(1), &btc(2)).is_err());
        assert!(validate_legs(&rgb(ASSET_1, 1), &rgb(ASSET_1, 2)).is_err());
        assert!(validate_legs(&rgb("invalid", 1), &btc(1)).is_err());
    }

    #[test]
    fn rejects_missing_or_extra_asset_ids() {
        assert!(
            validate_legs(
                &OnchainSwapLeg {
                    kind: OnchainSwapLegKind::Rgb,
                    asset_id: None,
                    amount: 1,
                },
                &btc(1_000),
            )
            .is_err()
        );
        assert!(
            validate_legs(
                &OnchainSwapLeg {
                    kind: OnchainSwapLegKind::Btc,
                    asset_id: Some(ASSET_1.to_string()),
                    amount: 1_000,
                },
                &rgb(ASSET_2, 1),
            )
            .is_err()
        );
    }

    #[test]
    fn validates_expected_swap_psbt_shape() {
        let mut proposal = rgb_rgb_proposal();
        let (psbt, _, _) = build_psbt(&proposal).unwrap();
        proposal.txid = psbt.unsigned_tx.compute_txid().to_string();
        proposal.psbt = psbt.to_string();
        validate_proposal_psbt(&proposal, &psbt).unwrap();
    }

    #[test]
    fn rejects_tampered_swap_psbt_output() {
        let mut proposal = rgb_rgb_proposal();
        let (mut psbt, _, _) = build_psbt(&proposal).unwrap();
        proposal.txid = psbt.unsigned_tx.compute_txid().to_string();
        proposal.psbt = psbt.to_string();
        psbt.unsigned_tx.output[1].value = BdkAmount::from_sat(42);
        assert!(validate_proposal_psbt(&proposal, &psbt).is_err());
    }

    #[test]
    fn rejects_expired_offer() {
        let mut proposal = rgb_rgb_proposal();
        proposal.request.offer.expiration_timestamp = Some(1);
        assert!(ensure_offer_not_expired(&proposal.request.offer).is_err());
    }
}
