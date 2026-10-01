//! RGB assets locked in a two-leaf P2TR swap tree HTLC (claim leaf + refund leaf) and moved out
//! of it through the claim leaf, the refund leaf and the key path.
//!
//! The HTLC is built and signed here: rgb-lib only colors the spend (`psbt_op_prepare`) and signs
//! the wallet-owned fee input.

use bdk_wallet::TxOrdering;
use bitcoin::{
    Amount as BtcAmount, OutPoint as BtcOutPoint, Sequence as BtcSequence,
    Transaction as BtcTransaction, TxOut as BtcTxOut, Weight, Witness as BtcWitness,
    absolute::LockTime as BtcLockTime,
    hashes::{Hash, hash160},
    key::{Keypair, TapTweak, XOnlyPublicKey},
    opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_EQUALVERIFY, OP_HASH160},
    psbt::Input as PsbtInput,
    script::Builder,
    secp256k1::{All, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{
        LeafVersion, Signature as TapSignature, TapLeafHash, TaprootBuilder, TaprootSpendInfo,
    },
};
use rand::RngExt;

use super::*;

const HTLC_SAT: u64 = 1_000;
const LOCK_AMOUNT: u64 = 600;
const LOCK_BLINDING: u64 = 4_242;
const FEE_UTXO_SAT: u32 = 5_000;
// blocks between the lock and the refund timeout, enough to test an early refund
const REFUND_DELTA: u32 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HtlcPath {
    Claim,
    Refund,
    KeyPath,
}

/// Boltz-style swap tree.
///
/// In production the internal key is the MuSig2 aggregate of the claim and refund keys. On-chain
/// it is just a Schnorr key, so a single key held by the test exercises the same key-path spend.
struct SwapTreeHtlc {
    secp: Secp256k1<All>,
    preimage: [u8; 32],
    claim_key: Keypair,
    refund_key: Keypair,
    internal_key: Keypair,
    timeout_height: u32,
    claim_leaf: ScriptBuf,
    refund_leaf: ScriptBuf,
    spend_info: TaprootSpendInfo,
}

fn random_keypair(secp: &Secp256k1<All>) -> Keypair {
    let secret = SecretKey::from_slice(&rand::rng().random::<[u8; 32]>()).unwrap();
    Keypair::from_secret_key(secp, &secret)
}

fn claim_leaf_script(payment_hash160: &hash160::Hash, claim_key: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_HASH160)
        .push_slice(payment_hash160.to_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(claim_key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

fn refund_leaf_script(refund_key: &XOnlyPublicKey, timeout_height: u32) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(refund_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_int(timeout_height as i64)
        .push_opcode(OP_CLTV)
        .into_script()
}

impl SwapTreeHtlc {
    fn new(timeout_height: u32) -> Self {
        let secp = Secp256k1::new();
        let preimage = rand::rng().random::<[u8; 32]>();
        let claim_key = random_keypair(&secp);
        let refund_key = random_keypair(&secp);
        let internal_key = random_keypair(&secp);
        let claim_leaf = claim_leaf_script(
            &hash160::Hash::hash(&preimage),
            &claim_key.x_only_public_key().0,
        );
        let refund_leaf = refund_leaf_script(&refund_key.x_only_public_key().0, timeout_height);
        let spend_info = TaprootBuilder::new()
            .add_leaf(1, claim_leaf.clone())
            .unwrap()
            .add_leaf(1, refund_leaf.clone())
            .unwrap()
            .finalize(&secp, internal_key.x_only_public_key().0)
            .unwrap();
        Self {
            secp,
            preimage,
            claim_key,
            refund_key,
            internal_key,
            timeout_height,
            claim_leaf,
            refund_leaf,
            spend_info,
        }
    }

    fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.spend_info.output_key())
    }

    fn leaf(&self, path: HtlcPath) -> Option<&ScriptBuf> {
        match path {
            HtlcPath::Claim => Some(&self.claim_leaf),
            HtlcPath::Refund => Some(&self.refund_leaf),
            HtlcPath::KeyPath => None,
        }
    }

    fn witness(&self, path: HtlcPath, signature: &[u8]) -> BtcWitness {
        let mut witness = BtcWitness::new();
        witness.push(signature);
        if path == HtlcPath::Claim {
            witness.push(self.preimage);
        }
        if let Some(leaf) = self.leaf(path) {
            let control_block = self
                .spend_info
                .control_block(&(leaf.clone(), LeafVersion::TapScript))
                .unwrap();
            witness.push(leaf.as_bytes());
            witness.push(control_block.serialize());
        }
        witness
    }

    fn satisfaction_weight(&self, path: HtlcPath) -> Weight {
        Weight::from_wu(self.witness(path, &[0u8; 64]).size() as u64)
    }

    /// Sign and finalize the HTLC input of `tx` (sighash over all prevouts).
    fn sign(&self, tx: &BtcTransaction, prevouts: &[BtcTxOut], path: HtlcPath) -> BtcWitness {
        let input_index = prevouts
            .iter()
            .position(|p| p.script_pubkey == self.script_pubkey())
            .expect("tx must spend the HTLC");
        let mut cache = SighashCache::new(tx);
        let prevouts = Prevouts::All(prevouts);
        let (sighash, keypair) = match self.leaf(path) {
            Some(leaf) => (
                cache
                    .taproot_script_spend_signature_hash(
                        input_index,
                        &prevouts,
                        TapLeafHash::from_script(leaf, LeafVersion::TapScript),
                        TapSighashType::Default,
                    )
                    .unwrap(),
                if path == HtlcPath::Claim {
                    self.claim_key
                } else {
                    self.refund_key
                },
            ),
            None => (
                cache
                    .taproot_key_spend_signature_hash(
                        input_index,
                        &prevouts,
                        TapSighashType::Default,
                    )
                    .unwrap(),
                self.internal_key
                    .tap_tweak(&self.secp, self.spend_info.merkle_root())
                    .to_keypair(),
            ),
        };
        let msg = Message::from_digest(sighash.to_byte_array());
        let signature = TapSignature {
            signature: self.secp.sign_schnorr_no_aux_rand(&msg, &keypair),
            sighash_type: TapSighashType::Default,
        };
        self.witness(path, &signature.to_vec())
    }
}

fn psbt_prevouts(psbt: &Psbt) -> Vec<BtcTxOut> {
    psbt.inputs
        .iter()
        .zip(&psbt.unsigned_tx.input)
        .map(|(input, txin)| {
            input.witness_utxo.clone().unwrap_or_else(|| {
                input.non_witness_utxo.as_ref().unwrap().output[txin.previous_output.vout as usize]
                    .clone()
            })
        })
        .collect()
}

fn htlc_input_index(psbt: &Psbt, outpoint: BtcOutPoint) -> usize {
    psbt.unsigned_tx
        .input
        .iter()
        .position(|i| i.previous_output == outpoint)
        .expect("PSBT must spend the HTLC")
}

fn expected_nia(asset_id: &str, amount: u64) -> ExpectedTransfer {
    ExpectedTransfer {
        asset_id: asset_id.to_string(),
        asset_schema: AssetSchema::Nia,
        assignment: Assignment::Fungible(amount),
    }
}

fn coloring_info_for(asset_id: &str, vout: u32, amount: u64, blinding: u64) -> ColoringInfo {
    let asset_info_map = HashMap::from([(
        ContractId::from_str(asset_id).unwrap(),
        AssetColoringInfo {
            output_map: HashMap::from([(vout, amount)]),
            static_blinding: Some(blinding),
        },
    )]);
    ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    }
}

fn insert_op_return_first(psbt: &mut Psbt) {
    psbt.unsigned_tx.output.insert(
        0,
        BtcTxOut {
            value: BtcAmount::ZERO,
            script_pubkey: ScriptBuf::new_op_return([]),
        },
    );
    psbt.outputs.insert(0, Default::default());
}

fn tip_height(party: &SinglesigParty) -> u32 {
    party.wallet.indexer().get_latest_block_height().unwrap()
}

fn fee_utxo(party: &mut SinglesigParty) -> BtcOutPoint {
    party
        .list_unspents(true)
        .into_iter()
        .find(|u| {
            u.utxo.colorable
                && u.rgb_allocations.is_empty()
                && u.utxo.btc_amount >= FEE_UTXO_SAT as u64
        })
        .expect("uncolored fee UTXO")
        .utxo
        .outpoint
        .into()
}

fn funded_party_with_fee_utxos() -> SinglesigParty {
    let mut party = get_funded_noutxo_party!();
    party.create_utxos(false, Some(3), Some(FEE_UTXO_SAT), FEE_RATE, None);
    party
}

struct LockedHtlc {
    htlc: SwapTreeHtlc,
    asset_id: String,
    contract_id: ContractId,
    recipient_id: String,
    outpoint: BtcOutPoint,
    txout: BtcTxOut,
}

/// Lock `LOCK_AMOUNT` of a freshly issued NIA in the HTLC through the regular send path: the HTLC
/// is a witness recipient (`recipient_id_from_script_buf` + `WitnessData`) and the send is a
/// donation, so it is broadcast without waiting for an ACK and the consignment is on the proxy
/// under the HTLC recipient ID.
fn lock_in_htlc(sender: &mut SinglesigParty, timeout_height: Option<u32>) -> LockedHtlc {
    let asset = sender.issue_asset_nia(Some(&[AMOUNT]));
    let htlc =
        SwapTreeHtlc::new(timeout_height.unwrap_or_else(|| tip_height(sender) + REFUND_DELTA));
    let htlc_spk = htlc.script_pubkey();
    let recipient_id =
        recipient_id_from_script_buf(htlc_spk.clone(), BitcoinNetwork::Regtest).unwrap();
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            recipient_id: recipient_id.clone(),
            witness_data: Some(WitnessData {
                amount_sat: HTLC_SAT,
                blinding: Some(LOCK_BLINDING),
            }),
            assignment: Assignment::Fungible(LOCK_AMOUNT),
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let online = sender.party_online();
    let lock_txid = sender
        .wallet
        .send(
            online,
            recipient_map,
            true,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            default_send_expiration(),
            None,
        )
        .unwrap()
        .txid;
    mine_tx(false, &lock_txid);

    let lock_tx = sender
        .wallet
        .bdk_wallet()
        .get_tx(bitcoin::Txid::from_str(&lock_txid).unwrap())
        .expect("the sender knows its lock transaction")
        .tx_node
        .tx
        .clone();
    let vout = lock_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == htlc_spk)
        .expect("lock transaction must pay the HTLC script") as u32;
    let outpoint = BtcOutPoint {
        txid: bitcoin::Txid::from_str(&lock_txid).unwrap(),
        vout,
    };
    LockedHtlc {
        htlc,
        contract_id: ContractId::from_str(&asset.asset_id).unwrap(),
        asset_id: asset.asset_id,
        recipient_id,
        outpoint,
        txout: BtcTxOut {
            value: BtcAmount::from_sat(HTLC_SAT),
            script_pubkey: htlc_spk,
        },
    }
}

/// Import the lock into a wallet that did not create it, pinning the proxy consignment to the HTLC
/// output.
fn accept_htlc_lock(party: &mut SinglesigParty, locked: &LockedHtlc) {
    let online = party.party_online();
    let (consignment, assignments) = party
        .wallet
        .fetch_and_accept_transfer_by_recipient_id(
            online,
            locked.recipient_id.clone(),
            locked.recipient_id.clone(),
            &PROXY_ENDPOINT,
            LOCK_BLINDING,
            MIN_CONFIRMATIONS,
            expected_nia(&locked.asset_id, LOCK_AMOUNT),
        )
        .unwrap();
    assert_eq!(assignments, vec![Assignment::Fungible(LOCK_AMOUNT)]);
    party
        .wallet
        .save_new_asset(online, consignment, locked.outpoint.txid.to_string())
        .unwrap();
}

fn assert_htlc_holds_lock(party: &SinglesigParty, locked: &LockedHtlc) {
    let rows = party
        .wallet
        .contract_assignments_for_outpoints(locked.contract_id, vec![locked.outpoint.into()])
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, vec![Assignment::Fungible(LOCK_AMOUNT)]);
}

/// Build an HTLC spend to `dest_script` with a fee input from `party`'s wallet. With `colored`
/// the PSBT carries the OP_RETURN commitment and the LOCK_AMOUNT allocation on `dest_script`.
fn build_htlc_spend(
    party: &mut SinglesigParty,
    locked: &LockedHtlc,
    path: HtlcPath,
    dest_script: ScriptBuf,
    colored: bool,
) -> Psbt {
    let fee_utxo = fee_utxo(party);
    let mut builder = party.wallet.bdk_wallet_mut().build_tx();
    builder.ordering(TxOrdering::Untouched);
    builder
        .add_foreign_utxo_with_sequence(
            locked.outpoint,
            PsbtInput {
                witness_utxo: Some(locked.txout.clone()),
                ..Default::default()
            },
            locked.htlc.satisfaction_weight(path),
            BtcSequence::ENABLE_RBF_NO_LOCKTIME,
        )
        .unwrap();
    builder.add_utxo(fee_utxo).unwrap();
    builder.manually_selected_only();
    builder
        .add_recipient(dest_script, BtcAmount::from_sat(HTLC_SAT))
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    if path == HtlcPath::Refund {
        builder.nlocktime(BtcLockTime::from_height(locked.htlc.timeout_height).unwrap());
    }
    let mut psbt = builder.finish().unwrap();
    if colored {
        insert_op_return_first(&mut psbt);
    }
    psbt
}

fn dest_vout(psbt: &Psbt, dest_script: &ScriptBuf) -> u32 {
    psbt.unsigned_tx
        .output
        .iter()
        .position(|o| &o.script_pubkey == dest_script)
        .unwrap() as u32
}

/// Finalize the HTLC input by hand, then let the wallet sign and finalize its fee input. Neither
/// step may touch the other's input. The HTLC goes first: `finalize_psbt` fails unless every input
/// ends up finalized, and BDK skips inputs that already are.
fn sign_htlc_spend(
    party: &SinglesigParty,
    locked: &LockedHtlc,
    psbt: &Psbt,
    path: HtlcPath,
) -> BtcTransaction {
    let mut psbt = psbt.clone();
    let htlc_index = htlc_input_index(&psbt, locked.outpoint);
    let witness = locked
        .htlc
        .sign(&psbt.unsigned_tx, &psbt_prevouts(&psbt), path);
    psbt.inputs[htlc_index].final_script_witness = Some(witness.clone());

    let signed = party.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let finalized = party.wallet.finalize_psbt(signed, None).unwrap();
    let finalized = Psbt::from_str(&finalized).unwrap();
    assert_eq!(
        finalized.inputs[htlc_index].final_script_witness,
        Some(witness),
        "wallet signing must leave the HTLC input untouched"
    );
    for (i, input) in finalized.inputs.iter().enumerate() {
        assert!(
            input.final_script_witness.is_some(),
            "input {i} must be finalized"
        );
    }
    finalized.extract_tx().expect("valid tx")
}

struct PreparedSpend {
    psbt: Psbt,
    operation_id: String,
    operation_dir: String,
    allocations: Vec<PsbtOpAllocation>,
    dest_vout: u32,
    receive_data: ReceiveData,
    proxy_recipient_id: String,
}

/// Color an HTLC spend to a fresh `witness_receive` output of `party`.
fn prepare_htlc_spend(
    party: &mut SinglesigParty,
    locked: &LockedHtlc,
    path: HtlcPath,
    blinding: u64,
) -> PreparedSpend {
    let receive_data = party.witness_receive();
    prepare_htlc_spend_to(party, locked, path, blinding, receive_data).unwrap()
}

fn prepare_htlc_spend_to(
    party: &mut SinglesigParty,
    locked: &LockedHtlc,
    path: HtlcPath,
    blinding: u64,
    receive_data: ReceiveData,
) -> Result<PreparedSpend, Error> {
    let proxy_recipient_id = Invoice::new(receive_data.invoice.clone())
        .unwrap()
        .invoice_data()
        .proxy_recipient_id;
    let dest_script = script_buf_from_recipient_id(receive_data.recipient_id.clone())
        .unwrap()
        .expect("witness_receive yields a script");
    let mut psbt = build_htlc_spend(party, locked, path, dest_script.clone(), true);
    let dest_vout = dest_vout(&psbt, &dest_script);
    let PsbtOpPrepareResult {
        operation_id,
        operation_dir,
        allocations,
        ..
    } = party.wallet.psbt_op_prepare(
        &mut psbt,
        coloring_info_for(&locked.asset_id, dest_vout, LOCK_AMOUNT, blinding),
        vec![locked.outpoint],
        MIN_CONFIRMATIONS,
        None,
    )?;
    assert!(
        psbt.unsigned_tx.output[0].script_pubkey.is_op_return(),
        "commitment must stay in output 0"
    );
    Ok(PreparedSpend {
        psbt,
        operation_id,
        operation_dir,
        allocations,
        dest_vout,
        receive_data,
        proxy_recipient_id,
    })
}

/// Broadcast, apply and settle the incoming `witness_receive`, as in
/// `psbt_op_foreign_escrow_witness_receive_apply_refresh_balance`.
fn broadcast_and_settle(
    party: &mut SinglesigParty,
    locked: &LockedHtlc,
    prepared: &PreparedSpend,
    tx: BtcTransaction,
) {
    let txid = tx.compute_txid().to_string();
    party.wallet.broadcast_tx(tx).unwrap();
    party
        .wallet
        .psbt_op_apply(party.party_online(), &prepared.operation_id)
        .unwrap();
    assert_eq!(
        party
            .wallet
            .psbt_op_reconcile(&prepared.operation_id)
            .unwrap(),
        PsbtOperationStatus::Applied
    );
    mine_tx(false, &txid);

    let consignment_path = crate::wallet::rust_only::psbt_op_consignment_path(
        &party.wallet.get_wallet_dir().join(&prepared.operation_dir),
        &locked.asset_id,
    );
    party
        .wallet
        .post_consignment_to_proxy(
            &get_proxy_client(None),
            prepared.proxy_recipient_id.clone(),
            consignment_path,
            txid,
            Some(prepared.dest_vout),
        )
        .unwrap();
    party.wait_for_refresh_raw(None, Some(&[prepared.receive_data.batch_transfer_idx]));
    mine(false);
    party.wait_for_refresh(None);

    let receive = party
        .list_transfers(Some(&locked.asset_id))
        .into_iter()
        .find(|t| {
            t.kind == TransferKind::ReceiveWitness
                && t.recipient_id.as_deref() == Some(prepared.receive_data.recipient_id.as_str())
        })
        .expect("incoming witness transfer");
    assert_eq!(receive.status, TransferStatus::Settled);
    assert_eq!(receive.assignments, vec![Assignment::Fungible(LOCK_AMOUNT)]);
}

/// Spend the asset with a regular send to prove the settled allocation is usable.
fn send_onward(party: &mut SinglesigParty, asset_id: &str, amount: u64) {
    let mut rcv_party = get_funded_party!();
    let receive_data = rcv_party.blind_receive();
    let recipient_map = HashMap::from([(
        asset_id.to_string(),
        vec![Recipient {
            assignment: Assignment::Fungible(amount),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let txid = party.send(recipient_map, FEE_RATE, None).txid;
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(asset_id));
    mine_tx(false, &txid);
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(asset_id));
    assert!(party.check_test_transfer_status_sender(&txid, TransferStatus::Settled));
    assert_eq!(rcv_party.get_asset_balance(asset_id).settled, amount);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn lock_then_claim() {
    initialize();

    let mut sender = get_funded_party!();
    let mut claimer = funded_party_with_fee_utxos();
    let locked = lock_in_htlc(&mut sender, None);
    accept_htlc_lock(&mut claimer, &locked);
    assert_htlc_holds_lock(&claimer, &locked);

    let prepared = prepare_htlc_spend(&mut claimer, &locked, HtlcPath::Claim, 888);
    let tx = sign_htlc_spend(&claimer, &locked, &prepared.psbt, HtlcPath::Claim);
    assert_eq!(
        tx.input[htlc_input_index(&prepared.psbt, locked.outpoint)]
            .witness
            .nth(1),
        Some(&locked.htlc.preimage[..]),
        "claim witness must reveal the preimage"
    );
    broadcast_and_settle(&mut claimer, &locked, &prepared, tx);

    let balance = claimer.get_asset_balance(&locked.asset_id);
    assert_eq!(balance.settled, LOCK_AMOUNT);
    assert_eq!(balance.spendable, LOCK_AMOUNT);
    send_onward(&mut claimer, &locked.asset_id, AMOUNT_SMALL);
    assert_eq!(
        claimer.get_asset_balance(&locked.asset_id).settled,
        LOCK_AMOUNT - AMOUNT_SMALL
    );
}

// serial: the early-refund check needs the tip to stay below the timeout
#[cfg(feature = "electrum")]
#[test]
#[serial]
fn lock_then_refund_after_timeout() {
    initialize();

    let mut sender = funded_party_with_fee_utxos();
    let locked = lock_in_htlc(&mut sender, None);
    // the sender consumed the lock fascia on broadcast, no import needed
    assert_htlc_holds_lock(&sender, &locked);
    sender.wait_for_refresh(Some(&locked.asset_id));
    assert_eq!(
        sender.get_asset_balance(&locked.asset_id).settled,
        AMOUNT - LOCK_AMOUNT
    );

    let prepared = prepare_htlc_spend(&mut sender, &locked, HtlcPath::Refund, 889);
    assert_eq!(
        prepared.psbt.unsigned_tx.lock_time,
        BtcLockTime::from_height(locked.htlc.timeout_height).unwrap()
    );
    assert_ne!(
        prepared.psbt.unsigned_tx.input[htlc_input_index(&prepared.psbt, locked.outpoint)].sequence,
        BtcSequence::MAX,
        "a final sequence would disable nLockTime"
    );
    let tx = sign_htlc_spend(&sender, &locked, &prepared.psbt, HtlcPath::Refund);

    assert!(tip_height(&sender) < locked.htlc.timeout_height);
    let early = sender.wallet.broadcast_tx(tx.clone());
    assert_matches!(
        early,
        Err(Error::FailedBroadcast { ref details }) if details.contains("non-final")
    );

    while tip_height(&sender) < locked.htlc.timeout_height {
        mine(false);
    }
    broadcast_and_settle(&mut sender, &locked, &prepared, tx);

    let balance = sender.get_asset_balance(&locked.asset_id);
    assert_eq!(balance.settled, AMOUNT);
    assert_eq!(balance.spendable, AMOUNT);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn lock_then_cooperative_key_path_spend() {
    initialize();

    let mut sender = get_funded_party!();
    let mut claimer = funded_party_with_fee_utxos();
    let locked = lock_in_htlc(&mut sender, None);
    accept_htlc_lock(&mut claimer, &locked);

    let prepared = prepare_htlc_spend(&mut claimer, &locked, HtlcPath::KeyPath, 890);
    let commitment = prepared.psbt.unsigned_tx.output[0].script_pubkey.clone();
    assert!(commitment.is_op_return());
    assert!(
        commitment.len() > 2,
        "coloring must write the commitment into the OP_RETURN"
    );
    let tx = sign_htlc_spend(&claimer, &locked, &prepared.psbt, HtlcPath::KeyPath);
    let htlc_witness = &tx.input[htlc_input_index(&prepared.psbt, locked.outpoint)].witness;
    assert_eq!(
        htlc_witness.len(),
        1,
        "key path spends carry only a signature"
    );
    assert_eq!(tx.output[0].script_pubkey, commitment);
    broadcast_and_settle(&mut claimer, &locked, &prepared, tx);

    let balance = claimer.get_asset_balance(&locked.asset_id);
    assert_eq!(balance.settled, LOCK_AMOUNT);
    assert_eq!(balance.spendable, LOCK_AMOUNT);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn claim_prepared_then_aborted_then_claimed() {
    initialize();

    let mut sender = get_funded_party!();
    let mut claimer = funded_party_with_fee_utxos();
    let locked = lock_in_htlc(&mut sender, None);
    accept_htlc_lock(&mut claimer, &locked);

    let receive_data = claimer.witness_receive();
    let balance_before = claimer.get_asset_balance(&locked.asset_id);
    let txos_before = claimer.db_txos().len();
    let colorings_before = claimer.db_colorings();

    let aborted =
        prepare_htlc_spend_to(&mut claimer, &locked, HtlcPath::Claim, 891, receive_data).unwrap();
    let aborted_txid = aborted.psbt.unsigned_tx.compute_txid().to_string();
    // signed but never broadcast
    let _ = sign_htlc_spend(&claimer, &locked, &aborted.psbt, HtlcPath::Claim);
    assert!(claimer.check_test_transfer_status_sender(&aborted_txid, TransferStatus::Initiated));
    claimer
        .wallet
        .psbt_op_abort(claimer.party_online(), &aborted.operation_id)
        .unwrap();
    assert_eq!(
        claimer
            .wallet
            .psbt_op_reconcile(&aborted.operation_id)
            .unwrap(),
        PsbtOperationStatus::Failed
    );
    assert!(claimer.check_test_transfer_status_sender(&aborted_txid, TransferStatus::Failed));

    // stash: the HTLC still holds the lock; DB: no new allocations, balance unchanged
    assert_htlc_holds_lock(&claimer, &locked);
    assert_eq!(claimer.get_asset_balance(&locked.asset_id), balance_before);
    let failed_idx: HashSet<i32> = claimer
        .db_batch_transfers()
        .into_iter()
        .filter(|b| b.status == TransferStatus::Failed)
        .map(|b| b.idx)
        .collect();
    let failed_asset_transfers: HashSet<i32> = claimer
        .db_asset_transfers()
        .into_iter()
        .filter(|a| failed_idx.contains(&a.batch_transfer_idx))
        .map(|a| a.idx)
        .collect();
    let live_colorings: Vec<_> = claimer
        .db_colorings()
        .into_iter()
        .filter(|c| !failed_asset_transfers.contains(&c.asset_transfer_idx))
        .collect();
    assert_eq!(live_colorings, colorings_before);
    assert_eq!(claimer.db_txos().len(), txos_before);
    assert!(
        !claimer.db_txos().iter().any(|t| t.txid == aborted_txid),
        "abort must not leave claim outputs as wallet TXOs"
    );
    let aborted_receive = claimer
        .list_transfers_filtered(AssetFilter::AnyOrNone, None)
        .into_iter()
        .find(|t| t.recipient_id.as_deref() == Some(aborted.receive_data.recipient_id.as_str()))
        .unwrap();
    assert_eq!(aborted_receive.status, TransferStatus::WaitingCounterparty);

    let prepared = prepare_htlc_spend(&mut claimer, &locked, HtlcPath::Claim, 892);
    let tx = sign_htlc_spend(&claimer, &locked, &prepared.psbt, HtlcPath::Claim);
    broadcast_and_settle(&mut claimer, &locked, &prepared, tx);
    assert_eq!(
        claimer.get_asset_balance(&locked.asset_id).settled,
        LOCK_AMOUNT
    );
}

/// Invariant: RGB state on the HTLC lives in a single-use seal. A spend of the HTLC without an RGB
/// commitment closes that seal with no transition, so the asset is burned: no output of the spend
/// carries it and the HTLC outpoint cannot be spent again. The stash still reports the stale
/// allocation (it is not spend-aware), so callers must also check the outpoint is unspent. This is
/// why a maker must never produce an uncolored HTLC spend.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn uncolored_htlc_spend_burns_asset() {
    initialize();

    let mut sender = get_funded_party!();
    let mut claimer = funded_party_with_fee_utxos();
    let locked = lock_in_htlc(&mut sender, None);
    accept_htlc_lock(&mut claimer, &locked);

    let dest_script = BdkAddress::from_str(&claimer.get_address())
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let psbt = build_htlc_spend(&mut claimer, &locked, HtlcPath::Claim, dest_script, false);
    assert!(
        !psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    let tx = sign_htlc_spend(&claimer, &locked, &psbt, HtlcPath::Claim);
    let burn_txid = tx.compute_txid();
    claimer.wallet.broadcast_tx(tx.clone()).unwrap();
    mine_tx(false, &burn_txid.to_string());

    let burn_outpoints: Vec<Outpoint> = (0..tx.output.len() as u32)
        .map(|vout| {
            BtcOutPoint {
                txid: burn_txid,
                vout,
            }
            .into()
        })
        .collect();
    for (outpoint, assignments) in claimer
        .wallet
        .contract_assignments_for_outpoints(locked.contract_id, burn_outpoints)
        .unwrap()
    {
        assert!(
            assignments.is_empty(),
            "uncolored spend output {outpoint:?} must not carry the asset"
        );
    }
    assert_htlc_holds_lock(&claimer, &locked);
    assert_eq!(claimer.get_asset_balance(&locked.asset_id).settled, 0);

    // a colored claim of the stale allocation, if it can be prepared at all, can never be mined
    let receive_data = claimer.witness_receive();
    if let Ok(prepared) =
        prepare_htlc_spend_to(&mut claimer, &locked, HtlcPath::Claim, 893, receive_data)
    {
        let tx = sign_htlc_spend(&claimer, &locked, &prepared.psbt, HtlcPath::Claim);
        let broadcast = claimer.wallet.broadcast_tx(tx);
        assert_matches!(broadcast, Err(Error::FailedBroadcast { .. }));
        claimer
            .wallet
            .psbt_op_abort(claimer.party_online(), &prepared.operation_id)
            .unwrap();
    }
    assert_eq!(claimer.get_asset_balance(&locked.asset_id).settled, 0);
}

// no services needed from here on

fn synthetic_spend(htlc: &SwapTreeHtlc, lock_time: BtcLockTime) -> (BtcTransaction, Vec<BtcTxOut>) {
    let other_prevout = BtcTxOut {
        value: BtcAmount::from_sat(5_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(
            random_keypair(&htlc.secp)
                .x_only_public_key()
                .0
                .dangerous_assume_tweaked(),
        ),
    };
    let htlc_prevout = BtcTxOut {
        value: BtcAmount::from_sat(HTLC_SAT),
        script_pubkey: htlc.script_pubkey(),
    };
    let txin = |byte: u8| bitcoin::TxIn {
        previous_output: BtcOutPoint {
            txid: bitcoin::Txid::from_byte_array([byte; 32]),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: BtcSequence::ENABLE_RBF_NO_LOCKTIME,
        witness: BtcWitness::new(),
    };
    let tx = BtcTransaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time,
        input: vec![txin(1), txin(2)],
        output: vec![
            BtcTxOut {
                value: BtcAmount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([7u8; 32]),
            },
            BtcTxOut {
                value: BtcAmount::from_sat(5_500),
                script_pubkey: htlc.script_pubkey(),
            },
        ],
    };
    // HTLC deliberately second, to check the input index is resolved
    (tx, vec![other_prevout, htlc_prevout])
}

fn htlc_signature_valid(htlc: &SwapTreeHtlc, tx: &BtcTransaction, prevouts: &[BtcTxOut]) -> bool {
    let witness = &tx.input[1].witness;
    let signature = TapSignature::from_slice(witness.nth(0).unwrap()).unwrap();
    assert_eq!(signature.sighash_type, TapSighashType::Default);
    let mut cache = SighashCache::new(tx);
    let prevouts = Prevouts::All(prevouts);
    let (sighash, key) = if witness.len() == 1 {
        (
            cache
                .taproot_key_spend_signature_hash(1, &prevouts, TapSighashType::Default)
                .unwrap(),
            htlc.spend_info.output_key().to_x_only_public_key(),
        )
    } else {
        let control_block =
            bitcoin::taproot::ControlBlock::decode(witness.last().unwrap()).unwrap();
        let leaf = ScriptBuf::from_bytes(witness.nth(witness.len() - 2).unwrap().to_vec());
        assert!(control_block.verify_taproot_commitment(
            &htlc.secp,
            htlc.spend_info.output_key().to_x_only_public_key(),
            &leaf,
        ));
        let key = if leaf == htlc.claim_leaf {
            assert_eq!(witness.len(), 4);
            let preimage = witness.nth(1).unwrap();
            assert_eq!(
                claim_leaf_script(
                    &hash160::Hash::hash(preimage),
                    &htlc.claim_key.x_only_public_key().0
                ),
                leaf,
                "preimage must satisfy the claim leaf hashlock"
            );
            htlc.claim_key.x_only_public_key().0
        } else {
            assert_eq!(leaf, htlc.refund_leaf);
            assert_eq!(witness.len(), 3);
            htlc.refund_key.x_only_public_key().0
        };
        (
            cache
                .taproot_script_spend_signature_hash(
                    1,
                    &prevouts,
                    TapLeafHash::from_script(&leaf, LeafVersion::TapScript),
                    TapSighashType::Default,
                )
                .unwrap(),
            key,
        )
    };
    htlc.secp
        .verify_schnorr(
            &signature.signature,
            &Message::from_digest(sighash.to_byte_array()),
            &key,
        )
        .is_ok()
}

#[test]
#[parallel]
fn swap_tree_leaves_match_boltz_layout() {
    let htlc = SwapTreeHtlc::new(1_234);
    let claim_x = htlc.claim_key.x_only_public_key().0.serialize();
    let refund_x = htlc.refund_key.x_only_public_key().0.serialize();

    let mut claim = vec![0xa9, 0x14];
    claim.extend(hash160::Hash::hash(&htlc.preimage).to_byte_array());
    claim.extend([0x88, 0x20]);
    claim.extend(claim_x);
    claim.push(0xac);
    assert_eq!(htlc.claim_leaf.as_bytes(), claim);

    let mut refund = vec![0x20];
    refund.extend(refund_x);
    // 1234 = 0x04d2, minimally encoded little endian
    refund.extend([0xad, 0x02, 0xd2, 0x04, 0xb1]);
    assert_eq!(htlc.refund_leaf.as_bytes(), refund);

    assert!(htlc.script_pubkey().is_p2tr());
    assert!(htlc.spend_info.merkle_root().is_some());
    for leaf in [&htlc.claim_leaf, &htlc.refund_leaf] {
        let control_block = htlc
            .spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        assert_eq!(control_block.leaf_version, LeafVersion::TapScript);
        assert_eq!(
            control_block.merkle_branch.len(),
            1,
            "both leaves at depth 1"
        );
    }
}

#[test]
#[parallel]
fn swap_tree_witnesses_verify() {
    let htlc = SwapTreeHtlc::new(1_234);
    for (path, lock_time) in [
        (HtlcPath::Claim, BtcLockTime::ZERO),
        (
            HtlcPath::Refund,
            BtcLockTime::from_height(htlc.timeout_height).unwrap(),
        ),
        (HtlcPath::KeyPath, BtcLockTime::ZERO),
    ] {
        let (mut tx, prevouts) = synthetic_spend(&htlc, lock_time);
        let witness = htlc.sign(&tx, &prevouts, path);
        assert_eq!(
            witness.size() as u64,
            htlc.satisfaction_weight(path).to_wu(),
            "{path:?} satisfaction weight must match the real witness"
        );
        tx.input[1].witness = witness;
        assert!(htlc_signature_valid(&htlc, &tx, &prevouts), "{path:?}");

        // the sighash commits to the OP_RETURN: rewriting the commitment invalidates it
        let mut recolored = tx.clone();
        recolored.output[0].script_pubkey = ScriptBuf::new_op_return([8u8; 32]);
        assert!(
            !htlc_signature_valid(&htlc, &recolored, &prevouts),
            "{path:?} signature must not survive recoloring"
        );
        // and to every prevout, not only the HTLC one
        let mut other_prevouts = prevouts.clone();
        other_prevouts[0].value = BtcAmount::from_sat(5_001);
        assert!(
            !htlc_signature_valid(&htlc, &tx, &other_prevouts),
            "{path:?}"
        );
    }
}

/// Import the lock with the wallet-free fetch and the pinned accept, which also saves the asset.
fn accept_htlc_lock_pinned(party: &mut SinglesigParty, locked: &LockedHtlc) -> AcceptedTransfer {
    let fetched = crate::wallet::rust_only::fetch_consignment_by_recipient_id(
        &PROXY_ENDPOINT,
        locked.recipient_id.clone(),
    )
    .unwrap();
    let online = party.party_online();
    party
        .wallet
        .accept_transfer_pinned(
            online,
            fetched,
            locked.recipient_id.clone(),
            LOCK_BLINDING,
            MIN_CONFIRMATIONS,
            expected_nia(&locked.asset_id, LOCK_AMOUNT),
        )
        .unwrap()
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn pinned_accept_then_claim_settles_through_the_operation() {
    initialize();

    let mut sender = get_funded_party!();
    let mut claimer = funded_party_with_fee_utxos();
    let locked = lock_in_htlc(&mut sender, None);

    // nothing posted under an unknown key
    let missing = crate::wallet::rust_only::fetch_consignment_by_recipient_id(
        &PROXY_ENDPOINT,
        claimer.witness_receive().recipient_id,
    );
    assert_matches!(missing, Err(Error::NoConsignment));

    // the consignment is pinned to the HTLC output, not to another script
    let fetched = crate::wallet::rust_only::fetch_consignment_by_recipient_id(
        &PROXY_ENDPOINT,
        locked.recipient_id.clone(),
    )
    .unwrap();
    let online = claimer.party_online();
    let other = claimer.witness_receive().recipient_id;
    let result = claimer.wallet.accept_transfer_pinned(
        online,
        fetched,
        other,
        LOCK_BLINDING,
        MIN_CONFIRMATIONS,
        expected_nia(&locked.asset_id, LOCK_AMOUNT),
    );
    assert_matches!(result, Err(Error::WitnessOutputMismatch { .. }));

    let accepted = accept_htlc_lock_pinned(&mut claimer, &locked);
    assert_eq!(
        accepted.assignments,
        vec![Assignment::Fungible(LOCK_AMOUNT)]
    );
    assert_eq!(accepted.outpoint, Outpoint::from(locked.outpoint));
    assert_htlc_holds_lock(&claimer, &locked);

    // the operation reports what its transition assigns, at prepare and on lookup
    let prepared = prepare_htlc_spend(&mut claimer, &locked, HtlcPath::Claim, 893);
    let expected = vec![PsbtOpAllocation {
        asset_id: locked.asset_id.clone(),
        vout: Some(prepared.dest_vout),
        assignment: Assignment::Fungible(LOCK_AMOUNT),
    }];
    assert_eq!(prepared.allocations, expected);
    let txid = prepared.psbt.unsigned_tx.compute_txid().to_string();
    assert_eq!(
        claimer.wallet.psbt_op_by_txid(&txid).unwrap().allocations,
        expected
    );

    let tx = sign_htlc_spend(&claimer, &locked, &prepared.psbt, HtlcPath::Claim);
    claimer.wallet.broadcast_tx(tx).unwrap();
    // not before the operation is applied
    let online = claimer.party_online();
    let result = claimer.wallet.psbt_op_provide_receive_consignment(
        online,
        &prepared.operation_id,
        &locked.asset_id,
    );
    assert_matches!(result, Err(Error::InvalidPsbtOperationStatus { .. }));
    claimer
        .wallet
        .psbt_op_apply(online, &prepared.operation_id)
        .unwrap();
    mine_tx(false, &txid);

    // a contract the operation doesn't move
    let other_asset = claimer.issue_asset_nia(Some(&[AMOUNT]));
    let result = claimer.wallet.psbt_op_provide_receive_consignment(
        online,
        &prepared.operation_id,
        &other_asset.asset_id,
    );
    assert_matches!(result, Err(Error::CannotProvideOutOfBandConsignment { .. }));

    // any spelling rgb-lib parses: no `rgb:` prefix, no dashes
    let bare_asset_id = locked.asset_id.trim_start_matches("rgb:").replace('-', "");
    claimer
        .wallet
        .psbt_op_provide_receive_consignment(online, &prepared.operation_id, &bare_asset_id)
        .unwrap();
    mine(false);
    claimer.wait_for_refresh(None);
    let receive = claimer
        .list_transfers(Some(&locked.asset_id))
        .into_iter()
        .find(|t| {
            t.kind == TransferKind::ReceiveWitness
                && t.recipient_id.as_deref() == Some(prepared.receive_data.recipient_id.as_str())
        })
        .expect("incoming witness transfer");
    assert_eq!(receive.status, TransferStatus::Settled);
    assert_eq!(receive.assignments, vec![Assignment::Fungible(LOCK_AMOUNT)]);
    assert_eq!(
        claimer.get_asset_balance(&locked.asset_id).settled,
        LOCK_AMOUNT
    );

    // the receive was handed over once; there is nothing left to match
    let result = claimer.wallet.psbt_op_provide_receive_consignment(
        online,
        &prepared.operation_id,
        &locked.asset_id,
    );
    assert_matches!(result, Err(Error::CannotProvideOutOfBandConsignment { .. }));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn ops_spending_lists_every_operation_on_an_outpoint() {
    initialize();

    let mut sender = get_funded_party!();
    let mut claimer = funded_party_with_fee_utxos();
    let locked = lock_in_htlc(&mut sender, None);
    accept_htlc_lock(&mut claimer, &locked);
    let htlc: Outpoint = locked.outpoint.into();

    assert!(
        claimer
            .wallet
            .psbt_ops_spending(htlc.clone())
            .unwrap()
            .is_empty()
    );

    let aborted = prepare_htlc_spend(&mut claimer, &locked, HtlcPath::Claim, 894);
    let ops = claimer.wallet.psbt_ops_spending(htlc.clone()).unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].operation_id, aborted.operation_id);
    assert_eq!(ops[0].status, PsbtOperationStatus::Prepared);
    assert_eq!(ops[0].allocations, aborted.allocations);

    // an aborted operation is still listed, with its status
    claimer
        .wallet
        .psbt_op_abort(claimer.party_online(), &aborted.operation_id)
        .unwrap();
    let prepared = prepare_htlc_spend(&mut claimer, &locked, HtlcPath::Claim, 895);
    let ops = claimer.wallet.psbt_ops_spending(htlc.clone()).unwrap();
    // both may be created within the same second, so compare regardless of order
    let mut listed: Vec<(&str, PsbtOperationStatus)> = ops
        .iter()
        .map(|op| (op.operation_id.as_str(), op.status))
        .collect();
    listed.sort_by_key(|(id, _)| *id);
    let mut expected = vec![
        (aborted.operation_id.as_str(), PsbtOperationStatus::Failed),
        (
            prepared.operation_id.as_str(),
            PsbtOperationStatus::Prepared,
        ),
    ];
    expected.sort_by_key(|(id, _)| *id);
    assert_eq!(listed, expected);

    // another output of the lock transaction is spent by neither
    let unrelated = Outpoint {
        txid: htlc.txid.clone(),
        vout: htlc.vout + 1,
    };
    assert!(
        claimer
            .wallet
            .psbt_ops_spending(unrelated)
            .unwrap()
            .is_empty()
    );

    let result = claimer.wallet.psbt_ops_spending(Outpoint {
        txid: s!("not a txid"),
        vout: 0,
    });
    assert_matches!(result, Err(Error::InvalidTxid));
}
