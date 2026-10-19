use super::*;

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn success() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    // wallets
    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();

    // create 1 UTXO and send the rest
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);

    // issue
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    // prepare PSBT
    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let mut psbt_copy = psbt.clone();
    assert!(
        !psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(psbt.proprietary.is_empty());

    // color PSBT
    assert_eq!(psbt.unsigned_tx.input.len(), 1);
    let mut output_map = HashMap::new();
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    let vout = output.0 as u32;
    output_map.insert(vout, AMOUNT); // sending AMOUNT since color_psbt doesn't support change
    let asset_coloring_info = AssetColoringInfo {
        output_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let (fascia, beneficiaries) = party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info.clone())
        .unwrap();

    // check PSBT
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(!psbt.proprietary.is_empty());
    let vout = vout + 1;

    // check fascia
    assert_eq!(fascia.bundles().len(), 1);
    let (_cid, bundle) = fascia.bundles().iter().next().unwrap();
    let im_keys = bundle.input_map.keys();
    assert_eq!(im_keys.len(), 1);
    let mut transitions = bundle.known_transitions.iter().map(|kt| &kt.transition);
    assert_eq!(transitions.len(), 1);
    let transition = transitions.next().unwrap();
    let assignments = &transition.assignments;
    assert_eq!(assignments.len(), 1);
    let (_, fungible) = assignments.iter().next().unwrap();
    let fungible = fungible.as_fungible();
    assert_eq!(fungible.len(), 1);
    let fungible = fungible.first().unwrap();
    let seal = fungible.revealed_seal().unwrap();
    let state = fungible.as_revealed_state();
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), vout);
    assert_eq!(seal.blinding, blinding);
    assert_eq!(state.as_u64(), AMOUNT);

    // check beneficiaries
    assert_eq!(beneficiaries.len(), 1);
    let (_cid, seals) = beneficiaries.first_key_value().unwrap();
    let seal = match seals.first().unwrap() {
        BuilderSeal::Revealed(r) => r,
        BuilderSeal::Concealed(_) => panic!("revealed expected"),
    };
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), vout);
    assert_eq!(seal.blinding, blinding);

    // color PSBT and consume
    let transfers = party_send
        .wallet
        .color_psbt_and_consume(&mut psbt_copy, coloring_info)
        .unwrap();

    // check that the two color_psbt* methods produce matching PSBTs (no additional changes)
    assert_eq!(psbt, psbt_copy);

    // save consignment to file
    let txid = psbt_copy.unsigned_tx.compute_txid().to_string();
    let transfers_dir = party_send.wallet.get_transfers_dir().join(&txid);
    let consignment_path = transfers_dir.join(CONSIGNMENT_FILE);
    std::fs::create_dir_all(&transfers_dir).unwrap();
    assert_eq!(transfers.len(), 1);
    transfers
        .first()
        .unwrap()
        .save_file(&consignment_path)
        .unwrap();

    // accept transfer
    recv_party
        .wallet
        .accept_transfer_consignment(
            recv_party.online,
            consignment_path,
            txid.clone(),
            vout,
            blinding,
        )
        .unwrap();

    // consume fascia
    party_send.wallet.consume_fascia(fascia, None).unwrap();
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn list_unspents_vanilla_success() {
    initialize();

    // wallets
    let mut party = get_empty_party!();

    // no unspents
    let bak_info_before = party.db_backup_info_opt();
    assert!(bak_info_before.is_none());
    let unspent_list = party.list_unspents_vanilla(None);
    let bak_info_after = party.db_backup_info_opt();
    assert!(bak_info_after.is_none());
    assert_eq!(unspent_list.len(), 0);

    let _guard = stop_mining();

    send_to_address(party.get_address());

    // one unspent, no confirmations
    let unspent_list = party.list_unspents_vanilla(None);
    assert_eq!(unspent_list.len(), 0);
    let unspent_list = party.list_unspents_vanilla(Some(0));
    assert_eq!(unspent_list.len(), 1);

    drop(_guard);
    mine(false);

    // one unspent, 1 confirmation
    let unspent_list = party.list_unspents_vanilla(None);
    assert_eq!(unspent_list.len(), 1);
    let unspent_list = party.list_unspents_vanilla(Some(0));
    assert_eq!(unspent_list.len(), 1);

    party.create_utxos_default();

    // one unspent (change), colored unspents not listed
    mine(false);
    let unspent_list = party.list_unspents_vanilla(None);
    assert_eq!(unspent_list.len(), 1);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn list_unspents_vanilla_skip_sync() {
    initialize();

    let mut party = get_empty_party!();

    fund_wallet(party.get_address());

    // no unspents if skipping sync
    let unspents = party
        .wallet
        .list_unspents_vanilla(party.online, MIN_CONFIRMATIONS, true)
        .unwrap();
    assert_eq!(unspents.len(), 0);

    // 1 unspent after manually syncing
    party
        .wallet
        .sync(
            party.online,
            SyncOptions {
                keychain: SyncKeychain::Vanilla {
                    lookback: INDEXER_SYNC_LOOKBACK as u32,
                },
                strategy: SyncStrategy::FastSync,
            },
        )
        .unwrap();
    let unspents = party
        .wallet
        .list_unspents_vanilla(party.online, MIN_CONFIRMATIONS, true)
        .unwrap();
    assert_eq!(unspents.len(), 1);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn save_new_asset_success() {
    initialize();
    let asset_amount: u64 = 66;

    // wallets
    let mut party = get_funded_party!();
    let mut rcv_party = get_empty_party!();

    // NIA
    let nia_asset = party.issue_asset_nia(None);
    party.check_save_new_asset(
        &mut rcv_party,
        &nia_asset.asset_id,
        Assignment::Fungible(asset_amount),
    );
    assert!(rcv_party.db_check_asset_exists(&nia_asset.asset_id).is_ok());
    let asset_model = rcv_party.db_asset(&nia_asset.asset_id);
    assert_eq!(asset_model.id, nia_asset.asset_id);
    assert_eq!(asset_model.initial_supply, AMOUNT.to_string());
    assert_eq!(asset_model.name, NAME);
    assert_eq!(asset_model.precision, PRECISION);
    assert_eq!(asset_model.ticker.unwrap(), TICKER);
    assert_eq!(asset_model.schema, AssetSchema::Nia);

    // CFA
    let cfa_asset = party.issue_asset_cfa(None, None);
    party.check_save_new_asset(
        &mut rcv_party,
        &cfa_asset.asset_id,
        Assignment::Fungible(asset_amount),
    );
    assert!(rcv_party.db_check_asset_exists(&cfa_asset.asset_id).is_ok());
    let asset_model = rcv_party.db_asset(&cfa_asset.asset_id);
    assert_eq!(asset_model.id, cfa_asset.asset_id);
    assert_eq!(asset_model.initial_supply, AMOUNT.to_string());
    assert_eq!(asset_model.name, NAME);
    assert_eq!(asset_model.precision, PRECISION);
    assert!(asset_model.ticker.is_none());
    assert_eq!(asset_model.schema, AssetSchema::Cfa);

    // UDA
    let image_str = ["tests", "qrcode.png"].join(MAIN_SEPARATOR_STR);
    let uda_asset =
        party.issue_asset_uda(Some(DETAILS), Some(FILE_STR), vec![&image_str, FILE_STR]);
    party.create_utxos(false, None, None, FEE_RATE, None);
    party.check_save_new_asset(&mut rcv_party, &uda_asset.asset_id, Assignment::NonFungible);
    assert!(rcv_party.db_check_asset_exists(&uda_asset.asset_id).is_ok());
    let asset_model = rcv_party.db_asset(&uda_asset.asset_id);
    assert_eq!(asset_model.id, uda_asset.asset_id);
    assert_eq!(asset_model.initial_supply, 1.to_string());
    assert_eq!(asset_model.name, NAME);
    assert_eq!(asset_model.precision, PRECISION);
    assert_eq!(asset_model.ticker.unwrap(), TICKER);
    assert_eq!(asset_model.schema, AssetSchema::Uda);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_uda() {
    initialize();

    let nonce = 42u64;

    // wallets
    let mut party_send = get_funded_noutxo_party!();

    // create 1 UTXO and send the rest
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    let mut recv_party = get_empty_party!();
    party_send.send_btc(&recv_party.get_address(), 99_998_200);

    // issue
    let asset = party_send.issue_asset_uda(None, None, vec![]);

    // create a custom BDK wallet with p2wpkh descriptor to avoid p2tr outputs,
    // so that the OP_RETURN is appended at the end
    let mnemonic = Mnemonic::parse_in(
        Language::English,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    let xprv = Xpriv::new_master(BdkNetwork::Regtest, &mnemonic.to_seed("")).unwrap();
    let custom_bdk_wallet =
        BdkWallet::create(format!("wpkh({xprv}/0/*)"), format!("wpkh({xprv}/1/*)"))
            .network(BdkNetwork::Regtest)
            .create_wallet_no_persist()
            .unwrap();
    let p2wpkh_addr = custom_bdk_wallet
        .peek_address(KeychainKind::External, 0)
        .address;

    // prepare PSBT: drain all wallet UTXOs to the p2wpkh address (no p2tr outputs, no change)
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .drain_wallet()
        .drain_to(p2wpkh_addr.script_pubkey())
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    assert!(
        !psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(psbt.proprietary.is_empty());

    // color PSBT
    assert_eq!(psbt.unsigned_tx.input.len(), 1);
    let mut output_map = HashMap::new();
    output_map.insert(0u32, 1u64); // UDA: assign to vout 0, amount 1
    let asset_coloring_info = AssetColoringInfo {
        output_map,
        static_blinding: None,
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: None,
        nonce: Some(nonce),
    };
    let (fascia, beneficiaries) = party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info)
        .unwrap();

    // check PSBT: OP_RETURN is appended at the end
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(!psbt.proprietary.is_empty());
    assert!(
        psbt.unsigned_tx
            .output
            .last()
            .unwrap()
            .script_pubkey
            .is_op_return()
    );

    // check fascia
    assert_eq!(fascia.bundles().len(), 1);
    let (_cid, bundle) = fascia.bundles().iter().next().unwrap();
    let im_keys = bundle.input_map.keys();
    assert_eq!(im_keys.len(), 1);
    let mut transitions = bundle.known_transitions.iter().map(|kt| &kt.transition);
    assert_eq!(transitions.len(), 1);
    let transition = transitions.next().unwrap();
    let assignments = &transition.assignments;
    assert_eq!(assignments.len(), 1);
    let (_, structured) = assignments.iter().next().unwrap();
    let structured = structured.as_structured();
    assert_eq!(structured.len(), 1);
    let seal = structured.first().unwrap().revealed_seal().unwrap();
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), 0);

    // check beneficiaries
    assert_eq!(beneficiaries.len(), 1);
    let (_cid, seals) = beneficiaries.first_key_value().unwrap();
    let seal = match seals.first().unwrap() {
        BuilderSeal::Revealed(r) => r,
        BuilderSeal::Concealed(_) => panic!("revealed expected"),
    };
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), 0);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_fail() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    // wallets
    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();

    // create 1 UTXO and send the rest
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);

    // issue
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    // prepare PSBT
    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();

    // prepare coloring data
    assert_eq!(psbt.unsigned_tx.input.len(), 1);
    let mut output_map = HashMap::new();
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    output_map.insert(output.0 as u32, AMOUNT);

    // wrong contract ID
    let fake_cid = "rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E";
    let asset_coloring_info = AssetColoringInfo {
        output_map: output_map.clone(),
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> =
        HashMap::from_iter([(ContractId::from_str(fake_cid).unwrap(), asset_coloring_info)]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    assert!(matches!(result, Err(Error::AssetNotFound { asset_id }) if asset_id == fake_cid));

    // wrong output map vout
    let fake_o_map: HashMap<u32, u64> = HashMap::from_iter([(666, AMOUNT)]);
    let asset_coloring_info = AssetColoringInfo {
        output_map: fake_o_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    let msg = "invalid vout in output_map, does not exist in the given PSBT";
    assert!(matches!(result, Err(Error::InvalidColoringInfo { details: m }) if m.starts_with(msg)));

    // wrong output map amount
    let fake_o_map = output_map.keys().map(|k| (*k, 999u64)).collect();
    let asset_coloring_info = AssetColoringInfo {
        output_map: fake_o_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info.clone());
    let msg = "total amount in output_map (999) greater than available (666)";
    assert!(matches!(result, Err(Error::InvalidColoringInfo { details: m }) if m == msg));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_overflow_fail() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    // wallets
    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();

    // create 1 UTXO and send the rest
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);

    // issue
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    // total amount in output_map overflows u64: two valid vouts whose amounts sum to
    // more than u64::MAX (the checked sum must error before reaching the available check)
    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let output_map: HashMap<u32, u64> = HashMap::from_iter([(0, u64::MAX), (1, 1)]);
    let asset_coloring_info = AssetColoringInfo {
        output_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    let msg = "total amount in output_map exceeds u64::MAX";
    assert!(matches!(result, Err(Error::InvalidColoringInfo { details: m }) if m == msg));

    // vout in output_map overflows u32 when shifted by 1 for the OP_RETURN output
    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let output_map: HashMap<u32, u64> = HashMap::from_iter([(u32::MAX, AMOUNT)]);
    let asset_coloring_info = AssetColoringInfo {
        output_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    let msg = "vout in output_map is too large";
    assert!(matches!(result, Err(Error::InvalidColoringInfo { details: m }) if m == msg));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_indexer_url_electrum_success() {
    initialize();

    let result = check_indexer_url(ELECTRUM_URL, BitcoinNetwork::Regtest);
    assert_matches!(result, Ok(IndexerProtocol::Electrum));

    let result = check_indexer_url(ELECTRUM_2_URL, BitcoinNetwork::Regtest);
    assert_matches!(result, Ok(IndexerProtocol::Electrum));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_indexer_url_electrum_fail() {
    initialize();

    let result = check_indexer_url(ELECTRUM_BLOCKSTREAM_URL, BitcoinNetwork::Regtest);
    let verbose_unsupported =
        "verbose transactions are unsupported by the provided electrum service";
    assert_matches!(result, Err(Error::InvalidIndexer { details: m }) if m.contains(verbose_unsupported));
}

#[cfg(feature = "esplora")]
#[test]
#[parallel]
fn check_indexer_url_esplora_success() {
    initialize();

    let result = check_indexer_url(ESPLORA_URL, BitcoinNetwork::Regtest);
    assert_matches!(result, Ok(IndexerProtocol::Esplora));
}

#[cfg(feature = "esplora")]
#[test]
#[parallel]
fn check_indexer_url_esplora_fail() {
    initialize();

    let result = check_indexer_url(PROXY_URL, BitcoinNetwork::Regtest);
    let invalid_indexer = s!("not a valid electrum nor esplora server");
    assert_matches!(result, Err(Error::InvalidIndexer { details: m }) if m == invalid_indexer);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_proxy_url_success() {
    initialize();

    assert!(check_proxy_url(PROXY_URL).is_ok());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_proxy_url_fail() {
    initialize();

    let result = check_proxy_url(PROXY_URL_MOD_PROTO);
    assert_matches!(result, Err(Error::InvalidProxyProtocol { version: _ }));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn accept_transfer_consignment_fail() {
    initialize();

    // === offline tests

    let mut offline_party = {
        let wallet = get_test_wallet(true, None);
        party!(wallet, Online { id: 0 })
    };
    let result = offline_party.wallet.accept_transfer_consignment(
        Online { id: 0 },
        PathBuf::from(s!("anyConsignmentPath")),
        FAKE_TXID.to_string(),
        0,
        0,
    );
    assert_matches!(result, Err(Error::Offline));

    // === online tests

    let mut party = get_empty_party!();

    // invalid txid
    let consignment_path = party.wallet.get_transfers_dir().join(CONSIGNMENT_FILE);
    let result = party.wallet.accept_transfer_consignment(
        party.online,
        consignment_path,
        s!("invalidTxid"),
        0,
        0,
    );
    assert_matches!(result, Err(Error::InvalidTxid));

    // invalid consignment path
    let result = party.wallet.accept_transfer_consignment(
        party.online,
        PathBuf::from(s!("invalidConsignmentPath")),
        FAKE_TXID.to_string(),
        0,
        0,
    );
    assert_matches!(result, Err(Error::InvalidFilePath { file_path: m }) if m == "invalidConsignmentPath");
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn get_tx_height_success() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_empty_party!();

    let _guard = stop_mining();
    let txid = party.send_btc(&rcv_party.get_address(), 1000);

    // unconfirmed TX
    let result = party.wallet.get_tx_height(party.online, txid.clone());
    assert_matches!(result, Ok(None));

    drop(_guard);
    mine(false);

    // confirmed TX
    let result = party.wallet.get_tx_height(party.online, txid);
    assert_matches!(result, Ok(Some(height)) if height > 0);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn get_tx_height_fail() {
    initialize();

    // === offline tests

    let offline_party = {
        let wallet = get_test_wallet(true, None);
        party!(wallet, Online { id: 0 })
    };
    let result = offline_party
        .wallet
        .get_tx_height(Online { id: 0 }, FAKE_TXID.to_string());
    assert_matches!(result, Err(Error::Offline));

    // === online tests

    let party = get_empty_party!();

    // invalid txid
    let result = party.wallet.get_tx_height(party.online, s!("invalidTxid"));
    assert_matches!(result, Err(Error::InvalidTxid));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn update_witnesses_fail() {
    initialize();

    let offline_party = {
        let wallet = get_test_wallet(true, None);
        party!(wallet, Online { id: 0 })
    };
    let result = offline_party
        .wallet
        .update_witnesses(Online { id: 0 }, 0, vec![]);
    assert_matches!(result, Err(Error::Offline));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn update_witnesses_success() {
    initialize();

    let party = get_empty_party!();

    let result = party.wallet.update_witnesses(party.online, 0, vec![]);
    assert!(result.is_ok());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn save_new_asset_fail() {
    initialize();

    let offline_party = {
        let wallet = get_test_wallet(true, None);
        party!(wallet, Online { id: 0 })
    };

    let mut party = get_funded_party!();
    let mut rcv_party = get_empty_party!();
    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.witness_receive();
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: Some(WitnessData {
                amount_sat: 1000,
                blinding: None,
            }),
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let txid = party.send_retry(&recipient_map);
    let consignment_path = party
        .wallet
        .get_send_consignment_path(&asset.asset_id, &txid);
    let consignment = RgbTransfer::load_file(consignment_path).unwrap();

    let result = offline_party
        .wallet
        .save_new_asset(Online { id: 0 }, consignment, txid);
    assert_matches!(result, Err(Error::Offline));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn send_end_db_update_only_fail() {
    initialize();

    let mut offline_party = {
        let wallet = get_test_wallet(true, None);
        party!(wallet, Online { id: 0 })
    };
    let result = offline_party
        .wallet
        .send_end_db_update_only(Online { id: 0 }, s!(""));
    assert_matches!(result, Err(Error::Offline));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn send_end_db_update_only_success() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive_asset_expiry(None, None);
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let begin = party
        .wallet
        .send_begin(
            party.online,
            recipient_map,
            true,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            default_send_expiration(),
            false,
        )
        .unwrap();
    let signed_psbt = party.wallet.sign_psbt(begin.psbt.clone(), None).unwrap();
    party.wallet.create_consignments(begin.psbt).unwrap();

    let result = party
        .wallet
        .send_end_db_update_only(party.online, signed_psbt)
        .unwrap();

    assert!(!result.txid.is_empty());
    assert_eq!(result.batch_transfer_idx, begin.batch_transfer_idx.unwrap());
    assert_eq!(result.entropy, begin.details.entropy);
    assert!(
        party
            .check_test_transfer_status_sender(&result.txid, TransferStatus::WaitingConfirmations,)
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn send_end_db_update_only_unknown_transfer() {
    initialize();

    let amount: u64 = 10;
    let mut party_1 = get_funded_party!();
    let mut party_2 = get_funded_party!();

    let asset = party_1.issue_asset_nia(None);
    let receive_data = party_1.blind_receive();
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(amount),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let unsigned_psbt = party_1.send_begin_result(&recipient_map).unwrap();
    let signed_psbt = party_1.wallet.sign_psbt(unsigned_psbt.psbt, None).unwrap();
    let psbt_txid = Psbt::from_str(&signed_psbt)
        .unwrap()
        .extract_tx()
        .unwrap()
        .compute_txid()
        .to_string();

    let result = party_2
        .wallet
        .send_end_db_update_only(party_2.online, signed_psbt);
    assert_matches!(result, Err(Error::UnknownTransfer { txid }) if txid == psbt_txid);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn upsert_witness_success() {
    initialize();

    let party = get_empty_party!();

    let result = party
        .wallet
        .upsert_witness(RgbTxid::from_str(FAKE_TXID).unwrap(), WitnessOrd::Tentative);
    assert!(result.is_ok());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn create_consignments_success() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive_asset_expiry(None, None);
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let psbt = party.send_begin_result(&recipient_map).unwrap().psbt;
    let result = party.wallet.create_consignments(psbt.clone());
    assert!(result.is_ok());
    let psbt = Psbt::from_str(&psbt).unwrap();
    let txid = psbt.extract_tx().unwrap().compute_txid().to_string();
    let consignment_path = party
        .wallet
        .get_asset_transfer_dir(party.wallet.get_transfers_dir().join(txid), &asset.asset_id)
        .join(CONSIGNMENT_FILE);
    assert!(consignment_path.is_file());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn offline() {
    initialize();

    let mut wallet = get_test_wallet(true, None);
    let result = wallet.list_unspents_vanilla(Online { id: 0 }, MIN_CONFIRMATIONS, false);
    assert_matches!(result, Err(Error::Offline));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn is_asset_known_success() {
    initialize();

    let mut party = get_funded_party!();
    let asset = party.issue_asset_nia(None);
    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();

    assert!(party.wallet.is_asset_known(contract_id).unwrap());

    let unknown_cid =
        ContractId::from_str("rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E").unwrap();
    assert!(!party.wallet.is_asset_known(unknown_cid).unwrap());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn list_asset_media_success() {
    initialize();

    let mut party = get_funded_party!();

    let nia_asset = party.issue_asset_nia(None);
    let nia_medias = party
        .wallet
        .list_asset_media(nia_asset.asset_id.clone())
        .unwrap();
    assert!(nia_medias.is_empty());

    let cfa_asset = party
        .wallet
        .issue_asset_cfa(
            NAME.to_string(),
            None,
            PRECISION,
            vec![AMOUNT],
            Some(FILE_STR.to_string()),
        )
        .unwrap();
    let cfa_medias = party
        .wallet
        .list_asset_media(cfa_asset.asset_id.clone())
        .unwrap();
    assert_eq!(cfa_medias.len(), 1);
    assert_eq!(cfa_medias.iter().next().unwrap().mime, "text/plain");

    let image_str = ["tests", "qrcode.png"].join(MAIN_SEPARATOR_STR);
    let uda_asset =
        party.issue_asset_uda(Some(DETAILS), Some(FILE_STR), vec![&image_str, FILE_STR]);
    let uda_medias = party
        .wallet
        .list_asset_media(uda_asset.asset_id.clone())
        .unwrap();
    // the token media and the 2nd attachment are the same file, so they are returned once
    assert_eq!(uda_medias.len(), 2);
    let mimes: Vec<_> = uda_medias.iter().map(|m| m.mime.as_str()).collect();
    assert!(mimes.contains(&"text/plain"));
    assert!(mimes.contains(&"image/png"));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn list_asset_media_fail() {
    initialize();

    let party = get_empty_party!();
    let unknown_asset_id = "rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E".to_string();
    let result = party.wallet.list_asset_media(unknown_asset_id);
    assert!(matches!(result, Err(Error::AssetNotFound { asset_id: _ })));
}

/// Build a PSBT sending `amt_sat` to `address` from the wallet of `party`, returning it with the
/// index of the recipient output.
#[cfg(feature = "electrum")]
fn build_send_psbt(party: &mut SinglesigParty, address: &str, amt_sat: u64) -> (Psbt, u32) {
    let address = BdkAddress::from_str(address).unwrap();
    let mut tx_builder = party.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let psbt = tx_builder.finish().unwrap();
    let vout = output_index_with_value(&psbt, amt_sat);
    (psbt, vout)
}

#[cfg(feature = "electrum")]
fn output_index_with_value(psbt: &Psbt, amt_sat: u64) -> u32 {
    psbt.unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32
}

/// Whether the RGB stash of `wallet` holds assignments of `contract_id` on `outpoint`.
#[cfg(feature = "electrum")]
fn stash_has_assignments(wallet: &Wallet, contract_id: ContractId, outpoint: OutPoint) -> bool {
    let runtime = wallet.rgb_runtime().unwrap();
    runtime
        .contract_assignments_for(contract_id, [outpoint])
        .unwrap()
        .values()
        .any(|assignments| !assignments.is_empty())
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_round_trip() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, vout) = build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let inserts_opreturn_at_front = psbt
        .unsigned_tx
        .output
        .iter()
        .any(|o| o.script_pubkey.is_p2tr());
    let final_vout = if inserts_opreturn_at_front {
        vout + 1
    } else {
        vout
    };
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);

    let ColorPrepareResult {
        transfers,
        batch_transfer_idx,
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();
    assert_eq!(output_index_with_value(&psbt, amt_sat), final_vout);
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let (_, _, batch_transfer) = party_send.get_test_transfer_sender(&txid);
    assert_eq!(batch_transfer.idx, batch_transfer_idx);
    assert_eq!(batch_transfer.status, TransferStatus::Initiated);
    let transfer_dir = party_send.wallet.get_transfer_dir(&txid);
    assert!(transfer_dir.join(FASCIA_FILE).exists());
    assert!(transfer_dir.join(UNSIGNED_PSBT_FILE).exists());

    assert_eq!(transfers.len(), 1);
    let mut consignment_bytes = vec![];
    transfers[0]
        .save(&mut consignment_bytes)
        .expect("serialize consignment");
    let loaded = RgbTransfer::load(&consignment_bytes[..]).expect("load consignment");
    assert_eq!(loaded.contract_id().to_string(), asset.asset_id);

    // the receiver accepts the consignment built before the stash update
    let consignment_dir = recv_party.wallet.get_transfers_dir().join(&txid);
    std::fs::create_dir_all(&consignment_dir).unwrap();
    let consignment_path = consignment_dir.join(CONSIGNMENT_FILE);
    loaded.save_file(&consignment_path).unwrap();
    let (_, assignments, _) = recv_party
        .wallet
        .accept_transfer_consignment(
            recv_party.online,
            consignment_path,
            txid.clone(),
            final_vout,
            blinding,
        )
        .unwrap();
    assert_eq!(assignments, vec![Assignment::Fungible(AMOUNT)]);

    // the sender applies the fascia once the TX is broadcast
    broadcast_wallet_psbt(&party_send.wallet, &psbt);
    party_send
        .wallet
        .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx)
        .unwrap();
    assert!(
        party_send.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations)
    );
    assert!(!transfer_dir.join("stash_consumed").exists());
}

/// `color_psbt_and_prepare_consume` registers an Initiated batch without consuming the stash, so
/// `fail_transfers` can roll back if the tx is never broadcast.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_fail_transfers_rolls_back_without_broadcast() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();

    let (mut psbt, recipient_vout) =
        build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let input = psbt.unsigned_tx.input[0].previous_output;
    // Pre-OP_RETURN index for legacy color_psbt_and_prepare_consume shift when P2TR inserts OP_RETURN.
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();

    assert!(party_send.check_test_transfer_status_sender(
        &psbt.unsigned_tx.compute_txid().to_string(),
        TransferStatus::Initiated
    ));

    // Stash still holds the allocation (consume deferred).
    assert!(stash_has_assignments(
        &party_send.wallet,
        contract_id,
        input
    ));

    assert!(party_send.fail_transfers_single(batch_transfer_idx));
    assert!(party_send.check_test_transfer_status_sender(
        &psbt.unsigned_tx.compute_txid().to_string(),
        TransferStatus::Failed
    ));

    // After fail, allocations remain available in the stash for a new coloring.
    assert!(stash_has_assignments(
        &party_send.wallet,
        contract_id,
        input
    ));
}

/// Once the tx is broadcast the inputs are spent for good, so `fail_transfers` has to refuse the
/// still-Initiated batch instead of crediting those inputs back.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_fail_transfers_refused_after_broadcast() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, recipient_vout) =
        build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    broadcast_wallet_psbt(&party_send.wallet, &psbt);

    let result = party_send.fail_transfers(Some(batch_transfer_idx), false, false);
    assert!(matches!(result, Err(Error::CannotFailBatchTransfer)));

    // the batch stays untouched, so the deferred consume can still be completed
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));
    party_send
        .wallet
        .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx)
        .unwrap();
    assert!(
        party_send.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations)
    );
}

/// The registered batch can only account for the destinations listed in `output_map`, so an
/// under-assignment, which would destroy the remainder, has to be rejected.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_rejects_partial_output_map() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, recipient_vout) =
        build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT / 2)]),
        blinding,
    );

    let result = party_send.wallet.color_psbt_and_prepare_consume(
        &mut psbt,
        coloring_info,
        MIN_CONFIRMATIONS,
        None,
    );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m.contains("less than available") && m.contains("full allocation required")
    );
}

/// No transition would assign a contract missing from `coloring_info`, so spending an input that
/// carries one has to be refused instead of destroying those allocations.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_rejects_unlisted_input_contract() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let _unlisted = party_send.issue_asset_nia(Some(&[AMOUNT]));

    // spending every allocated UTXO puts the second asset on the inputs wherever it landed
    let allocated: Vec<OutPoint> = party_send
        .list_unspents(true)
        .into_iter()
        .filter(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .map(|u| u.utxo.outpoint.into())
        .collect();
    assert!(!allocated.is_empty());

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    for outpoint in &allocated {
        tx_builder.add_utxo(*outpoint).unwrap();
    }
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let outputs_before = psbt.unsigned_tx.output.len();
    let recipient_vout = output_index_with_value(&psbt, amt_sat);
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    let result = party_send.wallet.color_psbt_and_prepare_consume(
        &mut psbt,
        coloring_info,
        MIN_CONFIRMATIONS,
        None,
    );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m.contains("contracts not listed in coloring_info")
    );
    // the rejection happens before the caller's PSBT gets an OP_RETURN
    assert_eq!(psbt.unsigned_tx.output.len(), outputs_before);
}

/// Only the asset-owner assignment is re-assigned by the coloring, so spending an input that also
/// carries an inflation right has to be refused: the right would be destroyed, and its amount would
/// be miscounted as spendable fungible value on the way there.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_rejects_input_carrying_inflation_right() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(3), None, FEE_RATE, None);
    let asset = party_send.issue_asset_ifa(Some(&[AMOUNT]), None, None);

    let inflation_utxo: OutPoint = party_send
        .list_unspents(true)
        .into_iter()
        .find(|u| {
            u.rgb_allocations
                .iter()
                .any(|a| matches!(a.assignment, Assignment::InflationRight(_)))
        })
        .expect("UTXO carrying the inflation right")
        .utxo
        .outpoint
        .into();

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(inflation_utxo).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let recipient_vout = output_index_with_value(&psbt, amt_sat);
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    let result = party_send.wallet.color_psbt_and_prepare_consume(
        &mut psbt,
        coloring_info,
        MIN_CONFIRMATIONS,
        None,
    );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m }) if m.contains("inflation right")
    );
}

/// The registered batch has to carry the caller's confirmation depth, which gates both settling and
/// the reorg-safety checks, and the caller's deadline, which gates the bulk `fail_transfers` sweep.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_registers_requested_batch_parameters() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;
    let min_confirmations: u8 = 3;
    let expiration_timestamp = default_send_expiration();

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, recipient_vout) =
        build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    party_send
        .wallet
        .color_psbt_and_prepare_consume(
            &mut psbt,
            coloring_info,
            min_confirmations,
            Some(expiration_timestamp),
        )
        .unwrap();

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let (_, _, batch_transfer) = party_send.get_test_transfer_sender(&txid);
    assert_eq!(batch_transfer.min_confirmations, min_confirmations);
    assert_eq!(batch_transfer.expiration, Some(expiration_timestamp as i64));
}

/// Preparing leaves the stash untouched and a static blinding makes the coloring deterministic, so
/// preparing the same PSBT twice commits to the same TXID: the second batch has to be refused.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_rejects_second_live_batch_for_same_txid() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, recipient_vout) =
        build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    let mut retried_psbt = psbt.clone();
    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info.clone(), MIN_CONFIRMATIONS, None)
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();

    let retried = party_send.wallet.color_psbt_and_prepare_consume(
        &mut retried_psbt,
        coloring_info,
        MIN_CONFIRMATIONS,
        None,
    );
    assert_matches!(
        retried,
        Err(Error::BatchTransferAlreadyExists { txid: ref t, idx }) if *t == txid && idx == batch_transfer_idx
    );
    assert_eq!(retried_psbt.unsigned_tx.compute_txid().to_string(), txid);
    let batch_transfers: Vec<_> = party_send
        .db_batch_transfers()
        .into_iter()
        .filter(|b| b.txid.as_deref() == Some(txid.as_str()))
        .collect();
    assert_eq!(batch_transfers.len(), 1);
}

/// A batch whose deadline passed without a broadcast is abandoned, so the bulk sweep has to reclaim
/// its reserved inputs.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_bulk_fail_transfers_reclaims_expired_batch() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;
    let expired = (now().unix_timestamp() - 1) as u64;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, recipient_vout) =
        build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, Some(expired))
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();

    assert!(party_send.fail_transfers_all());

    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Failed));
}

/// The same sweep must not touch an expired batch whose TX is already on-chain: crediting those
/// inputs back would let them be selected again.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_bulk_fail_transfers_spares_broadcast_expired_batch() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;
    let expired = (now().unix_timestamp() - 1) as u64;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, recipient_vout) =
        build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, Some(expired))
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();

    broadcast_wallet_psbt(&party_send.wallet, &psbt);

    assert!(!party_send.fail_transfers_all());

    // the batch stays untouched, so the deferred consume can still be completed
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));
    party_send
        .wallet
        .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx)
        .unwrap();
    assert!(
        party_send.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations)
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn consume_transfer_fascia_recovers_after_crash_between_stash_consume_and_db_commit() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, vout) = build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    broadcast_wallet_psbt(&party_send.wallet, &psbt);

    crate::wallet::rust_only::MOCK_FAIL_AFTER_STASH_CONSUME.with(|f| *f.borrow_mut() = true);
    assert!(matches!(
        party_send.wallet.consume_transfer_fascia(party_send.party_online(), batch_transfer_idx),
        Err(Error::Internal { details }) if details.contains("mock failure after stash consume")
    ));

    let marker = party_send
        .wallet
        .get_transfers_dir()
        .join(&txid)
        .join("stash_consumed");
    assert!(
        marker.exists(),
        "durable marker must exist after stash consume"
    );
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));

    // Retry finishes the SQL side without a second consume_fascia.
    party_send
        .wallet
        .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx)
        .unwrap();
    assert!(!marker.exists());
    assert!(
        party_send.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations)
    );
}

/// A crash after the stock is persisted but before the marker is written leaves no marker, so the
/// retry has to consume the fascia again (rgb-ops merge-reveals) and complete the SQL side.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn consume_transfer_fascia_recovers_after_crash_between_stock_persist_and_marker() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, vout) = build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    broadcast_wallet_psbt(&party_send.wallet, &psbt);

    crate::wallet::rust_only::MOCK_FAIL_AFTER_STOCK_PERSIST.with(|f| *f.borrow_mut() = true);
    assert!(matches!(
        party_send.wallet.consume_transfer_fascia(party_send.party_online(), batch_transfer_idx),
        Err(Error::Internal { details }) if details.contains("stock persist before marker")
    ));

    let marker = party_send
        .wallet
        .get_transfers_dir()
        .join(&txid)
        .join("stash_consumed");
    assert!(
        !marker.exists(),
        "marker must not exist if we crashed after stock persist"
    );
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));

    party_send
        .wallet
        .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx)
        .unwrap();
    assert!(!marker.exists());
    assert!(
        party_send.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations)
    );
}

/// Once the fascia is in the stash, only the SQL side is still rollable back, so failing the batch
/// would diverge the two. The consume path requires a broadcast first; the remaining crash window
/// is after `consume_fascia` and before the SQL commit, when both the indexer and the durable
/// marker tell `fail_transfers` to refuse.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn fail_transfers_refused_after_stash_consume_before_sql_commit() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, vout) = build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    broadcast_wallet_psbt(&party_send.wallet, &psbt);

    crate::wallet::rust_only::MOCK_FAIL_AFTER_STASH_CONSUME.with(|f| *f.borrow_mut() = true);
    assert!(matches!(
        party_send.wallet.consume_transfer_fascia(party_send.party_online(), batch_transfer_idx),
        Err(Error::Internal { details }) if details.contains("mock failure after stash consume")
    ));
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));

    let result = party_send.fail_transfers(Some(batch_transfer_idx), false, false);
    assert!(matches!(result, Err(Error::CannotFailBatchTransfer)));

    // the batch stays untouched, so the interrupted consume can still be completed
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));
    party_send
        .wallet
        .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx)
        .unwrap();
    assert!(
        party_send.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations)
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_persist_projects_change_for_wallet_owned_output() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let allocated: OutPoint = party_send
        .list_unspents(true)
        .into_iter()
        .find(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .unwrap()
        .utxo
        .outpoint
        .into();

    // Self-send: RGB destination is a wallet-owned script → Change coloring, not Burn.
    let self_address = BdkAddress::from_str(&party_send.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(allocated).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            self_address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let vout = output_index_with_value(&psbt, amt_sat);
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);

    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();
    let final_vout = output_index_with_value(&psbt, amt_sat);

    let transfers = party_send.list_transfers(Some(&asset.asset_id));
    let initiated = transfers
        .iter()
        .find(|t| t.status == TransferStatus::Initiated && t.kind == TransferKind::Send)
        .expect("self-send color transfer must be Send, not Burn");
    assert!(initiated.recipient_id.is_some());

    let asset_transfers = party_send.db_asset_transfers_filtered(batch_transfer_idx);
    assert_eq!(asset_transfers.len(), 1);
    let colorings = party_send.db_colorings_filtered(asset_transfers[0].idx);
    assert!(colorings.iter().any(|c| c.r#type == ColoringType::Input));
    let change = colorings
        .iter()
        .find(|c| c.r#type == ColoringType::Change)
        .expect("wallet-owned output_map vout must project Change");
    assert_eq!(change.assignment, Assignment::Fungible(AMOUNT));

    let change_txo = party_send
        .db_txos()
        .into_iter()
        .find(|t| t.idx == change.txo_idx)
        .unwrap();
    assert_eq!(change_txo.vout, final_vout);
    assert_eq!(change_txo.txid, psbt.unsigned_tx.compute_txid().to_string());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_persist_uda_change_is_non_fungible() {
    initialize();

    let amt_sat = 500;

    let mut party_send = get_funded_noutxo_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset = party_send.issue_asset_uda(None, None, vec![]);

    let allocated: OutPoint = party_send
        .list_unspents(true)
        .into_iter()
        .find(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .unwrap()
        .utxo
        .outpoint
        .into();

    let self_address = BdkAddress::from_str(&party_send.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(allocated).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            self_address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let vout = output_index_with_value(&psbt, amt_sat);
    let coloring_info = coloring_info_for(&asset.asset_id, HashMap::from([(vout, 1)]), 777);

    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();

    let asset_transfers = party_send.db_asset_transfers_filtered(batch_transfer_idx);
    assert_eq!(asset_transfers.len(), 1);
    let colorings = party_send.db_colorings_filtered(asset_transfers[0].idx);
    let change = colorings
        .iter()
        .find(|c| c.r#type == ColoringType::Change)
        .expect("UDA self-send must project Change");
    assert_eq!(
        change.assignment,
        Assignment::NonFungible,
        "UDA Change must not be stored as Fungible(1)"
    );
    let xfers = party_send.db_transfers_filtered(asset_transfers[0].idx);
    assert_eq!(xfers.len(), 1);
    assert_eq!(xfers[0].requested_assignment, Some(Assignment::NonFungible));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_persist_multi_contract_inputs_and_send() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset_a = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let asset_b = party_send.issue_asset_cfa(Some(&[AMOUNT]), None);

    let allocated: Vec<OutPoint> = party_send
        .list_unspents(true)
        .into_iter()
        .filter(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .map(|u| u.utxo.outpoint.into())
        .collect();
    assert!(allocated.len() >= 2);

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(allocated[0]).unwrap();
    tx_builder.add_utxo(allocated[1]).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let vout = output_index_with_value(&psbt, amt_sat);

    let mut asset_info_map = HashMap::new();
    for asset_id in [&asset_a.asset_id, &asset_b.asset_id] {
        asset_info_map.insert(
            ContractId::from_str(asset_id).unwrap(),
            AssetColoringInfo {
                output_map: HashMap::from([(vout, AMOUNT)]),
                static_blinding: Some(blinding),
            },
        );
    }
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };

    let ColorPrepareResult {
        batch_transfer_idx,
        transfers,
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();
    assert_eq!(transfers.len(), 2);
    let final_vout = output_index_with_value(&psbt, amt_sat);

    let asset_transfers = party_send.db_asset_transfers_filtered(batch_transfer_idx);
    assert_eq!(asset_transfers.len(), 2);
    for at in &asset_transfers {
        let colorings = party_send.db_colorings_filtered(at.idx);
        assert!(
            colorings.iter().any(|c| c.r#type == ColoringType::Input),
            "each contract needs Input coloring"
        );
        assert!(!colorings.iter().any(|c| c.r#type == ColoringType::Change));
        let xfers = party_send.db_transfers_filtered(at.idx);
        assert_eq!(xfers.len(), 1);
        assert!(xfers[0].recipient_id.is_some());
    }

    for asset_id in [&asset_a.asset_id, &asset_b.asset_id] {
        let kind = party_send
            .list_transfers(Some(asset_id))
            .into_iter()
            .find(|t| t.status == TransferStatus::Initiated)
            .unwrap()
            .kind;
        assert_eq!(kind, TransferKind::Send);
    }

    assert_eq!(
        party_send
            .db_txos()
            .iter()
            .filter(
                |t| t.txid == psbt.unsigned_tx.compute_txid().to_string() && t.vout == final_vout
            )
            .count(),
        0,
        "foreign recipient output must not be inserted as wallet TXO"
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_persist_updates_backup_info() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, vout) = build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);

    let bak_before = party_send.db_backup_info();
    party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();
    let bak_after = party_send.db_backup_info();
    assert!(
        bak_after.last_operation_timestamp.parse::<i128>().unwrap()
            > bak_before.last_operation_timestamp.parse::<i128>().unwrap()
    );
    assert!(party_send.wallet.backup_info().unwrap());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn consume_transfer_fascia_refused_before_broadcast() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, vout) = build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();

    assert!(matches!(
        party_send
            .wallet
            .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx),
        Err(Error::Internal { details })
            if details.contains("not known to the indexer")
    ));
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));

    // fail_transfers is still the way out: the stash was never consumed
    assert!(party_send.fail_transfers_single(batch_transfer_idx));
}

/// Missing or unreadable unsigned PSBT is operation corruption: consume must not advance stock or SQL.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn consume_transfer_fascia_rejects_missing_unsigned_psbt() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, vout) = build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let transfer_dir = party_send.wallet.get_transfer_dir(&txid);
    let psbt_path = transfer_dir.join("unsigned.psbt");
    std::fs::write(&psbt_path, b"not-a-psbt").unwrap();
    assert!(matches!(
        party_send
            .wallet
            .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx),
        Err(Error::Inconsistency { details })
            if details.contains("unsigned PSBT unreadable")
    ));
    std::fs::remove_file(&psbt_path).unwrap();
    assert!(matches!(
        party_send
            .wallet
            .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx),
        Err(Error::Inconsistency { details })
            if details.contains("unsigned PSBT missing")
    ));
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));
    assert!(!transfer_dir.join("stash_consumed").exists());
    assert!(party_send.fail_transfers_single(batch_transfer_idx));
}

/// `consume_transfer_fascia` is only for batches created by `color_psbt_and_prepare_consume`.
/// A `send_begin` batch writes fascia to the same transfer dir but must still go through `send_end`.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn consume_transfer_fascia_rejects_send_begin_batch() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive_asset_expiry(None, None);
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let begin = party.send_begin_result(&recipient_map).unwrap();
    let batch_transfer_idx = begin.batch_transfer_idx.unwrap();

    assert!(matches!(
        party
            .wallet
            .consume_transfer_fascia(party.party_online(), batch_transfer_idx),
        Err(Error::Internal { details })
            if details.contains("was not created by color_psbt_*_and_prepare_consume")
    ));
}

/// `rebuild_psbt_preserving_maps(.., false)`: no P2TR ⇒ OP_RETURN appended; original output maps
/// must stay at the same indices (unlike the P2TR front-insert / skip(1) path).
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_appends_opreturn_without_p2tr_preserves_output_maps() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    // Same funding shape as `success` (1 colored UTXO, BTC drained) but P2WPKH so color_psbt
    // takes the append path. Destination must also be P2WPKH — a taproot recipient would flip
    // onto the front-insert / +1-shift path.
    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::SegWitV0);
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);
    let mut wallet = get_test_wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest);
    let online = wallet.go_online(test_go_online_options(None)).unwrap();
    let mut party_send = party!(wallet, online);
    fund_wallet(party_send.get_address());
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);

    let mnemonic = Mnemonic::parse_in(
        Language::English,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    let xprv = Xpriv::new_master(BdkNetwork::Regtest, &mnemonic.to_seed("")).unwrap();
    let custom_bdk_wallet =
        BdkWallet::create(format!("wpkh({xprv}/0/*)"), format!("wpkh({xprv}/1/*)"))
            .network(BdkNetwork::Regtest)
            .create_wallet_no_persist()
            .unwrap();
    let p2wpkh_addr = custom_bdk_wallet
        .peek_address(KeychainKind::External, 0)
        .address;
    party_send.send_btc(&p2wpkh_addr.to_string(), 99_998_200);

    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(p2wpkh_addr.script_pubkey(), BdkAmount::from_sat(amt_sat))
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    assert!(
        !psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr() || o.script_pubkey.is_op_return()),
        "fixture must be no-P2TR and no OP_RETURN so color_psbt takes the append rebuild branch"
    );

    let recipient_vout = output_index_with_value(&psbt, amt_sat);
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );
    stamp_output_map_sentinels(&mut psbt);
    let psbt_before = psbt.clone();
    party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info)
        .unwrap();

    assert!(
        psbt.unsigned_tx
            .output
            .last()
            .unwrap()
            .script_pubkey
            .is_op_return()
    );
    assert_output_maps_preserved(&psbt_before, &psbt);
}

/// Legacy `color_psbt` P2TR / `OpretFirst` indexing: with a pre-inserted OP_RETURN at vout 0,
/// keys are still pre-OP_RETURN indices and get +1 (same as when this method inserts OP_RETURN).
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_existing_op_return_with_p2tr_uses_legacy_vout_shift() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, _) = build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr()),
        "test wallet must produce P2TR outputs"
    );
    let output_count_before = psbt.unsigned_tx.output.len();
    // Pre-existing OP_RETURN at vout 0 + P2TR: legacy still applies +1 to output_map keys.
    insert_op_return(&mut psbt, true);
    assert_eq!(psbt.unsigned_tx.output.len(), output_count_before + 1);
    assert!(psbt.unsigned_tx.output[0].script_pubkey.is_op_return());
    let witness_utxo_before = psbt.inputs[0].witness_utxo.clone();
    let tap_internal_key_before = psbt.inputs[0].tap_internal_key;
    assert!(witness_utxo_before.is_some());

    let final_recipient_vout = output_index_with_value(&psbt, amt_sat);
    assert_ne!(
        final_recipient_vout, 0,
        "recipient must not be the OP_RETURN vout"
    );
    let pre_opreturn_vout = final_recipient_vout - 1;

    // Passing a final index under the legacy +1 shift seals the next output (or fails OOB).
    let mut psbt_final = psbt.clone();
    let final_index_coloring = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(final_recipient_vout, AMOUNT)]),
        blinding,
    );
    match party_send
        .wallet
        .color_psbt(&mut psbt_final, final_index_coloring)
    {
        Err(Error::InvalidColoringInfo { .. }) => {}
        Ok((fascia, _)) => {
            let (_, bundle) = fascia.bundles().iter().next().unwrap();
            let seal = bundle
                .known_transitions
                .iter()
                .next()
                .unwrap()
                .transition
                .assignments
                .iter()
                .next()
                .unwrap()
                .1
                .as_fungible()
                .first()
                .unwrap()
                .revealed_seal()
                .unwrap();
            assert_eq!(seal.vout.into_u32(), final_recipient_vout + 1);
        }
        Err(e) => panic!("unexpected error: {e}"),
    }

    // Pre-OP_RETURN index (legacy): +1 lands on the recipient.
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(pre_opreturn_vout, AMOUNT)]),
        blinding,
    );
    let (fascia, beneficiaries) = party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info)
        .unwrap();
    assert_eq!(
        psbt.unsigned_tx.output.len(),
        output_count_before + 1,
        "must not insert a second OP_RETURN"
    );
    assert_eq!(psbt.inputs[0].witness_utxo, witness_utxo_before);
    assert_eq!(psbt.inputs[0].tap_internal_key, tap_internal_key_before);

    let (_cid, bundle) = fascia.bundles().iter().next().unwrap();
    let transition = bundle
        .known_transitions
        .iter()
        .next()
        .unwrap()
        .transition
        .clone();
    let (_, fungible) = transition.assignments.iter().next().unwrap();
    let seal = fungible
        .as_fungible()
        .first()
        .unwrap()
        .revealed_seal()
        .unwrap();
    assert_eq!(seal.vout.into_u32(), final_recipient_vout);
    assert_eq!(seal.blinding, blinding);

    let (_cid, seals) = beneficiaries.first_key_value().unwrap();
    let seal = match seals.first().unwrap() {
        BuilderSeal::Revealed(r) => r,
        BuilderSeal::Concealed(_) => panic!("revealed expected"),
    };
    assert_eq!(seal.vout.into_u32(), final_recipient_vout);
}

/// With P2TR + pre-existing OP_RETURN at index > 0, legacy +1 would silently mis-seal.
/// Reject instead; do not change the vout-0 legacy path.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_rejects_opreturn_not_first_when_p2tr() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, _) = build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr()),
        "test wallet must produce P2TR outputs"
    );
    insert_op_return(&mut psbt, false);
    let op_return_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .position(|o| o.script_pubkey.is_op_return())
        .unwrap();
    assert_ne!(
        op_return_vout, 0,
        "fixture must place OP_RETURN after vout 0"
    );

    let recipient_vout = output_index_with_value(&psbt, amt_sat);
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == "OP_RETURN must be the first PSBT output"
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_rejects_signed_psbt_with_existing_op_return() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let (mut psbt, _) = build_send_psbt(&mut party_send, &recv_party.get_address(), amt_sat);
    insert_op_return(&mut psbt, true);

    let output_map = HashMap::from([(output_index_with_value(&psbt, amt_sat), AMOUNT)]);
    let coloring_info = coloring_info_for(&asset.asset_id, output_map, blinding);

    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let mut signed_psbt = Psbt::from_str(&signed_psbt).unwrap();
    let result = party_send
        .wallet
        .color_psbt(&mut signed_psbt, coloring_info.clone());
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == "cannot color a signed PSBT: RGB commitment rewrites the OP_RETURN output"
    );

    let result = party_send.wallet.color_psbt_and_prepare_consume(
        &mut signed_psbt,
        coloring_info,
        MIN_CONFIRMATIONS,
        None,
    );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == "cannot color a signed PSBT: RGB commitment rewrites the OP_RETURN output"
    );
}

/// A UDA coloring on inputs without the token has to return a coloring error instead of
/// panicking.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_uda_missing_input_assignment_returns_coloring_error() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset = party_send.issue_asset_uda(None, None, vec![]);

    let vanilla: OutPoint = party_send
        .list_unspents(true)
        .into_iter()
        .find(|u| u.utxo.colorable && u.rgb_allocations.is_empty())
        .expect("uncolored colorable UTXO")
        .utxo
        .outpoint
        .into();

    let address = BdkAddress::from_str(&party_send.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(vanilla).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let vout = output_index_with_value(&psbt, amt_sat);
    let coloring_info = coloring_info_for(&asset.asset_id, HashMap::from([(vout, 1)]), blinding);

    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    assert!(
        matches!(
            result,
            Err(Error::InvalidColoringInfo { ref details })
                if details.contains("greater than available")
                    || details.contains("no token assignment")
        ),
        "color_psbt must return a coloring error, not panic; got {result:?}"
    );
}

#[cfg(feature = "electrum")]
fn broadcast_wallet_psbt(wallet: &Wallet, psbt: &Psbt) {
    let signed_psbt = wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let finalized_psbt = wallet.finalize_psbt(signed_psbt, None).unwrap();
    let tx = Psbt::from_str(&finalized_psbt)
        .unwrap()
        .extract_tx()
        .expect("valid tx");
    wallet.broadcast_tx(tx).unwrap();
}

/// The pre-OP_RETURN APIs (`color_psbt`, `color_psbt_stage`, `color_psbt_and_prepare_consume`)
/// must reject a final-vout `output_map` whenever the P2TR +1 shift lands on an output that
/// cannot carry a witness seal or past the last output.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn pre_opreturn_apis_reject_final_vout_output_map() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    // [OP_RETURN, .., recipient, bare multisig, ..]
    let recipient_vout = layout_index_mixup_psbt(&mut psbt, amt_sat);
    let base_psbt = psbt.clone();

    // final key shifted by +1 lands on the bare-multisig output
    let shifted_vout = recipient_vout + 1;
    let final_coloring = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );
    let result = party_send
        .wallet
        .color_psbt(&mut psbt, final_coloring.clone());
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m.starts_with(&format!("output_map vout {shifted_vout} script cannot carry an RGB witness seal"))
                && m.contains("pre-OP_RETURN")
    );
    assert_eq!(psbt, base_psbt);
    let result = party_send
        .wallet
        .color_psbt_stage(&mut psbt, final_coloring.clone());
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m.starts_with(&format!("output_map vout {shifted_vout} script cannot carry an RGB witness seal"))
                && m.contains("pre-OP_RETURN")
    );
    assert_eq!(psbt, base_psbt);
    let result = party_send.wallet.color_psbt_and_prepare_consume(
        &mut psbt,
        final_coloring,
        MIN_CONFIRMATIONS,
        None,
    );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m.starts_with(&format!("output_map vout {shifted_vout} script cannot carry an RGB witness seal"))
                && m.contains("pre-OP_RETURN")
    );
    assert_eq!(
        psbt, base_psbt,
        "a rejected output_map must not color the PSBT"
    );

    // the last final vout shifted by +1 falls off the end of the PSBT
    let last_vout = psbt.unsigned_tx.output.len() as u32 - 1;
    let result = party_send.wallet.color_psbt(
        &mut psbt,
        coloring_info_for(
            &asset.asset_id,
            HashMap::from([(last_vout, AMOUNT)]),
            blinding,
        ),
    );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m.starts_with("invalid vout in output_map, does not exist in the given PSBT")
                && m.contains("pre-OP_RETURN")
    );
    assert_eq!(psbt, base_psbt);

    // the pre-OP_RETURN index seals the recipient
    let (fascia, _) = party_send
        .wallet
        .color_psbt(
            &mut psbt,
            coloring_info_for(
                &asset.asset_id,
                HashMap::from([(recipient_vout - 1, AMOUNT)]),
                blinding,
            ),
        )
        .unwrap();
    assert_eq!(fascia_seal_vouts(&fascia), vec![recipient_vout]);
}

/// Lay out a P2TR PSBT for index-convention mix-up tests: put a bare-multisig output (which
/// cannot carry a witness seal) right after the `amt_sat` recipient, then an OP_RETURN at vout 0.
/// Returns the recipient's final vout.
#[cfg(feature = "electrum")]
fn layout_index_mixup_psbt(psbt: &mut Psbt, amt_sat: u64) -> u32 {
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr()),
        "test wallet must produce P2TR outputs"
    );
    let find_recipient = |psbt: &Psbt| {
        psbt.unsigned_tx
            .output
            .iter()
            .position(|o| o.value.to_sat() == amt_sat)
            .unwrap()
    };
    let at = find_recipient(psbt) + 1;
    psbt.unsigned_tx.output.insert(
        at,
        TxOut {
            value: BdkAmount::from_sat(amt_sat + 1),
            script_pubkey: bare_multisig_script(),
        },
    );
    psbt.outputs
        .insert(at, bdk_wallet::bitcoin::psbt::Output::default());
    insert_op_return(psbt, true);
    find_recipient(psbt) as u32
}

/// Vouts of the revealed seals assigned by every transition in `fascia`.
#[cfg(feature = "electrum")]
fn fascia_seal_vouts(fascia: &Fascia) -> Vec<u32> {
    let mut vouts = vec![];
    for (_, bundle) in fascia.bundles().iter() {
        for known in bundle.known_transitions.iter() {
            for (_, assignments) in known.transition.assignments.iter() {
                for assignment in assignments.as_fungible() {
                    vouts.push(assignment.revealed_seal().unwrap().vout.into_u32());
                }
            }
        }
    }
    vouts
}

/// A bare 1-of-1 multisig script: a standard output that cannot carry an RGB witness seal.
#[cfg(feature = "electrum")]
fn bare_multisig_script() -> ScriptBuf {
    let mut bytes = vec![0x51, 0x21, 0x02];
    bytes.extend([0x11u8; 32]);
    bytes.extend([0x51, 0xae]);
    ScriptBuf::from_bytes(bytes)
}

#[cfg(feature = "electrum")]
fn insert_op_return(psbt: &mut Psbt, at_front: bool) {
    let txout = TxOut {
        value: BdkAmount::ZERO,
        script_pubkey: ScriptBuf::new_op_return([]),
    };
    let map = bdk_wallet::bitcoin::psbt::Output::default();
    if at_front {
        psbt.unsigned_tx.output.insert(0, txout);
        psbt.outputs.insert(0, map);
    } else {
        psbt.unsigned_tx.output.push(txout);
        psbt.outputs.push(map);
    }
}

/// Proprietary marker used to verify `rebuild_psbt_preserving_maps` keeps per-output maps aligned.
/// Prefer this over bip32/tap origins: RGB coloring may touch those after the rebuild.
#[cfg(feature = "electrum")]
fn output_map_sentinel_key() -> bitcoin::psbt::raw::ProprietaryKey {
    bitcoin::psbt::raw::ProprietaryKey {
        prefix: b"rgb-lib-test".to_vec(),
        subtype: 0x7A,
        key: vec![0x01],
    }
}

#[cfg(feature = "electrum")]
fn stamp_output_map_sentinels(psbt: &mut Psbt) {
    let key = output_map_sentinel_key();
    for (i, out) in psbt.outputs.iter_mut().enumerate() {
        out.proprietary.insert(key.clone(), vec![i as u8]);
    }
}

/// Assert PSBT output maps survive a rebuild that appends outputs (`opreturn_first = false`).
#[cfg(feature = "electrum")]
fn assert_output_maps_preserved(before: &Psbt, after: &Psbt) {
    let key = output_map_sentinel_key();
    assert!(after.outputs.len() >= before.outputs.len());
    assert!(
        before
            .outputs
            .iter()
            .any(|o| o.proprietary.contains_key(&key)),
        "expected stamped output-map sentinels before coloring"
    );
    for (i, out_before) in before.outputs.iter().enumerate() {
        assert_eq!(
            after.outputs[i].proprietary.get(&key),
            out_before.proprietary.get(&key),
            "output-map sentinel mismatch at output {i}"
        );
    }
}

#[cfg(feature = "electrum")]
fn coloring_info_for(asset_id: &str, output_map: HashMap<u32, u64>, blinding: u64) -> ColoringInfo {
    let asset_coloring_info = AssetColoringInfo {
        output_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map =
        HashMap::from_iter([(ContractId::from_str(asset_id).unwrap(), asset_coloring_info)]);
    ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    }
}
