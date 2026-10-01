//! RGB singlesig wallet module.
//!
//! This module defines the methods of the [`Wallet`] structure.

#[cfg(any(feature = "electrum", feature = "esplora"))]
use super::offline::{
    SWAP_ACCEPTED_FILE, SWAP_BROADCAST_FILE, SWAP_CANCELLED_EXTENSION, SWAP_OFFER_FILE,
    SWAP_OUTGOING_FILE, SWAP_PROPOSAL_FILE, SWAP_REQUEST_FILE, SwapDirection, SwapOutgoingState,
    swap_build_psbt, swap_consignment_dir, swap_ensure_not_expired, swap_ensure_state_matches,
    swap_invalid, swap_load_state, swap_mpc_entropy, swap_random_blinding,
    swap_require_rgb_destination, swap_restore_input_metadata, swap_save_state,
    swap_side_rgb_output_cost, swap_state_path, swap_validate_legs, swap_validate_proposal_psbt,
    swap_validate_proxy_url,
};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use super::online::{
    SwapRgbSend, swap_accept_transfer_from_file, swap_color_rgb_leg, swap_emit_asset_history,
    swap_ensure_inputs_confirmed, swap_fetch_consignment_to_file, swap_finalize_psbt,
    swap_finalize_psbt_required, swap_import_asset_history, swap_prepare_rgb_leg,
    swap_select_inputs, swap_sign_psbt, swap_stage_rgb_leg, swap_validate_fascia_received_leg,
    swap_validate_received_swap_leg,
};
use super::*;

/// Keys for the singlesig wallet.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "camel_case", serde(rename_all = "camelCase"))]
pub struct SinglesigKeys {
    /// Wallet account-level xPub for the vanilla side of the wallet
    pub account_xpub_vanilla: String,
    /// Wallet account-level xPub for the colored side of the wallet
    pub account_xpub_colored: String,
    /// Keychain index for the vanilla-side of the wallet (default: 0)
    #[serde(deserialize_with = "from_str_or_number_optional")]
    pub vanilla_keychain: Option<u8>,
    /// Wallet master fingerprint
    pub master_fingerprint: String,
    /// Wallet mnemonic phrase
    pub mnemonic: Option<String>,
    /// Witness version these keys were derived with
    #[serde(default)]
    pub witness_version: WitnessVersion,
}

impl SinglesigKeys {
    pub(crate) fn build_descriptors(
        &self,
        bitcoin_network: &BitcoinNetwork,
    ) -> Result<(WalletDescriptors, bool), Error> {
        let network_kind = bitcoin_network.network_kind();
        let xpub_rgb = str_to_xpub(&self.account_xpub_colored, &network_kind)?;
        let xpub_btc = str_to_xpub(&self.account_xpub_vanilla, &network_kind)?;
        Ok(if let Some(mnemonic) = &self.mnemonic {
            let descs = get_descriptors(
                bitcoin_network,
                mnemonic,
                self.vanilla_keychain,
                &xpub_btc,
                &xpub_rgb,
                self.witness_version,
            )?;
            // check master fingerprint derived from mnemonic matches provided one
            let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)?;
            let master_xprv = Xpriv::new_master(*bitcoin_network, &mnemonic.to_seed("")).unwrap();
            let master_xpub = Xpub::from_priv(&Secp256k1::new(), &master_xprv);
            let master_fp = master_xpub.fingerprint();
            if master_fp
                != Fingerprint::from_str(&self.master_fingerprint)
                    .map_err(|_| Error::InvalidFingerprint)?
            {
                return Err(Error::FingerprintMismatch);
            }
            (descs, false)
        } else {
            let descs = get_descriptors_from_xpubs(
                bitcoin_network,
                &self.master_fingerprint,
                &xpub_rgb,
                &xpub_btc,
                self.vanilla_keychain,
                self.witness_version,
            )?;
            (descs, true)
        })
    }

    /// Create a new [`SinglesigKeys`] from a [`Keys`] object.
    pub fn from_keys(keys: &Keys, vanilla_keychain: Option<u8>) -> Self {
        Self {
            account_xpub_vanilla: keys.account_xpub_vanilla.clone(),
            account_xpub_colored: keys.account_xpub_colored.clone(),
            vanilla_keychain,
            master_fingerprint: keys.master_fingerprint.clone(),
            mnemonic: Some(keys.mnemonic.clone()),
            witness_version: keys.witness_version,
        }
    }

    /// Create a new [`SinglesigKeys`] from a [`Keys`] object without a mnemonic.
    pub fn from_keys_no_mnemonic(keys: &Keys, vanilla_keychain: Option<u8>) -> Self {
        Self {
            account_xpub_vanilla: keys.account_xpub_vanilla.clone(),
            account_xpub_colored: keys.account_xpub_colored.clone(),
            vanilla_keychain,
            master_fingerprint: keys.master_fingerprint.clone(),
            mnemonic: None,
            witness_version: keys.witness_version,
        }
    }
}

/// An RGB singlesig wallet.
///
/// Can be obtained with the [`Wallet::new`] method.
pub struct Wallet {
    pub(crate) internals: WalletInternals,
    pub(crate) keys: SinglesigKeys,
}

impl WalletCore for Wallet {
    fn internals(&self) -> &WalletInternals {
        &self.internals
    }

    fn internals_mut(&mut self) -> &mut WalletInternals {
        &mut self.internals
    }
}

impl WalletBackup for Wallet {}

impl WalletOffline for Wallet {}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl WalletOnline for Wallet {
    fn heal_psbt_ops_after_failed_transfers(&self) -> Result<bool, Error> {
        self.psbt_op_heal_failed()
    }

    fn psbt_op_live_broadcast_blocks_fail(
        &self,
        batch_transfer: &DbBatchTransfer,
    ) -> Result<bool, Error> {
        self.psbt_op_has_live_broadcast(batch_transfer)
    }

    fn wallet_specific_consistency_checks(&mut self, txn: &DbTxn) -> Result<(), Error> {
        self.sync_wallet(
            txn,
            SyncOptions {
                keychain: SyncKeychain::Colored,
                strategy: SyncStrategy::FullScan,
            },
            false,
        )?;
        self.sync_wallet(
            txn,
            SyncOptions {
                keychain: SyncKeychain::Vanilla {
                    lookback: self.vanilla_sync_lookback(),
                },
                strategy: SyncStrategy::FullScan,
            },
            false,
        )?;
        let bdk_utxos: Vec<String> = self
            .bdk_wallet()
            .list_unspent()
            .map(|u| u.outpoint.to_string())
            .collect();
        let bdk_utxos: HashSet<String> = HashSet::from_iter(bdk_utxos);
        let db_utxos: Vec<String> = txn
            .iter_txos()?
            .into_iter()
            .filter(|t| !t.spent && t.exists)
            .map(|u| u.outpoint().to_string())
            .collect();
        let db_utxos: HashSet<String> = HashSet::from_iter(db_utxos);
        let diff = db_utxos.difference(&bdk_utxos);
        if diff.clone().count() > 0 {
            return Err(Error::Inconsistency {
                details: format!("spent bitcoins with another wallet: {diff:?}"),
            });
        }
        Ok(())
    }
}

/// Common offline APIs of the wallet.
impl RgbWalletOpsOffline for Wallet {}

/// Common online APIs of the wallet.
#[cfg(any(feature = "electrum", feature = "esplora"))]
impl RgbWalletOpsOnline for Wallet {}

/// Offline APIs of the wallet.
impl Wallet {
    /// Create a new RGB singlesig wallet based on the provided [`WalletData`] and
    /// [`SinglesigKeys`].
    pub fn new(wallet_data: WalletData, keys: SinglesigKeys) -> Result<Self, Error> {
        let wdata = wallet_data.clone();

        // wallet keys
        let (descs, watch_only) = keys.build_descriptors(&wdata.bitcoin_network)?;

        // wallet directory and file logging setup
        let (wallet_dir, logger, _logger_guard) =
            setup_new_wallet(&wallet_data, &keys.master_fingerprint)?;

        // reject settings the wallet wasn't created with before any of them reaches the database
        WalletManifest::check_settings_unchanged(&wallet_dir, &wallet_data, &keys)?;

        // setup the BDK wallet
        let (bdk_wallet, bdk_database) = setup_bdk(
            &wdata,
            &wallet_dir,
            descs.colored,
            descs.vanilla,
            watch_only,
            BdkNetwork::from(wdata.bitcoin_network),
            &logger,
        )?;

        // setup RGB
        setup_rgb(&wallet_dir, wdata.supported_schemas, wdata.bitcoin_network)?;

        // setup rgb-lib DB
        let database = setup_db(&wallet_dir)?;
        let reuse_address_index = database.begin_transaction()?.get_reuse_address_index()?;

        // persist the settings needed to load the wallet back
        WalletManifest::new(&wallet_data, &keys).write(&wallet_dir)?;

        info!(logger, "New wallet completed");
        Ok(Self {
            internals: WalletInternals {
                wallet_data,
                logger,
                _logger_guard,
                database: Arc::new(database),
                wallet_dir,
                bdk_wallet,
                bdk_database,
                reuse_address_index,
                #[cfg(any(feature = "electrum", feature = "esplora"))]
                online_data: None,
                #[cfg(feature = "vss")]
                vss_client: None,
                #[cfg(feature = "vss")]
                auto_backup_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
            keys,
        })
    }

    /// Load an existing RGB singlesig wallet, identified by its master fingerprint, from the
    /// wallet directory inside `data_dir`.
    ///
    /// The settings are read back from the manifest that [`Wallet::new`] wrote in the wallet
    /// directory, so they don't need to be supplied again. Pass the `mnemonic` to load a wallet
    /// able to sign, or `None` to load it in watch-only mode.
    ///
    /// Wallets created before manifest support, or never opened with [`Wallet::new`] since, have
    /// no manifest and cannot be loaded; call [`Wallet::new`] once to write one.
    pub fn load(
        data_dir: &str,
        master_fingerprint: &str,
        mnemonic: Option<String>,
    ) -> Result<Self, Error> {
        let data_dir_path = Path::new(data_dir);
        if !data_dir_path.exists() {
            return Err(Error::InexistentDataDir);
        }
        let wallet_dir = fs::canonicalize(data_dir_path)?.join(master_fingerprint);
        let manifest = WalletManifest::read(&wallet_dir)?;
        // a manifest reached via a renamed wallet directory would make `new` set up a second,
        // unrelated wallet at the fingerprint the manifest names
        if manifest.master_fingerprint != master_fingerprint {
            return Err(Error::FingerprintMismatch);
        }
        let (wallet_data, keys) = manifest.into_parts(data_dir.to_string(), mnemonic);
        Self::new(wallet_data, keys)
    }

    /// Return the bitcoin keys of the wallet.
    pub fn get_keys(&self) -> SinglesigKeys {
        self.keys.clone()
    }

    /// Return the descriptors of the wallet.
    pub fn get_descriptors(&self) -> WalletDescriptors {
        self.keys
            .build_descriptors(&self.internals.wallet_data.bitcoin_network)
            .expect("already succeeded at wallet creation")
            .0
    }

    pub(crate) fn sign_psbt_impl(
        &self,
        psbt: &mut Psbt,
        sign_options: Option<SignOptions>,
    ) -> Result<(), Error> {
        let sign_options = sign_options.unwrap_or_default();
        self.bdk_wallet()
            .sign(psbt, sign_options)
            .map_err(InternalError::from)?;
        Ok(())
    }

    /// Sign a PSBT, optionally providing BDK sign options.
    pub fn sign_psbt(
        &self,
        unsigned_psbt: String,
        sign_options: Option<SignOptions>,
    ) -> Result<String, Error> {
        info!(self.logger(), "Signing PSBT...");
        let mut psbt = Psbt::from_str(&unsigned_psbt)?;
        self.sign_psbt_impl(&mut psbt, sign_options)?;
        info!(self.logger(), "Sign PSBT completed");
        Ok(psbt.to_string())
    }

    /// Return a new Bitcoin address from the vanilla wallet.
    pub fn get_address(&mut self) -> Result<String, Error> {
        info!(self.logger(), "Getting address...");
        let address = self.get_new_addresses(KeychainKind::Internal, 1)?;
        let txn = self.database().begin_transaction()?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Get address completed");
        Ok(address.to_string())
    }

    /// Rotate the pinned address for the given keychain.
    ///
    /// Only meaningful when `reuse_addresses` is `true`. Increments the pinned derivation
    /// index so subsequent address generation returns a fresh address.
    pub fn rotate_address(&mut self, keychain: KeychainKind) -> Result<String, Error> {
        if !self.wallet_data().reuse_addresses {
            return Err(Error::AddressReuseDisabled);
        }
        let index = self
            .internals()
            .reuse_address_index
            .get(&keychain)
            .copied()
            .unwrap_or(0);
        let new_index = index + 1;
        self.internals_mut()
            .reuse_address_index
            .insert(keychain, new_index);
        let txn = self.database().begin_transaction()?;
        txn.set_reuse_address_index(keychain, new_index)?;
        txn.commit()?;
        let address = self.bdk_wallet().peek_address(keychain, new_index).address;
        Ok(address.to_string())
    }

    /// List the pending vanilla transactions that have reserved TXOs in the wallet.
    ///
    /// A vanilla transaction becomes "pending" when the caller invokes a vanilla `_begin` method
    /// (e.g. [`send_btc_begin`](Wallet::send_btc_begin)) with `dry_run = false`. The reserved
    /// TXOs are freed when the matching `_end` method is called or via
    /// [`abort_pending_vanilla_tx`](Wallet::abort_pending_vanilla_tx).
    pub fn list_pending_vanilla_txs(&self) -> Result<Vec<PendingVanillaTx>, Error> {
        info!(self.logger(), "Listing pending vanilla TXs...");
        let txn = self.database().begin_transaction()?;
        let reserved_idxs: Vec<i32> = txn
            .iter_reserved_txos()?
            .into_iter()
            .filter_map(|r| r.reserved_for)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let result = if reserved_idxs.is_empty() {
            vec![]
        } else {
            txn.get_wallet_transactions_by_idxs(&reserved_idxs)?
                .into_iter()
                .map(|wt| PendingVanillaTx {
                    txid: wt.txid,
                    r#type: wt.r#type,
                })
                .collect()
        };
        txn.commit()?;
        info!(self.logger(), "List pending vanilla TXs completed");
        Ok(result)
    }

    /// Abort a pending vanilla transaction, releasing the TXOs it reserved.
    ///
    /// Errors with [`Error::CannotAbortPendingVanillaTx`] if no pending vanilla transaction with
    /// the given `txid` is found (e.g. because it was never created by the wallet, was already
    /// aborted or has been broadcast).
    pub fn abort_pending_vanilla_tx(&self, txid: String) -> Result<(), Error> {
        info!(self.logger(), "Aborting pending vanilla TX {}...", txid);
        let txn = self.database().begin_transaction()?;
        let (wt, reservations) = txn
            .get_wallet_transaction_with_reserved_txos_by_txid(&txid)?
            .ok_or(Error::CannotAbortPendingVanillaTx)?;
        if reservations.is_empty() {
            return Err(Error::CannotAbortPendingVanillaTx);
        }
        txn.del_wallet_transaction(wt.idx)?; // relies on cascade to delete reserved txos
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        info!(self.logger(), "Abort pending vanilla TX completed");
        Ok(())
    }

    fn finalize_offline_issuance<T: IssuedAssetDetails>(
        &self,
        txn: &DbTxn,
        issue_data: &IssueData,
    ) -> Result<T, Error> {
        let mut runtime = self.rgb_runtime()?;
        let asset = self.import_and_save_contract(txn, issue_data, &mut runtime)?;
        T::from_issuance(txn, self, &asset, issue_data)
    }

    /// Issue a new RGB NIA asset with the provided `ticker`, `name`, `precision` and `amounts`,
    /// then return it.
    ///
    /// At least 1 amount needs to be provided and the sum of all amounts cannot exceed the maximum
    /// `u64` value.
    ///
    /// If `amounts` contains more than 1 element, each one will be issued as a separate allocation
    /// for the same asset (on a separate UTXO that needs to be already available).
    pub fn issue_asset_nia(
        &self,
        ticker: String,
        name: String,
        precision: u8,
        amounts: Vec<u64>,
    ) -> Result<AssetNIA, Error> {
        info!(self.logger(), "Issuing NIA...");
        let txn = self.database().begin_transaction()?;
        let issue_data = self.create_nia_contract(&txn, ticker, name, precision, amounts)?;
        let res = self.finalize_offline_issuance(&txn, &issue_data)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Issue asset NIA completed");
        Ok(res)
    }

    /// Issue a new RGB UDA asset with the provided `ticker`, `name`, optional `details` and
    /// `precision`, then return it.
    ///
    /// An optional `media_file_path` containing the path to a media file can be provided. Its hash
    /// and mime type will be encoded in the contract.
    ///
    /// An optional `attachments_file_paths` containing paths to extra media files can be provided.
    /// Their hash and mime type will be encoded in the contract.
    pub fn issue_asset_uda(
        &self,
        ticker: String,
        name: String,
        details: Option<String>,
        precision: u8,
        media_file_path: Option<String>,
        attachments_file_paths: Vec<String>,
    ) -> Result<AssetUDA, Error> {
        info!(self.logger(), "Issuing UDA...");
        let txn = self.database().begin_transaction()?;
        let issue_data = self.create_uda_contract(
            &txn,
            ticker,
            name,
            details,
            precision,
            media_file_path,
            attachments_file_paths,
        )?;
        let res = self.finalize_offline_issuance(&txn, &issue_data)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Issue asset UDA completed");
        Ok(res)
    }

    /// Issue a new RGB CFA asset with the provided `name`, optional `details`, `precision` and
    /// `amounts`, then return it.
    ///
    /// An optional `file_path` containing the path to a media file can be provided. Its hash and
    /// mime type will be encoded in the contract.
    ///
    /// At least 1 amount needs to be provided and the sum of all amounts cannot exceed the maximum
    /// `u64` value.
    ///
    /// If `amounts` contains more than 1 element, each one will be issued as a separate allocation
    /// for the same asset (on a separate UTXO that needs to be already available).
    pub fn issue_asset_cfa(
        &self,
        name: String,
        details: Option<String>,
        precision: u8,
        amounts: Vec<u64>,
        file_path: Option<String>,
    ) -> Result<AssetCFA, Error> {
        info!(self.logger(), "Issuing CFA...");
        let txn = self.database().begin_transaction()?;
        let issue_data =
            self.create_cfa_contract(&txn, name, details, precision, amounts, file_path)?;
        let res = self.finalize_offline_issuance(&txn, &issue_data)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Issue asset CFA completed");
        Ok(res)
    }

    /// Issue a new RGB IFA asset with the provided `ticker`, `name`, `precision`, `amounts` and
    /// `inflation_amounts`, then return it.
    ///
    /// At least 1 amount needs to be provided and the sum of all amounts cannot exceed the maximum
    /// `u64` value.
    ///
    /// If `amounts` contains more than 1 element, each one will be issued as a separate allocation
    /// for the same asset (on a separate UTXO that needs to be already available).
    ///
    /// The `inflation_amounts` can be empty. If provided the sum of its elements plus the sum of
    /// `amounts` cannot exceed the maximum `u64` value.
    ///
    /// `issuance_type` controls whether a link-right UTXO is created and whether the genesis
    /// contract declares a parent contract.
    pub fn issue_asset_ifa(
        &self,
        ticker: String,
        name: String,
        precision: u8,
        amounts: Vec<u64>,
        inflation_amounts: Vec<u64>,
        reject_list_url: Option<String>,
        issuance_type: Option<IfaIssuanceType>,
    ) -> Result<AssetIFA, Error> {
        info!(self.logger(), "Issuing IFA...");
        let (create_link_right, linked_from_contract_id) =
            issuance_type.unwrap_or_default().into_ifa_link_data()?;
        let txn = self.database().begin_transaction()?;
        let issue_data = self.create_ifa_contract(
            &txn,
            ticker,
            name,
            precision,
            amounts,
            inflation_amounts,
            reject_list_url,
            linked_from_contract_id,
            create_link_right,
        )?;
        let res = self.finalize_offline_issuance(&txn, &issue_data)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Issue asset IFA completed");
        Ok(res)
    }

    /// Blind an UTXO to receive RGB assets and return the resulting [`ReceiveData`].
    ///
    /// An optional asset ID can be specified, which will be embedded in the invoice, resulting in
    /// the refusal of the transfer is the asset doesn't match.
    ///
    /// An optional amount can be specified, which will be embedded in the invoice. It will not be
    /// checked when accepting the transfer.
    ///
    /// An expiration UTC timestamp must be specified, which will set the expiration of the
    /// invoice and the transfer.
    ///
    /// Each endpoint in the provided `transport_endpoints` list will be used as RGB data exchange
    /// medium. The list can contain a maximum of 3 endpoints; strings specifying invalid endpoints
    /// and duplicate ones will cause an error to be raised. A valid endpoint string encodes an
    /// [`RgbTransport`](https://docs.rs/rgb-invoicing/latest/rgbinvoice/enum.RgbTransport.html).
    /// At the moment the only supported variant is JsonRpc (e.g. `rpc://127.0.0.1` or
    /// `rpcs://example.com`).
    /// Providing an empty list selects the out-of-band exchange: the invoice carries no transport
    /// endpoints and the consignment and ACK are exchanged out-of-band (see
    /// [`provide_out_of_band_consignment`](Wallet::provide_out_of_band_consignment) and
    /// [`provide_out_of_band_ack`](Wallet::provide_out_of_band_ack)), without using automated
    /// transport endpoints.
    ///
    /// The `min_confirmations` number determines the minimum number of confirmations needed for
    /// the transaction anchoring the transfer for it to be considered final and move (while
    /// refreshing) to the [`TransferStatus::Settled`] status.
    pub fn blind_receive(
        &mut self,
        asset_id: Option<String>,
        assignment: Assignment,
        expiration_timestamp: u64,
        transport_endpoints: Vec<String>,
        min_confirmations: u8,
    ) -> Result<ReceiveData, Error> {
        info!(
            self.logger(),
            "Receiving via blinded UTXO for asset '{:?}' with expiration '{}'...",
            asset_id,
            expiration_timestamp,
        );
        let txn = self.database().begin_transaction()?;
        let receive_data_internal = self.create_receive_data(
            &txn,
            asset_id,
            assignment,
            expiration_timestamp as i64,
            transport_endpoints,
            RecipientType::Blind,
        )?;
        let batch_transfer_idx =
            self.store_receive_transfer(&txn, &receive_data_internal, min_confirmations)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Blind receive completed");
        Ok(ReceiveData {
            invoice: receive_data_internal.invoice_string,
            recipient_id: receive_data_internal.recipient_id,
            expiration_timestamp: receive_data_internal.expiration_timestamp as u64,
            batch_transfer_idx,
        })
    }

    /// Create an address to receive RGB assets and return the resulting [`ReceiveData`].
    ///
    /// An optional asset ID can be specified, which will be embedded in the invoice, resulting in
    /// the refusal of the transfer is the asset doesn't match.
    ///
    /// An optional amount can be specified, which will be embedded in the invoice. It will not be
    /// checked when accepting the transfer.
    ///
    /// An expiration UTC timestamp must be specified, which will set the expiration of the
    /// invoice and the transfer.
    ///
    /// Each endpoint in the provided `transport_endpoints` list will be used as RGB data exchange
    /// medium. The list can contain a maximum of 3 endpoints; strings specifying invalid endpoints
    /// and duplicate ones will cause an error to be raised. A valid endpoint string encodes an
    /// [`RgbTransport`](https://docs.rs/rgb-invoicing/latest/rgbinvoice/enum.RgbTransport.html).
    /// At the moment the only supported variant is JsonRpc (e.g. `rpc://127.0.0.1` or
    /// `rpcs://example.com`).
    /// Providing an empty list selects the out-of-band exchange: the invoice carries no transport
    /// endpoints and the consignment and ACK are exchanged out-of-band (see
    /// [`provide_out_of_band_consignment`](Wallet::provide_out_of_band_consignment) and
    /// [`provide_out_of_band_ack`](Wallet::provide_out_of_band_ack)), without using automated
    /// transport endpoints.
    ///
    /// The `min_confirmations` number determines the minimum number of confirmations needed for
    /// the transaction anchoring the transfer for it to be considered final and move (while
    /// refreshing) to the [`TransferStatus::Settled`] status.
    pub fn witness_receive(
        &mut self,
        asset_id: Option<String>,
        assignment: Assignment,
        expiration_timestamp: u64,
        transport_endpoints: Vec<String>,
        min_confirmations: u8,
    ) -> Result<ReceiveData, Error> {
        info!(
            self.logger(),
            "Receiving via witness TX for asset '{:?}' with expiration '{}'...",
            asset_id,
            expiration_timestamp,
        );
        let txn = self.database().begin_transaction()?;
        let receive_data_internal = self.create_receive_data(
            &txn,
            asset_id,
            assignment,
            expiration_timestamp as i64,
            transport_endpoints,
            RecipientType::Witness,
        )?;
        let batch_transfer_idx =
            self.store_receive_transfer(&txn, &receive_data_internal, min_confirmations)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Witness receive completed");
        Ok(ReceiveData {
            invoice: receive_data_internal.invoice_string,
            recipient_id: receive_data_internal.recipient_id,
            expiration_timestamp: receive_data_internal.expiration_timestamp as u64,
            batch_transfer_idx,
        })
    }
}

/// Online APIs of the wallet.
#[cfg(any(feature = "electrum", feature = "esplora"))]
impl Wallet {
    pub(crate) fn watch_only(&self) -> bool {
        self.keys.mnemonic.is_none()
    }

    fn check_xprv(&self) -> Result<(), Error> {
        if self.watch_only() {
            error!(self.logger(), "Invalid operation for a watch only wallet");
            return Err(Error::WatchOnly);
        }
        Ok(())
    }

    /// Create new UTXOs.
    ///
    /// This calls [`create_utxos_begin`](Wallet::create_utxos_begin), signs the resulting PSBT and
    /// finally calls [`create_utxos_end`](Wallet::create_utxos_end).
    ///
    /// A wallet with private keys is required.
    pub fn create_utxos(
        &mut self,
        online: Online,
        up_to: bool,
        num: Option<u8>,
        size: Option<u32>,
        fee_rate: u64,
        skip_sync: bool,
    ) -> Result<u8, Error> {
        info!(self.logger(), "Creating UTXOs...");
        self.check_xprv()?;
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let mut psbt =
            self.create_utxos_begin_impl(&txn, up_to, num, size, fee_rate, skip_sync, true, &[])?;
        self.sign_psbt_impl(&mut psbt, None)?;
        let res = self.create_utxos_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Create UTXOs completed");
        Ok(res)
    }

    /// Prepare the PSBT to create new UTXOs to hold RGB allocations with the provided `fee_rate`
    /// (in sat/vB).
    ///
    /// If `up_to` is false, just create the required UTXOs, if it is true, create as many UTXOs as
    /// needed to reach the requested number or return an error if none need to be created.
    ///
    /// Providing the optional `num` parameter requests that many UTXOs, if it's not specified the
    /// default number (5<!--UTXO_NUM-->) is used.
    ///
    /// Providing the optional `size` parameter requests that UTXOs be created of that size (in
    /// sats), if it's not specified the default one (1000<!--UTXO_SIZE-->) is used.
    ///
    /// If not enough bitcoin funds are available to create the requested (or default) number of
    /// UTXOs, the number is decremented by one until it is possible to complete the operation. If
    /// the number reaches zero, an error is returned.
    ///
    /// If `dry_run` is true, the wallet does not reserve the selected vanilla TXOs. The returned
    /// PSBT can still be signed and completed with
    /// [`create_utxos_end`](Wallet::create_utxos_end) but concurrent vanilla operations may try
    /// to spend the same inputs.
    ///
    /// Signing of the returned PSBT needs to be carried out separately. The signed PSBT then needs
    /// to be fed to the [`create_utxos_end`](Wallet::create_utxos_end) function.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns a PSBT ready to be signed.
    pub fn create_utxos_begin(
        &mut self,
        online: Online,
        up_to: bool,
        num: Option<u8>,
        size: Option<u32>,
        fee_rate: u64,
        skip_sync: bool,
        dry_run: bool,
    ) -> Result<String, Error> {
        self.create_utxos_begin_excluding(
            online,
            up_to,
            num,
            size,
            fee_rate,
            skip_sync,
            dry_run,
            vec![],
        )
    }

    /// [`create_utxos_begin`](Wallet::create_utxos_begin) that never spends an outpoint in
    /// `exclude_outpoints`.
    ///
    /// The split is funded from every other vanilla UTXO the wallet hasn't reserved, so a caller
    /// keeping its own reservations (e.g. the inputs of in-flight swaps) can still create UTXOs
    /// while they are held. Outpoints the wallet doesn't own are ignored.
    ///
    /// Returns a PSBT ready to be signed.
    pub fn create_utxos_begin_excluding(
        &mut self,
        online: Online,
        up_to: bool,
        num: Option<u8>,
        size: Option<u32>,
        fee_rate: u64,
        skip_sync: bool,
        dry_run: bool,
        exclude_outpoints: Vec<Outpoint>,
    ) -> Result<String, Error> {
        info!(self.logger(), "Creating UTXOs (begin)...");
        self.check_online(online)?;
        let exclude = exclude_outpoints
            .iter()
            .map(BdkOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let txn = self.database().begin_transaction()?;
        let res = self.create_utxos_begin_impl(
            &txn, up_to, num, size, fee_rate, skip_sync, dry_run, &exclude,
        )?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        txn.commit()?;
        info!(self.logger(), "Create UTXOs (begin) completed");
        Ok(res.to_string())
    }

    /// Broadcast the provided PSBT to create new UTXOs.
    ///
    /// The provided PSBT, prepared with the [`create_utxos_begin`](Wallet::create_utxos_begin)
    /// function, needs to have already been signed.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns the number of created UTXOs.
    pub fn create_utxos_end(&mut self, online: Online, signed_psbt: String) -> Result<u8, Error> {
        info!(self.logger(), "Creating UTXOs (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let res = self.create_utxos_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        info!(self.logger(), "Create UTXOs (end) completed");
        Ok(res)
    }

    /// Return the existing or freshly generated wallet [`Online`] data.
    ///
    /// See [`OnlineOptions`] for details on the available options.
    pub fn go_online(&mut self, online_options: OnlineOptions) -> Result<Online, Error> {
        info!(self.logger(), "Going online...");
        let online = self.go_online_impl(&online_options)?;
        info!(self.logger(), "Go online completed");
        Ok(online)
    }

    /// Send bitcoin funds to the provided address.
    ///
    /// This calls [`drain_to_begin`](Wallet::drain_to_begin), signs the resulting PSBT and finally
    /// calls [`drain_to_end`](Wallet::drain_to_end).
    ///
    /// A wallet with private keys is required.
    pub fn drain_to(
        &mut self,
        online: Online,
        address: String,
        fee_rate: u64,
    ) -> Result<String, Error> {
        info!(self.logger(), "Draining to '{}'...", address);
        self.check_xprv()?;
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let mut psbt = self.drain_to_begin_impl(&txn, address, fee_rate, true)?;
        self.sign_psbt_impl(&mut psbt, None)?;
        let tx = self.drain_to_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Drain completed");
        Ok(tx.compute_txid().to_string())
    }

    /// Prepare the PSBT to send all bitcoin funds to the provided `address` with the provided
    /// `fee_rate` (in sat/vB).
    ///
    /// <div class="warning">Warning: draining all funds is a destructive and irreversible
    /// operation, only do this if you know what you're doing! After draining the wallet will not
    /// be usable anymore.</div>
    ///
    /// If `dry_run` is true, the wallet does not reserve the selected vanilla TXOs. The returned
    /// PSBT can still be signed and completed with [`drain_to_end`](Wallet::drain_to_end) but
    /// concurrent vanilla operations may try to spend the same inputs.
    ///
    /// Signing of the returned PSBT needs to be carried out separately. The signed PSBT then needs
    /// to be fed to the [`drain_to_end`](Wallet::drain_to_end) function.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns a PSBT ready to be signed.
    pub fn drain_to_begin(
        &mut self,
        online: Online,
        address: String,
        fee_rate: u64,
        dry_run: bool,
    ) -> Result<String, Error> {
        info!(self.logger(), "Draining (begin) to '{}'...", address);
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let psbt = self.drain_to_begin_impl(&txn, address, fee_rate, dry_run)?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        txn.commit()?;
        info!(self.logger(), "Drain (begin) completed");
        Ok(psbt.to_string())
    }

    /// Broadcast the provided PSBT to send bitcoin funds.
    ///
    /// The provided PSBT, prepared with the [`drain_to_begin`](Wallet::drain_to_begin) function,
    /// needs to have already been signed.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns the TXID of the transaction that's been broadcast.
    pub fn drain_to_end(&mut self, online: Online, signed_psbt: String) -> Result<String, Error> {
        info!(self.logger(), "Draining (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let tx = self.drain_to_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Drain (end) completed");
        Ok(tx.compute_txid().to_string())
    }

    /// Send RGB assets.
    ///
    /// This calls [`send_begin`](Wallet::send_begin), signs the resulting PSBT and finally calls
    /// [`send_end`](Wallet::send_end).
    ///
    /// A wallet with private keys is required.
    pub fn send(
        &mut self,
        online: Online,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: u64,
        min_confirmations: u8,
        expiration_timestamp: u64,
        lock_time: Option<u32>,
    ) -> Result<OperationResult, Error> {
        info!(self.logger(), "Sending to: {:?}...", recipient_map);
        self.check_xprv()?;
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let mut begin_op_data = self.send_begin_impl(
            &txn,
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
            Some(expiration_timestamp as i64),
            true,
            lock_time,
        )?;
        self.sign_psbt_impl(&mut begin_op_data.psbt, None)?;
        let res = self.send_end_impl(&txn, &begin_op_data.psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Send completed");
        Ok(res)
    }

    /// Prepare the PSBT to send RGB assets according to the given recipient map, with the provided
    /// `fee_rate` (in sat/vB).
    ///
    /// The `recipient_map` maps asset IDs to a vector of [`Recipient`]s. When multiple recipients
    /// are provided, a batch transfer will be performed, meaning a single Bitcoin transaction will
    /// be used to move all assets to the respective recipients. Each asset being sent will result
    /// in the creation of a single consignment, which will then be posted to the RGB proxy server
    /// for each of its recipients.
    ///
    /// If `donation` is true, the resulting transaction will be broadcast (by
    /// [`send_end`](Wallet::send_end)) as soon as it's ready, without the need for recipients to
    /// ACK the transfer.
    /// If `donation` is false, all recipients will need to ACK the transfer before the transaction
    /// is broadcast.
    ///
    /// The `min_confirmations` number determines the minimum number of confirmations needed for
    /// the transaction anchoring the transfer for it to be considered final and move (while
    /// refreshing) to the [`TransferStatus::Settled`] status.
    ///
    /// An expiration UTC timestamp must be specified, which will set the expiration of the
    /// transfer. This should be set to the same value specified by the recipient's invoice, so
    /// that sender and recipient enforce the same deadline; once it passes, the recipient is
    /// allowed to fail the transfer and the sender will avoid broadcasting it even if a late ACK is
    /// received. In case of a batch transfer, set it to the minimum (earliest) expiration across
    /// the recipients' invoices.
    ///
    /// If `dry_run` is true, the wallet does not persist the transfer in
    /// [`TransferStatus::Initiated`]. The returned [`SendBeginResult::batch_transfer_idx`] is None
    /// in that case. The PSBT and on-disk transfer data under the wallet directory are still
    /// produced. [`send_end`](Wallet::send_end) can still complete the operation and will persist
    /// the transfer.
    ///
    /// This API requires to be online since it checks the validity and reachability of the
    /// transport endpoints.
    ///
    /// Signing of the returned PSBT needs to be carried out separately. The signed PSBT then needs
    /// to be fed to the [`send_end`](Wallet::send_end) function to complete the send operation.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns a PSBT ready to be signed and operation details.
    pub fn send_begin(
        &mut self,
        online: Online,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: u64,
        min_confirmations: u8,
        expiration_timestamp: u64,
        dry_run: bool,
        lock_time: Option<u32>,
    ) -> Result<SendBeginResult, Error> {
        info!(self.logger(), "Sending (begin) to: {:?}...", recipient_map);
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let begin_op_data = self.send_begin_impl(
            &txn,
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
            Some(expiration_timestamp as i64),
            dry_run,
            lock_time,
        )?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        txn.commit()?;
        if !dry_run {
            self.trigger_auto_backup();
        }
        info!(self.logger(), "Send (begin) completed");
        Ok(SendBeginResult {
            psbt: begin_op_data.psbt.to_string(),
            batch_transfer_idx: begin_op_data.batch_transfer_idx,
            details: SendDetails {
                fascia_path: begin_op_data
                    .transfer_dir
                    .join(FASCIA_FILE)
                    .to_string_lossy()
                    .to_string(),
                min_confirmations,
                entropy: begin_op_data.info_batch_transfer.entropy,
                is_donation: donation,
            },
        })
    }

    /// Complete the send operation by saving the PSBT to disk, POSTing consignments to the RGB
    /// proxy server, saving the transfer to DB and broadcasting the provided PSBT, if appropriate.
    ///
    /// The provided PSBT, prepared with the [`send_begin`](Wallet::send_begin) function, needs to
    /// have already been signed.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns a [`OperationResult`].
    pub fn send_end(
        &mut self,
        online: Online,
        signed_psbt: String,
    ) -> Result<OperationResult, Error> {
        info!(self.logger(), "Sending (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let res = self.send_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Send (end) completed");
        Ok(res)
    }

    /// Receive an RGB transfer whose consignment was exchanged out-of-band, without using automated
    /// transport endpoints.
    ///
    /// This is the out-of-band counterpart of [`refresh`](Wallet::refresh) for transfers created
    /// with an empty transport endpoint list. The consignment at `consignment_path` (received
    /// through any external channel) is matched against the pending incoming out-of-band transfers,
    /// validated and if it carries an unknown asset this is imported.
    ///
    /// A single consignment transfers a single asset but can satisfy more than one pending invoice
    /// of this wallet (e.g. a sender batched a send to several of them); every matched receive is
    /// processed and the result is keyed by batch transfer idx, mirroring
    /// [`refresh`](Wallet::refresh).
    ///
    /// Media of an unknown asset is taken from the files already present in the wallet media
    /// directory, falling back to the out-of-band `media_file_paths` (matched by content hash). A
    /// consignment defining media that is neither already present nor provided fails locally.
    ///
    /// On success, if a signed witness transaction is found it is broadcast and the transfer moves
    /// to [`TransferStatus::WaitingConfirmations`], otherwise it moves to
    /// [`TransferStatus::WaitingBroadcast`], leaving the ACK to be communicated to the sender
    /// out-of-band. An invalid consignment fails the transfer locally, without any proxy NACK.
    pub fn provide_out_of_band_consignment(
        &mut self,
        online: Online,
        consignment_path: String,
        media_file_paths: Vec<String>,
    ) -> Result<RefreshResult, Error> {
        info!(self.logger(), "Providing out-of-band consignment...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let res =
            self.provide_out_of_band_consignment_impl(&txn, &consignment_path, media_file_paths)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Provide out-of-band consignment completed");
        Ok(res)
    }

    /// Record the out-of-band ACK for an out-of-band recipient of an outgoing
    /// [`TransferStatus::WaitingCounterparty`] batch transfer, identified by its `recipient_id`,
    /// after the ACK has been received out-of-band.
    ///
    /// This is the out-of-band counterpart of the proxy ACK flow driven by [`refresh`](Wallet::refresh).
    /// The batch is broadcast only once *every* recipient has ACKed (via this call for the
    /// out-of-band ones and via `refresh` for the proxy ones), so a batch may freely mix out-of-band
    /// and proxy recipients. Recipients using the JSON-RPC proxy are rejected here, keeping the
    /// `refresh` flow authoritative for them.
    ///
    /// Returns the broadcast [`OperationResult`] (transfer moved to
    /// [`TransferStatus::WaitingConfirmations`]) when this ACK completed the batch, or `None` when
    /// the batch still has recipients waiting to ACK.
    pub fn provide_out_of_band_ack(
        &mut self,
        online: Online,
        recipient_id: String,
    ) -> Result<Option<OperationResult>, Error> {
        info!(
            self.logger(),
            "Providing out-of-band ACK for recipient {recipient_id}..."
        );
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let res = self.provide_out_of_band_ack_impl(&txn, recipient_id)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Provide out-of-band ACK completed");
        Ok(res)
    }

    /// Send bitcoins using the vanilla wallet.
    ///
    /// This calls [`send_btc_begin`](Wallet::send_btc_begin), signs the resulting PSBT and finally
    /// calls [`send_btc_end`](Wallet::send_btc_end).
    ///
    /// A wallet with private keys and [`Online`] data are required.
    pub fn send_btc(
        &mut self,
        online: Online,
        address: String,
        amount: u64,
        fee_rate: u64,
        skip_sync: bool,
        lock_time: Option<u32>,
    ) -> Result<String, Error> {
        info!(self.logger(), "Sending BTC...");
        self.check_xprv()?;
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let mut psbt = self.send_btc_begin_impl(
            &txn,
            &[(address, amount)],
            fee_rate,
            skip_sync,
            true,
            lock_time,
            &[],
        )?;
        self.sign_psbt_impl(&mut psbt, None)?;
        let res = self.send_btc_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        info!(self.logger(), "Send BTC completed");
        Ok(res)
    }

    /// Prepare the PSBT to send the specified `amount` of bitcoins (in sats) using the vanilla
    /// wallet to the specified Bitcoin `address` with the specified `fee_rate` (in sat/vB).
    ///
    /// If `dry_run` is true, the wallet does not reserve the selected vanilla TXOs. The returned
    /// PSBT can still be signed and completed with [`send_btc_end`](Wallet::send_btc_end) but
    /// concurrent vanilla operations may try to spend the same inputs.
    ///
    /// Signing of the returned PSBT needs to be carried out separately. The signed PSBT then needs
    /// to be fed to the [`send_btc_end`](Wallet::send_btc_end) function.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns a PSBT ready to be signed.
    pub fn send_btc_begin(
        &mut self,
        online: Online,
        address: String,
        amount: u64,
        fee_rate: u64,
        skip_sync: bool,
        dry_run: bool,
        lock_time: Option<u32>,
    ) -> Result<String, Error> {
        self.send_btc_many_begin(
            online,
            vec![(address, amount)],
            fee_rate,
            skip_sync,
            dry_run,
            lock_time,
            vec![],
        )
    }

    /// Prepare the PSBT to send bitcoins using the vanilla wallet to several `recipients` in one
    /// transaction, with the specified `fee_rate` (in sat/vB).
    ///
    /// Each recipient is a Bitcoin address and the amount (in sats) it receives, one output each.
    /// Outpoints in `exclude_outpoints` are never spent; outpoints the wallet doesn't own are
    /// ignored. `skip_sync`, `dry_run` and `lock_time` are as in
    /// [`send_btc_begin`](Wallet::send_btc_begin).
    ///
    /// Signing of the returned PSBT needs to be carried out separately. The signed PSBT then needs
    /// to be fed to the [`send_btc_end`](Wallet::send_btc_end) function.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns a PSBT ready to be signed.
    pub fn send_btc_many_begin(
        &mut self,
        online: Online,
        recipients: Vec<(String, u64)>,
        fee_rate: u64,
        skip_sync: bool,
        dry_run: bool,
        lock_time: Option<u32>,
        exclude_outpoints: Vec<Outpoint>,
    ) -> Result<String, Error> {
        info!(self.logger(), "Sending BTC (begin)...");
        self.check_online(online)?;
        let exclude = exclude_outpoints
            .iter()
            .map(BdkOutPoint::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let txn = self.database().begin_transaction()?;
        let res = self.send_btc_begin_impl(
            &txn,
            &recipients,
            fee_rate,
            skip_sync,
            dry_run,
            lock_time,
            &exclude,
        )?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        txn.commit()?;
        info!(self.logger(), "Send BTC (begin) completed");
        Ok(res.to_string())
    }

    /// Broadcast the provided PSBT to send bitcoins using the vanilla wallet.
    ///
    /// The provided PSBT, prepared with the [`send_btc_begin`](Wallet::send_btc_begin) function,
    /// needs to have already been signed.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns the TXID of the broadcasted transaction.
    pub fn send_btc_end(&mut self, online: Online, signed_psbt: String) -> Result<String, Error> {
        info!(self.logger(), "Sending BTC (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let res = self.send_btc_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        info!(self.logger(), "Send BTC (end) completed");
        Ok(res)
    }

    /// Inflate RGB assets.
    ///
    /// This calls [`inflate_begin`](Wallet::inflate_begin), signs the resulting PSBT and finally
    /// calls [`inflate_end`](Wallet::inflate_end).
    ///
    /// A wallet with private keys is required.
    pub fn inflate(
        &mut self,
        online: Online,
        asset_id: String,
        inflation_amounts: Vec<u64>,
        fee_rate: u64,
        min_confirmations: u8,
    ) -> Result<OperationResult, Error> {
        info!(
            self.logger(),
            "Inflating amounts: {:?}...", inflation_amounts
        );
        self.check_xprv()?;
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let mut begin_op_data = self.inflate_begin_impl(
            &txn,
            asset_id,
            inflation_amounts,
            fee_rate,
            min_confirmations,
            true,
        )?;
        self.sign_psbt_impl(&mut begin_op_data.psbt, None)?;
        let res = self.inflate_end_impl(&txn, &begin_op_data.psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Inflate completed");
        Ok(res)
    }

    /// Prepare the PSBT to inflate RGB assets according to the given inflation amounts, with the
    /// provided `fee_rate` (in sat/vB).
    ///
    /// For every amount in `inflation_amounts` a new UTXO allocating the requested
    /// asset amount will be created. The sum of its elements plus the known circulating supply
    /// cannot exceed the maximum `u64` value.
    ///
    /// The `min_confirmations` number determines the minimum number of confirmations needed for
    /// the transaction anchoring the transfer for it to be considered final and move (while
    /// refreshing) to the [`TransferStatus::Settled`] status.
    ///
    /// If `dry_run` is true, the wallet does not persist the transfer in
    /// [`TransferStatus::Initiated`]. The returned [`InflateBeginResult::batch_transfer_idx`] is
    /// None in that case. The PSBT and on-disk transfer data under the wallet directory are still
    /// produced. [`inflate_end`](Wallet::inflate_end) can still complete the operation and will
    /// persist the transfer.
    ///
    /// Signing of the returned PSBT needs to be carried out separately. The signed PSBT then needs
    /// to be fed to the [`inflate_end`](Wallet::inflate_end) function for broadcasting.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns a PSBT ready to be signed and operation details.
    pub fn inflate_begin(
        &mut self,
        online: Online,
        asset_id: String,
        inflation_amounts: Vec<u64>,
        fee_rate: u64,
        min_confirmations: u8,
        dry_run: bool,
    ) -> Result<InflateBeginResult, Error> {
        info!(
            self.logger(),
            "Inflating (begin) amounts: {:?}...", inflation_amounts
        );
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let begin_operation_data = self.inflate_begin_impl(
            &txn,
            asset_id,
            inflation_amounts,
            fee_rate,
            min_confirmations,
            dry_run,
        )?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        txn.commit()?;
        if !dry_run {
            self.trigger_auto_backup();
        }
        info!(self.logger(), "Inflate (begin) completed");
        Ok(InflateBeginResult {
            psbt: begin_operation_data.psbt.to_string(),
            batch_transfer_idx: begin_operation_data.batch_transfer_idx,
            details: InflateDetails {
                fascia_path: begin_operation_data
                    .transfer_dir
                    .join(FASCIA_FILE)
                    .to_string_lossy()
                    .to_string(),
                min_confirmations,
                entropy: begin_operation_data.info_batch_transfer.entropy,
            },
        })
    }

    /// Complete the inflate operation by broadcasting the provided PSBT and saving the transfer to
    /// DB.
    ///
    /// The provided PSBT, prepared with the [`inflate_begin`](Wallet::inflate_begin) function,
    /// needs to have already been signed.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns a [`OperationResult`].
    pub fn inflate_end(
        &mut self,
        online: Online,
        signed_psbt: String,
    ) -> Result<OperationResult, Error> {
        info!(self.logger(), "Inflating (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let res = self.inflate_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Inflate (end) completed");
        Ok(res)
    }

    /// Burn RGB assets.
    ///
    /// This calls [`burn_begin`](Wallet::burn_begin), signs the resulting PSBT and finally
    /// calls [`burn_end`](Wallet::burn_end).
    ///
    /// A wallet with private keys is required.
    pub fn burn(
        &mut self,
        online: Online,
        asset_id: String,
        amount: u64,
        fee_rate: u64,
        min_confirmations: u8,
    ) -> Result<OperationResult, Error> {
        info!(self.logger(), "Burning amount: {}...", amount);
        self.check_xprv()?;
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let mut begin_op_data =
            self.burn_begin_impl(&txn, asset_id, amount, fee_rate, min_confirmations, true)?;
        self.sign_psbt_impl(&mut begin_op_data.psbt, None)?;
        let res = self.burn_end_impl(&txn, &begin_op_data.psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        info!(self.logger(), "Burn completed");
        Ok(res)
    }

    /// Prepare the PSBT to burn RGB assets according to the given amount, with the provided
    /// `fee_rate` (in sat/vB).
    ///
    /// The amount of assets to burn is specified by the `amount` parameter and cannot be zero.
    ///
    /// If `dry_run` is true, the wallet does not persist the transfer in
    /// [`TransferStatus::Initiated`]. The returned [`BurnBeginResult::batch_transfer_idx`] is None
    /// in that case. The PSBT and on-disk transfer data under the wallet directory are still
    /// produced. [`burn_end`](Wallet::burn_end) can still complete the operation and will persist
    /// the transfer.
    ///
    /// Signing of the returned PSBT needs to be carried out separately. The signed PSBT then needs
    /// to be fed to the [`burn_end`](Wallet::burn_end) function for broadcasting.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns a PSBT ready to be signed and operation details.
    pub fn burn_begin(
        &mut self,
        online: Online,
        asset_id: String,
        amount: u64,
        fee_rate: u64,
        min_confirmations: u8,
        dry_run: bool,
    ) -> Result<BurnBeginResult, Error> {
        info!(self.logger(), "Burning (begin) amount: {}...", amount);
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let begin_operation_data =
            self.burn_begin_impl(&txn, asset_id, amount, fee_rate, min_confirmations, dry_run)?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        txn.commit()?;
        info!(self.logger(), "Burn (begin) completed");
        Ok(BurnBeginResult {
            psbt: begin_operation_data.psbt.to_string(),
            batch_transfer_idx: begin_operation_data.batch_transfer_idx,
            details: BurnDetails {
                fascia_path: begin_operation_data
                    .transfer_dir
                    .join(FASCIA_FILE)
                    .to_string_lossy()
                    .to_string(),
                min_confirmations,
                entropy: begin_operation_data.info_batch_transfer.entropy,
            },
        })
    }

    /// Complete the burn operation by broadcasting the provided PSBT and saving the transfer to DB.
    ///
    /// The provided PSBT, prepared with the [`burn_begin`](Wallet::burn_begin) function, needs to
    /// have already been signed.
    ///
    /// This doesn't require the wallet to have private keys.
    ///
    /// Returns a [`OperationResult`].
    pub fn burn_end(
        &mut self,
        online: Online,
        signed_psbt: String,
    ) -> Result<OperationResult, Error> {
        info!(self.logger(), "Burning (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let res = self.burn_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        info!(self.logger(), "Burn (end) completed");
        Ok(res)
    }

    /// Link parent contract to child contract by consuming the parent's link-right single-use seal.
    pub fn link_ifa(
        &mut self,
        online: Online,
        parent_contract_id: String,
        child_contract_id: String,
        link_right_outpoint: Outpoint,
        fee_rate: u64,
        min_confirmations: u8,
    ) -> Result<OperationResult, Error> {
        info!(
            self.logger(),
            "Linking parent IFA contract ID '{}' to child contract ID '{}' using the link-right outpoint {}...",
            parent_contract_id,
            child_contract_id,
            link_right_outpoint,
        );
        self.check_xprv()?;
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let mut begin_op_data = self.link_ifa_begin_impl(
            &txn,
            parent_contract_id,
            child_contract_id,
            link_right_outpoint,
            fee_rate,
            min_confirmations,
            true,
        )?;
        self.sign_psbt_impl(&mut begin_op_data.psbt, None)?;
        let res = self.link_ifa_end_impl(&txn, &begin_op_data.psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Contract link completed");
        Ok(res)
    }

    // ─── On-chain swap ─────────────────────────────────────────────────────────

    /// Create a maker offer for an on-chain swap.
    ///
    /// The maker specifies what they give (`maker_gives`) and what they want in return
    /// (`maker_receives`). `network_fee_sat` is the total miner fee the taker will reserve in
    /// the swap transaction. `proxy_url` is required; consignments produced during the swap are
    /// posted there so the counterparty can fetch them, and it is also used to publish the current
    /// asset history so the taker can validate the asset before accepting.
    ///
    /// `platform_fee_sat`/`fee_recipient` reserve an additional output for a third-party
    /// facilitator, funded by the taker alongside `network_fee_sat`. Pass `0`/`None` when there
    /// is no facilitator.
    ///
    /// This method is **offline** — no network connection is required.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[allow(clippy::too_many_arguments)]
    pub fn create_swap_offer(
        &mut self,
        maker_gives: OnchainSwapLeg,
        maker_receives: OnchainSwapLeg,
        network_fee_sat: u64,
        expiration_timestamp: Option<u64>,
        proxy_url: Option<String>,
        platform_fee_sat: u64,
        fee_recipient: Option<String>,
    ) -> Result<OnchainSwapOffer, Error> {
        info!(self.logger(), "Creating on-chain swap offer...");
        let txn = self.database().begin_transaction()?;
        let offer = self.create_swap_offer_impl(
            &txn,
            maker_gives,
            maker_receives,
            network_fee_sat,
            expiration_timestamp,
            proxy_url,
            platform_fee_sat,
            fee_recipient,
        )?;
        swap_save_state(self.wallet_dir(), &offer.swap_id, SWAP_OFFER_FILE, &offer)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        info!(self.logger(), "Create swap offer completed");
        Ok(offer)
    }

    /// Accept a maker offer as the taker and return the taker's request message.
    ///
    /// The taker validates the offer, selects their inputs, and derives the receive destination.
    /// Inputs in `exclude_outpoints` are never selected. The returned [`OnchainSwapRequest`] must
    /// be forwarded to the maker.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_swap_offer(
        &mut self,
        online: Online,
        offer: OnchainSwapOffer,
        min_confirmations: u8,
        skip_sync: bool,
        exclude_outpoints: Vec<Outpoint>,
    ) -> Result<OnchainSwapRequest, Error> {
        info!(self.logger(), "Accepting on-chain swap offer...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        swap_validate_legs(&offer.maker_gives, &offer.maker_receives)?;
        swap_validate_proxy_url(&offer.proxy_url)?;
        swap_ensure_not_expired(&offer)?;
        if offer.bitcoin_network != self.bitcoin_network() {
            return Err(Error::BitcoinNetworkMismatch);
        }
        let taker_gives = offer.maker_receives.clone();
        let taker_receives = offer.maker_gives.clone();
        let taker_inputs = swap_select_inputs(
            self,
            &txn,
            online,
            &taker_gives,
            swap_side_rgb_output_cost(&taker_receives, offer.rgb_output_sat)
                .checked_add(offer.network_fee_sat)
                .and_then(|v| v.checked_add(offer.platform_fee_sat))
                .ok_or_else(|| swap_invalid("swap amounts overflow"))?,
            min_confirmations,
            skip_sync,
            &exclude_outpoints,
        )?;
        let (
            taker_btc_address,
            taker_rgb_recipient_id,
            taker_rgb_script_pubkey_hex,
            taker_rgb_blinding,
        ) = if matches!(taker_receives.kind, OnchainSwapLegKind::Btc) {
            // Use get_new_addresses directly (BDK-only, no DB) to avoid opening a second
            // connection while the outer transaction already holds the single pool connection.
            (
                Some(
                    self.get_new_addresses(KeychainKind::Internal, 1)?
                        .to_string(),
                ),
                None,
                None,
                None,
            )
        } else {
            let script = self
                .get_new_addresses(KeychainKind::External, 1)?
                .script_pubkey();
            let blinding = swap_random_blinding();
            (
                None,
                Some(recipient_id_from_script_buf(
                    script.clone(),
                    self.bitcoin_network(),
                )?),
                Some(script.to_hex_string()),
                Some(blinding),
            )
        };
        // RGB change is carried to the change output, which must then be colored
        let taker_change_keychain = if matches!(taker_gives.kind, OnchainSwapLegKind::Rgb) {
            KeychainKind::External
        } else {
            KeychainKind::Internal
        };
        let taker_change_script_pubkey_hex = self
            .get_new_addresses(taker_change_keychain, 1)?
            .script_pubkey()
            .to_hex_string();
        let request = OnchainSwapRequest {
            offer,
            taker_inputs,
            taker_btc_address,
            taker_rgb_recipient_id,
            taker_rgb_script_pubkey_hex,
            taker_rgb_blinding,
            taker_change_script_pubkey_hex,
        };
        swap_save_state(
            self.wallet_dir(),
            &request.offer.swap_id,
            SWAP_REQUEST_FILE,
            &request,
        )?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        info!(self.logger(), "Accept swap offer completed");
        Ok(request)
    }

    /// Accept a taker request as the maker and return the maker's PSBT proposal.
    ///
    /// The maker validates the request, selects their inputs, builds the collaborative PSBT and
    /// colors any RGB leg they are sending, without signing: the maker signs last, in
    /// [`process_swap_completion`](Wallet::process_swap_completion). Inputs in
    /// `exclude_outpoints` are never selected, so a caller running concurrent swaps can keep its
    /// own reservations. The returned [`OnchainSwapProposal`] must be forwarded to the taker.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_swap_request(
        &mut self,
        online: Online,
        request: OnchainSwapRequest,
        min_confirmations: u8,
        skip_sync: bool,
        exclude_outpoints: Vec<Outpoint>,
    ) -> Result<OnchainSwapProposal, Error> {
        info!(self.logger(), "Accepting on-chain swap request...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let offer = request.offer.clone();
        let local_offer: OnchainSwapOffer =
            swap_load_state(self.wallet_dir(), &offer.swap_id, SWAP_OFFER_FILE)?;
        swap_ensure_state_matches(&local_offer, &offer, "offer")?;
        let direction = swap_validate_legs(&offer.maker_gives, &offer.maker_receives)?;
        swap_validate_proxy_url(&offer.proxy_url)?;
        swap_ensure_not_expired(&offer)?;
        if offer.bitcoin_network != self.bitcoin_network() {
            return Err(Error::BitcoinNetworkMismatch);
        }
        // Correctness: verify the taker's inputs are sufficiently confirmed before the maker
        // commits resources to building the PSBT.
        swap_ensure_inputs_confirmed(self, &request.taker_inputs, min_confirmations)?;
        swap_require_rgb_destination(
            &offer.maker_gives,
            &request.taker_rgb_script_pubkey_hex,
            &request.taker_rgb_blinding,
        )?;
        swap_require_rgb_destination(
            &offer.maker_receives,
            &offer.maker_rgb_script_pubkey_hex,
            &offer.maker_rgb_blinding,
        )?;
        let maker_inputs = swap_select_inputs(
            self,
            &txn,
            online,
            &offer.maker_gives,
            swap_side_rgb_output_cost(&offer.maker_receives, offer.rgb_output_sat),
            min_confirmations,
            skip_sync,
            &exclude_outpoints,
        )?;
        let maker_change_keychain = if matches!(offer.maker_gives.kind, OnchainSwapLegKind::Rgb) {
            KeychainKind::External
        } else {
            KeychainKind::Internal
        };
        let maker_change_script_pubkey_hex = self
            .get_new_addresses(maker_change_keychain, 1)?
            .script_pubkey()
            .to_hex_string();
        let mut proposal = OnchainSwapProposal {
            request,
            maker_inputs,
            maker_change_script_pubkey_hex,
            psbt: String::new(),
            txid: String::new(),
            consignments: vec![],
            maker_history: None,
        };
        let (mut psbt, _maker_rgb_vout, taker_rgb_vout) = swap_build_psbt(&proposal)?;
        let mut consignments = vec![];
        let mut maker_history = None;
        if matches!(offer.maker_gives.kind, OnchainSwapLegKind::Rgb) {
            maker_history = swap_emit_asset_history(
                self,
                &offer.maker_gives,
                offer.proxy_url.as_deref(),
                &offer.swap_id,
            )?;
            let send = SwapRgbSend {
                leg: &offer.maker_gives,
                inputs: &proposal.maker_inputs,
                change_script_hex: &proposal.maker_change_script_pubkey_hex,
                recipient_id: proposal
                    .request
                    .taker_rgb_recipient_id
                    .as_deref()
                    .ok_or_else(|| swap_invalid("missing taker RGB recipient ID"))?,
                recipient_vout: taker_rgb_vout
                    .ok_or_else(|| swap_invalid("missing taker RGB vout"))?,
                blinding: proposal
                    .request
                    .taker_rgb_blinding
                    .ok_or_else(|| swap_invalid("missing taker RGB blinding"))?,
            };
            match direction {
                SwapDirection::RgbForBtc => {
                    consignments = swap_color_rgb_leg(
                        &txn,
                        self,
                        &mut psbt,
                        &send,
                        offer.proxy_url.as_deref(),
                        &offer.swap_id,
                        offer.expiration_timestamp,
                    )?;
                }
                SwapDirection::RgbForRgb => {
                    swap_stage_rgb_leg(self, &mut psbt, &send)?;
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
            swap_restore_input_metadata(&mut psbt, &inputs)?;
        }
        proposal.txid = psbt.unsigned_tx.compute_txid().to_string();
        proposal.psbt = psbt.to_string();
        proposal.consignments = consignments;
        proposal.maker_history = maker_history;
        swap_save_state(
            self.wallet_dir(),
            &offer.swap_id,
            SWAP_PROPOSAL_FILE,
            &proposal,
        )?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        info!(self.logger(), "Accept swap request completed");
        Ok(proposal)
    }

    /// Complete a maker proposal as the taker.
    ///
    /// The taker validates the PSBT, colors any RGB leg they are sending and signs the PSBT. The
    /// maker always signs last, so the returned [`OnchainSwapCompletion`] is never broadcastable
    /// by the taker: it must be forwarded to the maker, who calls
    /// [`process_swap_completion`](Wallet::process_swap_completion) and broadcasts.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
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
        let local_request: OnchainSwapRequest =
            swap_load_state(self.wallet_dir(), &offer.swap_id, SWAP_REQUEST_FILE)?;
        swap_ensure_state_matches(&local_request, &proposal.request, "request")?;
        let direction = swap_validate_legs(&offer.maker_gives, &offer.maker_receives)?;
        swap_validate_proxy_url(&offer.proxy_url)?;
        swap_ensure_not_expired(offer)?;
        if offer.bitcoin_network != self.bitcoin_network() {
            return Err(Error::BitcoinNetworkMismatch);
        }
        let mut psbt = Psbt::from_str(&proposal.psbt)?;
        swap_validate_proposal_psbt(&proposal, &psbt)?;
        if proposal.txid != psbt.unsigned_tx.compute_txid().to_string() {
            return Err(swap_invalid("swap proposal txid mismatch"));
        }
        let mut consignments = proposal.consignments.clone();
        let mut taker_history = None;
        let (_expected_psbt, maker_rgb_vout, taker_rgb_vout) = swap_build_psbt(&proposal)?;
        let all_inputs = proposal
            .maker_inputs
            .iter()
            .chain(proposal.request.taker_inputs.iter())
            .cloned()
            .collect::<Vec<_>>();
        swap_restore_input_metadata(&mut psbt, &all_inputs)?;
        let taker_send = SwapRgbSend {
            leg: &offer.maker_receives,
            inputs: &proposal.request.taker_inputs,
            change_script_hex: &proposal.request.taker_change_script_pubkey_hex,
            recipient_id: offer.maker_rgb_recipient_id.as_deref().unwrap_or_default(),
            recipient_vout: maker_rgb_vout.unwrap_or_default(),
            blinding: offer.maker_rgb_blinding.unwrap_or_default(),
        };
        if matches!(offer.maker_receives.kind, OnchainSwapLegKind::Rgb)
            && (offer.maker_rgb_recipient_id.is_none()
                || maker_rgb_vout.is_none()
                || offer.maker_rgb_blinding.is_none())
        {
            return Err(swap_invalid("missing maker RGB receive data"));
        }
        match direction {
            SwapDirection::BtcForRgb => {
                consignments.extend(swap_color_rgb_leg(
                    &txn,
                    self,
                    &mut psbt,
                    &taker_send,
                    offer.proxy_url.as_deref(),
                    &offer.swap_id,
                    offer.expiration_timestamp,
                )?);
                swap_restore_input_metadata(&mut psbt, &all_inputs)?;
            }
            SwapDirection::RgbForBtc => {
                let vout = taker_rgb_vout.ok_or_else(|| swap_invalid("missing taker RGB vout"))?;
                let blinding = proposal
                    .request
                    .taker_rgb_blinding
                    .ok_or_else(|| swap_invalid("missing taker RGB blinding"))?;
                let recipient_id = proposal
                    .request
                    .taker_rgb_recipient_id
                    .as_deref()
                    .ok_or_else(|| swap_invalid("missing taker RGB recipient ID"))?;
                swap_validate_received_swap_leg(
                    self,
                    &proposal.consignments,
                    &offer.maker_gives,
                    &proposal.txid,
                    vout,
                    blinding,
                    recipient_id,
                )?;
            }
            SwapDirection::RgbForRgb => {
                let maker_history = proposal
                    .maker_history
                    .as_ref()
                    .ok_or_else(|| swap_invalid("missing maker asset history"))?;
                swap_import_asset_history(self, &txn, maker_history)?;
                taker_history = swap_emit_asset_history(
                    self,
                    &offer.maker_receives,
                    offer.proxy_url.as_deref(),
                    &offer.swap_id,
                )?;
                swap_stage_rgb_leg(self, &mut psbt, &taker_send)?;
                let mpc_entropy = swap_mpc_entropy(&offer.swap_id);
                let fascia = self.color_psbt_finalize(&mut psbt, Some(mpc_entropy))?;
                let taker_recv_vout =
                    taker_rgb_vout.ok_or_else(|| swap_invalid("missing taker RGB vout"))?;
                let taker_recv_blinding = proposal
                    .request
                    .taker_rgb_blinding
                    .ok_or_else(|| swap_invalid("missing taker RGB blinding"))?;
                swap_validate_fascia_received_leg(
                    &fascia,
                    &offer.maker_gives,
                    taker_recv_vout,
                    taker_recv_blinding,
                )?;
                consignments.extend(swap_prepare_rgb_leg(
                    &txn,
                    self,
                    &psbt,
                    &fascia,
                    &taker_send,
                    offer.proxy_url.as_deref(),
                    &offer.swap_id,
                    offer.expiration_timestamp,
                )?);
                swap_restore_input_metadata(&mut psbt, &all_inputs)?;
            }
        }
        self.sync_if_requested(&txn, Some(online), skip_sync, KeychainKind::Internal)?;
        self.sync_if_requested(&txn, Some(online), skip_sync, KeychainKind::External)?;
        swap_ensure_inputs_confirmed(self, &proposal.maker_inputs, min_confirmations)?;
        swap_ensure_inputs_confirmed(self, &proposal.request.taker_inputs, min_confirmations)?;
        swap_sign_psbt(self, &mut psbt)?;
        let finalized_psbt = swap_finalize_psbt(self, &psbt)?;
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        let completion = OnchainSwapCompletion {
            proposal,
            psbt: psbt.to_string(),
            finalized_psbt,
            txid,
            consignments,
            taker_history,
        };
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        info!(self.logger(), "Complete swap proposal completed");
        Ok(completion)
    }

    /// Process a swap completion as the maker after receiving it from the taker.
    ///
    /// For BTC-for-RGB and RGB-for-RGB swaps, the maker first validates the incoming RGB
    /// consignment and only then signs/finalizes the PSBT. For RGB-for-RGB swaps, the maker also
    /// consumes the taker's fascia and generates the consignment for the leg they are sending.
    ///
    /// The returned (possibly updated) [`OnchainSwapCompletion`] is what both parties should
    /// use when calling [`accept_swap_transfers`](Wallet::accept_swap_transfers).
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn process_swap_completion(
        &mut self,
        online: Online,
        completion: OnchainSwapCompletion,
    ) -> Result<OnchainSwapCompletion, Error> {
        info!(self.logger(), "Processing on-chain swap completion...");
        self.check_online(online)?;
        let offer = completion.proposal.request.offer.clone();
        let local_proposal: OnchainSwapProposal =
            swap_load_state(self.wallet_dir(), &offer.swap_id, SWAP_PROPOSAL_FILE)?;
        swap_ensure_state_matches(&local_proposal, &completion.proposal, "proposal")?;
        let direction = swap_validate_legs(&offer.maker_gives, &offer.maker_receives)?;
        swap_validate_proxy_url(&offer.proxy_url)?;
        // the maker signs last: never sign a swap whose offer has expired
        swap_ensure_not_expired(&offer)?;
        let mut psbt = Psbt::from_str(&completion.psbt)?;
        swap_validate_proposal_psbt(&completion.proposal, &psbt)?;
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        if completion.txid != txid {
            return Err(swap_invalid("swap completion txid mismatch"));
        }
        let all_inputs = completion
            .proposal
            .maker_inputs
            .iter()
            .chain(completion.proposal.request.taker_inputs.iter())
            .cloned()
            .collect::<Vec<_>>();
        swap_restore_input_metadata(&mut psbt, &all_inputs)?;
        let (_expected_psbt, maker_rgb_vout, taker_rgb_vout) =
            swap_build_psbt(&completion.proposal)?;

        match direction {
            SwapDirection::RgbForBtc => {
                // the maker's RGB leg was committed when building the proposal: the taker may only
                // have added signatures
                if txid != completion.proposal.txid {
                    return Err(swap_invalid("swap completion txid mismatch"));
                }
                let txn = self.database().begin_transaction()?;
                self.sync_if_requested(&txn, Some(online), false, KeychainKind::Internal)?;
                self.sync_if_requested(&txn, Some(online), false, KeychainKind::External)?;
                swap_ensure_inputs_confirmed(self, &completion.proposal.maker_inputs, 0)?;
                swap_ensure_inputs_confirmed(self, &completion.proposal.request.taker_inputs, 0)?;
                swap_sign_psbt(self, &mut psbt)?;
                let finalized_psbt = Some(swap_finalize_psbt_required(self, &psbt)?);
                let completion = OnchainSwapCompletion {
                    psbt: psbt.to_string(),
                    finalized_psbt,
                    ..completion
                };
                self.update_backup_info(&txn, false)?;
                txn.commit()?;
                info!(self.logger(), "Process swap completion completed");
                Ok(completion)
            }
            SwapDirection::BtcForRgb => {
                let recv_vout =
                    maker_rgb_vout.ok_or_else(|| swap_invalid("missing maker RGB vout"))?;
                let recv_blinding = offer
                    .maker_rgb_blinding
                    .ok_or_else(|| swap_invalid("missing maker RGB blinding"))?;
                let recv_recipient_id = offer
                    .maker_rgb_recipient_id
                    .as_deref()
                    .ok_or_else(|| swap_invalid("missing maker RGB recipient ID"))?;
                swap_validate_received_swap_leg(
                    self,
                    &completion.consignments,
                    &offer.maker_receives,
                    &txid,
                    recv_vout,
                    recv_blinding,
                    recv_recipient_id,
                )?;

                let txn = self.database().begin_transaction()?;
                self.sync_if_requested(&txn, Some(online), false, KeychainKind::Internal)?;
                self.sync_if_requested(&txn, Some(online), false, KeychainKind::External)?;
                swap_ensure_inputs_confirmed(self, &completion.proposal.maker_inputs, 0)?;
                swap_ensure_inputs_confirmed(self, &completion.proposal.request.taker_inputs, 0)?;
                swap_sign_psbt(self, &mut psbt)?;
                let finalized_psbt = Some(swap_finalize_psbt_required(self, &psbt)?);
                let completion = OnchainSwapCompletion {
                    psbt: psbt.to_string(),
                    finalized_psbt,
                    ..completion
                };
                self.update_backup_info(&txn, false)?;
                txn.commit()?;
                info!(self.logger(), "Process swap completion completed");
                Ok(completion)
            }
            SwapDirection::RgbForRgb => {
                let recv_vout =
                    maker_rgb_vout.ok_or_else(|| swap_invalid("missing maker RGB vout"))?;
                let recv_blinding = offer
                    .maker_rgb_blinding
                    .ok_or_else(|| swap_invalid("missing maker RGB blinding"))?;
                let recv_recipient_id = offer
                    .maker_rgb_recipient_id
                    .as_deref()
                    .ok_or_else(|| swap_invalid("missing maker RGB recipient ID"))?;
                swap_validate_received_swap_leg(
                    self,
                    &completion.consignments,
                    &offer.maker_receives,
                    &txid,
                    recv_vout,
                    recv_blinding,
                    recv_recipient_id,
                )?;

                let txn = self.database().begin_transaction()?;
                let taker_history = completion
                    .taker_history
                    .as_ref()
                    .ok_or_else(|| swap_invalid("missing taker asset history"))?;
                swap_import_asset_history(self, &txn, taker_history)?;
                // the taker finalizes the commitment: the maker's staged transitions must be
                // committed unchanged
                let staged_bundles = Psbt::from_str(&local_proposal.psbt)?
                    .rgb_bundles()
                    .map_err(InternalError::from)?;
                let committed_bundles = psbt.rgb_bundles().map_err(InternalError::from)?;
                if staged_bundles
                    .iter()
                    .any(|(contract_id, bundle)| committed_bundles.get(contract_id) != Some(bundle))
                {
                    return Err(swap_invalid(
                        "swap PSBT does not commit the maker's staged RGB transitions",
                    ));
                }
                let fascia = self.fascia_from_finalized_psbt(&psbt)?;
                let maker_send = SwapRgbSend {
                    leg: &offer.maker_gives,
                    inputs: &completion.proposal.maker_inputs,
                    change_script_hex: &completion.proposal.maker_change_script_pubkey_hex,
                    recipient_id: completion
                        .proposal
                        .request
                        .taker_rgb_recipient_id
                        .as_deref()
                        .ok_or_else(|| swap_invalid("missing taker RGB recipient ID"))?,
                    recipient_vout: taker_rgb_vout
                        .ok_or_else(|| swap_invalid("missing taker RGB vout"))?,
                    blinding: completion
                        .proposal
                        .request
                        .taker_rgb_blinding
                        .ok_or_else(|| swap_invalid("missing taker RGB blinding"))?,
                };
                let mut consignments = completion.consignments.clone();
                consignments.extend(swap_prepare_rgb_leg(
                    &txn,
                    self,
                    &psbt,
                    &fascia,
                    &maker_send,
                    offer.proxy_url.as_deref(),
                    &offer.swap_id,
                    offer.expiration_timestamp,
                )?);
                self.sync_if_requested(&txn, Some(online), false, KeychainKind::Internal)?;
                self.sync_if_requested(&txn, Some(online), false, KeychainKind::External)?;
                swap_ensure_inputs_confirmed(self, &completion.proposal.maker_inputs, 0)?;
                swap_ensure_inputs_confirmed(self, &completion.proposal.request.taker_inputs, 0)?;
                swap_sign_psbt(self, &mut psbt)?;
                let finalized_psbt = Some(swap_finalize_psbt_required(self, &psbt)?);
                let completion = OnchainSwapCompletion {
                    psbt: psbt.to_string(),
                    finalized_psbt,
                    consignments,
                    ..completion
                };
                self.update_backup_info(&txn, false)?;
                txn.commit()?;
                info!(self.logger(), "Process swap completion completed");
                Ok(completion)
            }
        }
    }

    /// Broadcast the finalized Bitcoin transaction for a completed on-chain swap.
    ///
    /// The completion must be the latest processed completion for the swap, with
    /// `finalized_psbt` populated by the last signing party.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn broadcast_swap_completion(
        &mut self,
        online: Online,
        completion: OnchainSwapCompletion,
    ) -> Result<String, Error> {
        info!(self.logger(), "Broadcasting on-chain swap completion...");
        self.check_online(online)?;
        let offer = &completion.proposal.request.offer;
        swap_validate_legs(&offer.maker_gives, &offer.maker_receives)?;
        swap_validate_proxy_url(&offer.proxy_url)?;
        let finalized_psbt = completion
            .finalized_psbt
            .as_deref()
            .ok_or_else(|| swap_invalid("swap completion is not finalized"))?;
        let psbt = Psbt::from_str(finalized_psbt)?;
        swap_validate_proposal_psbt(&completion.proposal, &psbt)?;
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        if completion.txid != txid {
            return Err(swap_invalid("swap completion txid mismatch"));
        }

        // from here on the swap can no longer be cancelled
        let rebroadcast =
            swap_state_path(self.wallet_dir(), &offer.swap_id, SWAP_BROADCAST_FILE).exists();
        swap_save_state(
            self.wallet_dir(),
            &offer.swap_id,
            SWAP_BROADCAST_FILE,
            &txid,
        )?;
        // a broadcast leg must never be failed by the expiry sweep while the indexer hasn't seen
        // the transaction yet: that would release inputs the transaction spends. Committed before
        // broadcasting, since a failed broadcast attempt may still have reached the network; a
        // rejected swap stays cancellable, cancel_swap doesn't depend on the expiration.
        if let Some((_, batch_transfer)) = self.swap_outgoing_batch(&offer.swap_id)?
            && batch_transfer.expiration.is_some()
        {
            let txn = self.database().begin_transaction()?;
            let mut updated: DbBatchTransferActMod = batch_transfer.into();
            updated.expiration = ActiveValue::Set(None);
            txn.update_batch_transfer(&mut updated)?;
            txn.commit()?;
        }
        let txn = self.database().begin_transaction()?;
        let tx = match self.broadcast_psbt(&txn, &psbt) {
            Ok(tx) => tx,
            Err(
                e @ (Error::FailedBroadcast { .. }
                | Error::MinFeeNotMet { .. }
                | Error::MaxFeeExceeded { .. }),
            ) => {
                // a refused re-broadcast (e.g. the tx is already in the mempool or mined) or a tx
                // the indexer knows is out there: the swap must stay uncancellable
                if rebroadcast || self.indexer().get_tx_confirmations(&txid)?.is_some() {
                    return Err(e);
                }
                // rejected and unknown to the indexer: the swap can still be cancelled
                let _ = fs::remove_file(swap_state_path(
                    self.wallet_dir(),
                    &offer.swap_id,
                    SWAP_BROADCAST_FILE,
                ));
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        let txid = tx.compute_txid().to_string();
        if self.indexer().get_tx_confirmations(&txid)?.is_some() {
            self.swap_apply_outgoing(online, &offer.swap_id, &txid)?;
        }
        info!(self.logger(), "Broadcast swap completion completed");
        Ok(txid)
    }

    /// Cancel an on-chain swap whose transaction has not been broadcast.
    ///
    /// Fails the batch transfer recording the RGB leg this wallet prepared, if any, which releases
    /// its inputs, and archives the local swap state so no further step can be run on it.
    ///
    /// Returns [`Error::CannotFailBatchTransfer`] once the swap transaction has been broadcast by
    /// this wallet, is known to the indexer or the swap has been settled. A counterparty holding a
    /// fully signed transaction can still broadcast it: to rule that out, spend the inputs.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn cancel_swap(&mut self, online: Online, swap_id: String) -> Result<(), Error> {
        info!(self.logger(), "Cancelling on-chain swap {swap_id}...");
        self.check_online(online)?;
        let swap_dir = swap_consignment_dir(self.wallet_dir(), &swap_id);
        if swap_id.is_empty() || !swap_id.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(swap_invalid("invalid swap ID"));
        }
        if !swap_dir.is_dir() {
            return Err(swap_invalid(format!("unknown swap {swap_id}")));
        }
        if [SWAP_BROADCAST_FILE, SWAP_ACCEPTED_FILE]
            .iter()
            .any(|marker| swap_dir.join(marker).exists())
        {
            return Err(Error::CannotFailBatchTransfer);
        }
        if let Some((outgoing, batch_transfer)) = self.swap_outgoing_batch(&swap_id)? {
            if self
                .indexer()
                .get_tx_confirmations(&outgoing.txid)?
                .is_some()
            {
                return Err(Error::CannotFailBatchTransfer);
            }
            match batch_transfer.status {
                TransferStatus::Initiated => {
                    self.fail_transfers(online, Some(batch_transfer.idx), false, false)?;
                }
                TransferStatus::Failed => {}
                _ => return Err(Error::CannotFailBatchTransfer),
            }
        }
        fs::rename(&swap_dir, swap_dir.with_extension(SWAP_CANCELLED_EXTENSION))?;
        info!(self.logger(), "Cancel swap completed");
        Ok(())
    }

    /// Cancel every on-chain swap whose offer has expired and whose transaction has not been
    /// broadcast, as [`cancel_swap`](Wallet::cancel_swap) does. Returns the cancelled swap IDs.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn cancel_expired_swaps(&mut self, online: Online) -> Result<Vec<String>, Error> {
        info!(self.logger(), "Cancelling expired on-chain swaps...");
        self.check_online(online)?;
        let transfers_dir = swap_consignment_dir(self.wallet_dir(), "")
            .parent()
            .expect("swap dir has a parent")
            .to_path_buf();
        if !transfers_dir.is_dir() {
            return Ok(vec![]);
        }
        let mut swap_ids = vec![];
        for entry in fs::read_dir(&transfers_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(swap_id) = name.strip_prefix("swap-") else {
                continue;
            };
            if !entry.path().is_dir() || !swap_id.chars().all(|c| c.is_ascii_alphanumeric()) {
                continue;
            }
            let offer = if let Ok(offer) =
                swap_load_state::<OnchainSwapOffer>(self.wallet_dir(), swap_id, SWAP_OFFER_FILE)
            {
                offer
            } else if let Ok(request) =
                swap_load_state::<OnchainSwapRequest>(self.wallet_dir(), swap_id, SWAP_REQUEST_FILE)
            {
                request.offer
            } else {
                continue;
            };
            if swap_ensure_not_expired(&offer).is_ok() {
                continue;
            }
            match self.cancel_swap(online, swap_id.to_string()) {
                Ok(()) => swap_ids.push(swap_id.to_string()),
                Err(Error::CannotFailBatchTransfer) => {}
                Err(e) => return Err(e),
            }
        }
        info!(self.logger(), "Cancel expired swaps completed");
        Ok(swap_ids)
    }

    /// List the on-chain swaps this wallet has local state for, including cancelled ones, so a
    /// caller can reconcile them against its own records after a restart.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn list_swaps(&self) -> Result<Vec<OnchainSwapSummary>, Error> {
        let transfers_dir = swap_consignment_dir(self.wallet_dir(), "")
            .parent()
            .expect("swap dir has a parent")
            .to_path_buf();
        if !transfers_dir.is_dir() {
            return Ok(vec![]);
        }
        fn load<T: serde::de::DeserializeOwned>(dir: &Path, file: &str) -> Option<T> {
            serde_json::from_str(&fs::read_to_string(dir.join(file)).ok()?).ok()
        }
        let cancelled_suffix = format!(".{SWAP_CANCELLED_EXTENSION}");
        let mut swaps = vec![];
        for entry in fs::read_dir(&transfers_dir)? {
            let entry = entry?;
            let dir = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(rest) = name.strip_prefix("swap-") else {
                continue;
            };
            let (swap_id, cancelled) = match rest.strip_suffix(&cancelled_suffix) {
                Some(id) => (id, true),
                None => (rest, false),
            };
            if !dir.is_dir() || !swap_id.chars().all(|c| c.is_ascii_alphanumeric()) {
                continue;
            }
            let (role, offer) = if let Some(offer) = load::<OnchainSwapOffer>(&dir, SWAP_OFFER_FILE)
            {
                (OnchainSwapRole::Maker, offer)
            } else if let Some(request) = load::<OnchainSwapRequest>(&dir, SWAP_REQUEST_FILE) {
                (OnchainSwapRole::Taker, request.offer)
            } else {
                continue;
            };
            let proposal_txid =
                load::<OnchainSwapProposal>(&dir, SWAP_PROPOSAL_FILE).map(|p| p.txid);
            let broadcast_txid = load::<String>(&dir, SWAP_BROADCAST_FILE);
            let stage = if cancelled {
                OnchainSwapStage::Cancelled
            } else if dir.join(SWAP_ACCEPTED_FILE).exists() {
                OnchainSwapStage::Accepted
            } else if broadcast_txid.is_some() {
                OnchainSwapStage::Broadcast
            } else if proposal_txid.is_some() {
                OnchainSwapStage::Proposed
            } else if role == OnchainSwapRole::Maker {
                OnchainSwapStage::Offered
            } else {
                OnchainSwapStage::Requested
            };
            swaps.push(OnchainSwapSummary {
                swap_id: swap_id.to_string(),
                role,
                stage,
                expiration_timestamp: offer.expiration_timestamp,
                txid: broadcast_txid.or(proposal_txid),
            });
        }
        swaps.sort_by(|a, b| a.swap_id.cmp(&b.swap_id));
        Ok(swaps)
    }

    /// Make the broadcast swap TX known to BDK: parties that did not broadcast it would not
    /// discover it with a colored sync, leaving their swap outputs unknown.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn swap_apply_witness_tx(&mut self, completion: &OnchainSwapCompletion) -> Result<(), Error> {
        let finalized_psbt = completion
            .finalized_psbt
            .as_deref()
            .ok_or_else(|| swap_invalid("swap completion is not finalized"))?;
        let psbt = Psbt::from_str(finalized_psbt)?;
        swap_validate_proposal_psbt(&completion.proposal, &psbt)?;
        let tx = psbt.extract_tx().map_err(InternalError::from)?;
        if tx.compute_txid().to_string() != completion.txid {
            return Err(swap_invalid("swap completion txid mismatch"));
        }
        if self
            .indexer()
            .get_tx_confirmations(&completion.txid)?
            .is_none()
        {
            return Err(swap_invalid("swap transaction is not known to the indexer"));
        }
        let seen_at = now().unix_timestamp() as u64;
        let (bdk_wallet, bdk_db) = self.bdk_wallet_db_mut();
        bdk_wallet.apply_unconfirmed_txs([(tx, seen_at)]);
        bdk_wallet.persist(bdk_db)?;
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn swap_outgoing_batch(
        &self,
        swap_id: &str,
    ) -> Result<Option<(SwapOutgoingState, DbBatchTransfer)>, Error> {
        if !swap_state_path(self.wallet_dir(), swap_id, SWAP_OUTGOING_FILE).exists() {
            return Ok(None);
        }
        let outgoing: SwapOutgoingState =
            swap_load_state(self.wallet_dir(), swap_id, SWAP_OUTGOING_FILE)?;
        let txn = self.database().begin_transaction()?;
        let db_data = txn.get_db_data(false)?;
        let batch_transfer =
            txn.get_batch_transfer_or_fail(outgoing.batch_transfer_idx, &db_data.batch_transfers)?;
        if batch_transfer.incoming || batch_transfer.txid.as_deref() != Some(&outgoing.txid) {
            return Err(Error::Inconsistency {
                details: format!("swap {swap_id} outgoing batch does not match its local state"),
            });
        }
        Ok(Some((outgoing, batch_transfer)))
    }

    /// Consume this wallet's prepared RGB leg of a swap into the stash, once `txid` is known.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn swap_apply_outgoing(
        &mut self,
        online: Online,
        swap_id: &str,
        txid: &str,
    ) -> Result<(), Error> {
        let Some((outgoing, batch_transfer)) = self.swap_outgoing_batch(swap_id)? else {
            return Ok(());
        };
        if outgoing.txid != txid {
            return Err(swap_invalid(
                "swap txid does not match the prepared RGB leg",
            ));
        }
        if batch_transfer.status == TransferStatus::Initiated {
            self.consume_transfer_fascia(online, batch_transfer.idx)?;
        }
        Ok(())
    }

    /// Accept the RGB transfers received from a completed on-chain swap.
    ///
    /// Each party calls this method with their own `role` once the swap transaction has been
    /// broadcast (or confirmed, depending on `min_confirmations`). The consignments embedded in
    /// the completion are validated and accepted into the wallet's RGB state.
    ///
    /// Returns the list of [`Assignment`]s received, or an empty list if this party is receiving
    /// only BTC.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_swap_transfers(
        &mut self,
        online: Online,
        completion: OnchainSwapCompletion,
        role: OnchainSwapRole,
        skip_sync: bool,
    ) -> Result<OnchainSwapReceiveResult, Error> {
        info!(self.logger(), "Accepting on-chain swap transfers...");
        self.check_online(online)?;
        let offer = &completion.proposal.request.offer;
        swap_validate_proxy_url(&offer.proxy_url)?;
        self.swap_apply_witness_tx(&completion)?;
        self.swap_apply_outgoing(online, &offer.swap_id, &completion.txid)?;
        let txn = self.database().begin_transaction()?;
        self.sync_if_requested(&txn, Some(online), skip_sync, KeychainKind::External)?;
        let receives = match role {
            OnchainSwapRole::Maker => offer.maker_receives.clone(),
            OnchainSwapRole::Taker => offer.maker_gives.clone(),
        };
        if !matches!(receives.kind, OnchainSwapLegKind::Rgb) {
            let result = OnchainSwapReceiveResult {
                assignments: vec![],
            };
            self.update_backup_info(&txn, false)?;
            txn.commit()?;
            swap_save_state(
                self.wallet_dir(),
                &offer.swap_id,
                SWAP_ACCEPTED_FILE,
                &completion.txid,
            )?;
            return Ok(result);
        }
        let mut assignments = vec![];
        let matching_consignments = completion
            .consignments
            .iter()
            .filter(|c| receives.asset_id.as_deref() == Some(c.asset_id.as_str()))
            .collect::<Vec<_>>();
        if matching_consignments.is_empty() {
            return Err(swap_invalid("missing RGB swap consignment"));
        }
        for consignment in matching_consignments {
            let local_path = swap_fetch_consignment_to_file(self, consignment)?;
            let mut accepted = swap_accept_transfer_from_file(
                self,
                &txn,
                &local_path,
                consignment.txid.clone(),
                consignment.vout,
                consignment.blinding,
                &consignment.recipient_id,
                offer.rgb_output_sat,
            )?;
            assignments.append(&mut accepted);
        }
        if assignments.is_empty() {
            return Err(swap_invalid(
                "RGB swap consignment did not assign any state",
            ));
        }
        let result = OnchainSwapReceiveResult { assignments };
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        swap_save_state(
            self.wallet_dir(),
            &offer.swap_id,
            SWAP_ACCEPTED_FILE,
            &completion.txid,
        )?;
        info!(self.logger(), "Accept swap transfers completed");
        Ok(result)
    }
}

#[cfg(feature = "vss")]
impl Wallet {
    /// Configure VSS backup for this wallet.
    pub fn configure_vss_backup(
        &mut self,
        config: super::vss::VssBackupConfig,
    ) -> Result<(), Error> {
        WalletBackup::configure_vss_backup(self, config)
    }

    /// Disable VSS auto-backup.
    pub fn disable_vss_auto_backup(&mut self) {
        WalletBackup::disable_vss_auto_backup(self)
    }

    /// Perform a VSS backup.
    pub async fn vss_backup(&self, client: &super::vss::VssBackupClient) -> Result<i64, Error> {
        WalletBackup::vss_backup(self, client).await
    }

    /// Get VSS backup info.
    pub async fn vss_backup_info(
        &self,
        client: &super::vss::VssBackupClient,
    ) -> Result<super::vss::VssBackupInfo, Error> {
        WalletBackup::vss_backup_info(self, client).await
    }

    /// Returns the configured VSS backup client, if any.
    ///
    /// This is the client constructed by [`configure_vss_backup`](Self::configure_vss_backup);
    /// callers can reuse it for manual backup operations instead of building a
    /// second client with the same configuration.
    pub fn vss_client(&self) -> Option<Arc<super::vss::VssBackupClient>> {
        WalletCore::vss_client(self).clone()
    }
}
