use std::str::FromStr;

use bdk_wallet::bitcoin::psbt::Psbt;

use super::*;

const SWAP_RGB_AMOUNT: u64 = 1_000;
const SWAP_BTC_PRICE: u64 = 100_000;
const SWAP_FEE: u64 = 2_000;

#[derive(Debug, Clone, Copy)]
struct ExpectedBtcDelta {
    maker: i64,
    taker: i64,
}

#[derive(Debug, Clone, Copy)]
struct ExpectedAssetBalance<'a> {
    asset_id: &'a str,
    maker: u64,
    taker: u64,
}

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

#[test]
#[parallel]
fn swap_offer_requires_proxy_url() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SNOP",
        "Swap No Proxy",
        SWAP_RGB_AMOUNT,
    );

    let result = maker.create_swap_offer(
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        SWAP_FEE,
        None,
        None,
        vec![],
    );

    assert!(matches!(
        result,
        Err(Error::InvalidTransportEndpoints { .. })
    ));
}

#[test]
#[parallel]
fn maker_taker_rgb_for_btc_balances() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);

    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SRGB",
        "Swap RGB For BTC",
        SWAP_RGB_AMOUNT,
    );
    let maker_btc_before = total_btc(&mut maker, maker_online);
    let taker_btc_before = total_btc(&mut taker, taker_online);

    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        PROXY_URL,
    );

    assert_btc_delta(
        &mut maker,
        maker_online,
        maker_btc_before,
        &mut taker,
        taker_online,
        taker_btc_before,
        ExpectedBtcDelta {
            maker: SWAP_BTC_PRICE as i64,
            taker: -((SWAP_BTC_PRICE + SWAP_FEE) as i64),
        },
    );
    assert_asset_balances(
        &maker,
        &taker,
        &[ExpectedAssetBalance {
            asset_id: &asset_id,
            maker: 0,
            taker: SWAP_RGB_AMOUNT,
        }],
    );
}

#[test]
#[parallel]
fn swap_refuses_counterparty_inputs_that_belong_to_this_wallet() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SOWN",
        "Swap Own Inputs",
        SWAP_RGB_AMOUNT,
    );

    let offer = maker
        .create_swap_offer(
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            btc(SWAP_BTC_PRICE),
            SWAP_FEE,
            None,
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();

    // a taker that declares a coin of the maker's as its own input: the maker would sign it
    let maker_address = maker.get_address().unwrap();
    let maker_script = maker.get_script_pubkey(&maker_address).unwrap();
    let mut smuggled_request = request.clone();
    smuggled_request.taker_inputs[0].script_pubkey_hex = maker_script.to_hex_string();
    let err = maker
        .accept_swap_request(maker_online, smuggled_request, 0, false, vec![])
        .unwrap_err();
    assert!(err.to_string().contains("belongs to this wallet"), "{err}");

    // and a maker that declares one of the taker's coins as its own input
    let proposal = maker
        .accept_swap_request(maker_online, request.clone(), 0, false, vec![])
        .unwrap();
    let smuggled_proposal = smuggle_maker_input(&proposal, request.taker_inputs[0].clone());
    let err = taker
        .complete_swap_proposal(taker_online, smuggled_proposal, 0, false)
        .unwrap_err();
    assert!(err.to_string().contains("belongs to this wallet"), "{err}");
    taker
        .complete_swap_proposal(taker_online, proposal, 0, false)
        .unwrap();
}

/// A maker that lists one of the taker's coins the taker did not declare (not a duplicate of a
/// taker input), with a PSBT rebuilt to match so the shape checks pass. Covers an uncolored coin
/// and a colored one holding another asset.
#[test]
#[parallel]
fn taker_refuses_undeclared_own_coins_as_maker_inputs() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut taker,
        taker_online,
        "SUND",
        "Swap Undeclared",
        SWAP_RGB_AMOUNT,
    );
    // a second colored coin carrying another asset, which the swap must not touch
    issue_swap_asset(&mut taker, taker_online, "SOTH", "Swap Other", 500);

    let offer = maker
        .create_swap_offer(
            btc(SWAP_BTC_PRICE),
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            SWAP_FEE,
            None,
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    let proposal = maker
        .accept_swap_request(maker_online, request.clone(), 0, false, vec![])
        .unwrap();

    let declared = request
        .taker_inputs
        .iter()
        .map(|i| i.outpoint.clone())
        .collect::<Vec<_>>();
    let undeclared = taker
        .list_unspents(Some(taker_online), false, false)
        .unwrap()
        .into_iter()
        .filter(|u| !declared.contains(&u.utxo.outpoint))
        .collect::<Vec<_>>();
    let uncolored = undeclared
        .iter()
        .find(|u| !u.utxo.colorable)
        .expect("taker has an undeclared uncolored coin");
    let colored = undeclared
        .iter()
        .find(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .expect("taker has an undeclared colored coin");

    for unspent in [uncolored, colored] {
        let local_output = taker
            .bdk_wallet()
            .get_utxo(unspent.utxo.outpoint.clone().into())
            .unwrap();
        let smuggled = smuggle_maker_input(&proposal, swap_build_input(&local_output));
        let err = taker
            .complete_swap_proposal(taker_online, smuggled, 0, false)
            .unwrap_err();
        assert!(
            err.to_string().contains("belongs to this wallet"),
            "{}: {err}",
            unspent.utxo.outpoint
        );
    }

    // the refusals left nothing behind: the honest proposal still completes and settles
    let completion = taker
        .complete_swap_proposal(taker_online, proposal, 0, false)
        .unwrap();
    maker
        .process_swap_completion(maker_online, completion)
        .unwrap();
}

/// Add `input` to the maker inputs (its value goes to the maker's change) and rebuild the PSBT
/// and txid to match, as a malicious maker would.
fn smuggle_maker_input(
    proposal: &OnchainSwapProposal,
    input: OnchainSwapInput,
) -> OnchainSwapProposal {
    let mut smuggled = proposal.clone();
    smuggled.maker_inputs.push(input);
    let (psbt, _, _) = swap_build_psbt(&smuggled).unwrap();
    smuggled.txid = psbt.unsigned_tx.compute_txid().to_string();
    smuggled.psbt = psbt.to_string();
    smuggled
}

#[test]
#[parallel]
fn refresh_after_swap_settles_transfers_without_panicking() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);

    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SREF",
        "Swap Refresh",
        SWAP_RGB_AMOUNT,
    );

    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        PROXY_URL,
    );

    // Before the fix, the batch transfer `swap_record_outgoing`/`swap_record_incoming` create for
    // a swap leg left `incoming` unset, which fell back to the schema's `DEFAULT true`. For the
    // maker's outgoing leg that wrongly routed refresh() into the branch built for the ordinary
    // (non-swap) receive flow, which expects a `DbTransfer` row and a consignment file this
    // recording path never creates -- panicking on the very first refresh() after a swap send.
    maker
        .refresh(maker_online, None, vec![], false)
        .expect("refresh should not panic after a swap send");
    taker
        .refresh(taker_online, None, vec![], false)
        .expect("refresh should not panic after a swap receive");

    // The maker's asset balance should settle to zero -- not stay stuck showing the pre-swap
    // amount because its batch transfer can never reconcile from `WaitingConfirmations`.
    let maker_balance = maker.get_asset_balance(asset_id.clone()).unwrap();
    assert_eq!(maker_balance.settled, 0);
    assert_eq!(maker_balance.future, 0);
    assert_eq!(maker_balance.spendable, 0);

    let taker_balance = taker.get_asset_balance(asset_id).unwrap();
    assert_eq!(taker_balance.settled, SWAP_RGB_AMOUNT);
    assert_eq!(taker_balance.future, SWAP_RGB_AMOUNT);
    assert_eq!(taker_balance.spendable, SWAP_RGB_AMOUNT);
}

#[test]
#[parallel]
fn taker_funded_extra_output() {
    initialize();

    const PLATFORM_FEE: u64 = 500;

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let (mut fee_wallet, fee_online) = get_funded_noutxo_wallet(true, None);

    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SFEE",
        "Swap Platform Fee",
        SWAP_RGB_AMOUNT,
    );
    let maker_btc_before = total_btc(&mut maker, maker_online);
    let taker_btc_before = total_btc(&mut taker, taker_online);
    let fee_btc_before = total_btc(&mut fee_wallet, fee_online);
    let fee_recipient = fee_wallet.get_address().unwrap();

    execute_swap_with_extra_outputs(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        PROXY_URL,
        vec![OnchainSwapExtraOutput {
            address: fee_recipient,
            amount_sat: PLATFORM_FEE,
            funded_by: OnchainSwapRole::Taker,
        }],
    );

    assert_btc_delta_with_extra_outputs(
        &mut maker,
        maker_online,
        maker_btc_before,
        &mut taker,
        taker_online,
        taker_btc_before,
        ExpectedBtcDelta {
            maker: SWAP_BTC_PRICE as i64,
            taker: -((SWAP_BTC_PRICE + SWAP_FEE + PLATFORM_FEE) as i64),
        },
        PLATFORM_FEE,
    );
    assert_asset_balances(
        &maker,
        &taker,
        &[ExpectedAssetBalance {
            asset_id: &asset_id,
            maker: 0,
            taker: SWAP_RGB_AMOUNT,
        }],
    );
    let fee_btc_after = total_btc(&mut fee_wallet, fee_online);
    assert_eq!(
        fee_btc_after as i64 - fee_btc_before as i64,
        PLATFORM_FEE as i64,
        "the extra output recipient should have received exactly its amount"
    );
}

#[test]
#[parallel]
fn maker_taker_btc_for_rgb_balances() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);

    let asset_id = issue_swap_asset(
        &mut taker,
        taker_online,
        "SBTC",
        "Swap BTC For RGB",
        SWAP_RGB_AMOUNT,
    );
    let maker_btc_before = total_btc(&mut maker, maker_online);
    let taker_btc_before = total_btc(&mut taker, taker_online);

    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        btc(SWAP_BTC_PRICE),
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        PROXY_URL,
    );

    assert_btc_delta(
        &mut maker,
        maker_online,
        maker_btc_before,
        &mut taker,
        taker_online,
        taker_btc_before,
        ExpectedBtcDelta {
            maker: -(SWAP_BTC_PRICE as i64),
            taker: (SWAP_BTC_PRICE as i64) - (SWAP_FEE as i64),
        },
    );
    assert_asset_balances(
        &maker,
        &taker,
        &[ExpectedAssetBalance {
            asset_id: &asset_id,
            maker: SWAP_RGB_AMOUNT,
            taker: 0,
        }],
    );
}

#[test]
#[parallel]
fn maker_taker_rgb_for_rgb_balances() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);

    let maker_asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SRGA",
        "Maker RGB Swap Asset",
        SWAP_RGB_AMOUNT,
    );
    let taker_asset_id = issue_swap_asset(
        &mut taker,
        taker_online,
        "SRGB",
        "Taker RGB Swap Asset",
        SWAP_RGB_AMOUNT,
    );
    let maker_btc_before = total_btc(&mut maker, maker_online);
    let taker_btc_before = total_btc(&mut taker, taker_online);

    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&maker_asset_id, SWAP_RGB_AMOUNT),
        rgb(&taker_asset_id, SWAP_RGB_AMOUNT),
        PROXY_URL,
    );

    assert_btc_delta(
        &mut maker,
        maker_online,
        maker_btc_before,
        &mut taker,
        taker_online,
        taker_btc_before,
        ExpectedBtcDelta {
            maker: 0,
            taker: -(SWAP_FEE as i64),
        },
    );
    assert_asset_balances(
        &maker,
        &taker,
        &[
            ExpectedAssetBalance {
                asset_id: &maker_asset_id,
                maker: 0,
                taker: SWAP_RGB_AMOUNT,
            },
            ExpectedAssetBalance {
                asset_id: &taker_asset_id,
                maker: SWAP_RGB_AMOUNT,
                taker: 0,
            },
        ],
    );
}

#[test]
#[parallel]
fn maker_rejects_request_with_mutated_offer() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SMOF",
        "Swap Mutated Offer",
        SWAP_RGB_AMOUNT,
    );

    let offer = maker
        .create_swap_offer(
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            btc(SWAP_BTC_PRICE),
            SWAP_FEE,
            None,
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    let mut request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    request.offer.network_fee_sat += 1;

    assert!(
        maker
            .accept_swap_request(maker_online, request, 0, false, vec![])
            .is_err()
    );
}

#[test]
#[parallel]
fn taker_refuses_a_maker_input_declared_with_the_wrong_amount() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut taker,
        taker_online,
        "SPRV",
        "Swap Prevout",
        SWAP_RGB_AMOUNT,
    );

    let offer = maker
        .create_swap_offer(
            btc(SWAP_BTC_PRICE),
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            SWAP_FEE,
            None,
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    let mut proposal = maker
        .accept_swap_request(maker_online, request, 0, false, vec![])
        .unwrap();
    // the maker claims a bigger coin than it has, and builds a consistent PSBT on that claim
    proposal.maker_inputs[0].amount_sat += 1_000;
    let (psbt, _, _) = crate::wallet::offline::swap_build_psbt(&proposal).unwrap();
    proposal.txid = psbt.unsigned_tx.compute_txid().to_string();
    proposal.psbt = psbt.to_string();

    let err = taker
        .complete_swap_proposal(taker_online, proposal, 0, false)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("does not match its previous output"),
        "{err}"
    );
}

#[test]
#[parallel]
fn taker_rejects_proposal_with_mutated_request() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SMRQ",
        "Swap Mutated Request",
        SWAP_RGB_AMOUNT,
    );

    let offer = maker
        .create_swap_offer(
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            btc(SWAP_BTC_PRICE),
            SWAP_FEE,
            None,
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    let mut proposal = maker
        .accept_swap_request(maker_online, request, 0, false, vec![])
        .unwrap();
    proposal.request.taker_change_script_pubkey_hex = "00".to_string();

    assert!(
        taker
            .complete_swap_proposal(taker_online, proposal, 0, false)
            .is_err()
    );
}

#[test]
#[parallel]
fn maker_rejects_tampered_rgb_consignment_before_signing_btc() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut taker,
        taker_online,
        "SMCS",
        "Swap Mutated Consignment",
        SWAP_RGB_AMOUNT,
    );

    let offer = maker
        .create_swap_offer(
            btc(SWAP_BTC_PRICE),
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            SWAP_FEE,
            None,
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    let proposal = maker
        .accept_swap_request(maker_online, request, 0, false, vec![])
        .unwrap();
    assert_eq!(signature_count(&proposal.psbt), 0);

    let completion = taker
        .complete_swap_proposal(taker_online, proposal, 0, false)
        .unwrap();
    let mut tampered_completion = completion.clone();
    tampered_completion.consignments[0].blinding += 1;
    assert!(
        maker
            .process_swap_completion(maker_online, tampered_completion)
            .is_err()
    );

    let completion = maker
        .process_swap_completion(maker_online, completion)
        .unwrap();
    assert!(completion.finalized_psbt.is_some());
    assert!(signature_count(&completion.psbt) > 0);
}

#[test]
#[parallel]
fn partial_rgb_for_btc_keeps_change_spendable() {
    initialize();

    const PARTIAL: u64 = 400;

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SPRT",
        "Swap Partial",
        SWAP_RGB_AMOUNT,
    );

    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, PARTIAL),
        btc(SWAP_BTC_PRICE),
        PROXY_URL,
    );
    refresh_settled(&mut maker, maker_online);
    refresh_settled(&mut taker, taker_online);
    assert_settled_balance(&maker, &asset_id, SWAP_RGB_AMOUNT - PARTIAL);
    assert_settled_balance(&taker, &asset_id, PARTIAL);

    // the change is spendable in a second swap
    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT - PARTIAL),
        btc(SWAP_BTC_PRICE),
        PROXY_URL,
    );
    refresh_settled(&mut maker, maker_online);
    refresh_settled(&mut taker, taker_online);
    assert_settled_balance(&maker, &asset_id, 0);
    assert_settled_balance(&taker, &asset_id, SWAP_RGB_AMOUNT);
}

#[test]
#[parallel]
fn partial_rgb_for_rgb_keeps_change_on_both_sides() {
    initialize();

    const MAKER_PARTIAL: u64 = 300;
    const TAKER_PARTIAL: u64 = 700;

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let maker_asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SPMA",
        "Swap Partial Maker",
        SWAP_RGB_AMOUNT,
    );
    let taker_asset_id = issue_swap_asset(
        &mut taker,
        taker_online,
        "SPTA",
        "Swap Partial Taker",
        SWAP_RGB_AMOUNT,
    );

    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&maker_asset_id, MAKER_PARTIAL),
        rgb(&taker_asset_id, TAKER_PARTIAL),
        PROXY_URL,
    );
    refresh_settled(&mut maker, maker_online);
    refresh_settled(&mut taker, taker_online);
    assert_settled_balance(&maker, &maker_asset_id, SWAP_RGB_AMOUNT - MAKER_PARTIAL);
    assert_settled_balance(&taker, &maker_asset_id, MAKER_PARTIAL);
    assert_settled_balance(&taker, &taker_asset_id, SWAP_RGB_AMOUNT - TAKER_PARTIAL);
    assert_settled_balance(&maker, &taker_asset_id, TAKER_PARTIAL);
}

#[test]
#[parallel]
fn second_asset_on_swap_input_survives() {
    initialize();

    const OTHER_AMOUNT: u64 = 500;

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SCOA",
        "Swap Co-located A",
        SWAP_RGB_AMOUNT,
    );
    let other_asset_id = maker
        .issue_asset_nia(
            "SCOB".to_string(),
            "Swap Co-located B".to_string(),
            0,
            vec![OTHER_AMOUNT],
        )
        .unwrap()
        .asset_id;
    let unspents = maker
        .list_unspents(Some(maker_online), false, false)
        .unwrap();
    assert!(
        unspents.iter().any(|u| {
            let ids = u
                .rgb_allocations
                .iter()
                .filter_map(|a| a.asset_id.clone())
                .collect::<Vec<_>>();
            ids.contains(&asset_id) && ids.contains(&other_asset_id)
        }),
        "both assets should sit on the same UTXO"
    );

    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        PROXY_URL,
    );
    refresh_settled(&mut maker, maker_online);
    refresh_settled(&mut taker, taker_online);
    assert_settled_balance(&maker, &asset_id, 0);
    assert_settled_balance(&taker, &asset_id, SWAP_RGB_AMOUNT);
    assert_settled_balance(&maker, &other_asset_id, OTHER_AMOUNT);

    // the carried-over asset can still be sent
    let mut maker = party!(maker, maker_online);
    let mut rcv = get_funded_party!();
    normal_send(&mut maker, &mut rcv, &other_asset_id, OTHER_AMOUNT);
    assert_eq!(rcv.get_asset_balance(&other_asset_id).settled, OTHER_AMOUNT);
    assert_eq!(maker.get_asset_balance(&other_asset_id).settled, 0);
}

#[test]
#[parallel]
fn swap_received_utxo_is_spendable() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SRSP",
        "Swap Received Spend",
        SWAP_RGB_AMOUNT,
    );

    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        PROXY_URL,
    );
    refresh_settled(&mut taker, taker_online);
    assert_settled_balance(&taker, &asset_id, SWAP_RGB_AMOUNT);

    let mut taker = party!(taker, taker_online);
    let mut rcv = get_funded_party!();
    normal_send(&mut taker, &mut rcv, &asset_id, SWAP_RGB_AMOUNT);
    assert_eq!(rcv.get_asset_balance(&asset_id).settled, SWAP_RGB_AMOUNT);
    assert_eq!(taker.get_asset_balance(&asset_id).settled, 0);
}

#[test]
#[parallel]
fn cancel_before_broadcast_leaves_state_unchanged() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SCNL",
        "Swap Cancel",
        SWAP_RGB_AMOUNT,
    );
    let db_before = settled_unspents(&mut maker, maker_online);
    let stash_before = stash_assignments(&mut maker, maker_online, &asset_id);
    let balance_before = maker.get_asset_balance(asset_id.clone()).unwrap();

    let offer = maker
        .create_swap_offer(
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            btc(SWAP_BTC_PRICE),
            SWAP_FEE,
            None,
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    let swap_id = offer.swap_id.clone();
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    let proposal = maker
        .accept_swap_request(maker_online, request, 0, false, vec![])
        .unwrap();
    // coloring prepared the leg without touching the stash
    assert_eq!(
        stash_assignments(&mut maker, maker_online, &asset_id),
        stash_before
    );
    let _completion = taker
        .complete_swap_proposal(taker_online, proposal, 0, false)
        .unwrap();

    maker.cancel_swap(maker_online, swap_id.clone()).unwrap();
    taker.cancel_swap(taker_online, swap_id.clone()).unwrap();
    for wallet in [&maker, &taker] {
        let transfers_dir = wallet.get_wallet_dir().join("transfers");
        assert!(!transfers_dir.join(format!("swap-{swap_id}")).exists());
        assert!(
            transfers_dir
                .join(format!("swap-{swap_id}.cancelled"))
                .exists()
        );
    }
    assert!(maker.cancel_swap(maker_online, swap_id).is_err());

    assert_eq!(settled_unspents(&mut maker, maker_online), db_before);
    assert_eq!(
        stash_assignments(&mut maker, maker_online, &asset_id),
        stash_before
    );
    let balance_after = maker.get_asset_balance(asset_id.clone()).unwrap();
    assert_eq!(balance_after.settled, balance_before.settled);
    assert_eq!(balance_after.spendable, balance_before.spendable);
    assert!(
        maker
            .list_transfers(AssetFilter::Id(asset_id.clone()), None)
            .unwrap()
            .iter()
            .any(|t| t.status == TransferStatus::Failed)
    );

    // the released UTXO can be swapped again
    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        PROXY_URL,
    );
    refresh_settled(&mut maker, maker_online);
    refresh_settled(&mut taker, taker_online);
    assert_settled_balance(&maker, &asset_id, 0);
    assert_settled_balance(&taker, &asset_id, SWAP_RGB_AMOUNT);
}

#[test]
#[parallel]
fn expired_unbroadcast_swap_is_cancelled() {
    initialize();

    const EXPIRY_SECS: i64 = 30;

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut taker,
        taker_online,
        "SEXP",
        "Swap Expired",
        SWAP_RGB_AMOUNT,
    );
    let db_before = settled_unspents(&mut taker, taker_online);
    let stash_before = stash_assignments(&mut taker, taker_online, &asset_id);

    let expiration = now().unix_timestamp() + EXPIRY_SECS;
    let offer = maker
        .create_swap_offer(
            btc(SWAP_BTC_PRICE),
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            SWAP_FEE,
            Some(expiration as u64),
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    let swap_id = offer.swap_id.clone();
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    let proposal = maker
        .accept_swap_request(maker_online, request, 0, false, vec![])
        .unwrap();
    let completion = taker
        .complete_swap_proposal(taker_online, proposal, 0, false)
        .unwrap();
    let _completion = maker
        .process_swap_completion(maker_online, completion)
        .unwrap();
    // the taker's RGB leg is prepared but the transaction is never broadcast
    assert!(maker.cancel_expired_swaps(maker_online).unwrap().is_empty());
    assert!(taker.cancel_expired_swaps(taker_online).unwrap().is_empty());

    while now().unix_timestamp() <= expiration {
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(
        taker.cancel_expired_swaps(taker_online).unwrap(),
        vec![swap_id.clone()]
    );
    assert_eq!(
        maker.cancel_expired_swaps(maker_online).unwrap(),
        vec![swap_id]
    );
    assert!(taker.cancel_expired_swaps(taker_online).unwrap().is_empty());
    assert_eq!(settled_unspents(&mut taker, taker_online), db_before);
    assert_eq!(
        stash_assignments(&mut taker, taker_online, &asset_id),
        stash_before
    );
    assert_settled_balance(&taker, &asset_id, SWAP_RGB_AMOUNT);

    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        btc(SWAP_BTC_PRICE),
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        PROXY_URL,
    );
    refresh_settled(&mut maker, maker_online);
    refresh_settled(&mut taker, taker_online);
    assert_settled_balance(&maker, &asset_id, SWAP_RGB_AMOUNT);
    assert_settled_balance(&taker, &asset_id, 0);
}

#[test]
#[parallel]
fn exclude_outpoints_and_list_swaps() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SXCL",
        "Swap Exclude",
        SWAP_RGB_AMOUNT,
    );
    let outpoints = |wallet: &mut Wallet, online: Online, colorable: bool| {
        wallet
            .list_unspents(Some(online), false, false)
            .unwrap()
            .into_iter()
            .filter(|u| u.utxo.colorable == colorable)
            .map(|u| u.utxo.outpoint)
            .collect::<Vec<_>>()
    };
    let offer = maker
        .create_swap_offer(
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            btc(SWAP_BTC_PRICE),
            SWAP_FEE,
            Some(now().unix_timestamp() as u64 + 3600),
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    let swap_id = offer.swap_id.clone();

    // excluded inputs are never selected: excluding all of them leaves nothing to pay with
    let taker_btc = outpoints(&mut taker, taker_online, false);
    assert!(matches!(
        taker.accept_swap_offer(taker_online, offer.clone(), 0, false, taker_btc),
        Err(Error::InsufficientBitcoins { .. })
    ));
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    let maker_colored = outpoints(&mut maker, maker_online, true);
    assert!(
        maker
            .accept_swap_request(maker_online, request.clone(), 0, false, maker_colored)
            .is_err()
    );
    let proposal = maker
        .accept_swap_request(maker_online, request, 0, false, vec![])
        .unwrap();

    let summary = |wallet: &Wallet| {
        wallet
            .list_swaps()
            .unwrap()
            .into_iter()
            .find(|s| s.swap_id == swap_id)
            .unwrap()
    };
    let maker_summary = summary(&maker);
    assert_eq!(maker_summary.role, OnchainSwapRole::Maker);
    assert_eq!(maker_summary.stage, OnchainSwapStage::Proposed);
    assert_eq!(maker_summary.txid.as_deref(), Some(proposal.txid.as_str()));
    let taker_summary = summary(&taker);
    assert_eq!(taker_summary.role, OnchainSwapRole::Taker);
    assert_eq!(taker_summary.stage, OnchainSwapStage::Requested);

    let completion = taker
        .complete_swap_proposal(taker_online, proposal, 0, false)
        .unwrap();
    let completion = maker
        .process_swap_completion(maker_online, completion)
        .unwrap();
    let txid = completion.txid.clone();
    let outgoing_expiration = |wallet: &Wallet| {
        let txn = wallet.database().begin_transaction().unwrap();
        let db_data = txn.get_db_data(false).unwrap();
        db_data
            .batch_transfers
            .iter()
            .find(|b| !b.incoming && b.txid.as_deref() == Some(txid.as_str()))
            .unwrap()
            .expiration
    };
    assert!(outgoing_expiration(&maker).is_some());
    maker
        .broadcast_swap_completion(maker_online, completion.clone())
        .unwrap();
    // a broadcast leg can't be failed by the expiry sweep any more
    assert_eq!(outgoing_expiration(&maker), None);
    assert_eq!(summary(&maker).stage, OnchainSwapStage::Broadcast);

    mine(false);
    maker
        .accept_swap_transfers(
            maker_online,
            completion.clone(),
            OnchainSwapRole::Maker,
            false,
        )
        .unwrap();
    taker
        .accept_swap_transfers(taker_online, completion, OnchainSwapRole::Taker, false)
        .unwrap();
    assert_eq!(summary(&maker).stage, OnchainSwapStage::Accepted);
    assert_eq!(summary(&taker).stage, OnchainSwapStage::Accepted);

    let cancelled = maker
        .create_swap_offer(
            btc(SWAP_BTC_PRICE),
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            SWAP_FEE,
            None,
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    maker
        .cancel_swap(maker_online, cancelled.swap_id.clone())
        .unwrap();
    let cancelled_summary = maker
        .list_swaps()
        .unwrap()
        .into_iter()
        .find(|s| s.swap_id == cancelled.swap_id)
        .unwrap();
    assert_eq!(cancelled_summary.stage, OnchainSwapStage::Cancelled);
    assert_eq!(cancelled_summary.txid, None);
}

/// Run a swap up to the taker's completion, with the offer expiring at `expiration`.
#[allow(clippy::too_many_arguments)]
fn swap_to_completion(
    maker: &mut Wallet,
    maker_online: Online,
    taker: &mut Wallet,
    taker_online: Online,
    maker_gives: OnchainSwapLeg,
    maker_receives: OnchainSwapLeg,
    expiration: Option<u64>,
) -> OnchainSwapCompletion {
    let offer = maker
        .create_swap_offer(
            maker_gives,
            maker_receives,
            SWAP_FEE,
            expiration,
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    let proposal = maker
        .accept_swap_request(maker_online, request, 0, false, vec![])
        .unwrap();
    taker
        .complete_swap_proposal(taker_online, proposal, 0, false)
        .unwrap()
}

#[test]
#[parallel]
fn maker_refuses_to_sign_after_offer_expiry() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SEXP",
        "Swap Expiry",
        SWAP_RGB_AMOUNT,
    );
    let expiration = now().unix_timestamp() as u64 + 20;
    let completion = swap_to_completion(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        Some(expiration),
    );
    while (now().unix_timestamp() as u64) <= expiration {
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert!(
        maker
            .process_swap_completion(maker_online, completion)
            .is_err()
    );
}

#[test]
#[parallel]
fn maker_refuses_a_completion_missing_taker_signatures() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut taker,
        taker_online,
        "SSIG",
        "Swap Signatures",
        SWAP_RGB_AMOUNT,
    );
    let mut completion = swap_to_completion(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        btc(SWAP_BTC_PRICE),
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        None,
    );
    let taker_inputs = completion
        .proposal
        .request
        .taker_inputs
        .iter()
        .map(|i| i.outpoint.clone())
        .collect::<Vec<_>>();
    let mut psbt = Psbt::from_str(&completion.psbt).unwrap();
    for (txin, input) in psbt.unsigned_tx.input.iter().zip(psbt.inputs.iter_mut()) {
        let outpoint = Outpoint {
            txid: txin.previous_output.txid.to_string(),
            vout: txin.previous_output.vout,
        };
        if taker_inputs.contains(&outpoint) {
            input.tap_key_sig = None;
            input.tap_script_sigs.clear();
            input.partial_sigs.clear();
            input.final_script_witness = None;
        }
    }
    completion.psbt = psbt.to_string();
    assert!(
        maker
            .process_swap_completion(maker_online, completion)
            .is_err()
    );
}

/// Spend all of `wallet`'s coins to itself and mine, double-spending any swap input it declared.
fn double_spend_own_coins(wallet: &mut Wallet, online: Online, esplora: bool) {
    let address = wallet.get_address().unwrap();
    wallet.drain_to(online, address, FEE_RATE).unwrap();
    mine(esplora);
}

/// The taker spends its declared input after sending the request: the maker refuses to build a
/// proposal over it.
fn maker_refuses_request_with_spent_taker_input(indexer_url: Option<String>, esplora: bool) {
    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, indexer_url.clone());
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, indexer_url);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SDSR",
        "Swap Spent Request",
        SWAP_RGB_AMOUNT,
    );
    let offer = maker
        .create_swap_offer(
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            btc(SWAP_BTC_PRICE),
            SWAP_FEE,
            None,
            Some(PROXY_URL.to_string()),
            0,
            None,
        )
        .unwrap();
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    double_spend_own_coins(&mut taker, taker_online, esplora);
    let err = maker
        .accept_swap_request(maker_online, request, 0, false, vec![])
        .unwrap_err();
    assert!(err.to_string().contains("already spent"), "{err}");
}

/// The maker spends its declared input after sending the proposal: the taker refuses to sign.
fn taker_refuses_proposal_with_spent_maker_input(indexer_url: Option<String>, esplora: bool) {
    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, indexer_url.clone());
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, indexer_url);
    let asset_id = issue_swap_asset(
        &mut taker,
        taker_online,
        "SDSP",
        "Swap Spent Proposal",
        SWAP_RGB_AMOUNT,
    );
    let offer = maker
        .create_swap_offer(
            btc(SWAP_BTC_PRICE),
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            SWAP_FEE,
            None,
            Some(PROXY_URL.to_string()),
            0,
            None,
        )
        .unwrap();
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    let proposal = maker
        .accept_swap_request(maker_online, request, 0, false, vec![])
        .unwrap();
    double_spend_own_coins(&mut maker, maker_online, esplora);
    let err = taker
        .complete_swap_proposal(taker_online, proposal, 0, false)
        .unwrap_err();
    assert!(err.to_string().contains("already spent"), "{err}");
}

/// The taker spends its declared input after sending the completion: the maker refuses to sign.
fn maker_refuses_completion_with_spent_taker_input(indexer_url: Option<String>, esplora: bool) {
    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, indexer_url.clone());
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, indexer_url);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SDSC",
        "Swap Spent Completion",
        SWAP_RGB_AMOUNT,
    );
    let completion = swap_to_completion(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        None,
    );
    double_spend_own_coins(&mut taker, taker_online, esplora);
    let err = maker
        .process_swap_completion(maker_online, completion)
        .unwrap_err();
    assert!(err.to_string().contains("already spent"), "{err}");
}

/// The indexer reports a coin as spent as soon as the spend is in the mempool, and refuses a coin
/// declared with the wrong script or that does not exist.
fn indexer_reports_spent_txos(indexer_url: Option<String>, esplora: bool) {
    let (mut wallet, online) = get_funded_noutxo_wallet(true, indexer_url);
    wallet.get_btc_balance(Some(online), false).unwrap();
    let utxo = wallet.bdk_wallet().list_unspent().next().unwrap();
    let script = utxo.txout.script_pubkey.clone();
    let indexer = wallet.indexer();
    assert!(indexer.is_txo_unspent(&utxo.outpoint, &script).unwrap());
    assert!(
        !indexer
            .is_txo_unspent(&utxo.outpoint, &ScriptBuf::new())
            .unwrap()
    );
    let unknown = BdkOutPoint {
        vout: utxo.outpoint.vout + 100,
        ..utxo.outpoint
    };
    assert!(!indexer.is_txo_unspent(&unknown, &script).unwrap());

    let address = wallet.get_address().unwrap();
    wallet.drain_to(online, address, FEE_RATE).unwrap();
    let indexer = wallet.indexer();
    assert!(wait_for_function(
        || !indexer.is_txo_unspent(&utxo.outpoint, &script).unwrap(),
        10,
        200,
    ));
    mine(esplora);
    assert!(!indexer.is_txo_unspent(&utxo.outpoint, &script).unwrap());
}

#[test]
#[parallel]
fn indexer_reports_spent_txos_electrum() {
    initialize();

    indexer_reports_spent_txos(None, false);
}

#[cfg(feature = "esplora")]
#[test]
#[parallel]
fn indexer_reports_spent_txos_esplora() {
    initialize();

    indexer_reports_spent_txos(Some(ESPLORA_URL.to_string()), true);
}

#[test]
#[parallel]
fn maker_refuses_request_with_spent_taker_input_electrum() {
    initialize();

    maker_refuses_request_with_spent_taker_input(None, false);
}

#[cfg(feature = "esplora")]
#[test]
#[parallel]
fn maker_refuses_request_with_spent_taker_input_esplora() {
    initialize();

    maker_refuses_request_with_spent_taker_input(Some(ESPLORA_URL.to_string()), true);
}

#[test]
#[parallel]
fn taker_refuses_proposal_with_spent_maker_input_electrum() {
    initialize();

    taker_refuses_proposal_with_spent_maker_input(None, false);
}

#[cfg(feature = "esplora")]
#[test]
#[parallel]
fn taker_refuses_proposal_with_spent_maker_input_esplora() {
    initialize();

    taker_refuses_proposal_with_spent_maker_input(Some(ESPLORA_URL.to_string()), true);
}

#[test]
#[parallel]
fn maker_refuses_completion_with_spent_taker_input_electrum() {
    initialize();

    maker_refuses_completion_with_spent_taker_input(None, false);
}

#[cfg(feature = "esplora")]
#[test]
#[parallel]
fn maker_refuses_completion_with_spent_taker_input_esplora() {
    initialize();

    maker_refuses_completion_with_spent_taker_input(Some(ESPLORA_URL.to_string()), true);
}

#[test]
#[parallel]
fn refused_rebroadcast_keeps_swap_uncancellable() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SRBC",
        "Swap Rebroadcast",
        SWAP_RGB_AMOUNT,
    );
    let completion = swap_to_completion(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        None,
    );
    let swap_id = completion.proposal.request.offer.swap_id.clone();
    let completion = maker
        .process_swap_completion(maker_online, completion)
        .unwrap();
    maker
        .broadcast_swap_completion(maker_online, completion.clone())
        .unwrap();
    // re-broadcasting a swap already out (in the mempool, then mined) must never reopen it. The
    // electrum backend used here accepts a known tx; esplora refuses it, which is the path the
    // marker guard in broadcast_swap_completion covers
    let _ = maker.broadcast_swap_completion(maker_online, completion.clone());
    mine(false);
    let _ = maker.broadcast_swap_completion(maker_online, completion);
    let stage = maker
        .list_swaps()
        .unwrap()
        .into_iter()
        .find(|s| s.swap_id == swap_id)
        .unwrap()
        .stage;
    assert_eq!(stage, OnchainSwapStage::Broadcast);
    assert!(matches!(
        maker.cancel_swap(maker_online, swap_id),
        Err(Error::CannotFailBatchTransfer)
    ));
}

#[test]
#[parallel]
fn taker_invalidates_a_withheld_swap() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SINV",
        "Swap Invalidate",
        SWAP_RGB_AMOUNT,
    );
    // an asset the taker holds outside the swap must not be touched by the invalidation
    let taker_asset_id = issue_swap_asset(
        &mut taker,
        taker_online,
        "SOWN",
        "Swap Own",
        SWAP_RGB_AMOUNT,
    );
    let taker_btc_before = total_btc(&mut taker, taker_online);
    let taker_unspents_before = settled_unspents(&mut taker, taker_online);

    let completion = swap_to_completion(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        None,
    );
    let swap_id = completion.proposal.request.offer.swap_id.clone();
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Proposed);
    // the maker holds a fully signed swap transaction and withholds it
    let completion = maker
        .process_swap_completion(maker_online, completion)
        .unwrap();
    assert!(completion.finalized_psbt.is_some());

    let invalidation_txid = taker
        .invalidate_swap(taker_online, swap_id.clone(), FEE_RATE)
        .unwrap();
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Invalidating);
    // a retry re-broadcasts the same invalidation
    assert_eq!(
        taker
            .invalidate_swap(taker_online, swap_id.clone(), FEE_RATE)
            .unwrap(),
        invalidation_txid
    );
    // the swap transaction may still win until the invalidation confirms
    assert!(matches!(
        taker.cancel_swap(taker_online, swap_id.clone()),
        Err(Error::InvalidDetails { .. })
    ));
    assert!(taker.cancel_expired_swaps(taker_online).unwrap().is_empty());

    // the invalidation only spends the uncolored inputs the taker declared, paying at least the
    // swap transaction's fee so the swap transaction can't replace it
    let invalidation_tx = taker
        .bdk_wallet()
        .get_tx(Txid::from_str(&invalidation_txid).unwrap())
        .unwrap()
        .tx_node
        .tx
        .clone();
    let declared = completion
        .proposal
        .request
        .taker_inputs
        .iter()
        .map(|i| i.outpoint.clone())
        .collect::<Vec<_>>();
    for input in &invalidation_tx.input {
        assert!(declared.contains(&Outpoint {
            txid: input.previous_output.txid.to_string(),
            vout: input.previous_output.vout,
        }));
    }
    let invalidation_fee = taker
        .bdk_wallet()
        .calculate_fee(&invalidation_tx)
        .unwrap()
        .to_sat();
    assert!(invalidation_fee >= SWAP_FEE);

    mine(false);
    assert!(
        maker
            .broadcast_swap_completion(maker_online, completion)
            .is_err()
    );
    assert_eq!(
        taker.cancel_expired_swaps(taker_online).unwrap(),
        vec![swap_id.clone()]
    );
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Cancelled);
    assert!(taker.cancel_expired_swaps(taker_online).unwrap().is_empty());
    // invalidating an invalidated swap is a no-op
    assert_eq!(
        taker
            .invalidate_swap(taker_online, swap_id.clone(), FEE_RATE)
            .unwrap(),
        invalidation_txid
    );
    // the rejected broadcast left the maker's swap cancellable, releasing its RGB leg
    maker.cancel_swap(maker_online, swap_id).unwrap();

    refresh_settled(&mut maker, maker_online);
    refresh_settled(&mut taker, taker_online);
    assert_settled_balance(&maker, &asset_id, SWAP_RGB_AMOUNT);
    assert_settled_balance(&taker, &taker_asset_id, SWAP_RGB_AMOUNT);
    assert_eq!(asset_amount(&taker, &asset_id), 0);
    assert_eq!(
        settled_unspents(&mut taker, taker_online)
            .into_iter()
            .filter(|u| !u.ends_with("[]"))
            .collect::<Vec<_>>(),
        taker_unspents_before
            .into_iter()
            .filter(|u| !u.ends_with("[]"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        total_btc(&mut taker, taker_online),
        taker_btc_before - invalidation_fee
    );

    // the maker's released UTXO can be swapped again
    execute_swap(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        PROXY_URL,
    );
    refresh_settled(&mut maker, maker_online);
    refresh_settled(&mut taker, taker_online);
    assert_settled_balance(&maker, &asset_id, 0);
    assert_settled_balance(&taker, &asset_id, SWAP_RGB_AMOUNT);
}

#[test]
#[parallel]
fn invalidating_swap_is_recovered_after_restart() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SRST",
        "Swap Restart",
        SWAP_RGB_AMOUNT,
    );
    let completion = swap_to_completion(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        None,
    );
    let swap_id = completion.proposal.request.offer.swap_id.clone();
    let completion = maker
        .process_swap_completion(maker_online, completion)
        .unwrap();
    let invalidation_txid = taker
        .invalidate_swap(taker_online, swap_id.clone(), FEE_RATE)
        .unwrap();

    // the taker restarts before the invalidation confirms
    let (mut taker, taker_online) = reopen_wallet(taker);
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Invalidating);
    assert!(taker.cancel_expired_swaps(taker_online).unwrap().is_empty());
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Invalidating);

    mine(false);
    assert_eq!(
        taker.cancel_expired_swaps(taker_online).unwrap(),
        vec![swap_id.clone()]
    );
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Cancelled);
    assert_eq!(
        taker
            .invalidate_swap(taker_online, swap_id.clone(), FEE_RATE)
            .unwrap(),
        invalidation_txid
    );
    assert!(
        maker
            .broadcast_swap_completion(maker_online, completion)
            .is_err()
    );
    maker.cancel_swap(maker_online, swap_id).unwrap();
    refresh_settled(&mut maker, maker_online);
    assert_settled_balance(&maker, &asset_id, SWAP_RGB_AMOUNT);
}

#[test]
#[parallel]
fn cancelled_signed_swap_can_still_be_invalidated() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SCIV",
        "Swap Cancel Invalidate",
        SWAP_RGB_AMOUNT,
    );
    let completion = swap_to_completion(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        None,
    );
    let swap_id = completion.proposal.request.offer.swap_id.clone();
    let completion = maker
        .process_swap_completion(maker_online, completion)
        .unwrap();
    // cancelling only drops the taker's local state, the maker can still broadcast
    taker.cancel_swap(taker_online, swap_id.clone()).unwrap();
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Cancelled);

    taker
        .invalidate_swap(taker_online, swap_id.clone(), FEE_RATE)
        .unwrap();
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Invalidating);
    mine(false);
    assert!(
        maker
            .broadcast_swap_completion(maker_online, completion)
            .is_err()
    );
    assert_eq!(
        taker.cancel_expired_swaps(taker_online).unwrap(),
        vec![swap_id.clone()]
    );
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Cancelled);
}

#[test]
#[parallel]
fn maker_broadcast_wins_over_invalidation() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut maker,
        maker_online,
        "SRCE",
        "Swap Race",
        SWAP_RGB_AMOUNT,
    );
    let completion = swap_to_completion(
        &mut maker,
        maker_online,
        &mut taker,
        taker_online,
        rgb(&asset_id, SWAP_RGB_AMOUNT),
        btc(SWAP_BTC_PRICE),
        None,
    );
    let swap_id = completion.proposal.request.offer.swap_id.clone();
    let completion = maker
        .process_swap_completion(maker_online, completion)
        .unwrap();
    maker
        .broadcast_swap_completion(maker_online, completion.clone())
        .unwrap();

    // the swap transaction is out: the swap settles instead
    assert!(matches!(
        taker.invalidate_swap(taker_online, swap_id.clone(), FEE_RATE),
        Err(Error::CannotFailBatchTransfer)
    ));
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Broadcast);
    assert!(matches!(
        taker.cancel_swap(taker_online, swap_id.clone()),
        Err(Error::CannotFailBatchTransfer)
    ));
    assert!(taker.cancel_expired_swaps(taker_online).unwrap().is_empty());

    mine(false);
    maker
        .accept_swap_transfers(
            maker_online,
            completion.clone(),
            OnchainSwapRole::Maker,
            false,
        )
        .unwrap();
    taker
        .accept_swap_transfers(taker_online, completion, OnchainSwapRole::Taker, false)
        .unwrap();
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Accepted);
    assert!(matches!(
        taker.invalidate_swap(taker_online, swap_id, FEE_RATE),
        Err(Error::CannotFailBatchTransfer)
    ));
    refresh_settled(&mut maker, maker_online);
    refresh_settled(&mut taker, taker_online);
    assert_settled_balance(&maker, &asset_id, 0);
    assert_settled_balance(&taker, &asset_id, SWAP_RGB_AMOUNT);
}

#[test]
#[parallel]
fn invalidate_swap_rejects_invalid_calls() {
    initialize();

    let (mut maker, maker_online) = get_funded_noutxo_wallet(true, None);
    let (mut taker, taker_online) = get_funded_noutxo_wallet(true, None);
    let asset_id = issue_swap_asset(
        &mut taker,
        taker_online,
        "SIVC",
        "Swap Invalid Calls",
        SWAP_RGB_AMOUNT,
    );
    let invalid_details = |res: Result<String, Error>| {
        assert!(
            matches!(res, Err(Error::InvalidDetails { .. })),
            "unexpected result {res:?}"
        )
    };

    // unknown or malformed swap IDs
    invalid_details(taker.invalidate_swap(taker_online, s!("unknown"), FEE_RATE));
    invalid_details(taker.invalidate_swap(taker_online, s!("../swap"), FEE_RATE));
    invalid_details(taker.invalidate_swap(taker_online, s!(""), FEE_RATE));

    // the taker sends the RGB leg: it only declared colored inputs
    let offer = maker
        .create_swap_offer(
            btc(SWAP_BTC_PRICE),
            rgb(&asset_id, SWAP_RGB_AMOUNT),
            SWAP_FEE,
            None,
            Some(PROXY_URL.to_string()),
            vec![],
        )
        .unwrap();
    let swap_id = offer.swap_id.clone();
    // the maker side can't invalidate
    invalid_details(maker.invalidate_swap(maker_online, swap_id.clone(), FEE_RATE));
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    // nothing to invalidate before the taker signed
    invalid_details(taker.invalidate_swap(taker_online, swap_id.clone(), FEE_RATE));
    let proposal = maker
        .accept_swap_request(maker_online, request, 0, false, vec![])
        .unwrap();
    invalid_details(maker.invalidate_swap(maker_online, swap_id.clone(), FEE_RATE));
    let _completion = taker
        .complete_swap_proposal(taker_online, proposal, 0, false)
        .unwrap();
    // spending a colored input outside the swap would destroy its allocations
    let stash_before = stash_assignments(&mut taker, taker_online, &asset_id);
    invalid_details(taker.invalidate_swap(taker_online, swap_id.clone(), FEE_RATE));
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Proposed);
    assert_eq!(
        stash_assignments(&mut taker, taker_online, &asset_id),
        stash_before
    );
    // a refused invalidation of a cancelled swap leaves it cancelled
    taker.cancel_swap(taker_online, swap_id.clone()).unwrap();
    invalid_details(taker.invalidate_swap(taker_online, swap_id.clone(), FEE_RATE));
    assert_eq!(swap_stage(&taker, &swap_id), OnchainSwapStage::Cancelled);
    maker.cancel_swap(maker_online, swap_id).unwrap();
    assert_settled_balance(&taker, &asset_id, SWAP_RGB_AMOUNT);
}

/// Drop a wallet and open it again from the same directory, as after a restart.
fn reopen_wallet(wallet: Wallet) -> (Wallet, Online) {
    let wallet_data = wallet.get_wallet_data();
    let keys = wallet.get_keys();
    drop(wallet);
    let mut wallet = Wallet::new(wallet_data, keys).unwrap();
    let online = wallet.go_online(test_go_online_options(None)).unwrap();
    (wallet, online)
}

fn swap_stage(wallet: &Wallet, swap_id: &str) -> OnchainSwapStage {
    wallet
        .list_swaps()
        .unwrap()
        .into_iter()
        .find(|s| s.swap_id == swap_id)
        .unwrap()
        .stage
}

fn refresh_settled(wallet: &mut Wallet, online: Online) {
    wallet.refresh(online, None, vec![], false).unwrap();
}

fn assert_settled_balance(wallet: &Wallet, asset_id: &str, expected: u64) {
    let balance = wallet.get_asset_balance(asset_id.to_string()).unwrap();
    assert_eq!(balance.settled, expected, "settled balance of {asset_id}");
    assert_eq!(
        balance.spendable, expected,
        "spendable balance of {asset_id}"
    );
}

fn settled_unspents(wallet: &mut Wallet, online: Online) -> Vec<String> {
    let mut unspents = wallet
        .list_unspents(Some(online), true, false)
        .unwrap()
        .into_iter()
        .map(|u| format!("{} {:?}", u.utxo.outpoint, u.rgb_allocations))
        .collect::<Vec<_>>();
    unspents.sort();
    unspents
}

fn stash_assignments(
    wallet: &mut Wallet,
    online: Online,
    asset_id: &str,
) -> Vec<(Outpoint, Vec<Assignment>)> {
    let outpoints = wallet
        .list_unspents(Some(online), false, false)
        .unwrap()
        .into_iter()
        .map(|u| u.utxo.outpoint)
        .collect::<Vec<_>>();
    let mut assignments = wallet
        .contract_assignments_for_outpoints(ContractId::from_str(asset_id).unwrap(), outpoints)
        .unwrap();
    assignments.sort_by_key(|(outpoint, _)| outpoint.to_string());
    assignments
}

fn normal_send(sender: &mut SinglesigParty, rcv: &mut SinglesigParty, asset_id: &str, amount: u64) {
    let receive_data = rcv.blind_receive();
    let recipient_map = HashMap::from([(
        asset_id.to_string(),
        vec![Recipient {
            assignment: Assignment::Fungible(amount),
            recipient_id: receive_data.recipient_id,
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    sender.send(recipient_map, FEE_RATE, None);
    rcv.wait_for_refresh(None);
    sender.wait_for_refresh(Some(asset_id));
    mine(false);
    rcv.wait_for_refresh(None);
    sender.wait_for_refresh(Some(asset_id));
}

fn issue_swap_asset(
    wallet: &mut Wallet,
    online: Online,
    ticker: &str,
    name: &str,
    amount: u64,
) -> String {
    wallet
        .create_utxos(online, false, Some(1), Some(10_000), FEE_RATE, false)
        .unwrap();
    let asset = wallet
        .issue_asset_nia(ticker.to_string(), name.to_string(), 0, vec![amount])
        .unwrap();
    assert_eq!(asset_amount(wallet, &asset.asset_id), amount);
    asset.asset_id
}

fn execute_swap(
    maker: &mut Wallet,
    maker_online: Online,
    taker: &mut Wallet,
    taker_online: Online,
    maker_gives: OnchainSwapLeg,
    maker_receives: OnchainSwapLeg,
    proxy_url: &str,
) {
    execute_swap_with_extra_outputs(
        maker,
        maker_online,
        taker,
        taker_online,
        maker_gives,
        maker_receives,
        proxy_url,
        vec![],
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_swap_with_extra_outputs(
    maker: &mut Wallet,
    maker_online: Online,
    taker: &mut Wallet,
    taker_online: Online,
    maker_gives: OnchainSwapLeg,
    maker_receives: OnchainSwapLeg,
    proxy_url: &str,
    extra_outputs: Vec<OnchainSwapExtraOutput>,
) {
    let maker_receives_rgb = matches!(maker_receives.kind, OnchainSwapLegKind::Rgb);
    let taker_receives_rgb = matches!(maker_gives.kind, OnchainSwapLegKind::Rgb);
    let rgb_for_rgb = maker_receives_rgb && taker_receives_rgb;
    let maker_gives_asset_id = maker_gives.asset_id.clone();
    let maker_receives_asset_id = maker_receives.asset_id.clone();

    let offer = maker
        .create_swap_offer(
            maker_gives,
            maker_receives,
            SWAP_FEE,
            None,
            Some(proxy_url.to_string()),
            extra_outputs,
        )
        .unwrap();
    let request = taker
        .accept_swap_offer(taker_online, offer, 0, false, vec![])
        .unwrap();
    let proposal = maker
        .accept_swap_request(maker_online, request, 0, false, vec![])
        .unwrap();
    // the maker signs last in every direction: its proposal carries no signature
    assert_eq!(signature_count(&proposal.psbt), 0);
    // locked to the maker's chain tip, like an ordinary wallet transaction
    assert!(proposal.lock_time > 0);
    assert_eq!(
        Psbt::from_str(&proposal.psbt)
            .unwrap()
            .unsigned_tx
            .lock_time
            .to_consensus_u32(),
        proposal.lock_time
    );
    assert_consignment_transport(&proposal.consignments);
    if taker_receives_rgb {
        assert!(
            proposal.maker_history.is_some(),
            "maker RGB history should be exposed as a high-level history ref"
        );
        assert_asset_history_transport(proposal.maker_history.as_ref());
    }
    let completion = taker
        .complete_swap_proposal(taker_online, proposal, 0, false)
        .unwrap();
    assert!(
        completion.finalized_psbt.is_none(),
        "the taker must never hold a broadcastable swap transaction"
    );
    assert!(signature_count(&completion.psbt) > 0);
    if rgb_for_rgb {
        assert!(
            completion.taker_history.is_some(),
            "taker RGB history should be exposed as a high-level history ref"
        );
        assert_asset_history_transport(completion.taker_history.as_ref());
        let mut missing_history_endpoint = completion.clone();
        missing_history_endpoint
            .taker_history
            .as_mut()
            .unwrap()
            .endpoint = None;
        assert!(
            maker
                .process_swap_completion(maker_online, missing_history_endpoint)
                .is_err()
        );
        let mut tampered_completion = completion.clone();
        tampered_completion.txid =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(
            maker
                .process_swap_completion(maker_online, tampered_completion)
                .is_err()
        );
    }
    // the maker validates the taker's leg, signs last and finalizes
    let completion = maker
        .process_swap_completion(maker_online, completion)
        .unwrap();
    assert!(completion.finalized_psbt.is_some());
    assert_consignment_transport(&completion.consignments);

    let broadcast_txid = maker
        .broadcast_swap_completion(maker_online, completion.clone())
        .unwrap();
    assert_eq!(broadcast_txid, completion.txid);
    mine(false);

    if taker_receives_rgb {
        let mut bad_endpoint = completion.clone();
        bad_endpoint
            .consignments
            .iter_mut()
            .filter(|c| Some(c.asset_id.as_str()) == maker_gives_asset_id.as_deref())
            .for_each(|c| c.endpoint = Some(format!("rpc://{PROXY_HOST_MOD_PROTO}")));
        assert!(
            taker
                .accept_swap_transfers(taker_online, bad_endpoint, OnchainSwapRole::Taker, false)
                .is_err()
        );

        let mut missing_endpoint = completion.clone();
        missing_endpoint
            .consignments
            .iter_mut()
            .filter(|c| Some(c.asset_id.as_str()) == maker_gives_asset_id.as_deref())
            .for_each(|c| c.endpoint = None);
        assert!(
            taker
                .accept_swap_transfers(
                    taker_online,
                    missing_endpoint,
                    OnchainSwapRole::Taker,
                    false,
                )
                .is_err()
        );

        let mut wrong_recipient = completion.clone();
        let wrong_id = alternate_swap_recipient_id(taker);
        wrong_recipient
            .consignments
            .iter_mut()
            .filter(|c| Some(c.asset_id.as_str()) == maker_gives_asset_id.as_deref())
            .for_each(|c| c.recipient_id = wrong_id.clone());
        assert!(
            taker
                .accept_swap_transfers(taker_online, wrong_recipient, OnchainSwapRole::Taker, false)
                .is_err()
        );

        let mut missing_consignment = completion.clone();
        missing_consignment
            .consignments
            .retain(|c| Some(c.asset_id.as_str()) != maker_gives_asset_id.as_deref());
        assert!(
            taker
                .accept_swap_transfers(
                    taker_online,
                    missing_consignment,
                    OnchainSwapRole::Taker,
                    false,
                )
                .is_err()
        );
        let receive_result = taker
            .accept_swap_transfers(
                taker_online,
                completion.clone(),
                OnchainSwapRole::Taker,
                false,
            )
            .unwrap();
        assert!(!receive_result.assignments.is_empty());
    }
    if maker_receives_rgb {
        let mut bad_endpoint = completion.clone();
        bad_endpoint
            .consignments
            .iter_mut()
            .filter(|c| Some(c.asset_id.as_str()) == maker_receives_asset_id.as_deref())
            .for_each(|c| c.endpoint = Some(format!("rpc://{PROXY_HOST_MOD_PROTO}")));
        assert!(
            maker
                .accept_swap_transfers(maker_online, bad_endpoint, OnchainSwapRole::Maker, false)
                .is_err()
        );

        let mut missing_endpoint = completion.clone();
        missing_endpoint
            .consignments
            .iter_mut()
            .filter(|c| Some(c.asset_id.as_str()) == maker_receives_asset_id.as_deref())
            .for_each(|c| c.endpoint = None);
        assert!(
            maker
                .accept_swap_transfers(
                    maker_online,
                    missing_endpoint,
                    OnchainSwapRole::Maker,
                    false,
                )
                .is_err()
        );

        let mut wrong_recipient = completion.clone();
        let wrong_id = alternate_swap_recipient_id(maker);
        wrong_recipient
            .consignments
            .iter_mut()
            .filter(|c| Some(c.asset_id.as_str()) == maker_receives_asset_id.as_deref())
            .for_each(|c| c.recipient_id = wrong_id.clone());
        assert!(
            maker
                .accept_swap_transfers(maker_online, wrong_recipient, OnchainSwapRole::Maker, false)
                .is_err()
        );

        let mut missing_consignment = completion.clone();
        missing_consignment
            .consignments
            .retain(|c| Some(c.asset_id.as_str()) != maker_receives_asset_id.as_deref());
        assert!(
            maker
                .accept_swap_transfers(
                    maker_online,
                    missing_consignment,
                    OnchainSwapRole::Maker,
                    false,
                )
                .is_err()
        );
        let receive_result = maker
            .accept_swap_transfers(
                maker_online,
                completion.clone(),
                OnchainSwapRole::Maker,
                false,
            )
            .unwrap();
        assert!(!receive_result.assignments.is_empty());
    }
    // parties receiving only BTC still settle the RGB leg they sent
    if !taker_receives_rgb {
        let receive_result = taker
            .accept_swap_transfers(
                taker_online,
                completion.clone(),
                OnchainSwapRole::Taker,
                false,
            )
            .unwrap();
        assert!(receive_result.assignments.is_empty());
    }
    if !maker_receives_rgb {
        let receive_result = maker
            .accept_swap_transfers(maker_online, completion, OnchainSwapRole::Maker, false)
            .unwrap();
        assert!(receive_result.assignments.is_empty());
    }
}

fn alternate_swap_recipient_id(wallet: &mut Wallet) -> String {
    let address = wallet.get_address().unwrap();
    let script = wallet.get_script_pubkey(&address).unwrap();
    recipient_id_from_script_buf(script, BitcoinNetwork::Regtest).unwrap()
}

fn assert_consignment_transport(consignments: &[OnchainSwapConsignment]) {
    if consignments.is_empty() {
        return;
    }
    for consignment in consignments {
        assert_eq!(
            consignment.endpoint.as_deref(),
            Some(PROXY_ENDPOINT.as_str())
        );
        assert!(
            consignment.path.is_empty(),
            "proxy-mode consignments must not expose sender-local paths"
        );
    }
}

fn assert_asset_history_transport(history: Option<&OnchainSwapAssetHistory>) {
    let Some(history) = history else {
        return;
    };
    assert_eq!(history.endpoint.as_deref(), Some(PROXY_ENDPOINT.as_str()));
    assert!(
        history.path.is_empty(),
        "proxy-mode asset histories must not expose sender-local paths"
    );
}

fn signature_count(psbt: &str) -> usize {
    Psbt::from_str(psbt)
        .unwrap()
        .inputs
        .iter()
        .map(|input| {
            input.partial_sigs.len()
                + input.tap_script_sigs.len()
                + usize::from(input.tap_key_sig.is_some())
                + usize::from(input.final_script_sig.is_some())
                + usize::from(input.final_script_witness.is_some())
        })
        .sum()
}

fn total_btc(wallet: &mut Wallet, online: Online) -> u64 {
    let balance = wallet.get_btc_balance(Some(online), false).unwrap();

    balance.vanilla.future + balance.colored.future
}

fn asset_amount(wallet: &Wallet, asset_id: &str) -> u64 {
    wallet
        .get_asset_balance(asset_id.to_string())
        .map(|balance| balance.future)
        .unwrap_or(0)
}

fn assert_btc_delta(
    maker: &mut Wallet,
    maker_online: Online,
    maker_before: u64,
    taker: &mut Wallet,
    taker_online: Online,
    taker_before: u64,
    expected: ExpectedBtcDelta,
) {
    assert_btc_delta_with_extra_outputs(
        maker,
        maker_online,
        maker_before,
        taker,
        taker_online,
        taker_before,
        expected,
        0,
    )
}

#[allow(clippy::too_many_arguments)]
fn assert_btc_delta_with_extra_outputs(
    maker: &mut Wallet,
    maker_online: Online,
    maker_before: u64,
    taker: &mut Wallet,
    taker_online: Online,
    taker_before: u64,
    expected: ExpectedBtcDelta,
    extra_outputs_sat: u64,
) {
    let maker_after = total_btc(maker, maker_online);
    let taker_after = total_btc(taker, taker_online);
    assert_eq!(
        maker_after as i64 - maker_before as i64,
        expected.maker,
        "maker BTC delta mismatch"
    );
    assert_eq!(
        taker_after as i64 - taker_before as i64,
        expected.taker,
        "taker BTC delta mismatch"
    );
    assert_eq!(
        maker_after + taker_after + SWAP_FEE + extra_outputs_sat,
        maker_before + taker_before,
        "total BTC should only decrease by the swap fee and the extra outputs"
    );
}

fn assert_asset_balances(
    maker: &Wallet,
    taker: &Wallet,
    expected_balances: &[ExpectedAssetBalance<'_>],
) {
    for expected in expected_balances {
        let maker_amount = asset_amount(maker, expected.asset_id);
        let taker_amount = asset_amount(taker, expected.asset_id);
        assert_eq!(
            maker_amount, expected.maker,
            "maker asset balance mismatch for {}",
            expected.asset_id
        );
        assert_eq!(
            taker_amount, expected.taker,
            "taker asset balance mismatch for {}",
            expected.asset_id
        );
        assert_eq!(
            maker_amount + taker_amount,
            SWAP_RGB_AMOUNT,
            "asset amount should be conserved for {}",
            expected.asset_id
        );
    }
}
