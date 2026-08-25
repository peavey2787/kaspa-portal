use super::{branch::*, consolidation::*, *};
use crate::{
    chain::utxo::UtxoEntry,
    test_support::{fail_network_client, ready},
};

const KPUB_A: &str = "kpub1:038f332e03405ab68380000000f0453f0894cc8c84ebf6e6208e0c7916e9ddbd14919f9bbb92b0690b4e353392020327c7136972883eab5a7722ec3d4302f888804ecce61658ae962a2c56bb7571";
const KPUB_B: &str = "kpub1:038f332e03a7457270800000002908be01d75735944f29befbdbcd173ab00df2d44c6d5ab51a839413fda90cbf035b986b584de244f5d6a1939192f676a9f2992a63b0f43cdc452dcb40d9dd7081";

fn descriptor_text() -> String {
    format!("multi_hd45(1,{KPUB_A},{KPUB_B})")
}

fn descriptor() -> MultisigDescriptor {
    MultisigDescriptor::parse(&descriptor_text()).expect("45' descriptor")
}

fn source_address(descriptor: &MultisigDescriptor, cosigner: u32, index: u32) -> String {
    branch_address(descriptor, cosigner, 0, index, "kaspa")
        .expect("source address")
        .2
}

fn consolidation_request<'a>(
    descriptor_text: &'a str,
    sources_json: &'a str,
    destination_address: &'a str,
    amount: u64,
    fee: u64,
    cosigner: u32,
    change_index_hint: u32,
) -> MultisigConsolidationRequest<'a> {
    MultisigConsolidationRequest {
        descriptor_text,
        sources_json,
        destination_address,
        amount,
        fee,
        cosigner,
        change_index_hint,
    }
}

fn change_request<'a>(
    descriptor: &'a MultisigDescriptor,
    source_address: &'a str,
    prefix: &'a str,
    cosigner: u32,
    change_index_hint: u32,
    client: &'a crate::network::client::NetworkClient,
    change: u64,
) -> ChangeOutputRequest<'a> {
    ChangeOutputRequest {
        descriptor,
        source_address,
        prefix,
        cosigner,
        change_index_hint,
        client,
        change,
    }
}

fn utxo(address: &str, tx_byte: u8, index: u32, amount: u64) -> UtxoEntry {
    UtxoEntry {
        tx_id: format!("{tx_byte:02x}").repeat(32),
        index,
        amount,
        script_public_key: crate::primitives::address::address_to_script_pubkey(address)
            .expect("source script"),
        block_daa_score: 0,
        covenant_id: None,
    }
}

fn request<'a>(
    text: &'a str,
    source: &'a str,
    selection: MultisigSelection<'a>,
) -> MultisigTransactionRequest<'a> {
    MultisigTransactionRequest {
        descriptor_text: text,
        source_address: source,
        destination_address: source,
        amount: 20_000_000,
        fee: 1_000,
        change_address: source,
        requested_index: 0,
        change_index_hint: 0,
        selection,
    }
}

#[test]
fn hd45_preparation_selection_and_derivation_maps_are_covered() {
    let text = descriptor_text();
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);
    let automatic = request(&text, &source, MultisigSelection::Automatic);
    let prepared = prepare_request(&automatic).expect("prepared multisig");
    assert_eq!(prepared.source_path.cosigner, 0);
    assert_eq!(prepared.source_path.chain, 0);
    assert!(verify_source_address(&source, &prepared.redeem_script).is_ok());
    assert!(verify_source_address(
        "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e",
        &prepared.redeem_script
    )
    .is_err());

    assert!(encode_from_utxos(&automatic, &prepared, Vec::new())
        .unwrap_err()
        .contains("No UTXOs"));
    let wire = encode_from_utxos(
        &automatic,
        &prepared,
        vec![utxo(&source, 0x11, 0, 40_000_000)],
    )
    .expect("automatic multisig PSKB");
    assert!(!wire.is_empty());

    let selected = [0usize];
    let explicit = request(&text, &source, MultisigSelection::Explicit(&selected));
    let wire = encode_from_utxos(
        &explicit,
        &prepared,
        vec![utxo(&source, 0x22, 1, 20_001_000)],
    )
    .expect("explicit multisig PSKB");
    assert!(!wire.is_empty());

    let mut invalid = request(&text, &source, MultisigSelection::Automatic);
    invalid.amount = 0;
    assert!(validate_amounts(&invalid).is_err());
    invalid.amount = 1;
    assert!(validate_amounts(&invalid).is_err());
}

#[test]
fn branch_helpers_cover_both_chains_usage_and_first_free_indexes() {
    let descriptor = descriptor();
    let addresses = branch_addresses(&descriptor, 0, 3, "kaspa").expect("branches");
    assert_eq!(addresses.len(), 6);
    assert_eq!(branch_query(&addresses).len(), 6);
    let by_script = branch_address_map(&addresses).expect("script map");

    let receive0 = addresses
        .iter()
        .find(|(chain, index, _)| *chain == 0 && *index == 0)
        .unwrap();
    let change1 = addresses
        .iter()
        .find(|(chain, index, _)| *chain == 1 && *index == 1)
        .unwrap();
    let summary = summarize_branch_utxos(
        vec![
            utxo(&receive0.2, 0x31, 0, 10),
            utxo(&change1.2, 0x32, 1, 20),
            UtxoEntry {
                script_public_key: vec![0xaa],
                ..utxo(&receive0.2, 0x33, 2, 30)
            },
        ],
        &by_script,
        3,
    )
    .expect("summary");
    assert_eq!(summary.balance, 30);
    assert_eq!(summary.labelled.len(), 2);
    assert_eq!(first_free(&summary.receive_used), 1);
    assert_eq!(first_free(&summary.change_used), 0);
    assert_eq!(first_free(&[true, true]), 2);
    let json = encode_branch_summary(summary, 0, 3).expect("summary json");
    assert!(json.contains("\"balance_sompi\":\"30\""));

    let change = change_branch_addresses(&descriptor, 0, 3, "kaspa").expect("change branch");
    assert_eq!(first_unused_change_index(&change, &[], 3), Ok(0));
    let used0 = utxo(&change[0].2, 0x34, 0, 10);
    assert_eq!(first_unused_change_index(&change, &[used0], 3), Ok(1));
    let all_used = change
        .iter()
        .enumerate()
        .map(|(slot, (_, _, address))| utxo(address, 0x40 + slot as u8, slot as u32, 10))
        .collect::<Vec<_>>();
    assert_eq!(first_unused_change_index(&change, &all_used, 3), Ok(3));
}

#[test]
fn branch_scan_and_change_index_reaches_injected_transport_after_validation() {
    let client = fail_network_client();
    let text = descriptor_text();
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);

    let static_descriptor = format!("multi(1,{},{})", "11".repeat(32), "22".repeat(32));
    assert!(
        ready(scan_branch_json(&static_descriptor, 0, 1, &client, "kaspa"))
            .unwrap_err()
            .contains("Branch scan requires")
    );
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(scan_branch_json(&text, 0, 2, &client, "kaspa"))
        .unwrap_err()
        .contains("test transport unavailable"));

    assert_eq!(
        ready(resolve_change_index(&descriptor, &source, 0, 7, &client)),
        Ok(7)
    );
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(resolve_change_index(
        &descriptor,
        &source,
        0,
        u32::MAX,
        &client
    ))
    .unwrap_err()
    .contains("test transport unavailable"));
}

#[test]
fn consolidation_helpers_cover_limits_resolution_inputs_and_change() {
    let descriptor = descriptor();
    let source0 = source_address(&descriptor, 0, 0);
    let source1 = source_address(&descriptor, 0, 1);
    let first = MultisigConsolidationSource {
        address: source0.clone(),
        tx_id: "11".repeat(32),
        index: 0,
    };
    let second = MultisigConsolidationSource {
        address: source1.clone(),
        tx_id: "22".repeat(32),
        index: 1,
    };
    let sources = vec![first.clone(), second.clone()];

    assert!(parse_consolidation_sources("not-json").is_err());
    assert!(parse_consolidation_sources("[]").is_err());
    assert!(parse_consolidation_sources("[{\"address\":\"a\",\"tx_id\":\"b\",\"index\":0},{\"address\":\"a\",\"tx_id\":\"b\",\"index\":1},{\"address\":\"a\",\"tx_id\":\"b\",\"index\":2},{\"address\":\"a\",\"tx_id\":\"b\",\"index\":3}]").is_err());
    assert_eq!(
        unique_source_addresses(&[first.clone(), first.clone(), second.clone()]).len(),
        2
    );

    let resolved =
        resolve_consolidation_sources(&descriptor, &sources, 0).expect("resolved sources");
    assert_eq!(resolved.len(), 2);
    let duplicate_resolved =
        resolve_consolidation_sources(&descriptor, &[first.clone(), first.clone()], 0)
            .expect("deduplicated resolved source");
    assert_eq!(duplicate_resolved.len(), 1);
    assert!(resolve_consolidation_sources(&descriptor, &sources, 1).is_err());

    let available = vec![
        utxo(&source0, 0x11, 0, 20_000_000),
        utxo(&source1, 0x22, 1, 30_000_000),
    ];
    let (inputs, total) =
        build_consolidation_inputs(&sources, &available, &resolved).expect("inputs");
    assert_eq!(inputs.len(), 2);
    assert_eq!(total, 50_000_000);
    assert!(build_consolidation_inputs(&sources, &available[..1], &resolved).is_err());
    assert_eq!(required_total(4_000_000, 1_000), Ok(4_001_000));
    assert!(required_total(u64::MAX, 1).is_err());
    assert!(require_selected_total(4_001_000, 4_001_000).is_ok());
    assert!(require_selected_total(4_000_999, 4_001_000).is_err());

    let mut outputs = vec![PlannedOutput::new(1_000_000, vec![0x51])];
    assert!(ready(append_consolidation_change(
        change_request(
            &descriptor,
            &source0,
            "kaspa",
            0,
            2,
            &fail_network_client(),
            20_000_000
        ),
        &mut outputs,
    ))
    .is_ok());
    assert_eq!(outputs.len(), 2);
    assert!(ready(append_consolidation_change(
        change_request(
            &descriptor,
            &source0,
            "kaspa",
            0,
            2,
            &fail_network_client(),
            0
        ),
        &mut outputs,
    ))
    .is_ok());
    assert_eq!(outputs.len(), 2);
    assert!(ready(append_consolidation_change(
        change_request(
            &descriptor,
            &source0,
            "kaspa",
            0,
            2,
            &fail_network_client(),
            1
        ),
        &mut outputs,
    ))
    .is_ok());
    assert_eq!(outputs.len(), 2);

    let sources_json = format!(
        "[{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":0}},{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":1}}]",
        source0, "11".repeat(32), source1, "22".repeat(32),
    );
    let static_descriptor = format!("multi(1,{},{})", "11".repeat(32), "22".repeat(32));
    assert!(prepare_consolidation(&static_descriptor, &sources_json, 0).is_err());
    let prepared = prepare_consolidation(&descriptor_text(), &sources_json, 0)
        .expect("prepared consolidation");
    let encoded = ready(finish_consolidation(
        prepared,
        &available,
        &consolidation_request(
            &descriptor_text(),
            &sources_json,
            &source0,
            20_000_000,
            1_000,
            0,
            2,
        ),
        &fail_network_client(),
    ))
    .expect("finished consolidation");
    assert!(!encoded.is_empty());
}

#[test]
fn public_async_multisig_boundaries_fail_closed_before_or_at_native_transport() {
    let text = descriptor_text();
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);
    let client = fail_network_client();
    let mut tx_request = request(&text, &source, MultisigSelection::Automatic);
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(create(&client, tx_request))
        .unwrap_err()
        .contains("test transport unavailable"));

    tx_request = request(&text, &source, MultisigSelection::Automatic);
    tx_request.change_index_hint = u32::MAX;
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(create(&client, tx_request))
        .unwrap_err()
        .contains("test transport unavailable"));

    let sources_json = format!(
        "[{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":0}}]",
        source,
        "11".repeat(32),
    );
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(create_multi_address(
        &consolidation_request(&text, &sources_json, &source, 20_000_000, 1_000, 0, 0),
        &client,
    ))
    .unwrap_err()
    .contains("test transport unavailable"));
}

#[test]
fn static_multisig_change_policy_and_prefix_fallback_are_covered() {
    let static_text = format!("multi(1,{},{})", "11".repeat(32), "22".repeat(32));
    let descriptor = MultisigDescriptor::parse(&static_text).expect("static descriptor");
    let keys = descriptor.public_keys_at(0, 0, 0).expect("static keys");
    let redeem = build_redeem_script(1, &keys).expect("redeem");
    let source =
        crate::contract::script::p2sh::script_to_address(&redeem, "kaspa").expect("source");
    let client = fail_network_client();
    let mut request_value = request(&static_text, &source, MultisigSelection::Automatic);
    let source_path = crate::wallet::multisig::resolve_address_path(&descriptor, &source, 0)
        .expect("static path");
    request_value.change_index_hint = u32::MAX;
    assert_eq!(
        ready(transaction_change_index(
            &client,
            &descriptor,
            &source_path,
            &request_value
        )),
        Ok(0)
    );
    assert!(prepare_request(&request_value).is_ok());
    request_value.change_address =
        "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";
    let error = match prepare_request(&request_value) {
        Ok(_) => panic!("static multisig change mismatch must fail"),
        Err(error) => error,
    };
    assert!(error.contains("multisig change"));
    assert_eq!(address_prefix("without-prefix"), "kaspa");
    assert_eq!(address_prefix("kaspatest:value"), "kaspatest");
}

#[test]
fn new_hd45_branch_error_paths_cover_overflow_invalid_address_and_zero_depth() {
    let descriptor = descriptor();
    let source0 = source_address(&descriptor, 0, 0);
    let source1 = source_address(&descriptor, 0, 1);
    let first = MultisigConsolidationSource {
        address: source0.clone(),
        tx_id: "11".repeat(32),
        index: 0,
    };
    let second = MultisigConsolidationSource {
        address: source1.clone(),
        tx_id: "22".repeat(32),
        index: 1,
    };
    let sources = vec![first.clone(), second.clone()];
    let resolved = resolve_consolidation_sources(&descriptor, &sources, 0).expect("resolved");

    assert!(
        build_consolidation_inputs(&sources, &[], &ResolvedConsolidationSources::new()).is_err()
    );
    let overflow_available = vec![
        utxo(&source0, 0x11, 0, u64::MAX),
        utxo(&source1, 0x22, 1, 1),
    ];
    let overflow_error = build_consolidation_inputs(&sources, &overflow_available, &resolved)
        .expect_err("selected total overflow");
    assert!(overflow_error.contains("overflow"));

    assert!(branch_address_map(&[(0, 0, "not-an-address".to_string())]).is_err());
    assert!(first_unused_change_index(&[(1, 0, "not-an-address".to_string())], &[], 1).is_err());
    assert!(branch_addresses(&descriptor, 0, 0, "kaspa")
        .expect("zero depth")
        .is_empty());
    assert!(change_branch_addresses(&descriptor, 0, 0, "kaspa")
        .expect("zero change depth")
        .is_empty());

    let addresses = branch_addresses(&descriptor, 0, 1, "kaspa").expect("one branch");
    let by_script = branch_address_map(&addresses).expect("map");
    let receive = addresses
        .iter()
        .find(|(chain, _, _)| *chain == 0)
        .expect("receive");
    let overflow_utxos = vec![
        utxo(&receive.2, 0x31, 0, u64::MAX),
        utxo(&receive.2, 0x32, 1, 1),
    ];
    let overflow_error =
        summarize_branch_utxos(overflow_utxos, &by_script, 1).expect_err("branch balance overflow");
    assert!(overflow_error.contains("overflow"));

    // A known script with a summary depth of zero reaches the out-of-range
    // mark_branch_used path without affecting the balance/labelled result.
    let single = vec![utxo(&receive.2, 0x33, 2, 7)];
    let summary = summarize_branch_utxos(single, &by_script, 0).expect("depth-zero summary");
    assert_eq!(summary.balance, 7);
    assert!(summary.receive_used.is_empty());
}

#[test]
fn consolidation_finish_rejects_bad_destination_and_unresolved_material() {
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);
    let item = MultisigConsolidationSource {
        address: source.clone(),
        tx_id: "44".repeat(32),
        index: 0,
    };
    let sources_json = format!(
        "[{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":0}}]",
        source,
        "44".repeat(32),
    );
    let prepared = prepare_consolidation(&descriptor_text(), &sources_json, 0).expect("prepared");
    let available = vec![utxo(&source, 0x44, 0, 30_000_000)];
    assert!(ready(finish_consolidation(
        prepared,
        &available,
        &consolidation_request(
            &descriptor_text(),
            &sources_json,
            "not-an-address",
            20_000_000,
            1_000,
            0,
            2,
        ),
        &fail_network_client(),
    ))
    .is_err());

    let resolved = ResolvedConsolidationSources::new();
    assert!(build_consolidation_inputs(&[item], &available, &resolved).is_err());
}

#[test]
fn branch_and_consolidation_helpers_cover_short_circuit_and_change_marking_edges() {
    assert_eq!(first_free(&[]), 0);
    assert_eq!(first_free(&[true, true]), 2);
    assert_eq!(first_free(&[true, false, true]), 1);
    assert!(branch_query(&[]).is_empty());
    assert!(require_source_count(1).is_ok());
    assert!(require_source_count(3).is_ok());
    assert!(require_source_count(0).is_err());
    assert!(require_source_count(4).is_err());

    let descriptor = descriptor();
    let receive = branch_address(&descriptor, 0, 0, 0, "kaspa").expect("receive branch");
    let change = branch_address(&descriptor, 0, 1, 0, "kaspa").expect("change branch");
    let addresses = vec![receive.clone(), change.clone()];
    let by_script = branch_address_map(&addresses).expect("branch map");
    let summary = summarize_branch_utxos(vec![utxo(&change.2, 0x71, 4, 9)], &by_script, 1)
        .expect("change summary");
    assert_eq!(summary.balance, 9);
    assert_eq!(summary.change_used, vec![true]);
    assert_eq!(summary.receive_used, vec![false]);

    let source = MultisigConsolidationSource {
        address: receive.2.clone(),
        tx_id: "72".repeat(32),
        index: 7,
    };
    let resolved = resolve_consolidation_sources(&descriptor, core::slice::from_ref(&source), 0)
        .expect("resolved source");
    let available = vec![
        // Same output index but wrong txid: exercises the left side of && false.
        utxo(&receive.2, 0x73, 7, 1),
        // Correct txid but wrong output index: left side true, right side false.
        UtxoEntry {
            tx_id: source.tx_id.clone(),
            index: 8,
            amount: 2,
            script_public_key: crate::primitives::address::address_to_script_pubkey(&receive.2)
                .expect("receive script"),
            block_daa_score: 0,
            covenant_id: None,
        },
        UtxoEntry {
            tx_id: source.tx_id.clone(),
            index: source.index,
            amount: 3,
            script_public_key: crate::primitives::address::address_to_script_pubkey(&receive.2)
                .expect("receive script"),
            block_daa_score: 0,
            covenant_id: None,
        },
    ];
    let (_, total) =
        build_consolidation_inputs(core::slice::from_ref(&source), &available, &resolved)
            .expect("selected source after decoys");
    assert_eq!(total, 3);
}

#[test]
fn hd45_branch_scan_covers_descriptor_parse_depth_cap_and_derivation_failures() {
    let client = fail_network_client();
    assert!(ready(scan_branch_json("not-a-descriptor", 0, 1, &client, "kaspa")).is_err());

    let text = descriptor_text();
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Depth > 100 must take the cap branch before native transport rejects
        // the request. This exercises the safety cap without requiring a node.
        let error = ready(scan_branch_json(&text, 0, 101, &client, "kaspa")).unwrap_err();
        assert!(error.contains("test transport unavailable"));
    }

    let descriptor = descriptor();
    assert!(branch_address(&descriptor, 0, 2, 0, "kaspa").is_err());
    assert!(branch_address(&descriptor, u32::MAX, 0, 0, "kaspa").is_err());
}

#[test]
fn consolidation_covers_parse_source_and_change_derivation_failures() {
    let descriptor = descriptor();
    let source = source_address(&descriptor, 0, 0);
    let sources_json = format!(
        "[{{\"address\":\"{}\",\"tx_id\":\"{}\",\"index\":0}}]",
        source,
        "91".repeat(32),
    );
    assert!(prepare_consolidation("not-a-descriptor", &sources_json, 0).is_err());

    let bad_source_json = format!(
        "[{{\"address\":\"not-an-address\",\"tx_id\":\"{}\",\"index\":0}}]",
        "92".repeat(32),
    );
    assert!(prepare_consolidation(&descriptor_text(), &bad_source_json, 0).is_err());

    let mut outputs = Vec::new();
    let error = ready(append_consolidation_change(
        change_request(
            &descriptor,
            &source,
            "kaspa",
            u32::MAX,
            0,
            &fail_network_client(),
            20_000_000,
        ),
        &mut outputs,
    ))
    .unwrap_err();
    assert!(!error.is_empty());
    assert!(outputs.is_empty());
}
