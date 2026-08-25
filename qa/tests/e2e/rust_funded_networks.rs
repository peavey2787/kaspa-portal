#![deny(warnings)]

mod funded_support;

use std::time::Duration;

use kaspa_portal::{
    contract::script::p2sh::script_to_address,
    primitives::NetworkId,
    transaction::{
        builder::{CovenantBuildRequest, CovenantEncoding, MultisigConsolidationRequest},
        consensus::ConsensusTransaction,
        interchange::{
            kspt::{
                is_fully_signed, parse_compact_kspt, serialize_compact_kspt_vec,
                sign_transaction_account_multi_addr_with_entropy,
                sign_transaction_multisig_with_entropy,
            },
            pskt::{merge_signed_kspt_into_pskb, relay_pskb_as_kspt_hex_for_network},
        },
        model::{SigHashType, Transaction},
    },
    wallet::{
        key::xpub::{
            import_xprv_with_metadata, serialize_account_kpub, ImportedAccountXprv, KPUB_MAX_LEN,
        },
        multisig::{build_redeem_script, MultisigDescriptor},
    },
    KaspaPortal,
};

use funded_support::{
    covenant_endpoint, covenant_network, covenant_network_name, deterministic_multisig_kpub,
    standard_endpoint, standard_network, standard_network_name, FUNDED_XPRV_ENV,
    MIN_FUNDED_BALANCE_SOMPI, PRIORITY_FEE_SOMPI, SPEND_AMOUNT_SOMPI,
};

fn funded_wallet(
    portal: &KaspaPortal,
) -> (
    ImportedAccountXprv,
    kaspa_portal::wallet::account::derivation::WalletData,
) {
    let xprv = std::env::var(FUNDED_XPRV_ENV).unwrap_or_else(|_| {
        panic!(
            "{FUNDED_XPRV_ENV} is required for funded E2E; provide the dedicated test account XPRV with at least 10 KAS on the selected funded network"
        )
    });
    let imported = import_xprv_with_metadata(xprv.as_bytes()).expect("import funded account XPRV");
    let mut encoded = [0u8; KPUB_MAX_LEN];
    let len = serialize_account_kpub(&imported.key, imported.parent_fingerprint, &mut encoded)
        .expect("serialize funded account kpub");
    let kpub = std::str::from_utf8(&encoded[..len]).expect("funded kpub UTF-8");
    let wallet = portal.wallet().import_kpub(kpub).expect("import funded wallet");
    (imported, wallet)
}

fn relay_transaction(wire: &str, network_name: &str) -> Transaction {
    let relay_hex = relay_pskb_as_kspt_hex_for_network(wire, network_name)
        .expect("relay funded PSKB as compact KSPT");
    let relay = hex::decode(relay_hex).expect("decode relayed KSPT");
    let mut transaction = Transaction::new();
    parse_compact_kspt(&relay, &mut transaction).expect("parse relayed KSPT");
    transaction
}

fn merge_signed_transaction(wire: &str, transaction: &Transaction) -> String {
    assert!(
        is_fully_signed(transaction),
        "funded transaction is not fully signed"
    );
    let signed_wire = serialize_compact_kspt_vec(transaction).expect("serialize signed KSPT");
    merge_signed_kspt_into_pskb(&hex::encode(signed_wire), wire)
        .expect("merge signed KSPT into PSKB")
}

fn sign_and_merge(wire: &str, imported: &ImportedAccountXprv, network_name: &str) -> String {
    let mut transaction = relay_transaction(wire, network_name);
    let signed = sign_transaction_account_multi_addr_with_entropy(
        &mut transaction,
        &imported.key,
        SigHashType::All,
        &[0x7au8; 32],
    )
    .expect("sign funded wallet inputs");
    assert!(signed > 0, "funded transaction had no signable wallet inputs");
    merge_signed_transaction(wire, &transaction)
}

fn fee_with_headroom(recommended_fee_sompi: u64) -> u64 {
    recommended_fee_sompi
        .saturating_add(recommended_fee_sompi / 10)
        .saturating_add(10_000)
}

fn next_adaptive_fee(current_fee: u64, recommended_fee_sompi: u64) -> u64 {
    fee_with_headroom(recommended_fee_sompi).max(current_fee.saturating_add(10_000))
}

async fn plan_signed_send_with_adaptive_fee(
    portal: &KaspaPortal,
    wallet: &kaspa_portal::wallet::account::derivation::WalletData,
    imported: &ImportedAccountXprv,
    destination: &str,
    amount: u64,
    payload: Option<&[u8]>,
    network_name: &str,
) -> (String, kaspa_portal::transaction::mass::TransactionAnalysis, u64) {
    let tx = portal.transaction();
    let mut fee = PRIORITY_FEE_SOMPI;
    for _ in 0..6 {
        let wire = match payload {
            Some(payload) => tx
                .plan_send_with_payload(wallet, destination, amount, fee, payload)
                .await
                .expect("plan funded send with payload"),
            None => tx
                .plan_send(wallet, destination, amount, fee)
                .await
                .expect("plan funded send"),
        };
        let signed_wire = sign_and_merge(&wire, imported, network_name);
        let analysis = tx
            .analyze(&signed_wire)
            .await
            .expect("analyze signed funded transaction");
        assert!(analysis.mass_valid, "signed funded transaction exceeds mass limits");
        if analysis.fee_sufficient {
            return (signed_wire, analysis, fee);
        }
        fee = next_adaptive_fee(fee, analysis.recommended_fee_sompi);
    }
    panic!("could not converge on a sufficient live-network transaction fee after 6 attempts");
}

fn sign_multisig_and_merge(wire: &str, network_name: &str) -> String {
    let mut transaction = relay_transaction(wire, network_name);
    let signed = sign_transaction_multisig_with_entropy(
        &mut transaction,
        &[([0x71u8; 64], true)],
        SigHashType::All,
        None,
        &[0x7bu8; 32],
    )
    .expect("sign deterministic 1-of-2 multisig fixture");
    assert!(signed > 0, "multisig fixture had no signable inputs");
    merge_signed_transaction(wire, &transaction)
}

async fn plan_multisig_spend_with_adaptive_fee(
    portal: &KaspaPortal,
    descriptor: &str,
    sources_json: &str,
    destination: &str,
    source_amount: u64,
    network_name: &str,
) -> (ConsensusTransaction, u64) {
    let tx = portal.transaction();
    let mut fee = PRIORITY_FEE_SOMPI;
    for _ in 0..6 {
        let amount = source_amount
            .checked_sub(fee)
            .expect("multisig fixture amount exceeds adaptive fee");
        let wire = tx
            .plan_multisig_consolidation(MultisigConsolidationRequest {
                descriptor_text: descriptor,
                sources_json,
                destination_address: destination,
                amount,
                fee,
                cosigner: 0,
                change_index_hint: 0,
            })
            .await
            .expect("live plan_multisig_consolidation");
        let signed_wire = sign_multisig_and_merge(&wire, network_name);
        let analysis = tx
            .analyze(&signed_wire)
            .await
            .expect("analyze signed multisig transaction");
        assert!(analysis.mass_valid, "signed multisig transaction exceeds mass limits");
        if analysis.fee_sufficient {
            return (
                tx.finalize(&signed_wire)
                    .expect("finalize fee-sufficient multisig transaction"),
                fee,
            );
        }
        fee = next_adaptive_fee(fee, analysis.recommended_fee_sompi);
    }
    panic!("could not converge on a sufficient multisig fee after 6 attempts");
}

async fn wait_for_output(portal: &KaspaPortal, address: &str, txid: &str) {
    for _ in 0..90 {
        let entries = portal
            .chain()
            .expect("chain")
            .utxos(address)
            .await
            .expect("poll funded-network UTXOs");
        if entries.iter().any(|entry| entry.tx_id == txid) {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("broadcast transaction {txid} did not appear at {address} within 90 seconds");
}

async fn broadcast_consensus(
    portal: &KaspaPortal,
    transaction: &ConsensusTransaction,
    destination: &str,
) -> String {
    let txid = portal
        .transaction()
        .broadcast(transaction)
        .await
        .expect("broadcast funded transaction");
    assert_eq!(txid.len(), 64, "node returned unexpected transaction id");
    wait_for_output(portal, destination, &txid).await;
    txid
}

fn multisig_fixture(network: NetworkId) -> (String, String) {
    let first = deterministic_multisig_kpub(0x71);
    let second = deterministic_multisig_kpub(0x72);
    let descriptor_text = format!("multi_hd45(1,{first},{second})");
    let descriptor = MultisigDescriptor::parse(&descriptor_text).expect("multisig descriptor");
    let keys = descriptor
        .public_keys_at(0, 0, 0)
        .expect("multisig receive keys");
    let redeem = build_redeem_script(descriptor.threshold(), &keys).expect("multisig redeem script");
    let address = script_to_address(&redeem, network.address_prefix()).expect("multisig address");
    (descriptor_text, address)
}

async fn assert_funded_balance(
    portal: &KaspaPortal,
    wallet: &kaspa_portal::wallet::account::derivation::WalletData,
) {
    let initial_balance = portal
        .wallet()
        .balance(wallet)
        .await
        .expect("funded wallet balance");
    assert!(
        initial_balance.total_sompi >= MIN_FUNDED_BALANCE_SOMPI,
        "funded E2E wallet has {} sompi; at least {} sompi (10 KAS) is required",
        initial_balance.total_sompi,
        MIN_FUNDED_BALANCE_SOMPI
    );
}

#[tokio::test]
#[ignore = "Funded standard-network E2E: requires KASPA_PORTAL_E2E_XPRV with funds on the configured standard network"]
async fn rust_funded_standard_network_transactions() {
    let network = standard_network();
    let network_name = standard_network_name();
    let portal = KaspaPortal::builder()
        .network(network)
        .endpoint(standard_endpoint())
        .timeout_ms(15_000)
        .max_retries(3)
        .connect()
        .await
        .expect("connect funded E2E portal to public standard network");
    let (imported, wallet) = funded_wallet(&portal);
    assert_funded_balance(&portal, &wallet).await;

    let tx = portal.transaction();
    let address_prefix = network.address_prefix();
    let destination = wallet.receive_addresses[1].as_str();

    let payload = format!("kaspa-portal-e2e-{network_name}");
    let (signed_payload_wire, analysis, payload_fee) = plan_signed_send_with_adaptive_fee(
        &portal,
        &wallet,
        &imported,
        destination,
        SPEND_AMOUNT_SOMPI,
        Some(payload.as_bytes()),
        &network_name,
    )
    .await;
    assert!(analysis.fee_sufficient, "adaptive payload fee must be sufficient");
    eprintln!(
        "funded {network_name} payload fee: {payload_fee} sompi (recommended {} sompi)",
        analysis.recommended_fee_sompi
    );

    let ordinary = tx
        .plan_send(&wallet, destination, SPEND_AMOUNT_SOMPI, payload_fee)
        .await
        .expect("live plan_send");
    assert!(tx.review(&ordinary, address_prefix).is_ok());

    let utxos = portal.wallet().utxos(&wallet).await.expect("funded UTXOs");
    assert!(!utxos.is_empty(), "funded wallet returned no UTXOs");
    let selected = tx
        .plan_selected_send(
            &wallet,
            destination,
            20_000_000,
            payload_fee,
            &[0],
        )
        .await
        .expect("live plan_selected_send");
    assert!(tx.review(&selected, address_prefix).is_ok());

    let signed_payload = tx
        .finalize(&signed_payload_wire)
        .expect("finalize analyzed payload transaction");
    let payload_txid = broadcast_consensus(&portal, &signed_payload, destination).await;
    assert_eq!(payload_txid.len(), 64);

    let post_send_utxos = portal.wallet().utxos(&wallet).await.expect("post-send UTXOs");
    assert!(
        post_send_utxos.len() >= 2,
        "funded E2E requires at least two wallet UTXOs after the bootstrap self-payment"
    );
    let consolidation = tx
        .plan_consolidation(&wallet, payload_fee)
        .await
        .expect("live plan_consolidation");
    assert!(tx.review(&consolidation, address_prefix).is_ok());

    let (descriptor, multisig_address) = multisig_fixture(network);
    let (signed_multisig_funding, funding_analysis, funding_fee) =
        plan_signed_send_with_adaptive_fee(
            &portal,
            &wallet,
            &imported,
            &multisig_address,
            SPEND_AMOUNT_SOMPI,
            None,
            &network_name,
        )
        .await;
    eprintln!(
        "funded {network_name} multisig-funding fee: {funding_fee} sompi (recommended {} sompi)",
        funding_analysis.recommended_fee_sompi
    );
    let multisig_funding_tx = tx
        .finalize(&signed_multisig_funding)
        .expect("finalize fee-sufficient multisig funding transaction");
    let multisig_txid =
        broadcast_consensus(&portal, &multisig_funding_tx, &multisig_address).await;
    let multisig_utxos = portal
        .chain()
        .expect("chain")
        .utxos(&multisig_address)
        .await
        .expect("live multisig UTXOs");
    let source = multisig_utxos
        .iter()
        .find(|entry| entry.tx_id == multisig_txid)
        .expect("new multisig UTXO");
    let sources_json = serde_json::to_string(&vec![serde_json::json!({
        "address": multisig_address,
        "tx_id": source.tx_id,
        "index": source.index
    })])
    .expect("multisig source JSON");
    let (multisig_spend, multisig_fee) = plan_multisig_spend_with_adaptive_fee(
        &portal,
        &descriptor,
        &sources_json,
        &wallet.receive_addresses[2],
        source.amount,
        &network_name,
    )
    .await;
    eprintln!("funded {network_name} multisig-spend fee: {multisig_fee} sompi");
    let recovered_txid =
        broadcast_consensus(&portal, &multisig_spend, &wallet.receive_addresses[2]).await;
    assert_eq!(recovered_txid.len(), 64);
    portal.disconnect().expect("disconnect standard funded portal");
}

#[tokio::test]
#[ignore = "Funded covenant-network E2E: requires KASPA_PORTAL_E2E_XPRV with funds on the configured covenant network"]
async fn rust_funded_covenant_network_transactions() {
    let network = covenant_network();
    let portal = KaspaPortal::builder()
        .network(network)
        .endpoint(covenant_endpoint())
        .timeout_ms(15_000)
        .max_retries(3)
        .connect()
        .await
        .expect("connect funded E2E portal to public covenant network");
    let (_, wallet) = funded_wallet(&portal);
    assert_funded_balance(&portal, &wallet).await;

    let tx = portal.transaction();
    let address_prefix = network.address_prefix();
    let covenant_script = portal
        .contract()
        .covenant()
        .dms(&[0x11; 32], &[0x22; 32], 144);
    let covenant_address = portal
        .contract()
        .script()
        .p2sh_address(&covenant_script, address_prefix)
        .expect("covenant address");
    let change_address = wallet.change_addresses[0].as_str();
    let covenant_wire = tx
        .plan_covenant(CovenantBuildRequest {
            wallet: &wallet,
            covenant_address: &covenant_address,
            send_amount: 50_000_000,
            fee: PRIORITY_FEE_SOMPI,
            change_address,
            utxo_indices_csv: "",
            encoding: CovenantEncoding::Payload {
                payload_hex: "706f7274616c2d653265",
                tag_genesis: false,
            },
        })
        .await
        .expect("live plan_covenant");
    assert!(tx.review(&covenant_wire, address_prefix).is_ok());

    let (bound_wire, binding) = tx
        .plan_covenant_with_binding(CovenantBuildRequest {
            wallet: &wallet,
            covenant_address: &covenant_address,
            send_amount: 50_000_000,
            fee: PRIORITY_FEE_SOMPI,
            change_address,
            utxo_indices_csv: "",
            encoding: CovenantEncoding::Payload {
                payload_hex: "706f7274616c2d626f756e64",
                tag_genesis: true,
            },
        })
        .await
        .expect("live plan_covenant_with_binding");
    assert!(binding.is_some(), "tagged genesis must return a covenant binding");
    assert!(tx.review(&bound_wire, address_prefix).is_ok());
    assert_eq!(covenant_network_name(), network.canonical_name());
    portal.disconnect().expect("disconnect covenant funded portal");
}
