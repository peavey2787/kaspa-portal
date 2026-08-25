use std::{env, fs, path::PathBuf, time::Duration};

use kaspa_portal::{
    contract::script::p2sh::script_to_address,
    primitives::NetworkId,
    transaction::{
        interchange::{
            kspt::{
                is_fully_signed, parse_compact_kspt, serialize_compact_kspt_vec,
                sign_transaction_account_multi_addr_with_entropy,
            },
            pskt::{merge_signed_kspt_into_pskb, relay_pskb_as_kspt_hex_for_network},
        },
        model::{SigHashType, Transaction},
    },
    wallet::{
        key::xpub::{
            derive_and_serialize_multisig_kpub, import_xprv_with_metadata, serialize_account_kpub,
            ImportedAccountXprv, KPUB_MAX_LEN,
        },
        multisig::{build_redeem_script, MultisigDescriptor},
    },
    KaspaPortal,
};
use serde_json::{json, Value};

const FUNDED_XPRV_ENV: &str = "KASPA_PORTAL_E2E_XPRV";
const MIN_FUNDED_BALANCE_SOMPI: u64 = 1_000_000_000;
const PRIORITY_FEE_SOMPI: u64 = 300_000;

fn role_network(role: &str, default: &str) -> (String, NetworkId) {
    let name = env::var(format!("KASPA_PORTAL_E2E_{}_NETWORK", role.to_ascii_uppercase()))
        .unwrap_or_else(|_| default.to_owned());
    let network = NetworkId::parse(&name).expect("valid configured E2E network");
    (name, network)
}

fn role_endpoint(role: &str, default: &str) -> String {
    env::var(format!("KASPA_PORTAL_E2E_{}_ENDPOINT", role.to_ascii_uppercase()))
        .unwrap_or_else(|_| default.to_owned())
}

fn role_skipped(role: &str) -> bool {
    env::var(format!("KASPA_PORTAL_E2E_SKIP_{}_FUNDED", role.to_ascii_uppercase()))
        .is_ok_and(|value| value == "1")
}

fn funded_wallet(
    portal: &KaspaPortal,
) -> (
    ImportedAccountXprv,
    kaspa_portal::wallet::account::derivation::WalletData,
) {
    let xprv = env::var(FUNDED_XPRV_ENV).unwrap_or_else(|_| {
        panic!("{FUNDED_XPRV_ENV} is required for funded browser E2E")
    });
    let imported = import_xprv_with_metadata(xprv.as_bytes()).expect("import funded account XPRV");
    let mut encoded = [0u8; KPUB_MAX_LEN];
    let len = serialize_account_kpub(&imported.key, imported.parent_fingerprint, &mut encoded)
        .expect("serialize funded account kpub");
    let kpub = std::str::from_utf8(&encoded[..len]).expect("funded kpub UTF-8");
    let wallet = portal.wallet().import_kpub(kpub).expect("import funded wallet");
    (imported, wallet)
}

fn sign_pskb(
    wire: &str,
    imported: &ImportedAccountXprv,
    entropy: u8,
    network_name: &str,
) -> String {
    let relay_hex = relay_pskb_as_kspt_hex_for_network(wire, network_name)
        .expect("relay PSKB as compact KSPT");
    let relay = hex::decode(relay_hex).expect("decode relayed KSPT");
    let mut transaction = Transaction::new();
    parse_compact_kspt(&relay, &mut transaction).expect("parse relayed KSPT");
    let signed = sign_transaction_account_multi_addr_with_entropy(
        &mut transaction,
        &imported.key,
        SigHashType::All,
        &[entropy; 32],
    )
    .expect("sign funded wallet inputs");
    assert!(signed > 0, "funded transaction had no signable wallet inputs");
    assert!(
        is_fully_signed(&transaction),
        "funded transaction is not fully signed"
    );
    let signed_wire = serialize_compact_kspt_vec(&transaction).expect("serialize signed KSPT");
    merge_signed_kspt_into_pskb(&hex::encode(signed_wire), wire)
        .expect("merge signed KSPT into PSKB")
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
    entropy: u8,
    network_name: &str,
) -> (String, u64) {
    let tx = portal.transaction();
    let mut fee = PRIORITY_FEE_SOMPI;
    for _ in 0..6 {
        let wire = match payload {
            Some(payload) => tx
                .plan_send_with_payload(wallet, destination, amount, fee, payload)
                .await
                .expect("plan funded browser send with payload"),
            None => tx
                .plan_send(wallet, destination, amount, fee)
                .await
                .expect("plan funded browser send"),
        };
        let signed_wire = sign_pskb(&wire, imported, entropy, network_name);
        let analysis = tx
            .analyze(&signed_wire)
            .await
            .expect("analyze signed funded browser transaction");
        assert!(analysis.mass_valid, "signed funded browser transaction exceeds mass limits");
        if analysis.fee_sufficient {
            return (signed_wire, fee);
        }
        fee = next_adaptive_fee(fee, analysis.recommended_fee_sompi);
    }
    panic!("could not converge on a sufficient funded-browser fee after 6 attempts");
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

async fn broadcast_bootstrap(
    portal: &KaspaPortal,
    signed_wire: &str,
    destination: &str,
) -> String {
    let transaction = portal
        .transaction()
        .finalize(signed_wire)
        .expect("finalize bootstrap");
    let txid = portal
        .transaction()
        .broadcast(&transaction)
        .await
        .expect("broadcast bootstrap");
    wait_for_output(portal, destination, &txid).await;
    txid
}

fn deterministic_multisig_kpub(seed_byte: u8) -> String {
    let seed = [seed_byte; 64];
    let mut encoded = [0u8; KPUB_MAX_LEN];
    let len = derive_and_serialize_multisig_kpub(&seed, &mut encoded)
        .expect("derive deterministic multisig kpub");
    std::str::from_utf8(&encoded[..len])
        .expect("multisig kpub text")
        .to_owned()
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

async fn require_balance(
    portal: &KaspaPortal,
    wallet: &kaspa_portal::wallet::account::derivation::WalletData,
) {
    let balance = portal.wallet().balance(wallet).await.expect("funded balance");
    assert!(
        balance.total_sompi >= MIN_FUNDED_BALANCE_SOMPI,
        "funded browser E2E wallet has {} sompi; at least {} is required",
        balance.total_sompi,
        MIN_FUNDED_BALANCE_SOMPI
    );
}

async fn build_standard_fixture() -> Value {
    let (network_name, network) = role_network("standard", "testnet-10");
    let endpoint = role_endpoint(
        "standard",
        "wss://photon-10.kaspa.red/kaspa/testnet-10/wrpc/borsh",
    );
    let portal = KaspaPortal::builder()
        .network(network)
        .endpoint(endpoint.clone())
        .timeout_ms(15_000)
        .max_retries(3)
        .connect()
        .await
        .expect("connect funded browser fixture to standard network");
    let (imported, wallet) = funded_wallet(&portal);
    require_balance(&portal, &wallet).await;

    let (descriptor, multisig_address) = multisig_fixture(network);
    let existing_multisig = portal
        .chain()
        .expect("chain")
        .utxos(&multisig_address)
        .await
        .expect("query multisig fixture");
    let source = if let Some(source) = existing_multisig.first().cloned() {
        source
    } else {
        let (signed_fund_wire, fund_fee) = plan_signed_send_with_adaptive_fee(
            &portal,
            &wallet,
            &imported,
            &multisig_address,
            100_000_000,
            None,
            0x81,
            &network_name,
        )
        .await;
        eprintln!("browser funded {network_name} multisig-funding fee: {fund_fee} sompi");
        let txid = broadcast_bootstrap(&portal, &signed_fund_wire, &multisig_address).await;
        portal
            .chain()
            .expect("chain")
            .utxos(&multisig_address)
            .await
            .expect("reload multisig fixture")
            .into_iter()
            .find(|entry| entry.tx_id == txid)
            .expect("new multisig fixture output")
    };

    let fresh_wallet = portal
        .wallet()
        .import_kpub(&wallet.kpub)
        .expect("refresh funded wallet");
    let destination = fresh_wallet.receive_addresses[1].clone();
    let payload = format!("kaspa-portal-wasm-e2e-{network_name}");
    let (signed_broadcast, adaptive_fee) = plan_signed_send_with_adaptive_fee(
        &portal,
        &fresh_wallet,
        &imported,
        &destination,
        100_000_000,
        Some(payload.as_bytes()),
        0x82,
        &network_name,
    )
    .await;
    eprintln!("browser funded {network_name} broadcast fee: {adaptive_fee} sompi");
    let multisig_amount = source
        .amount
        .checked_sub(adaptive_fee)
        .expect("multisig source covers adaptive fee");
    let sources_json = serde_json::to_string(&vec![json!({
        "address": multisig_address,
        "tx_id": source.tx_id,
        "index": source.index
    })])
    .expect("multisig source JSON");

    let result = json!({
        "network": network_name,
        "endpoint": endpoint,
        "addressPrefix": network.address_prefix(),
        "wallet": fresh_wallet,
        "destination": destination,
        "signedBroadcastWire": signed_broadcast,
        "multisig": {
            "descriptor": descriptor,
            "sourcesJson": sources_json,
            "amountSompi": multisig_amount.to_string()
        },
        "feeSompi": adaptive_fee.to_string()
    });
    portal
        .disconnect()
        .expect("disconnect standard funded fixture portal");
    result
}

async fn build_covenant_fixture() -> Value {
    let (network_name, network) = role_network("covenant", "testnet-12");
    let endpoint = role_endpoint("covenant", "ws://tn12-node.kaspa.com:17210");
    let portal = KaspaPortal::builder()
        .network(network)
        .endpoint(endpoint.clone())
        .timeout_ms(15_000)
        .max_retries(3)
        .connect()
        .await
        .expect("connect funded browser fixture to covenant network");
    let (_, wallet) = funded_wallet(&portal);
    require_balance(&portal, &wallet).await;

    let covenant_script = portal
        .contract()
        .covenant()
        .dms(&[0x11; 32], &[0x22; 32], 144);
    let covenant_address = portal
        .contract()
        .script()
        .p2sh_address(&covenant_script, network.address_prefix())
        .expect("covenant address");
    let change_address = wallet.change_addresses[0].clone();
    let result = json!({
        "network": network_name,
        "endpoint": endpoint,
        "addressPrefix": network.address_prefix(),
        "wallet": wallet,
        "address": covenant_address,
        "changeAddress": change_address,
        "feeSompi": PRIORITY_FEE_SOMPI.to_string()
    });
    portal
        .disconnect()
        .expect("disconnect covenant funded fixture portal");
    result
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: browser-funded-fixture <output.json>");
    let standard = if role_skipped("standard") {
        Value::Null
    } else {
        build_standard_fixture().await
    };
    let covenant = if role_skipped("covenant") {
        Value::Null
    } else {
        build_covenant_fixture().await
    };
    let fixture = json!({
        "schema": 2,
        "standard": standard,
        "covenant": covenant
    });
    fs::write(
        &output,
        serde_json::to_vec_pretty(&fixture).expect("fixture JSON"),
    )
    .expect("write funded fixture");
}
