use kaspa_portal::{
    primitives::NetworkId,
    chain::utxo::UtxoEntry,
    primitives::address::address_to_script_pubkey,
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
        account::derivation::WalletData,
        key::xpub::{
            derive_account_raw_kpub_payload, derive_and_serialize_kpub,
            derive_and_serialize_xprv, import_xprv_with_metadata, ImportedAccountXprv,
            KPUB_MAX_LEN, XPRV_MAX_LEN, XPUB_PAYLOAD_LEN,
        },
    },
    KaspaPortal,
};
use serde_json::Value;

pub const DEFAULT_STANDARD_NETWORK: &str = "testnet-10";
pub const DEFAULT_COVENANT_NETWORK: &str = "testnet-12";

pub fn standard_network_name() -> String {
    std::env::var("KASPA_PORTAL_E2E_STANDARD_NETWORK")
        .unwrap_or_else(|_| DEFAULT_STANDARD_NETWORK.to_owned())
}

pub fn covenant_network_name() -> String {
    std::env::var("KASPA_PORTAL_E2E_COVENANT_NETWORK")
        .unwrap_or_else(|_| DEFAULT_COVENANT_NETWORK.to_owned())
}

pub fn standard_network() -> NetworkId {
    NetworkId::parse(&standard_network_name()).expect("valid standard E2E network")
}

pub fn covenant_network() -> NetworkId {
    NetworkId::parse(&covenant_network_name()).expect("valid covenant E2E network")
}

pub const RELAY_KSPT_HEX: &str = "4b53505401000000010000000100000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111010000006400000000000000000000000000000001000022204444444444444444444444444444444444444444444444444444444444444444ac0000005a00000000000000000022205555555555555555555555555555555555555555555555555555555555555555ac4e01";

pub fn deterministic_account_xprv(seed_byte: u8) -> ImportedAccountXprv {
    let seed = [seed_byte; 64];
    let mut encoded = [0u8; XPRV_MAX_LEN];
    let len = derive_and_serialize_xprv(&seed, &mut encoded).expect("derive deterministic xprv");
    import_xprv_with_metadata(&encoded[..len]).expect("import deterministic account xprv")
}

pub fn sign_pskb_for_account(
    wire: &str,
    imported: &ImportedAccountXprv,
    entropy_byte: u8,
) -> String {
    let relay_hex = relay_pskb_as_kspt_hex_for_network(wire, &standard_network_name())
        .expect("relay offline PSKB as compact KSPT");
    let relay = hex::decode(relay_hex).expect("decode offline relayed KSPT");
    let mut transaction = Transaction::new();
    parse_compact_kspt(&relay, &mut transaction).expect("parse offline relayed KSPT");
    let signed = sign_transaction_account_multi_addr_with_entropy(
        &mut transaction,
        &imported.key,
        SigHashType::All,
        &[entropy_byte; 32],
    )
    .expect("sign deterministic offline wallet inputs");
    assert!(signed > 0, "offline transaction had no signable wallet inputs");
    assert!(
        is_fully_signed(&transaction),
        "offline transaction is not fully signed"
    );
    let signed_wire =
        serialize_compact_kspt_vec(&transaction).expect("serialize signed offline KSPT");
    merge_signed_kspt_into_pskb(&hex::encode(signed_wire), wire)
        .expect("merge signed offline KSPT into PSKB")
}

pub fn deterministic_wallet(portal: &KaspaPortal, seed_byte: u8) -> WalletData {
    let seed = [seed_byte; 64];
    let mut encoded = [0u8; KPUB_MAX_LEN];
    let len = derive_and_serialize_kpub(&seed, &mut encoded).expect("derive deterministic kpub");
    let text = std::str::from_utf8(&encoded[..len]).expect("kpub text");
    portal.wallet().import_kpub(text).expect("import kpub")
}

pub fn deterministic_kpub(seed_byte: u8) -> String {
    let seed = [seed_byte; 64];
    let mut encoded = [0u8; KPUB_MAX_LEN];
    let len = derive_and_serialize_kpub(&seed, &mut encoded).expect("derive deterministic kpub");
    std::str::from_utf8(&encoded[..len])
        .expect("kpub text")
        .to_owned()
}

pub fn deterministic_raw_kpub(seed_byte: u8) -> [u8; XPUB_PAYLOAD_LEN] {
    let seed = [seed_byte; 64];
    let mut raw = [0u8; XPUB_PAYLOAD_LEN];
    derive_account_raw_kpub_payload(&seed, &mut raw).expect("derive raw kpub");
    raw
}

pub fn dummy_utxo(wallet: &WalletData, tx_byte: u8, index: u32, amount: u64) -> UtxoEntry {
    let source = wallet
        .receive_addresses
        .first()
        .expect("wallet receive address");
    UtxoEntry {
        tx_id: format!("{tx_byte:02x}").repeat(32),
        index,
        amount,
        script_public_key: address_to_script_pubkey(source).expect("source script"),
        block_daa_score: 1,
        covenant_id: None,
    }
}

pub fn raw_scanner_fixture(transaction_id: &[u8; 32], preimage: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(preimage.len() + 1);
    script.push(u8::try_from(preimage.len()).expect("small preimage"));
    script.extend_from_slice(preimage);
    let script_length = script.len().max(10);
    let mut raw = Vec::new();
    raw.extend_from_slice(&37u32.to_le_bytes());
    raw.push(1);
    raw.extend_from_slice(transaction_id);
    raw.extend_from_slice(&7u32.to_le_bytes());
    raw.extend_from_slice(&(script_length as u32).to_le_bytes());
    raw.extend_from_slice(&script);
    raw.resize(raw.len() + script_length.saturating_sub(script.len()), 0);
    raw
}

pub fn decode_pskb_wire(wire: &str) -> Value {
    let envelope = hex::decode(wire).expect("outer PSKB hex");
    assert_eq!(&envelope[..4], b"PSKB");
    let json_hex = std::str::from_utf8(&envelope[4..]).expect("PSKB JSON hex text");
    let json_bytes = hex::decode(json_hex).expect("PSKB JSON bytes");
    serde_json::from_slice(&json_bytes).expect("PSKB JSON")
}
