use kaspa_portal::KaspaPortal;

use crate::support::{deterministic_multisig_kpub, live_endpoint, live_network};

#[tokio::test]
#[ignore = "Pass 2 live E2E: requires the configured public standard network"]
async fn rust_live_standard_transaction_reads() {
    let network = live_network();
    let portal = KaspaPortal::builder()
        .network(network)
        .endpoint(live_endpoint())
        .connect()
        .await
        .expect("connect public selected network");
    let first = deterministic_multisig_kpub(0x61);
    let second = deterministic_multisig_kpub(0x62);
    let descriptor = format!("multi_hd45(2,{first},{second})");
    let scanned = portal
        .transaction()
        .scan_multisig_branch(&descriptor, 0, 2, network.address_prefix())
        .await
        .expect("live multisig branch scan");
    let value: serde_json::Value = serde_json::from_str(&scanned).expect("multisig scan JSON");
    let object = value.as_object().expect("multisig scan object");
    assert_eq!(
        object
            .get("cosigner_index")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
    assert_eq!(
        object.get("depth").and_then(serde_json::Value::as_u64),
        Some(2)
    );

    let utxos = object
        .get("utxos")
        .and_then(serde_json::Value::as_array)
        .expect("multisig scan UTXO array");
    let utxo_count = object
        .get("utxo_count")
        .and_then(serde_json::Value::as_u64)
        .expect("multisig scan UTXO count");
    assert_eq!(utxo_count as usize, utxos.len());
    let balance = object
        .get("balance_sompi")
        .and_then(serde_json::Value::as_str)
        .expect("decimal multisig balance")
        .parse::<u64>()
        .expect("valid multisig balance");

    for field in ["next_receive_index", "next_change_index"] {
        let next = object
            .get(field)
            .and_then(serde_json::Value::as_u64)
            .expect("next branch index");
        assert!(next <= 2);
    }
    let mut summed_balance = 0u64;
    for utxo in utxos {
        let item = utxo.as_object().expect("labelled multisig UTXO");
        assert!(item
            .get("address")
            .and_then(serde_json::Value::as_str)
            .expect("multisig UTXO address")
            .starts_with(&format!("{}:", network.address_prefix())));
        assert!(item
            .get("chain")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|chain| chain <= 1));
        assert!(item
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|index| index < 2));
        let amount = item
            .get("amount")
            .and_then(serde_json::Value::as_str)
            .expect("decimal multisig UTXO amount")
            .parse::<u64>()
            .expect("valid multisig UTXO amount");
        summed_balance = summed_balance
            .checked_add(amount)
            .expect("multisig UTXO balance sum");
    }
    assert_eq!(summed_balance, balance);
}
