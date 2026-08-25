use super::*;
use serde_json::json;

fn input_object() -> Map<String, Value> {
    json!({
        "utxoEntry": {
            "amount": "123",
            "scriptPublicKey": format!("0000{}", "51".repeat(34))
        },
        "previousOutpoint": {
            "transactionId": "ab".repeat(32),
            "index": 7
        }
    })
    .as_object()
    .expect("input object")
    .clone()
}

#[test]
fn input_field_helpers_cover_defaults_exact_values_and_fail_closed_shapes() {
    let object = input_object();
    let fields = InputFields::parse(&object).expect("defaulted input fields");
    assert_eq!(fields.amount, 123);
    assert_eq!(fields.previous_tx_id, [0xab; 32]);
    assert_eq!(fields.previous_index, 7);
    assert_eq!(fields.sequence, 0);
    assert_eq!(fields.sig_op_count, 1);
    assert_eq!(fields.script_version, 0);
    assert_eq!(fields.script_public_key, vec![0x51; 34]);
    assert_eq!(fields.redeem_script, None);
    assert!(fields.partial_signatures.is_empty());

    let mut exact = object.clone();
    exact.insert("sequence".into(), json!("9"));
    exact.insert("sigOpCount".into(), json!(3));
    exact.insert("redeemScript".into(), json!("5152"));
    let fields = InputFields::parse(&exact).expect("explicit input fields");
    assert_eq!(fields.sequence, 9);
    assert_eq!(fields.sig_op_count, 3);
    assert_eq!(fields.redeem_script, Some(vec![0x51, 0x52]));

    let mut missing = object.clone();
    missing.remove("utxoEntry");
    assert_eq!(
        parse_utxo_fields(&missing).unwrap_err(),
        "missing utxoEntry"
    );
    let mut missing_amount = object.clone();
    missing_amount
        .get_mut("utxoEntry")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("amount");
    assert_eq!(
        parse_utxo_fields(&missing_amount).unwrap_err(),
        "missing amount"
    );
    let mut missing_spk = object.clone();
    missing_spk
        .get_mut("utxoEntry")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("scriptPublicKey");
    assert_eq!(
        parse_utxo_fields(&missing_spk).unwrap_err(),
        "missing scriptPublicKey"
    );
    let mut long_spk = object.clone();
    long_spk
        .get_mut("utxoEntry")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "scriptPublicKey".into(),
            json!(format!("0000{}", "51".repeat(513))),
        );
    assert!(parse_utxo_fields(&long_spk)
        .unwrap_err()
        .contains("513 > 512"));

    let mut missing_outpoint = object.clone();
    missing_outpoint.remove("previousOutpoint");
    assert_eq!(
        parse_outpoint_fields(&missing_outpoint).unwrap_err(),
        "missing previousOutpoint"
    );
    let mut missing_txid = object.clone();
    missing_txid
        .get_mut("previousOutpoint")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("transactionId");
    assert_eq!(
        parse_outpoint_fields(&missing_txid).unwrap_err(),
        "missing transactionId"
    );
    let mut bad_hex = object.clone();
    bad_hex
        .get_mut("previousOutpoint")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("transactionId".into(), json!("zz"));
    assert!(parse_outpoint_fields(&bad_hex)
        .unwrap_err()
        .starts_with("bad tx_id hex:"));
    let mut short_txid = object.clone();
    short_txid
        .get_mut("previousOutpoint")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("transactionId".into(), json!("ab".repeat(31)));
    assert_eq!(
        parse_outpoint_fields(&short_txid).unwrap_err(),
        "tx_id not 32 bytes"
    );
    let mut missing_index = object.clone();
    missing_index
        .get_mut("previousOutpoint")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("index");
    assert_eq!(
        parse_outpoint_fields(&missing_index).unwrap_err(),
        "missing index"
    );
    let mut large_index = object.clone();
    large_index
        .get_mut("previousOutpoint")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("index".into(), json!(u64::from(u32::MAX) + 1));
    assert_eq!(
        parse_outpoint_fields(&large_index).unwrap_err(),
        "index exceeds u32"
    );
}

#[test]
fn optional_redeem_signature_and_spk_length_helpers_cover_boundaries() {
    let mut object = Map::new();
    assert_eq!(parse_optional_exact(&object, "sequence", 17), Ok(17));
    object.insert("sequence".into(), json!("18"));
    assert_eq!(parse_optional_exact(&object, "sequence", 17), Ok(18));

    object.insert("redeemScript".into(), Value::Null);
    assert_eq!(parse_redeem_script(&object), Ok(None));
    object.insert("redeemScript".into(), json!("5152"));
    assert_eq!(parse_redeem_script(&object), Ok(Some(vec![0x51, 0x52])));
    object.insert("redeemScript".into(), json!("zz"));
    assert!(parse_redeem_script(&object)
        .unwrap_err()
        .starts_with("redeem hex:"));
    object.insert("redeemScript".into(), json!(true));
    assert_eq!(parse_redeem_script(&object), Ok(None));

    let valid = json!({"schnorr": "11".repeat(64)});
    assert_eq!(decode_signature(&valid, "missing").unwrap(), [0x11; 64]);
    assert_eq!(
        decode_signature(&json!({}), "missing").unwrap_err(),
        "missing"
    );
    assert_eq!(
        decode_signature(&json!({"schnorr": "11"}), "missing").unwrap_err(),
        "bad sig length: 2",
    );
    assert!(
        decode_signature(&json!({"schnorr": "zz".repeat(64)}), "missing")
            .unwrap_err()
            .starts_with("sig hex:")
    );

    let mut encoded = Vec::new();
    push_spk_len(&mut encoded, 254);
    assert_eq!(encoded, vec![254]);
    encoded.clear();
    push_spk_len(&mut encoded, 255);
    assert_eq!(encoded, vec![0xff, 0xff, 0x00]);
}

#[test]
fn multisig_collection_sorts_positions_and_rejects_unbound_keys() {
    let first_x = "31".repeat(32);
    let second_x = "32".repeat(32);
    let mut redeem = vec![0x52, 0x20];
    redeem.extend_from_slice(&hex::decode(&first_x).unwrap());
    redeem.push(0x20);
    redeem.extend_from_slice(&hex::decode(&second_x).unwrap());
    redeem.extend_from_slice(&[0x52, 0xae]);

    let mut signatures = Map::new();
    signatures.insert(format!("02{second_x}"), json!({"schnorr": "22".repeat(64)}));
    signatures.insert(format!("02{first_x}"), json!({"schnorr": "11".repeat(64)}));
    signatures.insert("short".into(), json!({"schnorr": "33".repeat(64)}));
    let collected = collect_multisig_signatures(&redeem, &signatures).expect("multisig signatures");
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0].pubkey_position, 0);
    assert_eq!(collected[0].bytes, [0x11; 64]);
    assert_eq!(collected[1].pubkey_position, 1);
    assert_eq!(collected[1].bytes, [0x22; 64]);

    signatures.insert(
        format!("02{}", "44".repeat(32)),
        json!({"schnorr": "44".repeat(64)}),
    );
    let error = match collect_multisig_signatures(&redeem, &signatures) {
        Ok(_) => panic!("unbound multisig key must be rejected"),
        Err(error) => error,
    };
    assert!(error.starts_with("pubkey not in redeem:"));
}
