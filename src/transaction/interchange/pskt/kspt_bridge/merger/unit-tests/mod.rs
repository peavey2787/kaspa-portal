use super::*;
use serde_json::json;

fn record(byte: u8) -> KsptSigRecord {
    KsptSigRecord {
        pubkey_pos: 0,
        sighash_type: 0x01,
        sig: [byte; 64],
    }
}

fn p2pk_input() -> Map<String, Value> {
    json!({
        "utxoEntry": {
            "scriptPublicKey": format!("000020{}ac", "44".repeat(32))
        },
        "partialSigs": {}
    })
    .as_object()
    .expect("P2PK input")
    .clone()
}

#[test]
fn p2pk_merge_helper_covers_success_duplicate_and_every_shape_error() {
    let sig = record(0x22);
    let mut input = p2pk_input();
    merge_p2pk_signature(&mut input, &sig, 3).expect("merge P2PK signature");
    let signatures = input.get("partialSigs").and_then(Value::as_object).unwrap();
    assert_eq!(signatures.len(), 1);
    let expected_signature = "22".repeat(64);
    assert_eq!(
        signatures
            .get(&format!("02{}", "44".repeat(32)))
            .and_then(|value| value.get("schnorr"))
            .and_then(Value::as_str),
        Some(expected_signature.as_str()),
    );
    merge_p2pk_signature(&mut input, &record(0x33), 3).expect("duplicate key ignored");
    assert_eq!(
        input
            .get("partialSigs")
            .and_then(Value::as_object)
            .unwrap()
            .len(),
        1
    );

    let mut missing_utxo = Map::new();
    assert_eq!(
        merge_p2pk_signature(&mut missing_utxo, &sig, 1).unwrap_err(),
        "input[1] missing utxoEntry"
    );
    let mut missing_spk = json!({"utxoEntry": {}}).as_object().unwrap().clone();
    assert_eq!(
        merge_p2pk_signature(&mut missing_spk, &sig, 2).unwrap_err(),
        "input[2] missing scriptPublicKey"
    );
    let mut short = json!({"utxoEntry": {"scriptPublicKey": "000051"}})
        .as_object()
        .unwrap()
        .clone();
    assert_eq!(
        merge_p2pk_signature(&mut short, &sig, 4).unwrap_err(),
        "input[4] scriptPublicKey too short for P2PK"
    );
    let mut bad_hex = json!({"utxoEntry": {"scriptPublicKey": format!("0000{}", "zz".repeat(34))}})
        .as_object()
        .unwrap()
        .clone();
    assert!(merge_p2pk_signature(&mut bad_hex, &sig, 5)
        .unwrap_err()
        .starts_with("input[5] spk hex:"));
    let mut wrong_shape =
        json!({"utxoEntry": {"scriptPublicKey": format!("000021{}ac", "44".repeat(33))}})
            .as_object()
            .unwrap()
            .clone();
    assert_eq!(
        merge_p2pk_signature(&mut wrong_shape, &sig, 6).unwrap_err(),
        "input[6] spk is not P2PK"
    );

    let mut wrong_length_only =
        json!({"utxoEntry": {"scriptPublicKey": format!("000020{}ac", "44".repeat(33))}})
            .as_object()
            .unwrap()
            .clone();
    assert_eq!(
        merge_p2pk_signature(&mut wrong_length_only, &sig, 7).unwrap_err(),
        "input[7] spk is not P2PK"
    );

    let mut wrong_prefix_only =
        json!({"utxoEntry": {"scriptPublicKey": format!("000021{}ac", "44".repeat(32))}})
            .as_object()
            .unwrap()
            .clone();
    assert_eq!(
        merge_p2pk_signature(&mut wrong_prefix_only, &sig, 8).unwrap_err(),
        "input[8] spk is not P2PK"
    );

    let mut wrong_suffix_only =
        json!({"utxoEntry": {"scriptPublicKey": format!("000020{}ad", "44".repeat(32))}})
            .as_object()
            .unwrap()
            .clone();
    assert_eq!(
        merge_p2pk_signature(&mut wrong_suffix_only, &sig, 9).unwrap_err(),
        "input[9] spk is not P2PK"
    );
}

#[test]
fn signature_map_and_sighash_helpers_fail_closed_without_panics() {
    assert_eq!(validate_signature_sighashes(&[record(1)], 0), Ok(()));
    let mut wrong = record(2);
    wrong.sighash_type = 0x02;
    assert_eq!(
        validate_signature_sighashes(&[wrong], 7).unwrap_err(),
        "input[7] signed KSPT changed sighash type to 0x02",
    );

    let mut input = Map::new();
    input.insert("partialSigs".into(), json!(null));
    let signatures = partial_signatures_mut(&mut input).expect("normalize partialSigs");
    assert!(signatures.is_empty());
    insert_signature(signatures, "02aa".into(), &[0x11; 64]);
    let first_signature = "11".repeat(64);
    assert_eq!(
        signatures
            .get("02aa")
            .and_then(|value| value.get("schnorr"))
            .and_then(Value::as_str),
        Some(first_signature.as_str()),
    );
    insert_signature(signatures, "02aa".into(), &[0x22; 64]);
    assert_eq!(signatures.len(), 1);
    let first_signature = "11".repeat(64);
    assert_eq!(
        signatures
            .get("02aa")
            .and_then(|value| value.get("schnorr"))
            .and_then(Value::as_str),
        Some(first_signature.as_str()),
    );
}

#[test]
fn redeem_merge_helpers_cover_success_duplicate_empty_decode_and_position_paths() {
    let mut redeem = vec![0x20];
    redeem.extend_from_slice(&[0x44; 32]);
    redeem.push(0xac);
    let redeem_hex = hex::encode(&redeem);

    let mut input = Map::new();
    merge_redeem_signatures(&mut input, &[record(0x22)], 3, &redeem_hex)
        .expect("merge redeem signature");
    let signatures = input.get("partialSigs").and_then(Value::as_object).unwrap();
    assert_eq!(signatures.len(), 1);
    let expected_signature = "22".repeat(64);
    assert_eq!(
        signatures
            .get(&format!("02{}", "44".repeat(32)))
            .and_then(|value| value.get("schnorr"))
            .and_then(Value::as_str),
        Some(expected_signature.as_str()),
    );

    merge_redeem_signatures(&mut input, &[record(0x33)], 3, &redeem_hex)
        .expect("duplicate redeem key ignored");
    assert_eq!(
        input
            .get("partialSigs")
            .and_then(Value::as_object)
            .unwrap()
            .len(),
        1
    );

    let mut empty = Map::new();
    merge_redeem_signatures(&mut empty, &[], 4, &redeem_hex).expect("empty redeem signature set");
    assert!(empty
        .get("partialSigs")
        .and_then(Value::as_object)
        .unwrap()
        .is_empty());

    let decode_error = decode_redeem_script("zz", 5).unwrap_err();
    assert!(decode_error.starts_with("input[5] redeem hex:"));

    let mut invalid_redeem_input = Map::new();
    assert!(
        merge_redeem_signatures(&mut invalid_redeem_input, &[record(0x44)], 5, "zz")
            .unwrap_err()
            .starts_with("input[5] redeem hex:")
    );
    assert!(!invalid_redeem_input.contains_key("partialSigs"));

    let mut out_of_range = record(0x55);
    out_of_range.pubkey_pos = 1;
    assert_eq!(
        merge_redeem_signatures(&mut Map::new(), &[out_of_range], 6, &redeem_hex).unwrap_err(),
        "input[6] pubkey_pos 1 out of range for redeem",
    );
}

#[test]
fn merge_metadata_helpers_preserve_format_specific_errors_and_exact_counts() {
    use crate::transaction::interchange::pskt::PsktFormat;

    assert_eq!(pskt_object_error(PsktFormat::Pskb), "PSKB entry not object");
    assert_eq!(pskt_object_error(PsktFormat::PsktSingle), "PSKT not object");
    assert_eq!(
        pskt_object_error(PsktFormat::Unknown),
        "unknown PSKT format"
    );

    assert_eq!(validate_input_count(0, 0), Ok(()));
    assert_eq!(validate_input_count(3, 3), Ok(()));
    assert_eq!(
        validate_input_count(2, 3).unwrap_err(),
        "input count mismatch: PSKB has 2, compact KSPT has 3"
    );
}
