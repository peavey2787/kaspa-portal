use serde_json::json;

use super::super::exact_json::{parse_exact_u64, validate_pskt_exact_fields};

#[test]
fn exact_u64_accepts_only_decimal_string() {
    assert_eq!(
        parse_exact_u64(&json!("18446744073709551615"), "amount").unwrap(),
        u64::MAX
    );
    assert!(parse_exact_u64(&json!(1u64), "amount").is_err());
}

#[test]
fn exact_u64_rejects_noncanonical_and_numeric_forms() {
    for invalid in ["", "01", "1x", "+1", "-1"] {
        assert!(
            parse_exact_u64(&json!(invalid), "amount").is_err(),
            "accepted noncanonical decimal form {invalid:?}"
        );
    }
    assert!(parse_exact_u64(&json!(9_007_199_254_740_992u64), "amount").is_err());
    assert!(parse_exact_u64(&json!(1.5), "amount").is_err());
}

#[test]
fn validator_accepts_canonical_decimal_strings() {
    let pskt = json!({
        "global": {"fallbackLockTime": "7", "gas": "0"},
        "inputs": [{"sequence": "0", "utxoEntry": {"amount": "10", "blockDaaScore": "11"}}],
        "outputs": [{"amount": "9"}]
    });
    validate_pskt_exact_fields(&pskt).unwrap();
    assert_eq!(pskt["global"]["fallbackLockTime"], "7");
    assert_eq!(pskt["inputs"][0]["utxoEntry"]["amount"], "10");
    assert_eq!(pskt["inputs"][0]["utxoEntry"]["blockDaaScore"], "11");
    assert_eq!(pskt["outputs"][0]["amount"], "9");
}

#[test]
fn validator_allows_missing_input_amount_but_requires_output_amount() {
    let finalization_only = json!({
        "global": {},
        "inputs": [{"utxoEntry": {"scriptPublicKey": "000051"}}],
        "outputs": [{"amount": "1"}]
    });
    validate_pskt_exact_fields(&finalization_only).unwrap();
    assert!(finalization_only["inputs"][0]["utxoEntry"]
        .get("amount")
        .is_none());
    assert_eq!(finalization_only["outputs"][0]["amount"], "1");

    let missing_output_amount = json!({
        "global": {},
        "inputs": [],
        "outputs": [{"scriptPublicKey": "000051"}]
    });
    assert_eq!(
        validate_pskt_exact_fields(&missing_output_amount).unwrap_err(),
        "missing amount"
    );
}

#[test]
fn validator_rejects_a_noncanonical_value_in_every_exact_field() {
    let valid = json!({
        "global": {"fallbackLockTime": "7", "gas": "0"},
        "inputs": [{
            "sequence": "0",
            "minTime": "3",
            "utxoEntry": {"amount": "10", "blockDaaScore": "11"}
        }],
        "outputs": [{"amount": "9"}]
    });
    assert_eq!(validate_pskt_exact_fields(&valid), Ok(()));
    for pointer in [
        "/global/fallbackLockTime",
        "/global/gas",
        "/inputs/0/sequence",
        "/inputs/0/minTime",
        "/inputs/0/utxoEntry/amount",
        "/inputs/0/utxoEntry/blockDaaScore",
        "/outputs/0/amount",
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).expect("field") = json!("01");
        assert!(
            validate_pskt_exact_fields(&invalid).is_err(),
            "{pointer} accepted a noncanonical decimal"
        );
        *invalid.pointer_mut(pointer).expect("field") = json!(null);
        assert_eq!(
            validate_pskt_exact_fields(&invalid).is_err(),
            pointer == "/outputs/0/amount",
            "{pointer} null handling"
        );
    }
    assert!(validate_pskt_exact_fields(&json!([])).is_err());
    assert!(validate_pskt_exact_fields(&json!({"inputs": [7]})).is_err());
    assert!(validate_pskt_exact_fields(&json!({"outputs": [7]})).is_err());
}
