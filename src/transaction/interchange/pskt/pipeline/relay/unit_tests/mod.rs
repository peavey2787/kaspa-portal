use super::*;
use crate::transaction::interchange::pskt::pipeline::test_support::SIGNER_TEST_LIMITS;
use serde_json::json;

#[test]
fn stealth_tweak_discovery_covers_absent_invalid_duplicate_and_conflict_paths() {
    assert_eq!(find_stealth(&[]).unwrap(), None);
    assert_eq!(find_stealth(&[json!({})]).unwrap(), None);
    crate::test_support::assert_err_text(
        &find_stealth(&[json!({"proprietaries": []})]),
        "input[0] proprietaries must be an object",
    );
    crate::test_support::assert_err_text(
        &find_stealth(&[json!({"proprietaries": {"stealthTweak": 1}})]),
        "input[0] stealthTweak must be a hex string",
    );
    crate::test_support::assert_err_text(
        &find_stealth(&[json!({"proprietaries": {"stealthTweak": "00"}})]),
        "input[0] stealthTweak must be 32 bytes",
    );

    let one = "11".repeat(32);
    let two = "22".repeat(32);
    assert_eq!(
        find_stealth(&[json!({"proprietaries": {"stealthTweak": one.clone()}})]).unwrap(),
        Some([0x11; 32])
    );
    assert_eq!(
        find_stealth(&[
            json!({"proprietaries": {"stealthTweak": one.clone()}}),
            json!({"proprietaries": {"stealthTweak": one}}),
        ])
        .unwrap(),
        Some([0x11; 32])
    );
    crate::test_support::assert_err_text(
        &find_stealth(&[
            json!({"proprietaries": {"stealthTweak": "11".repeat(32)}}),
            json!({"proprietaries": {"stealthTweak": two}}),
        ]),
        "inputs contain conflicting stealth tweaks",
    );
}

#[test]
fn first_outpoint_covers_every_required_shape_and_numeric_boundary() {
    assert_eq!(first_outpoint(&[]).unwrap(), None);
    crate::test_support::assert_err_text(
        &first_outpoint(&[json!(1)]),
        "input[0] must be an object",
    );
    crate::test_support::assert_err_text(
        &first_outpoint(&[json!({})]),
        "input[0] previousOutpoint must be an object",
    );
    crate::test_support::assert_err_text(
        &first_outpoint(&[json!({"previousOutpoint": 1})]),
        "input[0] previousOutpoint must be an object",
    );
    crate::test_support::assert_err_text(
        &first_outpoint(&[json!({"previousOutpoint": {"index": 0}})]),
        "input[0] transactionId must be a hex string",
    );
    crate::test_support::assert_err_text(
        &first_outpoint(&[json!({"previousOutpoint": {"transactionId": 1, "index": 0}})]),
        "input[0] transactionId must be a hex string",
    );
    crate::test_support::assert_err_text(
        &first_outpoint(&[json!({"previousOutpoint": {"transactionId": "00", "index": 0}})]),
        "input[0] transactionId must be 32 bytes",
    );
    crate::test_support::assert_err_text(
        &first_outpoint(&[json!({"previousOutpoint": {"transactionId": "11".repeat(32)}})]),
        "input[0] previousOutpoint.index is missing",
    );
    crate::test_support::assert_err_text(
        &first_outpoint(&[
            json!({"previousOutpoint": {"transactionId": "11".repeat(32), "index": u64::from(u32::MAX) + 1}}),
        ]),
        "input[0] previousOutpoint.index must be a u32",
    );

    let parsed = first_outpoint(&[json!({
        "previousOutpoint": {
            "transactionId": "11".repeat(32),
            "index": "7"
        }
    })])
    .expect("valid outpoint")
    .expect("present outpoint");
    assert_eq!(parsed, ([0x11; 32], 7));
}

#[test]
fn transaction_payload_decoding_covers_default_hex_type_and_capability_limits() {
    let global = |payload: Option<serde_json::Value>| {
        let mut map = serde_json::Map::new();
        if let Some(payload) = payload {
            map.insert("txPayload".to_string(), payload);
        }
        map
    };
    assert_eq!(
        decode_payload(&global(None), SIGNER_TEST_LIMITS),
        Ok(Vec::new())
    );
    assert_eq!(
        decode_payload(&global(Some(json!(null))), SIGNER_TEST_LIMITS),
        Ok(Vec::new())
    );
    assert_eq!(
        decode_payload(&global(Some(json!("0aff"))), SIGNER_TEST_LIMITS),
        Ok(vec![0x0a, 0xff])
    );
    crate::test_support::assert_err_text(
        &decode_payload(&global(Some(json!("0AFF"))), SIGNER_TEST_LIMITS),
        "txPayload must be even-length lowercase hexadecimal",
    );
    assert_eq!(
        decode_payload(&global(Some(json!(7))), SIGNER_TEST_LIMITS),
        Err("txPayload must be a hex string or null".to_string())
    );
    let limit = SIGNER_TEST_LIMITS.max_payload();
    assert_eq!(
        decode_payload(&global(Some(json!("00".repeat(limit)))), SIGNER_TEST_LIMITS)
            .map(|payload| payload.len()),
        Ok(limit)
    );
    let error = decode_payload(
        &global(Some(json!("00".repeat(limit + 1)))),
        SIGNER_TEST_LIMITS,
    )
    .unwrap_err();
    assert!(error.contains("exceeds signer capabilities"), "{error}");
}
