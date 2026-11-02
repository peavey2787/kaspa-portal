use super::*;
use serde_json::json;

#[test]
fn value_kind_validation_covers_every_kind_and_type_failure() {
    assert!(validate_kind(&json!({}), ValueKind::Object, "v").is_ok());
    assert!(validate_kind(&json!([]), ValueKind::Array, "v").is_ok());
    assert!(validate_kind(&json!(true), ValueKind::Boolean, "v").is_ok());
    assert!(validate_kind(&json!("text"), ValueKind::String, "v").is_ok());
    assert!(validate_kind(&json!(7), ValueKind::ExactUnsigned, "v").is_ok());
    assert!(validate_kind(&json!("7"), ValueKind::ExactUnsigned, "v").is_ok());
    assert!(validate_kind(&json!("00ff"), ValueKind::HexString, "v").is_ok());
    assert!(validate_kind(&json!("0000"), ValueKind::ScriptPublicKey, "v").is_ok());

    crate::test_support::assert_err_text(
        &validate_kind(&json!([]), ValueKind::Object, "v"),
        "v has the wrong JSON type",
    );
    crate::test_support::assert_err_text(
        &validate_kind(&json!({}), ValueKind::Array, "v"),
        "v has the wrong JSON type",
    );
    crate::test_support::assert_err_text(
        &validate_kind(&json!(0), ValueKind::Boolean, "v"),
        "v has the wrong JSON type",
    );
    crate::test_support::assert_err_text(
        &validate_kind(&json!(0), ValueKind::String, "v"),
        "v has the wrong JSON type",
    );
    crate::test_support::assert_err_text(
        &validate_kind(&json!(-1), ValueKind::ExactUnsigned, "v"),
        "v must be an unsigned integer",
    );
    crate::test_support::assert_err_text(
        &validate_kind(&json!("01"), ValueKind::ExactUnsigned, "v"),
        "v must be a canonical unsigned decimal string",
    );
    crate::test_support::assert_err_text(
        &validate_kind(
            &json!(9_007_199_254_740_992_u64),
            ValueKind::ExactUnsigned,
            "v",
        ),
        "legacy numeric v exceeds JavaScript's exact integer range; encode it as a decimal string",
    );
    crate::test_support::assert_err_text(
        &validate_kind(&json!(0), ValueKind::HexString, "v"),
        "v must be a lowercase hexadecimal string",
    );
    crate::test_support::assert_err_text(
        &validate_kind(&json!("0"), ValueKind::HexString, "v"),
        "v must be even-length lowercase hexadecimal",
    );
    crate::test_support::assert_err_text(
        &validate_kind(&json!(0), ValueKind::ScriptPublicKey, "v"),
        "v must be a scriptPublicKey string",
    );
    crate::test_support::assert_err_text(
        &validate_kind(&json!("00"), ValueKind::ScriptPublicKey, "v"),
        "v must contain a four-hex-digit script version",
    );
}

#[test]
fn object_helpers_cover_required_optional_and_null_boundaries() {
    let object = json!({"o": {}, "a": [], "n": null, "x": 1});
    let map = object.as_object().expect("object");
    assert!(required_object(map, "o", "o").is_ok());
    crate::test_support::assert_err_text(
        &required_object(map, "missing", "missing"),
        "missing must be an object",
    );
    assert!(required_array(map, "a", "a").is_ok());
    crate::test_support::assert_err_text(&required_array(map, "x", "x"), "x must be an array");
    assert!(optional_object(None, "o").unwrap().is_none());
    assert!(optional_object(map.get("n"), "n").unwrap().is_none());
    assert!(optional_object(map.get("o"), "o").unwrap().is_some());
    crate::test_support::assert_err_text(
        &optional_object(map.get("x"), "x"),
        "x must be an object or null",
    );
}
