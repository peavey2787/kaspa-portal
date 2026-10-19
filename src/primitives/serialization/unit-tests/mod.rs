use serde::{Deserialize, Serialize};

use super::{decimal_opt_u64, decimal_u64};

#[derive(Debug, Deserialize)]
struct Wrapper {
    #[serde(with = "decimal_u64")]
    value: u64,
}

#[test]
fn accepts_canonical_decimal_string() {
    let parsed: Wrapper = serde_json::from_str(r#"{"value":"18446744073709551615"}"#).unwrap();
    assert_eq!(parsed.value, u64::MAX);
}

#[test]
fn rejects_json_numbers_even_when_javascript_safe() {
    for (encoded, expected) in [
        (
            r#"{"value":1}"#,
            "invalid type: integer `1`, expected a string at line 1 column 10",
        ),
        (
            r#"{"value":9007199254740991}"#,
            "invalid type: integer `9007199254740991`, expected a string at line 1 column 25",
        ),
    ] {
        crate::test_support::assert_err_text(&serde_json::from_str::<Wrapper>(encoded), expected);
    }
}

#[test]
fn rejects_noncanonical_decimal_string() {
    crate::test_support::assert_err(
        &serde_json::from_str::<Wrapper>(r#"{"value":"01"}"#),
        r#"Error("decimal string must be canonical (no leading zeroes)", line: 1, column: 14)"#,
    );
}

#[derive(Debug, Serialize)]
struct SerializeWrapper {
    #[serde(with = "decimal_u64")]
    value: u64,
}

#[test]
fn serializes_consensus_u64_as_decimal_string() {
    let encoded = serde_json::to_string(&SerializeWrapper { value: u64::MAX }).unwrap();
    assert_eq!(encoded, r#"{"value":"18446744073709551615"}"#);
}

#[test]
fn rejects_empty_nondigit_and_overflow_decimal_strings_independently() {
    for (encoded, expected) in [
        (
            r#"{"value":""}"#,
            "expected an unsigned decimal string at line 1 column 12",
        ),
        (
            r#"{"value":"12x"}"#,
            "expected an unsigned decimal string at line 1 column 15",
        ),
        (
            r#"{"value":"18446744073709551616"}"#,
            "decimal string exceeds u64 at line 1 column 32",
        ),
    ] {
        crate::test_support::assert_err_text(&serde_json::from_str::<Wrapper>(encoded), expected);
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
struct OptionalWrapper {
    #[serde(with = "decimal_opt_u64")]
    value: Option<u64>,
}

#[test]
fn optional_u64_round_trips_max_as_decimal_string() {
    let value = OptionalWrapper {
        value: Some(u64::MAX),
    };
    let encoded = serde_json::to_string(&value).unwrap();
    assert_eq!(encoded, r#"{"value":"18446744073709551615"}"#);
    let decoded: OptionalWrapper = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn optional_u64_round_trips_none_as_null() {
    let value = OptionalWrapper { value: None };
    let encoded = serde_json::to_string(&value).unwrap();
    assert_eq!(encoded, r#"{"value":null}"#);
    let decoded: OptionalWrapper = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, value);
}

#[test]
fn optional_u64_rejects_json_numbers() {
    crate::test_support::assert_err(
        &serde_json::from_str::<OptionalWrapper>(r#"{"value":1}"#),
        r#"Error("invalid type: integer `1`, expected a string", line: 1, column: 10)"#,
    );
}
