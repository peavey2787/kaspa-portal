#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

use super::{validate_canonical_json, JsonSyntaxError};

#[test]
fn canonical_json_rejects_duplicate_keys_recursively_in_every_container_shape() {
    let cases: &[&[u8]] = &[
        br#"{"x":1,"x":2}"#,
        br#"{"outer":{"x":1,"x":2}}"#,
        br#"{"outer":{"deeper":{"x":1,"x":2}}}"#,
        br#"{"items":[{"x":1,"x":2}]}"#,
        br#"[{"outer":{"x":1,"x":2}}]"#,
        br#"{"unknownExtension":{"array":[{"future":1,"future":2}]}}"#,
    ];
    for json in cases {
        assert_eq!(
            validate_canonical_json(json),
            Err(JsonSyntaxError::DuplicateKey),
            "duplicate escaped canonical validation: {}",
            core::str::from_utf8(json).expect("ASCII fixture"),
        );
    }
}

#[test]
fn canonical_json_allows_same_key_name_in_distinct_object_scopes() {
    assert_eq!(
        validate_canonical_json(br#"{"left":{"x":1},"right":{"x":2}}"#),
        Ok(())
    );
}

#[test]
fn canonical_json_value_and_structure_boundaries_cover_each_parser_branch() {
    for valid in [
        br#"{}"#.as_slice(),
        br#"[]"#.as_slice(),
        br#"{ "string" : "ASCII", "zero":0, "number":123, "yes":true, "no":false, "none":null, "array":[0,1,{}], "object":{"nested":2} }"#.as_slice(),
    ] {
        assert_eq!(validate_canonical_json(valid), Ok(()));
    }

    let invalid = [
        (br#"{"x":01}"#.as_slice(), JsonSyntaxError::InvalidNumber),
        (br#"{"x":1.0}"#.as_slice(), JsonSyntaxError::InvalidNumber),
        (br#"{"x":-1}"#.as_slice(), JsonSyntaxError::UnexpectedToken),
        (br#"{"x":tru}"#.as_slice(), JsonSyntaxError::UnexpectedToken),
        (
            br#"{"x":"a\nb"}"#.as_slice(),
            JsonSyntaxError::InvalidString,
        ),
        (
            b"{\"x\":\"unterminated}".as_slice(),
            JsonSyntaxError::InvalidString,
        ),
        (br#"{"x" 1}"#.as_slice(), JsonSyntaxError::UnexpectedToken),
        (
            br#"{"x":1 "y":2}"#.as_slice(),
            JsonSyntaxError::UnexpectedToken,
        ),
        (br#"{"x":1,}"#.as_slice(), JsonSyntaxError::UnexpectedToken),
        (br#"[1 2]"#.as_slice(), JsonSyntaxError::UnexpectedToken),
        (br#"[1,]"#.as_slice(), JsonSyntaxError::UnexpectedToken),
        (br#"{} trailing"#.as_slice(), JsonSyntaxError::TrailingData),
    ];
    for (json, expected) in invalid {
        assert_eq!(validate_canonical_json(json), Err(expected));
    }

    let deeply_nested = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    assert_eq!(
        validate_canonical_json(deeply_nested.as_bytes()),
        Err(JsonSyntaxError::NestingTooDeep),
    );
}

#[test]
fn every_json_syntax_error_has_a_distinct_actionable_message() {
    let messages = [
        (
            JsonSyntaxError::UnexpectedToken,
            "invalid canonical JSON structure",
        ),
        (
            JsonSyntaxError::InvalidNumber,
            "PSKT JSON numbers must be canonical non-negative integers",
        ),
        (
            JsonSyntaxError::InvalidString,
            "PSKT JSON strings must be printable ASCII without escapes",
        ),
        (JsonSyntaxError::DuplicateKey, "duplicate JSON object key"),
        (
            JsonSyntaxError::NestingTooDeep,
            "PSKT JSON exceeds maximum nesting depth",
        ),
        (
            JsonSyntaxError::TrailingData,
            "PSKT JSON contains trailing data",
        ),
    ];
    for (error, message) in messages {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn canonical_json_nesting_limit_is_exact_for_objects_and_arrays() {
    let max = super::MAX_JSON_NESTING;
    let arrays = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
    let objects = |depth: usize| {
        format!(
            "{}{{}}{}",
            r#"{"a":"#.repeat(depth - 1),
            "}".repeat(depth - 1)
        )
    };
    assert_eq!(validate_canonical_json(arrays(max).as_bytes()), Ok(()));
    assert_eq!(validate_canonical_json(objects(max).as_bytes()), Ok(()));
    assert_eq!(
        validate_canonical_json(arrays(max + 1).as_bytes()),
        Err(JsonSyntaxError::NestingTooDeep)
    );
    assert_eq!(
        validate_canonical_json(objects(max + 1).as_bytes()),
        Err(JsonSyntaxError::NestingTooDeep)
    );
}

#[test]
fn duplicate_keys_are_found_past_nested_values_and_whitespace() {
    assert_eq!(
        validate_canonical_json(br#"{ "a" : [ {"b":1} , 2 ] ,  "c" : {"a":3} , "a" : 4 }"#),
        Err(JsonSyntaxError::DuplicateKey)
    );
    assert_eq!(
        validate_canonical_json(br#"{ "a" : [ {"b":1} , 2 ] ,  "c" : {"a":3} , "d" : 4 }"#),
        Ok(())
    );
    for valid in [
        &br#"[0, 10, 9007199254740993]"#[..],
        b"\t[ true ,false,null ]\r\n",
    ] {
        assert_eq!(validate_canonical_json(valid), Ok(()));
    }
    for (json, expected) in [
        (&b"[00]"[..], JsonSyntaxError::InvalidNumber),
        (b"[1e5]", JsonSyntaxError::InvalidNumber),
        (b"[1+]", JsonSyntaxError::InvalidNumber),
        (b"[nul]", JsonSyntaxError::UnexpectedToken),
        (b"[\"\x7f\"]", JsonSyntaxError::InvalidString),
        (b"[\"a\\\"\"]", JsonSyntaxError::InvalidString),
        (b"", JsonSyntaxError::UnexpectedToken),
    ] {
        assert_eq!(validate_canonical_json(json), Err(expected));
    }
}
