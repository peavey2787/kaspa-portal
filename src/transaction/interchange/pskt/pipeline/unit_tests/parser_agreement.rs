//! The host pipeline and the allocation-free Vault parser read every u64
//! field of one PSKB identically: a canonical decimal string or a JSON number
//! within JavaScript's exact range is accepted by both, anything else by
//! neither. A form only one side accepts would let a reviewed transaction
//! differ from the signed one.

use serde_json::{json, Value};

use super::super::test_support::{unsigned_document, SIGNER_TEST_LIMITS};
use crate::primitives::address::KaspaNetwork;
use crate::transaction::interchange::pskt::model::PSKB_MAGIC;
use crate::transaction::interchange::pskt::schema::JS_MAX_SAFE_U64;
use crate::transaction::interchange::pskt::shared::PsktParsed;
use crate::transaction::interchange::pskt::standard::parse_pskt;
use crate::transaction::model::Transaction;

const U64_FIELDS: &[&str] = &[
    "/global/version",
    "/global/txVersion",
    "/global/inputCount",
    "/global/outputCount",
    "/global/fallbackLockTime",
    "/global/gas",
    "/inputs/0/previousOutpoint/index",
    "/inputs/0/utxoEntry/amount",
    "/inputs/0/sequence",
    "/inputs/0/sigOpCount",
    "/inputs/0/sighashType",
    "/outputs/0/amount",
];

/// The PSKB wire for `document` as written, without the pipeline encoder's
/// canonicality check, so forms it would refuse to emit still reach both
/// parsers: magic and hex JSON for the Vault, hex of that again for the host.
fn pskb(document: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(&json!([document])).expect("JSON test body");
    let mut wire = PSKB_MAGIC.to_vec();
    wire.extend_from_slice(hex::encode(body).as_bytes());
    wire
}

fn verdicts_for(document: &Value) -> (bool, bool) {
    let wire = pskb(document);
    let pipeline = super::super::is_complete(
        &hex::encode(&wire),
        KaspaNetwork::Mainnet,
        SIGNER_TEST_LIMITS,
    );
    let mut scratch = vec![0u8; wire.len()];
    let mut tx = Transaction::try_new().expect("transaction test allocation");
    let mut parsed = PsktParsed::empty();
    let vault = parse_pskt(&wire, &mut scratch, &mut tx, &mut parsed);
    (pipeline.is_ok(), vault.is_ok())
}

fn field_value(document: &Value, pointer: &str) -> u64 {
    match document.pointer(pointer).expect("fixture field") {
        Value::String(text) => text.parse().expect("fixture decimal"),
        Value::Number(number) => number.as_u64().expect("fixture integer"),
        other => panic!("{pointer} holds {other}"),
    }
}

fn verdicts(pointer: &str, form: &Value) -> (bool, bool) {
    let mut document = unsigned_document(None, 0x11);
    *document.pointer_mut(pointer).expect("fixture field") = form.clone();
    verdicts_for(&document)
}

#[test]
fn both_parsers_accept_the_fixture() {
    assert_eq!(verdicts_for(&unsigned_document(None, 0x11)), (true, true));
}

#[test]
fn every_u64_field_accepts_a_decimal_string_or_an_exact_number_on_both_sides() {
    let fixture = unsigned_document(None, 0x11);
    for pointer in U64_FIELDS {
        let value = field_value(&fixture, pointer);
        for form in [json!(value), json!(value.to_string())] {
            assert_eq!(verdicts(pointer, &form), (true, true), "{pointer} = {form}");
        }
    }
}

#[test]
fn every_u64_field_refuses_inexact_and_noncanonical_forms_on_both_sides() {
    let fixture = unsigned_document(None, 0x11);
    for pointer in U64_FIELDS {
        let value = field_value(&fixture, pointer);
        for form in [
            json!(JS_MAX_SAFE_U64 + 1),
            json!(format!("0{value}")),
            json!(format!("{value}.0")),
            json!(-1),
            json!(1.5),
            json!(true),
        ] {
            assert_eq!(
                verdicts(pointer, &form),
                (false, false),
                "{pointer} = {form}"
            );
        }
    }
}
