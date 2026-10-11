//! Each schema rule of the verified boundary rejects with its own message.

use serde_json::{json, Value};

use super::super::schema_validate::validate_document;
use super::super::test_support::unsigned_document;

fn validate(document: &Value) -> Result<(), String> {
    validate_document(document.as_object().expect("document object"))
}

fn rejected_with(change: impl Fn(&mut Value), message: &str) {
    let mut document = unsigned_document(None, 0x11);
    change(&mut document);
    let error = validate(&document).expect_err(message);
    assert!(
        error.contains(message),
        "expected {message:?}, got {error:?}"
    );
}

#[test]
fn the_fixture_document_satisfies_every_rule() {
    assert_eq!(validate(&unsigned_document(None, 0x11)), Ok(()));
}

#[test]
fn nested_objects_need_their_required_fields() {
    rejected_with(
        |document| {
            document["inputs"][0]["utxoEntry"]
                .as_object_mut()
                .unwrap()
                .remove("amount");
        },
        "missing input[0].utxoEntry.amount",
    );
    rejected_with(
        |document| {
            document["inputs"][0]["previousOutpoint"]
                .as_object_mut()
                .unwrap()
                .remove("index");
        },
        "missing input[0].previousOutpoint.index",
    );
    rejected_with(
        |document| document["inputs"][0]["covenantExecution"] = json!({"suppliedMask": "1"}),
        "missing input[0].covenantExecution.suppliedTrueMask",
    );
    rejected_with(
        |document| document["outputs"][0]["covenantBinding"] = json!({"authorizingInput": 0}),
        "missing output[0].covenantBinding.covenantId",
    );
    rejected_with(
        |document| {
            document["global"]
                .as_object_mut()
                .unwrap()
                .remove("inputCount");
        },
        "missing global.inputCount",
    );
}

#[test]
fn minimum_signatures_and_partials_are_bounded_by_five() {
    let mut five = unsigned_document(None, 0x11);
    five["inputs"][0]["minimumSignatures"] = json!(5);
    assert_eq!(validate(&five), Ok(()));
    rejected_with(
        |document| document["inputs"][0]["minimumSignatures"] = json!(6),
        "minimumSignatures must be within 1..=5",
    );

    let partials = |count: u8| {
        Value::Object(
            (0..count)
                .map(|key| (format!("{key:02x}"), json!({"schnorr": "00"})))
                .collect(),
        )
    };
    let mut at_limit = unsigned_document(None, 0x11);
    at_limit["inputs"][0]["partialSigs"] = partials(5);
    assert_eq!(validate(&at_limit), Ok(()));
    rejected_with(
        |document| document["inputs"][0]["partialSigs"] = partials(6),
        "exceeds the five-signature consumer limit",
    );
    rejected_with(
        |document| document["inputs"][0]["partialSigs"] = json!({"02aa": {}}),
        "missing input[0].partialSigs[02aa].schnorr",
    );
}

#[test]
fn nulls_are_accepted_only_where_a_default_exists() {
    let mut defaulted = unsigned_document(None, 0x11);
    defaulted["global"]["gas"] = Value::Null;
    defaulted["inputs"][0]["redeemScript"] = Value::Null;
    assert_eq!(validate(&defaulted), Ok(()));
    rejected_with(
        |document| document["outputs"][0]["amount"] = Value::Null,
        "output[0].amount must not be null",
    );
}

#[test]
fn global_routes_and_versions_are_checked() {
    let mut owner = unsigned_document(None, 0x11);
    owner["global"]["covenantBranch"] = json!("owner");
    assert_eq!(validate(&owner), Ok(()));
    rejected_with(
        |document| document["global"]["covenantBranch"] = json!("thief"),
        "unsupported global.covenantBranch",
    );
    rejected_with(
        |document| document["global"]["txVersion"] = json!(9),
        "unsupported transaction version: 9",
    );
}
