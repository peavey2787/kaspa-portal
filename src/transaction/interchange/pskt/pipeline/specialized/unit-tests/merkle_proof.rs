//! Merkle proofs parse only bounded arrays of exact sibling/direction pairs.

use serde_json::{json, Value};

use super::parse_merkle_proof;

const SIBLING: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn item(direction: Value) -> Value {
    json!({ "sibling": SIBLING, "direction": direction })
}

fn parse(proof: Value) -> Result<Vec<(Vec<u8>, u8)>, String> {
    parse_merkle_proof(Some(&proof), 3).map(|items| {
        items
            .into_iter()
            .map(|item| (item.sibling.to_vec(), item.direction))
            .collect()
    })
}

#[test]
fn proofs_decode_siblings_and_both_direction_encodings() {
    let sibling = hex::decode(SIBLING).unwrap();
    assert_eq!(
        parse(json!([
            item(json!(0)),
            item(json!(1)),
            item(json!("1")),
            item(json!("0"))
        ])),
        Ok(vec![
            (sibling.clone(), 0),
            (sibling.clone(), 1),
            (sibling.clone(), 1),
            (sibling, 0),
        ])
    );
    assert_eq!(parse(json!([])), Ok(vec![]));
}

#[test]
fn proofs_are_bounded_to_fifteen_levels() {
    let levels = |count| Value::Array(vec![item(json!(0)); count]);
    assert_eq!(parse(levels(15)).map(|items| items.len()), Ok(15));
    assert_eq!(
        parse(levels(16)),
        Err("input[3] merkle proof exceeds 15 levels".to_string())
    );
    crate::test_support::assert_err_text(
        &parse_merkle_proof(None, 3),
        "input[3].proprietaries.merkleProof must be an array",
    );
    crate::test_support::assert_err_text(
        &parse(json!({})),
        "input[3].proprietaries.merkleProof must be an array",
    );
}

#[test]
fn proof_items_reject_every_malformed_field() {
    let mut extra = item(json!(0));
    extra["extra"] = json!(true);
    let mut sibling_without_direction = item(json!(0));
    sibling_without_direction
        .as_object_mut()
        .unwrap()
        .remove("direction");
    sibling_without_direction["other"] = json!(0);
    let mut direction_without_sibling = item(json!(0));
    direction_without_sibling
        .as_object_mut()
        .unwrap()
        .remove("sibling");
    direction_without_sibling["other"] = json!(0);
    let sibling = |text: Value| json!({ "sibling": text, "direction": 0 });
    for (malformed, expected) in [
        (
            json!("not an object"),
            "input[3] merkle proof[0] must be an object",
        ),
        (
            extra,
            "input[3] merkle proof[0] must contain only sibling and direction",
        ),
        (
            sibling_without_direction,
            "input[3] merkle proof[0].direction must be 0 or 1",
        ),
        (
            direction_without_sibling,
            "input[3] merkle proof[0].sibling must be 32-byte lowercase hex",
        ),
        (
            sibling(json!(SIBLING.to_uppercase())),
            "input[3] merkle proof[0].sibling must be 32-byte lowercase hex",
        ),
        (
            sibling(json!(&SIBLING[..62])),
            "input[3] merkle proof[0].sibling must be 32-byte lowercase hex",
        ),
        (
            sibling(json!(format!("{SIBLING}00"))),
            "input[3] merkle proof[0].sibling must be 32-byte lowercase hex",
        ),
        (
            sibling(json!(format!("{}g", &SIBLING[..63]))),
            "input[3] merkle proof[0].sibling must be 32-byte lowercase hex",
        ),
        (
            sibling(json!(7)),
            "input[3] merkle proof[0].sibling must be 32-byte lowercase hex",
        ),
        (
            item(json!(2)),
            "input[3] merkle proof[0].direction must be 0 or 1",
        ),
        (
            item(json!(256)),
            "input[3] merkle proof[0].direction must be 0 or 1",
        ),
        (
            item(json!(-1)),
            "input[3] merkle proof[0].direction must be 0 or 1",
        ),
        (
            item(json!(1.0)),
            "input[3] merkle proof[0].direction must be 0 or 1",
        ),
        (
            item(json!("01")),
            "input[3] merkle proof[0].direction must be 0 or 1",
        ),
        (
            item(json!(null)),
            "input[3] merkle proof[0].direction must be 0 or 1",
        ),
    ] {
        crate::test_support::assert_err_text(&parse(json!([malformed])), expected);
    }
}
