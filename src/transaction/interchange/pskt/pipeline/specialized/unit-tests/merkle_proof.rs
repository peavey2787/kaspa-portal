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
    assert!(parse_merkle_proof(None, 3).is_err());
    assert!(parse(json!({})).is_err());
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
    for malformed in [
        json!("not an object"),
        extra,
        sibling_without_direction,
        direction_without_sibling,
        sibling(json!(SIBLING.to_uppercase())),
        sibling(json!(&SIBLING[..62])),
        sibling(json!(format!("{SIBLING}00"))),
        sibling(json!(format!("{}g", &SIBLING[..63]))),
        sibling(json!(7)),
        item(json!(2)),
        item(json!(256)),
        item(json!(-1)),
        item(json!(1.0)),
        item(json!("01")),
        item(json!(null)),
    ] {
        assert!(parse(json!([malformed])).is_err(), "{malformed}");
    }
}
