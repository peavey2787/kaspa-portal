//! Strict parsing of Merkle inclusion proofs supplied with a claim.

use super::{Map, Value};
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

pub(crate) struct MerkleProofItem {
    pub(crate) sibling: [u8; 32],
    pub(crate) direction: u8,
}

pub(crate) fn parse_merkle_proof(
    value: Option<&Value>,
    index: usize,
) -> Result<Vec<MerkleProofItem>, String> {
    let array = value
        .and_then(Value::as_array)
        .ok_or_else(|| format!("input[{index}].proprietaries.merkleProof must be an array"))?;
    if array.len() > 15 {
        return Err(format!("input[{index}] merkle proof exceeds 15 levels"));
    }
    array
        .iter()
        .enumerate()
        .map(|(level, value)| parse_merkle_proof_item(value, index, level))
        .collect()
}

pub(crate) fn parse_merkle_proof_item(
    value: &Value,
    index: usize,
    level: usize,
) -> Result<MerkleProofItem, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("input[{index}] merkle proof[{level}] must be an object"))?;
    validate_merkle_proof_item_shape(object, index, level)?;
    let sibling = parse_merkle_sibling(object, index, level)?;
    let direction = parse_merkle_direction(object, index, level)?;
    Ok(MerkleProofItem { sibling, direction })
}

pub(crate) fn validate_merkle_proof_item_shape(
    object: &Map<String, Value>,
    index: usize,
    level: usize,
) -> Result<(), String> {
    // Exactly two keys; the sibling and direction parsers each require theirs.
    if object.len() != 2 {
        return Err(format!(
            "input[{index}] merkle proof[{level}] must contain only sibling and direction"
        ));
    }
    Ok(())
}

pub(crate) fn parse_merkle_sibling(
    object: &Map<String, Value>,
    index: usize,
    level: usize,
) -> Result<[u8; 32], String> {
    let mut sibling = [0u8; 32];
    match object.get("sibling").and_then(Value::as_str) {
        Some(text)
            if crate::primitives::bytes::decode_lower_hex(text.as_bytes(), &mut sibling)
                == Some(32) =>
        {
            Ok(sibling)
        }
        _ => Err(format!(
            "input[{index}] merkle proof[{level}].sibling must be 32-byte lowercase hex"
        )),
    }
}

pub(crate) fn parse_merkle_direction(
    object: &Map<String, Value>,
    index: usize,
    level: usize,
) -> Result<u8, String> {
    match merkle_direction_u64(object.get("direction")) {
        Some(0) => Ok(0),
        Some(1) => Ok(1),
        _ => Err(format!(
            "input[{index}] merkle proof[{level}].direction must be 0 or 1"
        )),
    }
}

pub(crate) fn merkle_direction_u64(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(text)) => {
            crate::transaction::interchange::pskt::schema::parse_canonical_u64_bytes(
                text.as_bytes(),
            )
            .ok()
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "unit-tests/merkle_proof.rs"]
mod unit_tests;
