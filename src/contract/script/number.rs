use super::opcode;
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

pub fn push_int(script: &mut Vec<u8>, value: u64) {
    if value == 0 {
        script.push(opcode::OP_0);
        return;
    }
    if value <= 16 {
        script.push(0x50 + value as u8);
        return;
    }

    let mut bytes = value.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.last().is_some_and(|last| last & 0x80 != 0) {
        bytes.push(0);
    }
    script.push(u8::try_from(bytes.len()).expect("u64 script integers use at most 9 bytes"));
    script.extend_from_slice(&bytes);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ScriptItem {
    Opcode,
    Integer(u64),
    OversizedInteger,
}

#[must_use]
fn read_script_int(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes[..data.len()].copy_from_slice(data);
    u64::from_le_bytes(bytes)
}

fn classify_push(data: &[u8]) -> ScriptItem {
    if data.len() > 8 {
        ScriptItem::OversizedInteger
    } else {
        ScriptItem::Integer(read_script_int(data))
    }
}

/// The element at `position` and the integer it encodes, if any.
pub(super) fn next_script_item(
    script: &[u8],
    position: usize,
) -> Result<(usize, ScriptItem), String> {
    let (element, next) = crate::primitives::script::read_element(script, position)
        .ok_or_else(|| "Truncated script item".to_string())?;
    Ok((next, classify_element(&element)))
}

fn classify_element(element: &crate::primitives::script::Element<'_>) -> ScriptItem {
    match element.opcode {
        _ if element.is_push() => classify_push(element.data),
        opcode @ opcode::OP_1..=opcode::OP_16 => {
            ScriptItem::Integer(u64::from(opcode - opcode::OP_1 + 1))
        }
        _ => ScriptItem::Opcode,
    }
}

/// The non-negative integer an element pushes: `OP_0`, `OP_1..=OP_16`, or
/// little-endian bytes (a ninth, zero sign byte is allowed above `i64::MAX`).
/// Callers rebuild the script to reject non-minimal encodings.
pub(crate) fn element_integer(element: &crate::primitives::script::Element<'_>) -> Option<u64> {
    let element = match element.data {
        [value @ .., 0] if element.is_push() && value.len() == 8 => {
            crate::primitives::script::Element {
                opcode: element.opcode,
                data: value,
            }
        }
        _ => *element,
    };
    match classify_element(&element) {
        ScriptItem::Integer(value) => Some(value),
        _ => None,
    }
}

pub(super) fn find_preceding_script_integer(
    script: &[u8],
    target_opcode: u8,
) -> Result<Option<u64>, String> {
    let mut position = 0usize;
    let mut previous = ScriptItem::Opcode;
    for _ in 0..script.len() {
        let Some(&current_opcode) = script.get(position) else {
            return Ok(None);
        };
        if current_opcode == target_opcode {
            return match previous {
                ScriptItem::Integer(value) => Ok(Some(value)),
                ScriptItem::OversizedInteger => Err("Script integer exceeds 8 bytes".to_string()),
                ScriptItem::Opcode => Ok(None),
            };
        }
        let (next, item) = next_script_item(script, position)?;
        previous = item;
        position = next;
    }
    // Every item is at least one byte, so `script.len()` steps reach the end.
    Ok(None)
}
