//! Which path a covenant spend took, read from the spend itself.

use crate::primitives::{
    opcode::{OP_0, OP_1, OP_CHECKSIGVERIFY, OP_DROP},
    script::read_element,
};

/// The spend path of a two-branch (`OP_IF` owner / `OP_ELSE` other) covenant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpendPath {
    /// The `OP_IF` branch, or the only path of a single-path covenant.
    Owner,
    /// The `OP_ELSE` branch.
    Other,
}

/// Whether `redeem_script`, after an optional `<8-byte salt> OP_DROP`, opens
/// with `<x-only key> OP_CHECKSIGVERIFY`: a single-path covenant with no
/// branch selector.
#[must_use]
pub fn is_single_path(redeem_script: &[u8]) -> bool {
    let body = salted_body_offset(redeem_script);
    let key = read_element(redeem_script, body);
    matches!(key, Some((element, next))
        if element.opcode == 32 && redeem_script.get(next) == Some(&OP_CHECKSIGVERIFY))
}

fn salted_body_offset(script: &[u8]) -> usize {
    match read_element(script, 0) {
        Some((salt, next)) if salt.opcode == 8 && script.get(next) == Some(&OP_DROP) => next + 1,
        _ => 0,
    }
}

/// The path a spend of `redeem_script` took, from its `signature_script`:
/// the branch selector pushed just before the redeem script. `None` when
/// the signature script does not end with that selector and redeem push.
#[must_use]
pub fn spend_path(signature_script: &[u8], redeem_script: &[u8]) -> Option<SpendPath> {
    if is_single_path(redeem_script) {
        return Some(SpendPath::Owner);
    }
    let elements = crate::contract::script::complete_elements(signature_script)?;
    let [.., selector, redeem] = elements.as_slice() else {
        return None;
    };
    if redeem.data != redeem_script {
        return None;
    }
    match selector.opcode {
        OP_1 => Some(SpendPath::Owner),
        OP_0 => Some(SpendPath::Other),
        _ => None,
    }
}

#[cfg(test)]
#[path = "unit-tests/spend_path.rs"]
mod unit_tests;
