use super::{push_int, push_pubkey};
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
/// Build a true dead man's switch script using CSV (relative timelock).
///
/// Owner can spend anytime (heartbeat: send back to same address to reset timer).
/// Heir can only spend if the UTXO has been untouched for `inactivity_daa` DAA units.
///
/// Script:
///   OP_IF
///       <owner_pk> OP_CHECKSIG
///   OP_ELSE
///       <inactivity_daa> OP_CHECKSEQUENCEVERIFY
///       <heir_pk> OP_CHECKSIG
///   OP_ENDIF
pub fn build_dms_csv_script(
    owner_pubkey: &[u8; 32],
    heir_pubkey: &[u8; 32],
    inactivity_daa: u64,
) -> Vec<u8> {
    use super::covenant_ops::*;
    let mut s = Vec::with_capacity(80);

    s.push(OP_IF);
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIG);

    s.push(OP_ELSE);
    // Relative time-lock: UTXO must be at least inactivity_daa old
    push_int(&mut s, inactivity_daa);
    s.push(OP_CHECKSEQUENCEVERIFY);
    // Heir must also sign
    push_pubkey(&mut s, heir_pubkey);
    s.push(OP_CHECKSIG);

    s.push(OP_ENDIF);
    s
}

/// The fields of a canonical dead man's switch script.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmsFields {
    pub owner_pubkey: [u8; 32],
    pub heir_pubkey: [u8; 32],
    pub inactivity_daa: u64,
}

/// Recognize `script` as exactly what [`build_dms_csv_script`] builds.
#[must_use]
pub fn dms_script_fields(script: &[u8]) -> Option<DmsFields> {
    let elements = crate::contract::script::complete_elements(script)?;
    let fields = DmsFields {
        owner_pubkey: elements.get(1)?.data.try_into().ok()?,
        inactivity_daa: crate::contract::script::element_integer(elements.get(4)?)?,
        heir_pubkey: elements.get(6)?.data.try_into().ok()?,
    };
    let rebuilt = build_dms_csv_script(
        &fields.owner_pubkey,
        &fields.heir_pubkey,
        fields.inactivity_daa,
    );
    (rebuilt == script).then_some(fields)
}
