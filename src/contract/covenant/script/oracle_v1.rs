//! Human-attested Oracle-v1 covenant.
//!
//! Each covenant embeds one unique exact 32-byte statement commitment at
//! creation time. The oracle signs that commitment through the isolated covenant-key hierarchy. The claim branch verifies only that
//! attestation from another covenant or another statement cannot be substituted.
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

use super::{push_data, push_int, push_pubkey};

pub const ORACLE_V1_SIG_OP_COUNT: u8 = 2;

pub fn build_oracle_v1_covenant_script(
    owner_pubkey: &[u8; 32],
    beneficiary_pubkey: &[u8; 32],
    oracle_pubkey: &[u8; 32],
    expected_message_commitment: &[u8; 32],
    locktime_daa: u64,
    salt: &[u8; 16],
) -> Vec<u8> {
    use super::covenant_ops::*;
    let mut script = Vec::with_capacity(240);

    script.push(0x10);
    script.extend_from_slice(salt);
    script.push(OP_DROP);

    // Owner refund after timeout.
    script.push(OP_IF);
    push_pubkey(&mut script, owner_pubkey);
    script.push(OP_CHECKSIGVERIFY);
    push_int(&mut script, locktime_daa);
    script.push(OP_CHECKLOCKTIMEVERIFY);
    script.push(OP_1);

    script.push(OP_ELSE);

    // Beneficiary claim: the oracle signature must be over this covenant's
    // exact, unique release-statement commitment. The oracle is NOT granted a
    // transaction-spend branch; optional beacons are ordinary oracle-funded
    // deposits carrying the authenticated attestation in the transaction payload.
    push_pubkey(&mut script, beneficiary_pubkey);
    script.push(OP_CHECKSIGVERIFY);
    push_data(&mut script, expected_message_commitment);
    push_pubkey(&mut script, oracle_pubkey);
    script.push(OP_CHECKSIGFROMSTACK);
    script.push(OP_VERIFY);
    script.push(OP_1);

    script.push(OP_ENDIF);
    script
}

/// The fields of a canonical Oracle-v1 covenant script.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OracleV1Fields {
    pub owner_pubkey: [u8; 32],
    pub beneficiary_pubkey: [u8; 32],
    pub oracle_pubkey: [u8; 32],
    pub message_commitment: [u8; 32],
    pub locktime_daa: u64,
    pub salt: [u8; 16],
}

/// Recognize `script` as exactly what [`build_oracle_v1_covenant_script`]
/// builds. Rebuilding prevents imported data from smuggling extra branches
/// around an Oracle-looking claim segment.
#[must_use]
pub fn oracle_v1_script_fields(script: &[u8]) -> Option<OracleV1Fields> {
    let elements = crate::contract::script::complete_elements(script)?;
    let fields = OracleV1Fields {
        salt: elements.first()?.data.try_into().ok()?,
        owner_pubkey: elements.get(3)?.data.try_into().ok()?,
        locktime_daa: crate::contract::script::element_integer(elements.get(5)?)?,
        beneficiary_pubkey: elements.get(9)?.data.try_into().ok()?,
        message_commitment: elements.get(11)?.data.try_into().ok()?,
        oracle_pubkey: elements.get(12)?.data.try_into().ok()?,
    };
    let rebuilt = build_oracle_v1_covenant_script(
        &fields.owner_pubkey,
        &fields.beneficiary_pubkey,
        &fields.oracle_pubkey,
        &fields.message_commitment,
        fields.locktime_daa,
        &fields.salt,
    );
    (rebuilt == script).then_some(fields)
}

/// The beneficiary, statement commitment and oracle key a canonical
/// Oracle-v1 script binds.
pub fn oracle_v1_attestation_binding(script: &[u8]) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
    oracle_v1_script_fields(script).map(|fields| {
        (
            fields.beneficiary_pubkey,
            fields.message_commitment,
            fields.oracle_pubkey,
        )
    })
}

pub fn oracle_v1_script_commits_to(
    script: &[u8],
    commitment: &[u8; 32],
    oracle_pubkey: &[u8; 32],
) -> bool {
    oracle_v1_attestation_binding(script).is_some_and(
        |(_, embedded_commitment, embedded_oracle)| {
            embedded_commitment == *commitment && embedded_oracle == *oracle_pubkey
        },
    )
}
