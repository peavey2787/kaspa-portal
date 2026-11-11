//! Cryptographic validation for signatures already present in untrusted PSKT/KSPT input.
//!
//! Completion/status must never be inferred from slot counts alone. Every counted
//! signature is bound to the exact script key/position and verified over the exact
//! transaction sighash before it contributes to status.

use crate::{
    crypto::schnorr::{schnorr_verify, SchnorrSignature},
    transaction::{
        interchange::kspt::{analyze_input_script, checked_redeem_bytes},
        model::{
            CovenantExecution, MultisigInfo, ScriptType, SigHashType, Transaction,
            MAX_SIGS_PER_INPUT,
        },
        sighash::calculate_sighash,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SignatureValidationError {
    InvalidModel,
    InvalidSighash,
    InvalidBinding,
    DuplicateBinding,
    InvalidSignature,
}

#[derive(Clone, Copy)]
enum SignatureSource {
    Kspt,
    StandardPskt,
}

fn required_for_input(tx: &Transaction, input_index: usize) -> Option<u8> {
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    match (script_type, multisig) {
        (ScriptType::P2PK, _) => Some(1),
        (ScriptType::Multisig | ScriptType::P2SH, Some(info)) => Some(info.m),
        (ScriptType::P2SH, None) => covenant_required_for_execution(tx, input_index),
        _ => None,
    }
}

fn covenant_required_for_execution(tx: &Transaction, input_index: usize) -> Option<u8> {
    let (execution, resolved) = resolved_execution(tx, input_index).ok()?;
    let count = active_execution_key_count(execution, &resolved)?;
    (count > 0 && usize::from(count) <= MAX_SIGS_PER_INPUT).then_some(count)
}

/// Resolve the covenant branches of `input_index` and check that the input's
/// declared execution selectors exactly cover them.
fn resolved_execution(
    tx: &Transaction,
    input_index: usize,
) -> Result<
    (
        CovenantExecution,
        crate::contract::covenant::branch::BranchResolution,
    ),
    SignatureValidationError,
> {
    let input = tx
        .inputs
        .get(input_index)
        .ok_or(SignatureValidationError::InvalidModel)?;
    let redeem = checked_redeem_bytes(tx, input_index)
        .map_err(|_| SignatureValidationError::InvalidModel)?;
    let resolved = crate::contract::covenant::branch::resolve_covenant_branches(redeem)
        .map_err(|_| SignatureValidationError::InvalidBinding)?;
    let execution = validate_covenant_execution_binding(input, resolved.selector_mask())?;
    Ok((execution, resolved))
}

fn active_execution_key_count(
    execution: CovenantExecution,
    resolved: &crate::contract::covenant::branch::BranchResolution,
) -> Option<u8> {
    let mut count = 0u8;
    for position in 0..resolved.len() {
        let binding = resolved.key_at(u8::try_from(position).ok()?).ok()?;
        if binding.matches_selectors(execution.supplied_mask, execution.supplied_true_mask) {
            count = count.checked_add(1)?;
        }
    }
    Some(count)
}

fn covenant_position_matches_execution(
    tx: &Transaction,
    input_index: usize,
    position: u8,
) -> Result<(), SignatureValidationError> {
    let (execution, resolved) = resolved_execution(tx, input_index)?;
    let binding = resolved
        .key_at(position)
        .map_err(|_| SignatureValidationError::InvalidBinding)?;
    if binding.matches_selectors(execution.supplied_mask, execution.supplied_true_mask) {
        Ok(())
    } else {
        Err(SignatureValidationError::InvalidBinding)
    }
}

fn expected_xonly_for_position(
    tx: &Transaction,
    input_index: usize,
    position: u8,
) -> Result<[u8; 32], SignatureValidationError> {
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    match (script_type, multisig) {
        (ScriptType::P2PK, _) => p2pk_xonly_for_position(tx, input_index, position),
        (ScriptType::Multisig | ScriptType::P2SH, Some(info)) => {
            multisig_xonly_for_position(&info, position)
        }
        (ScriptType::P2SH, None) => covenant_xonly_for_position(tx, input_index, position),
        _ => Err(SignatureValidationError::InvalidBinding),
    }
}

fn p2pk_xonly_for_position(
    tx: &Transaction,
    input_index: usize,
    position: u8,
) -> Result<[u8; 32], SignatureValidationError> {
    if position != 0 {
        return Err(SignatureValidationError::InvalidBinding);
    }
    let input = tx
        .inputs
        .get(input_index)
        .ok_or(SignatureValidationError::InvalidModel)?;
    let script = input
        .utxo_entry
        .script_public_key
        .script
        .get(..input.utxo_entry.script_public_key.script_len)
        .ok_or(SignatureValidationError::InvalidModel)?;
    crate::primitives::address::p2pk_xonly(script).ok_or(SignatureValidationError::InvalidBinding)
}

fn multisig_xonly_for_position(
    info: &crate::transaction::model::MultisigInfo,
    position: u8,
) -> Result<[u8; 32], SignatureValidationError> {
    info.pubkeys
        .get(..usize::from(info.n))
        .and_then(|keys| keys.get(usize::from(position)))
        .copied()
        .ok_or(SignatureValidationError::InvalidBinding)
}

fn covenant_xonly_for_position(
    tx: &Transaction,
    input_index: usize,
    position: u8,
) -> Result<[u8; 32], SignatureValidationError> {
    let redeem = checked_redeem_bytes(tx, input_index)
        .map_err(|_| SignatureValidationError::InvalidModel)?;
    let resolved = crate::contract::covenant::branch::resolve_covenant_branches(redeem)
        .map_err(|_| SignatureValidationError::InvalidBinding)?;
    resolved
        .key_at(position)
        .map(|branch| branch.key)
        .map_err(|_| SignatureValidationError::InvalidBinding)
}

fn verify_signature_bytes(
    tx: &Transaction,
    input_index: usize,
    position: u8,
    sighash_byte: u8,
    signature: &[u8; 64],
) -> Result<(), SignatureValidationError> {
    // Standard PSKT and compact KSPT consumer signing are currently SIGHASH_ALL-only.
    if sighash_byte != SigHashType::All.to_byte() {
        return Err(SignatureValidationError::InvalidSighash);
    }
    let public_key = expected_xonly_for_position(tx, input_index, position)?;
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    if matches!((script_type, multisig), (ScriptType::P2SH, None)) {
        covenant_position_matches_execution(tx, input_index, position)?;
    }
    let message = calculate_sighash(tx, input_index, SigHashType::All);
    schnorr_verify(
        &public_key,
        &message,
        &SchnorrSignature { bytes: *signature },
    )
    .map_err(|_| SignatureValidationError::InvalidSignature)
}

fn compressed_xonly(pubkey: &[u8; 33]) -> Result<[u8; 32], SignatureValidationError> {
    if !matches!(pubkey[0], 0x02 | 0x03) {
        return Err(SignatureValidationError::InvalidBinding);
    }
    pubkey[1..33]
        .try_into()
        .map_err(|_| SignatureValidationError::InvalidBinding)
}

fn position_for_pskt_key(
    tx: &Transaction,
    input_index: usize,
    pubkey: &[u8; 33],
) -> Result<u8, SignatureValidationError> {
    let key = compressed_xonly(pubkey)?;
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    match (script_type, multisig) {
        (ScriptType::P2PK, _) => position_for_p2pk_key(tx, input_index, &key),
        (ScriptType::Multisig | ScriptType::P2SH, Some(info)) => {
            position_for_multisig_key(&info, &key)
        }
        (ScriptType::P2SH, None) => position_for_covenant_key(tx, input_index, &key),
        _ => Err(SignatureValidationError::InvalidBinding),
    }
}

fn position_for_p2pk_key(
    tx: &Transaction,
    input_index: usize,
    key: &[u8; 32],
) -> Result<u8, SignatureValidationError> {
    let expected = expected_xonly_for_position(tx, input_index, 0)?;
    (*key == expected)
        .then_some(0)
        .ok_or(SignatureValidationError::InvalidBinding)
}

fn position_for_multisig_key(
    info: &MultisigInfo,
    key: &[u8; 32],
) -> Result<u8, SignatureValidationError> {
    let candidates = info
        .pubkeys
        .get(..usize::from(info.n))
        .ok_or(SignatureValidationError::InvalidModel)?;
    candidates
        .iter()
        .position(|candidate| candidate == key)
        .and_then(|position| u8::try_from(position).ok())
        .ok_or(SignatureValidationError::InvalidBinding)
}

fn position_for_covenant_key(
    tx: &Transaction,
    input_index: usize,
    key: &[u8; 32],
) -> Result<u8, SignatureValidationError> {
    let (execution, resolved) = resolved_execution(tx, input_index)?;
    resolved
        .position_for_key_with_selectors(key, execution.supplied_mask, execution.supplied_true_mask)
        .map_err(|_| SignatureValidationError::InvalidBinding)
}

fn validate_covenant_execution_binding(
    input: &crate::transaction::model::TransactionInput,
    selector_mask: u16,
) -> Result<CovenantExecution, SignatureValidationError> {
    input
        .covenant_execution
        .filter(|execution| execution.is_well_formed() && execution.supplied_mask == selector_mask)
        .ok_or(SignatureValidationError::InvalidBinding)
}

fn verified_count(
    tx: &Transaction,
    input_index: usize,
    source: SignatureSource,
) -> Result<u8, SignatureValidationError> {
    let input = tx
        .inputs
        .get(input_index)
        .ok_or(SignatureValidationError::InvalidModel)?;
    match source {
        SignatureSource::Kspt => verified_kspt_count(tx, input_index, input),
        SignatureSource::StandardPskt => verified_pskt_count(tx, input_index, input),
    }
}

fn verified_kspt_count(
    tx: &Transaction,
    input_index: usize,
    input: &crate::transaction::model::TransactionInput,
) -> Result<u8, SignatureValidationError> {
    let mut seen = [false; 256];
    for slot in input.sigs.iter() {
        mark_signature_position(&mut seen, usize::from(slot.pubkey_pos))?;
        verify_signature_bytes(
            tx,
            input_index,
            slot.pubkey_pos,
            slot.sighash_type,
            &slot.signature,
        )?;
    }
    Ok(input.sigs.count())
}

fn verified_pskt_count(
    tx: &Transaction,
    input_index: usize,
    input: &crate::transaction::model::TransactionInput,
) -> Result<u8, SignatureValidationError> {
    let partial_sigs = &input.incoming_partial_sigs;
    if input.sighash_type != SigHashType::All.to_byte() && !partial_sigs.is_empty() {
        return Err(SignatureValidationError::InvalidSighash);
    }
    let mut seen = [false; 256];
    for slot in partial_sigs.iter() {
        let position = position_for_pskt_key(tx, input_index, &slot.pubkey)?;
        mark_signature_position(&mut seen, usize::from(position))?;
        verify_signature_bytes(
            tx,
            input_index,
            position,
            input.sighash_type,
            &slot.signature,
        )?;
    }
    Ok(partial_sigs.count())
}

fn mark_signature_position(
    seen: &mut [bool; 256],
    position: usize,
) -> Result<(), SignatureValidationError> {
    if seen[position] {
        return Err(SignatureValidationError::DuplicateBinding);
    }
    seen[position] = true;
    Ok(())
}

pub(crate) fn kspt_status(tx: &Transaction) -> (u32, u32) {
    status(tx, SignatureSource::Kspt)
}

pub(crate) fn pskt_status(tx: &Transaction) -> (u32, u32) {
    status(tx, SignatureSource::StandardPskt)
}

fn status(tx: &Transaction, source: SignatureSource) -> (u32, u32) {
    if tx.num_inputs == 0 || tx.num_inputs > tx.inputs.len() {
        return (0, 0);
    }
    let mut present = 0u32;
    let mut required = 0u32;
    for input_index in 0..tx.num_inputs {
        let Some(required_input) = required_for_input(tx, input_index) else {
            // Unsupported/generic covenant inputs can carry individually valid
            // signatures but cannot be generically declared complete without
            // execution-branch evidence.
            required = required.saturating_add(1);
            continue;
        };
        required = required.saturating_add(u32::from(required_input));
        let Ok(valid) = verified_count(tx, input_index, source) else {
            continue;
        };
        if valid <= required_input {
            present = present.saturating_add(u32::from(valid));
        }
    }
    (present, required)
}

pub(crate) fn kspt_is_fully_signed(tx: &Transaction) -> bool {
    if tx.num_inputs == 0 || tx.num_inputs > tx.inputs.len() {
        return false;
    }
    for input_index in 0..tx.num_inputs {
        let Some(required) = required_for_input(tx, input_index) else {
            return false;
        };
        let Ok(valid) = verified_count(tx, input_index, SignatureSource::Kspt) else {
            return false;
        };
        if valid != required {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[path = "unit_tests/mod.rs"]
mod unit_tests;
