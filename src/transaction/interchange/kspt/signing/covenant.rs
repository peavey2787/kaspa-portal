use crate::primitives::bytes::zeroize_bytes;

use crate::transaction::model::{SigHashType, Transaction};

use super::super::{error::PsktError, validation::checked_redeem_bytes};
use super::{context::SigningContext, signature_state::set_single_signature};

const MAX_COVENANT_KEYS: usize = 8;

pub(super) struct CandidateKeys {
    pub(super) keys: [[u8; 32]; MAX_COVENANT_KEYS],
    pub(super) len: usize,
}

impl CandidateKeys {
    const fn new() -> Self {
        Self {
            keys: [[0u8; 32]; MAX_COVENANT_KEYS],
            len: 0,
        }
    }

    fn push(&mut self, key: &[u8]) {
        if self.len < MAX_COVENANT_KEYS {
            self.keys[self.len].copy_from_slice(key);
            self.len += 1;
        }
    }
}

fn checked_advance(offset: usize, amount: usize, script_len: usize) -> Result<usize, PsktError> {
    let next = offset.checked_add(amount).ok_or(PsktError::InvalidModel)?;
    if next > script_len || next <= offset {
        return Err(PsktError::InvalidModel);
    }
    Ok(next)
}

pub(super) fn scan_candidate_keys(script: &[u8]) -> Result<CandidateKeys, PsktError> {
    let mut candidates = CandidateKeys::new();
    let mut offset = 0usize;
    while offset < script.len() {
        record_candidate_key(script, offset, &mut candidates)?;
        let next_offset = next_script_offset(script, offset)?;
        if next_offset <= offset {
            return Err(PsktError::InvalidModel);
        }
        offset = next_offset;
    }
    Ok(candidates)
}

fn record_candidate_key(
    script: &[u8],
    offset: usize,
    candidates: &mut CandidateKeys,
) -> Result<(), PsktError> {
    if script.get(offset).copied() != Some(0x20) {
        return Ok(());
    }
    let after = checked_advance(offset, 33, script.len())?;
    let tail = script.get(after..).unwrap_or_default();
    let has_checksig = tail
        .first()
        .is_some_and(|opcode| matches!(opcode, 0xac | 0xad))
        || tail
            .get(1)
            .is_some_and(|opcode| matches!(opcode, 0xac | 0xad));
    if has_checksig {
        candidates.push(&script[offset + 1..offset + 33]);
    }
    Ok(())
}

fn next_script_offset(script: &[u8], offset: usize) -> Result<usize, PsktError> {
    let opcode = *script.get(offset).ok_or(PsktError::InvalidModel)?;
    match opcode {
        0x01..=0x4b => checked_advance(offset, 1 + opcode as usize, script.len()),
        0x4c => next_pushdata1_offset(script, offset),
        0x4d => next_pushdata2_offset(script, offset),
        0x4e => next_pushdata4_offset(script, offset),
        _ => checked_advance(offset, 1, script.len()),
    }
}

fn next_pushdata1_offset(script: &[u8], offset: usize) -> Result<usize, PsktError> {
    let header_end = checked_advance(offset, 2, script.len())?;
    checked_advance(header_end, script[offset + 1] as usize, script.len())
}

fn next_pushdata2_offset(script: &[u8], offset: usize) -> Result<usize, PsktError> {
    let header_end = checked_advance(offset, 3, script.len())?;
    let length = u16::from_le_bytes([script[offset + 1], script[offset + 2]]) as usize;
    checked_advance(header_end, length, script.len())
}

fn next_pushdata4_offset(script: &[u8], offset: usize) -> Result<usize, PsktError> {
    let header_end = checked_advance(offset, 5, script.len())?;
    let length = u32::from_le_bytes([
        script[offset + 1],
        script[offset + 2],
        script[offset + 3],
        script[offset + 4],
    ]) as usize;
    checked_advance(header_end, length, script.len())
}

pub(super) fn candidate_keys_for_input(
    tx: &Transaction,
    input_index: usize,
) -> Result<CandidateKeys, PsktError> {
    checked_redeem_bytes(tx, input_index).and_then(scan_candidate_keys)
}

pub(super) fn sign_covenant_input(
    tx: &mut Transaction,
    input_index: usize,
    context: &mut SigningContext,
    sighash_type: SigHashType,
    active_seed_index: Option<usize>,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<usize, PsktError> {
    if tx.inputs[input_index].sig_count != 0 {
        return Ok(0);
    }
    let candidates = candidate_keys_for_input(tx, input_index)?;
    for candidate_index in 0..candidates.len {
        if sign_covenant_candidate(
            tx,
            context,
            CovenantCandidateRequest {
                input_index,
                sighash_type,
                active_seed_index,
                signing_entropy,
                candidate_index,
                target: &candidates.keys[candidate_index],
            },
        )? {
            return Ok(1);
        }
    }
    Ok(0)
}

struct CovenantCandidateRequest<'a> {
    input_index: usize,
    sighash_type: SigHashType,
    active_seed_index: Option<usize>,
    signing_entropy: Option<&'a [u8; 32]>,
    candidate_index: usize,
    target: &'a [u8; 32],
}

fn sign_covenant_candidate(
    tx: &mut Transaction,
    context: &mut SigningContext,
    request: CovenantCandidateRequest<'_>,
) -> Result<bool, PsktError> {
    for seed_index in 0..context.seed_count() {
        if !seed_is_active(request.active_seed_index, seed_index) {
            continue;
        }
        let Some(mut material) = covenant_material(context, seed_index, request.target) else {
            continue;
        };
        let signature = super::sign_input_with_optional_entropy(
            tx,
            request.input_index,
            &material.private_key,
            request.sighash_type,
            request.signing_entropy,
        )?;
        zeroize_bytes(&mut material.private_key);
        set_single_signature(
            &mut tx.inputs[request.input_index],
            signature,
            request.sighash_type.to_byte(),
            request.candidate_index as u8,
            material.compressed_public_key,
        );
        return Ok(true);
    }
    Ok(false)
}

fn seed_is_active(active_seed_index: Option<usize>, seed_index: usize) -> bool {
    active_seed_index.is_none() || active_seed_index == Some(seed_index)
}

fn covenant_material(
    context: &mut SigningContext,
    seed_index: usize,
    target: &[u8; 32],
) -> Option<super::context::SigningKeyMaterial> {
    if context.account_xonly(seed_index) == Some(*target) {
        context.account_material(seed_index)
    } else {
        context.cached_address_material(seed_index, target)
    }
}
