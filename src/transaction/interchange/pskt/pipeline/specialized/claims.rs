//! Witness construction for each specialized covenant claim route.

use super::super::verified::witness::push_data;
use super::{
    parse_merkle_proof, recognize_commit_reveal, recognize_merkle, recognize_oracle_v1,
    recognize_private_swap, CommitTemplate, Input, K256Signature, Map, MerkleProofItem,
    MerkleTemplate, OracleTemplate, Params, Signature, SpecializedRoute, Value, VerifyingKey, OP_0,
    OP_1,
};
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

pub(crate) fn bind_private_swap(
    index: usize,
    fields: &Map<String, Value>,
    input: &Input,
    mask: u16,
    truth: u16,
    signature: &Signature,
) -> Result<(SpecializedRoute, Vec<u8>), String> {
    require_true(fields, "privateSwapClaim", index)?;
    recognize_private_swap(&input.redeem)
        .map_err(|error| format!("input[{index}] private-swap template mismatch: {error}"))?;
    if mask != 0b1 || truth != 0b1 {
        return Err(format!(
            "input[{index}] private-swap claim requires covenantExecution 1/1"
        ));
    }
    let mut script = Vec::new();
    push_signature(&mut script, signature)?;
    script.push(OP_1);
    push_data(&mut script, &input.redeem)?;
    Ok((SpecializedRoute::PrivateSwapClaim, script))
}

pub(crate) fn bind_oracle_v1(
    index: usize,
    fields: &Map<String, Value>,
    input: &Input,
    mask: u16,
    truth: u16,
    signature: &Signature,
) -> Result<(SpecializedRoute, Vec<u8>), String> {
    require_true(fields, "oracleV1Claim", index)?;
    let oracle_signature = required_hex(fields, "oracleV1Signature", Some(64), index)?;
    let template = recognize_oracle_v1(&input.redeem)
        .map_err(|error| format!("input[{index}] oracle-v1 template mismatch: {error}"))?;
    validate_oracle_execution(index, mask, truth)?;
    let oracle_signature = verify_oracle_attestation(index, &template, &oracle_signature)?;
    let script = oracle_claim_script(&oracle_signature, signature, &input.redeem)?;
    Ok((SpecializedRoute::OracleV1Claim, script))
}

pub(crate) fn validate_oracle_execution(index: usize, mask: u16, truth: u16) -> Result<(), String> {
    if mask != 0b1 || truth != 0 {
        return Err(format!(
            "input[{index}] oracle-v1 claim requires covenantExecution 1/0"
        ));
    }
    Ok(())
}

pub(crate) fn verify_oracle_attestation(
    index: usize,
    template: &OracleTemplate,
    signature: &[u8],
) -> Result<K256Signature, String> {
    let key = VerifyingKey::from_bytes(&template.oracle_key)
        .map_err(|_| format!("input[{index}] oracle-v1 embedded oracle key is invalid"))?;
    let signature = K256Signature::try_from(signature).map_err(|_| {
        format!("input[{index}] oracle-v1 attestation signature encoding is invalid")
    })?;
    key.verify_raw(&template.commitment, &signature)
        .map_err(|_| format!("input[{index}] oracle-v1 attestation signature is invalid"))?;
    Ok(signature)
}

pub(crate) fn oracle_claim_script(
    oracle_signature: &K256Signature,
    signature: &Signature,
    redeem: &[u8],
) -> Result<Vec<u8>, String> {
    let mut script = Vec::new();
    push_data(&mut script, oracle_signature.to_bytes().as_slice())?;
    push_signature(&mut script, signature)?;
    script.push(OP_0);
    push_data(&mut script, redeem)?;
    Ok(script)
}

pub(crate) fn bind_commit_reveal(
    index: usize,
    fields: &Map<String, Value>,
    input: &Input,
    mask: u16,
    truth: u16,
    signature: &Signature,
) -> Result<(SpecializedRoute, Vec<u8>), String> {
    let (part_a, part_b) = commit_reveal_parts(fields, index)?;
    let template = recognize_commit_reveal(&input.redeem)
        .map_err(|error| format!("input[{index}] commit-reveal template mismatch: {error}"))?;
    validate_commit_reveal_claim(index, mask, truth, &part_a, &part_b, &template)?;
    let script = commit_reveal_claim_script(&part_a, &part_b, signature, &input.redeem)?;
    Ok((SpecializedRoute::CommitRevealClaim, script))
}

pub(crate) fn commit_reveal_parts(
    fields: &Map<String, Value>,
    index: usize,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let part_a = required_hex(fields, "commitPartA", None, index)?;
    let part_b = required_hex(fields, "commitPartB", None, index)?;
    Ok((part_a, part_b))
}

pub(crate) fn validate_commit_reveal_claim(
    index: usize,
    mask: u16,
    truth: u16,
    part_a: &[u8],
    part_b: &[u8],
    template: &CommitTemplate,
) -> Result<(), String> {
    if mask != 0b1 || truth != 0 {
        return Err(format!(
            "input[{index}] commit-reveal claim requires covenantExecution 1/0"
        ));
    }
    let mut preimage = Vec::with_capacity(part_a.len() + part_b.len());
    preimage.extend_from_slice(part_a);
    preimage.extend_from_slice(part_b);
    if blake2b32(&preimage) != template.commitment {
        return Err(format!(
            "input[{index}] commit-reveal preimage does not match redeem commitment"
        ));
    }
    Ok(())
}

pub(crate) fn commit_reveal_claim_script(
    part_a: &[u8],
    part_b: &[u8],
    signature: &Signature,
    redeem: &[u8],
) -> Result<Vec<u8>, String> {
    let mut script = Vec::new();
    push_data(&mut script, part_a)?;
    push_data(&mut script, part_b)?;
    push_signature(&mut script, signature)?;
    script.push(OP_0);
    push_data(&mut script, redeem)?;
    Ok(script)
}

pub(crate) fn bind_merkle(
    index: usize,
    fields: &Map<String, Value>,
    input: &Input,
    mask: u16,
    truth: u16,
    signature: &Signature,
) -> Result<(SpecializedRoute, Vec<u8>), String> {
    let dest_spk = required_hex(fields, "merkleDestSpk", None, index)?;
    let proof = parse_merkle_proof(fields.get("merkleProof"), index)?;
    let template = recognize_merkle(&input.redeem)
        .map_err(|error| format!("input[{index}] merkle template mismatch: {error}"))?;
    validate_merkle_claim(index, &proof, &template, mask, truth)?;
    verify_merkle_root(index, &dest_spk, &proof, template.root)?;
    let script = build_merkle_witness(&dest_spk, &proof, signature, &input.redeem)?;
    Ok((SpecializedRoute::MerkleClaim, script))
}

pub(crate) fn validate_merkle_claim(
    index: usize,
    proof: &[MerkleProofItem],
    template: &MerkleTemplate,
    mask: u16,
    truth: u16,
) -> Result<(), String> {
    if proof.len() != usize::from(template.depth) {
        return Err(format!(
            "input[{index}] merkle proof depth {} does not match redeem depth {}",
            proof.len(),
            template.depth
        ));
    }
    // The claim branch selector plus one direction selector per level.
    let expected_mask = u16::MAX >> (15 - template.depth);
    if mask != expected_mask {
        return Err(format!(
            "input[{index}] merkle covenantExecution does not select the claim branch"
        ));
    }
    if truth != merkle_truth_from_proof(proof) {
        return Err(format!(
            "input[{index}] merkle proof directions do not match covenantExecution"
        ));
    }
    Ok(())
}

/// The true-selector bits the proof directions imply: bit 0 (the claim
/// branch) stays false and level `n` sets bit `n + 1`. Proofs are at most 15
/// levels deep, so every bit fits.
pub(crate) fn merkle_truth_from_proof(proof: &[MerkleProofItem]) -> u16 {
    proof.iter().enumerate().fold(0, |truth, (level, item)| {
        truth + (u16::from(item.direction) << (level + 1))
    })
}

pub(crate) fn verify_merkle_root(
    index: usize,
    dest_spk: &[u8],
    proof: &[MerkleProofItem],
    expected_root: [u8; 32],
) -> Result<(), String> {
    let mut current = blake2b32(dest_spk);
    for item in proof {
        current = merkle_step(current, item);
    }
    if current != expected_root {
        return Err(format!(
            "input[{index}] merkle proof does not match redeem root"
        ));
    }
    Ok(())
}

pub(crate) fn merkle_step(current: [u8; 32], item: &MerkleProofItem) -> [u8; 32] {
    let mut pair = [0u8; 64];
    if item.direction == 1 {
        pair[..32].copy_from_slice(&current);
        pair[32..].copy_from_slice(&item.sibling);
    } else {
        pair[..32].copy_from_slice(&item.sibling);
        pair[32..].copy_from_slice(&current);
    }
    blake2b32(&pair)
}

pub(crate) fn build_merkle_witness(
    dest_spk: &[u8],
    proof: &[MerkleProofItem],
    signature: &Signature,
    redeem: &[u8],
) -> Result<Vec<u8>, String> {
    let mut script = Vec::new();
    push_data(&mut script, dest_spk)?;
    for item in proof.iter().rev() {
        push_data(&mut script, &item.sibling)?;
        script.push(if item.direction == 0 { OP_0 } else { OP_1 });
    }
    push_data(&mut script, dest_spk)?;
    push_signature(&mut script, signature)?;
    script.push(OP_0);
    push_data(&mut script, redeem)?;
    Ok(script)
}

pub(crate) fn require_true(
    fields: &Map<String, Value>,
    key: &str,
    index: usize,
) -> Result<(), String> {
    match fields.get(key) {
        Some(Value::Bool(true)) => Ok(()),
        _ => Err(format!("input[{index}].proprietaries.{key} must be true")),
    }
}

pub(crate) fn required_hex(
    fields: &Map<String, Value>,
    key: &str,
    exact_len: Option<usize>,
    index: usize,
) -> Result<Vec<u8>, String> {
    let text = fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("input[{index}].proprietaries.{key} must be lowercase hex"))?;
    let decoded =
        super::super::wire::decode_lower_hex(text, &format!("input[{index}].proprietaries.{key}"))?;
    if exact_len.is_some_and(|length| decoded.len() != length) {
        return Err(format!(
            "input[{index}].proprietaries.{key} must be {} bytes",
            exact_len.unwrap_or_default()
        ));
    }
    Ok(decoded)
}

pub(crate) fn exactly_one_signature(
    index: usize,
    signatures: &[Signature],
) -> Result<&Signature, String> {
    match signatures {
        [signature] => Ok(signature),
        _ => Err(format!(
            "input[{index}] typed specialized covenant requires exactly one verified transaction signature"
        )),
    }
}

fn push_signature(script: &mut Vec<u8>, signature: &Signature) -> Result<(), String> {
    super::super::verified::witness::push_schnorr_signature(
        script,
        &signature.bytes,
        signature.sighash,
    )
}

pub(crate) fn blake2b32(data: &[u8]) -> [u8; 32] {
    let hash = Params::new().hash_length(32).hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}
