//! Signature-script materialization from a verified witness plan.

use super::{VerifiedSignature, VerifiedWitnessPlan};
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

impl VerifiedWitnessPlan {
    /// Serialize exactly the witness plan that was authorized. No source JSON or
    /// KSPT bytes are consulted here.
    pub fn materialize_signature_script(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::P2pk { signature } => materialize_p2pk(signature),
            Self::Multisig {
                threshold,
                signatures,
                redeem_script,
            } => materialize_multisig(*threshold, signatures, redeem_script),
            Self::Covenant {
                signature,
                redeem_script,
                supplied_mask,
                supplied_true_mask,
            } => materialize_covenant(
                signature,
                redeem_script,
                *supplied_mask,
                *supplied_true_mask,
            ),
            Self::SpecializedCovenant {
                signature_script,
                supplied_mask,
                supplied_true_mask,
                ..
            } => materialize_specialized(signature_script, *supplied_mask, *supplied_true_mask),
        }
    }
}

pub(crate) fn materialize_p2pk(signature: &VerifiedSignature) -> Result<Vec<u8>, String> {
    let mut script = Vec::with_capacity(66);
    push_signature(&mut script, signature)?;
    Ok(script)
}

pub(crate) fn materialize_multisig(
    threshold: u8,
    signatures: &[VerifiedSignature],
    redeem_script: &[u8],
) -> Result<Vec<u8>, String> {
    if signatures.len() != usize::from(threshold) {
        return Err("verified multisig witness cardinality changed".to_string());
    }
    let mut script = Vec::new();
    for signature in signatures {
        push_signature(&mut script, signature)?;
    }
    push_data(&mut script, redeem_script)?;
    Ok(script)
}

pub(crate) fn materialize_covenant(
    signature: &VerifiedSignature,
    redeem_script: &[u8],
    supplied_mask: u16,
    supplied_true_mask: u16,
) -> Result<Vec<u8>, String> {
    if supplied_mask != 0b1 || supplied_true_mask & !supplied_mask != 0 {
        return Err("verified generic covenant selector plan is invalid".to_string());
    }
    let mut script = Vec::new();
    push_signature(&mut script, signature)?;
    script.push(if supplied_true_mask & 1 != 0 {
        0x51
    } else {
        0x00
    });
    push_data(&mut script, redeem_script)?;
    Ok(script)
}

pub(crate) fn materialize_specialized(
    signature_script: &[u8],
    supplied_mask: u16,
    supplied_true_mask: u16,
) -> Result<Vec<u8>, String> {
    if supplied_true_mask & !supplied_mask != 0 {
        return Err("verified specialized covenant selector plan is invalid".to_string());
    }
    Ok(signature_script.to_vec())
}

/// Push one 64-byte Schnorr signature with its SIGHASH_ALL byte.
pub(crate) fn push_schnorr_signature(
    script: &mut Vec<u8>,
    bytes: &[u8; 64],
    sighash: u8,
) -> Result<(), String> {
    if sighash != crate::transaction::interchange::pskt::schema::SIGHASH_ALL {
        return Err("witness contains unsupported sighash".to_string());
    }
    script.push(65);
    script.extend_from_slice(bytes);
    script.push(sighash);
    Ok(())
}

fn push_signature(script: &mut Vec<u8>, signature: &VerifiedSignature) -> Result<(), String> {
    push_schnorr_signature(script, &signature.bytes, signature.sighash)
}

pub(crate) use crate::transaction::interchange::pskt::scripts::push_data_item as push_data;
