//! Partial-signature collection for relayed PSKT inputs.

use super::{find_pubkey_position, parse_multisig_redeem, InputFields, Value};
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

pub(crate) struct Signature {
    pub position: u8,
    pub bytes: [u8; 64],
}

pub(crate) fn collect_signatures(fields: &InputFields) -> Result<Vec<Signature>, String> {
    if fields.partial_signatures.is_empty() {
        return Ok(Vec::new());
    }
    match fields.redeem_script.as_deref() {
        Some(redeem) if parse_multisig_redeem(redeem).is_some() => {
            collect_multisig_signatures(fields, redeem)
        }
        Some(redeem) => collect_covenant_signatures(fields, redeem),
        None => collect_p2pk_signature(fields),
    }
}

pub(crate) fn collect_multisig_signatures(
    fields: &InputFields,
    redeem: &[u8],
) -> Result<Vec<Signature>, String> {
    let mut signatures = Vec::with_capacity(fields.partial_signatures.len());
    for (public_key, value) in &fields.partial_signatures {
        let position = find_pubkey_position(redeem, public_key).ok_or_else(|| {
            format!("partial-signature pubkey is not in redeem script: {public_key}")
        })?;
        signatures.push(Signature {
            position,
            bytes: decode_signature(value)?,
        });
    }
    sort_unique_signatures(signatures, "duplicate partial-signature position")
}

pub(crate) fn collect_covenant_signatures(
    fields: &InputFields,
    redeem: &[u8],
) -> Result<Vec<Signature>, String> {
    let resolution = crate::contract::covenant::branch::resolve_covenant_branches(redeem)
        .map_err(|error| format!("invalid covenant branch structure: {error:?}"))?;
    let mut signatures = Vec::with_capacity(fields.partial_signatures.len());
    for (public_key, value) in &fields.partial_signatures {
        let key = compressed_xonly(public_key).ok_or_else(|| {
            format!("invalid covenant partial-signature public key: {public_key}")
        })?;
        let position = covenant_signature_position(fields, &resolution, public_key, &key)?;
        signatures.push(Signature {
            position,
            bytes: decode_signature(value)?,
        });
    }
    sort_unique_signatures(signatures, "duplicate covenant partial-signature position")
}

pub(crate) fn covenant_signature_position(
    fields: &InputFields,
    resolution: &crate::contract::covenant::branch::BranchResolution,
    public_key: &str,
    key: &[u8; 32],
) -> Result<u8, String> {
    let result = match fields.covenant_execution {
        Some((mask, truth)) => resolution.position_for_key_with_selectors(key, mask, truth),
        None => resolution.unique_position_for_key(key),
    };
    result.map_err(|error| match error {
        crate::contract::covenant::branch::BranchResolveError::KeyNotFound => {
            format!("covenant partial-signature pubkey is not branch-bound: {public_key}")
        }
        crate::contract::covenant::branch::BranchResolveError::AmbiguousKey => format!(
            "covenant partial-signature pubkey is branch-ambiguous without execution selectors: {public_key}"
        ),
        other => format!("invalid covenant branch binding: {other:?}"),
    })
}

pub(crate) fn sort_unique_signatures(
    mut signatures: Vec<Signature>,
    duplicate_error: &str,
) -> Result<Vec<Signature>, String> {
    signatures.sort_by_key(|entry| entry.position);
    if signatures
        .windows(2)
        .any(|pair| pair[0].position == pair[1].position)
    {
        return Err(duplicate_error.to_string());
    }
    Ok(signatures)
}

pub(crate) fn collect_p2pk_signature(fields: &InputFields) -> Result<Vec<Signature>, String> {
    if fields.partial_signatures.len() != 1 {
        return Err("standard P2PK input must contain exactly one partial signature".to_string());
    }
    let (public_key, value) = fields.partial_signatures.iter().next().ok_or_else(|| {
        "standard P2PK input is missing its required partial signature".to_string()
    })?;
    let key = compressed_xonly(public_key)
        .ok_or_else(|| "P2PK partial-signature public key is malformed".to_string())?;
    if crate::primitives::address::p2pk_xonly(&fields.script_public_key) != Some(key) {
        return Err(
            "P2PK partial-signature public key does not match a canonical P2PK scriptPublicKey"
                .to_string(),
        );
    }
    Ok(vec![Signature {
        position: 0,
        bytes: decode_signature(value)?,
    }])
}

/// The x-only key of a lowercase-hex compressed SEC1 public key.
pub(crate) fn compressed_xonly(public_key_hex: &str) -> Option<[u8; 32]> {
    let x = public_key_hex
        .strip_prefix("02")
        .or_else(|| public_key_hex.strip_prefix("03"))?;
    super::super::wire::decode_lower_hex(x, "compressed public key")
        .ok()?
        .try_into()
        .ok()
}

pub(crate) fn decode_signature(value: &Value) -> Result<[u8; 64], String> {
    let object = value
        .as_object()
        .ok_or_else(|| "partial signature value must be an object".to_string())?;
    let text = match object.get("schnorr") {
        Some(Value::String(text)) if object.len() == 1 => text,
        _ => {
            return Err(
                "partial signature object must contain only the schnorr hex string".to_string(),
            )
        }
    };
    let bytes = super::super::wire::decode_lower_hex(text, "signature")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Schnorr signature must be 64 bytes".to_string())
}
