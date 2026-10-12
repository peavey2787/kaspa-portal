//! Redeem-script and MuSig-45 path parsing for relayed PSKT inputs.

use super::{compressed_xonly, Value};
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

/// `(threshold, keys)` of a multisig redeem script within signer capacity.
pub(crate) fn parse_multisig_redeem(script: &[u8]) -> Option<(u8, u8)> {
    crate::primitives::multisig_script::parse(script)
        .filter(|parsed| {
            usize::from(parsed.key_count()) <= crate::transaction::model::MAX_MULTISIG_KEYS
        })
        .map(|parsed| (parsed.threshold(), parsed.key_count()))
}

pub(crate) fn find_pubkey_position(redeem: &[u8], public_key_hex: &str) -> Option<u8> {
    let xonly = compressed_xonly(public_key_hex)?;
    crate::primitives::multisig_script::parse(redeem)?.position_of(&xonly)
}

pub(crate) fn parse_ms45(value: &Value) -> Result<Option<(u32, u32, u32)>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let map = value
        .as_object()
        .ok_or_else(|| "bip32Derivations must be an object or null".to_string())?;
    let mut parsed = None;
    for entry in map.values() {
        if let Some(candidate) = parse_ms45_entry(entry)? {
            merge_ms45_candidate(&mut parsed, candidate)?;
        }
    }
    Ok(parsed)
}

pub(crate) fn parse_ms45_entry(entry: &Value) -> Result<Option<(u32, u32, u32)>, String> {
    // A key listed without a key source (rusty-kaspa `Option<KeySource>`)
    // names no derivation path; signers record their key this way.
    if entry.is_null() {
        return Ok(None);
    }
    let path = entry
        .get("derivationPath")
        .and_then(Value::as_str)
        .ok_or_else(|| "bip32Derivations entry is missing derivationPath".to_string())?;
    let Some(tail) = path.strip_prefix("m/45'/111111'/0'/") else {
        return Ok(None);
    };
    let mut parts = tail.split('/');
    let cosigner = parse_ms45_part(&mut parts, "cosigner", None)?;
    let chain = parse_ms45_part(&mut parts, "chain", Some(1))?;
    let index = parse_ms45_part(&mut parts, "index", None)?;
    if parts.next().is_some() {
        return Err("MS45 path has trailing components".to_string());
    }
    Ok(Some((cosigner, chain, index)))
}

pub(crate) fn parse_ms45_part<'a, I>(
    parts: &mut I,
    label: &str,
    maximum: Option<u32>,
) -> Result<u32, String>
where
    I: Iterator<Item = &'a str>,
{
    let value = parts
        .next()
        .ok_or_else(|| format!("MS45 path missing {label}"))?;
    let parsed = parse_soft(value).ok_or_else(|| format!("MS45 {label} must be non-hardened"))?;
    if maximum.is_some_and(|limit| parsed > limit) {
        return Err("MS45 chain must be 0 or 1".to_string());
    }
    Ok(parsed)
}

pub(crate) fn merge_ms45_candidate(
    parsed: &mut Option<(u32, u32, u32)>,
    candidate: (u32, u32, u32),
) -> Result<(), String> {
    match parsed {
        Some(existing) if *existing != candidate => {
            Err("bip32Derivations contain conflicting MS45 paths".to_string())
        }
        Some(_) => Ok(()),
        None => {
            *parsed = Some(candidate);
            Ok(())
        }
    }
}

pub(crate) fn parse_soft(value: &str) -> Option<u32> {
    if value.ends_with('\'') {
        return None;
    }
    let parsed = value.parse::<u32>().ok()?;
    (parsed < 0x8000_0000).then_some(parsed)
}
