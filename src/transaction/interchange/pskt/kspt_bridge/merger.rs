// Kaspa Portal — signed KSPT merge into PSKT / PSKB
// License: GPL-3.0

use serde_json::{Map, Value};

use super::{parse_compact_kspt_signatures, xonly_at_position, KsptSigRecord};
use crate::transaction::interchange::pskt::wire::{decode_root, encode_root, pskt_from_root_mut};
use crate::transaction::interchange::pskt::PsktFormat;

pub fn merge_signed_kspt_into_pskb(
    signed_kspt_hex: &str,
    pskb_wire_hex: &str,
) -> Result<String, String> {
    let kspt = decode_signed_kspt_bytes(signed_kspt_hex)?;
    validate_compact_version(&kspt)?;
    let (format, mut root) = decode_root(pskb_wire_hex)?;
    merge_compact_root(&mut root, format, &kspt)?;
    encode_root(format, &root).map_err(|error| format!("re-serialize: {}", error))
}

fn decode_signed_kspt_bytes(signed_kspt_hex: &str) -> Result<Vec<u8>, String> {
    hex::decode(signed_kspt_hex).map_err(|error| format!("KSPT hex: {error}"))
}

fn validate_compact_version(kspt: &[u8]) -> Result<(), String> {
    let version = *kspt
        .get(4)
        .ok_or_else(|| "KSPT blob too short".to_string())?;
    if version != 0x01 {
        return Err(format!("unsupported compact KSPT version: 0x{version:02x}"));
    }
    Ok(())
}

fn merge_compact_root(root: &mut Value, format: PsktFormat, kspt: &[u8]) -> Result<(), String> {
    let object_error = pskt_object_error(format);
    let inputs = pskt_from_root_mut(root, format)?
        .as_object_mut()
        .ok_or_else(|| object_error.to_string())?
        .get_mut("inputs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "missing inputs".to_string())?;
    merge_compact_inputs(inputs, kspt)
}

fn pskt_object_error(format: PsktFormat) -> &'static str {
    match format {
        PsktFormat::Pskb => "PSKB entry not object",
        PsktFormat::PsktSingle => "PSKT not object",
        PsktFormat::Unknown => "unknown PSKT format",
    }
}

fn merge_compact_inputs(inputs: &mut [Value], kspt: &[u8]) -> Result<(), String> {
    let signatures = parse_compact_kspt_signatures(kspt)?;
    validate_input_count(inputs.len(), signatures.len())?;
    for (index, input_signatures) in signatures.iter().enumerate() {
        merge_compact_input(&mut inputs[index], input_signatures, index)?;
    }
    Ok(())
}

fn validate_input_count(pskb_count: usize, kspt_count: usize) -> Result<(), String> {
    if pskb_count == kspt_count {
        Ok(())
    } else {
        Err(format!(
            "input count mismatch: PSKB has {pskb_count}, compact KSPT has {kspt_count}"
        ))
    }
}

fn merge_compact_input(
    value: &mut Value,
    signatures: &[KsptSigRecord],
    index: usize,
) -> Result<(), String> {
    if signatures.is_empty() {
        return Ok(());
    }
    let input = value
        .as_object_mut()
        .ok_or_else(|| format!("input[{index}] not object"))?;
    validate_signature_sighashes(signatures, index)?;
    match input
        .get("redeemScript")
        .and_then(Value::as_str)
        .map(str::to_string)
    {
        Some(redeem_hex) => merge_redeem_signatures(input, signatures, index, &redeem_hex),
        None => merge_p2pk_signature(input, &signatures[0], index),
    }
}

fn merge_redeem_signatures(
    input: &mut Map<String, Value>,
    signatures: &[KsptSigRecord],
    index: usize,
    redeem_hex: &str,
) -> Result<(), String> {
    decode_redeem_script(redeem_hex, index)
        .and_then(|redeem| merge_decoded_redeem_signatures(input, signatures, index, &redeem))
}

fn decode_redeem_script(redeem_hex: &str, index: usize) -> Result<Vec<u8>, String> {
    hex::decode(redeem_hex).map_err(|error| format!("input[{index}] redeem hex: {error}"))
}

fn merge_decoded_redeem_signatures(
    input: &mut Map<String, Value>,
    signatures: &[KsptSigRecord],
    index: usize,
    redeem: &[u8],
) -> Result<(), String> {
    partial_signatures_mut(input).and_then(|partial_signatures| {
        signatures.iter().try_for_each(|signature| {
            merge_redeem_signature(partial_signatures, redeem, signature, index)
        })
    })
}

fn merge_redeem_signature(
    partial_signatures: &mut Map<String, Value>,
    redeem: &[u8],
    signature: &KsptSigRecord,
    index: usize,
) -> Result<(), String> {
    let xonly_public_key = xonly_at_position(redeem, signature.pubkey_pos).ok_or_else(|| {
        format!(
            "input[{index}] pubkey_pos {} out of range for redeem",
            signature.pubkey_pos
        )
    })?;
    let public_key = format!("02{}", hex::encode(xonly_public_key));
    insert_signature(partial_signatures, public_key, &signature.sig);
    Ok(())
}

fn validate_signature_sighashes(
    signatures: &[KsptSigRecord],
    input_index: usize,
) -> Result<(), String> {
    for signature in signatures {
        if signature.sighash_type != 0x01 {
            return Err(format!(
                "input[{}] signed KSPT changed sighash type to 0x{:02x}",
                input_index, signature.sighash_type
            ));
        }
    }
    Ok(())
}

fn merge_p2pk_signature(
    input: &mut Map<String, Value>,
    record: &KsptSigRecord,
    input_index: usize,
) -> Result<(), String> {
    let utxo = input
        .get("utxoEntry")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("input[{}] missing utxoEntry", input_index))?;
    let script_public_key = utxo
        .get("scriptPublicKey")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("input[{}] missing scriptPublicKey", input_index))?;
    if script_public_key.len() < 72 {
        return Err(format!(
            "input[{}] scriptPublicKey too short for P2PK",
            input_index
        ));
    }
    let script = hex::decode(&script_public_key[4..])
        .map_err(|error| format!("input[{}] spk hex: {}", input_index, error))?;
    if script.len() != 34 || script[0] != 0x20 || script[33] != 0xac {
        return Err(format!("input[{}] spk is not P2PK", input_index));
    }
    let public_key = format!("02{}", hex::encode(&script[1..33]));
    let partial_signatures = partial_signatures_mut(input)?;
    insert_signature(partial_signatures, public_key, &record.sig);
    Ok(())
}

fn partial_signatures_mut(
    input: &mut Map<String, Value>,
) -> Result<&mut Map<String, Value>, String> {
    if !matches!(input.get("partialSigs"), Some(Value::Object(_))) {
        input.insert("partialSigs".to_string(), Value::Object(Map::new()));
    }
    input
        .get_mut("partialSigs")
        .and_then(Value::as_object_mut)
        .ok_or("partialSigs normalization failed".to_string())
}

fn insert_signature(
    partial_signatures: &mut Map<String, Value>,
    public_key: String,
    signature: &[u8; 64],
) {
    if partial_signatures.contains_key(&public_key) {
        return;
    }
    let mut signature_object = Map::new();
    signature_object.insert("schnorr".to_string(), Value::String(hex::encode(signature)));
    partial_signatures.insert(public_key, Value::Object(signature_object));
}

#[cfg(test)]
#[path = "merger/unit-tests/mod.rs"]
mod unit_tests;
