// Kaspa Portal — KSPT encoding shared by finalized and relay PSKT paths
// License: GPL-3.0

use serde_json::{Map, Value};

use crate::transaction::interchange::pskt::exact_json::parse_exact_u64;
use crate::transaction::interchange::pskt::review::{
    find_pubkey_position_in_redeem, parse_multisig_redeem, parse_spk_hex,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KsptEncodingMode {
    Finalized,
    Relay,
}

pub(crate) fn encode_compact_kspt_input(
    buffer: &mut Vec<u8>,
    input: &Value,
    mode: KsptEncodingMode,
) -> Result<(), String> {
    let object = input.as_object().ok_or_else(|| "not object".to_string())?;
    let fields = InputFields::parse(object)?;
    let signatures = collect_signatures(
        &fields.script_public_key,
        fields.redeem_script.as_deref(),
        &fields.partial_signatures,
        mode,
    )?;

    buffer.extend_from_slice(&fields.previous_tx_id);
    buffer.extend_from_slice(&fields.previous_index.to_le_bytes());
    buffer.extend_from_slice(&fields.amount.to_le_bytes());
    buffer.extend_from_slice(&fields.sequence.to_le_bytes());
    buffer.push(fields.sig_op_count);
    buffer.extend_from_slice(&fields.script_version.to_le_bytes());
    push_spk_len(buffer, fields.script_public_key.len());
    buffer.extend_from_slice(&fields.script_public_key);

    // Signature collection is bounded by the standard M-of-N parser (N <= 16)
    // or a single-path signature, so the wire count always fits in u8.
    buffer.push(signatures.len() as u8);
    for signature in signatures {
        buffer.push(signature.pubkey_position);
        buffer.push(0x01); // SIGHASH_ALL
        buffer.extend_from_slice(&signature.bytes);
    }

    match fields.redeem_script {
        Some(redeem_script) => {
            if redeem_script.len() > 1024 {
                return Err(format!(
                    "redeem too long for compact KSPT ({} > 1024)",
                    redeem_script.len()
                ));
            }
            buffer.extend_from_slice(&(redeem_script.len() as u16).to_le_bytes());
            buffer.extend_from_slice(&redeem_script);
        }
        None => buffer.extend_from_slice(&0u16.to_le_bytes()),
    }

    Ok(())
}

pub(crate) fn encode_output_kspt(buffer: &mut Vec<u8>, output: &Value) -> Result<(), String> {
    let object = output.as_object().ok_or_else(|| "not object".to_string())?;
    let value = parse_exact_u64(
        object
            .get("amount")
            .ok_or_else(|| "missing amount".to_string())?,
        "amount",
    )?;
    let script_public_key = object
        .get("scriptPublicKey")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (script_version, script) = parse_spk_hex(script_public_key)?;
    if script.len() > 512 {
        return Err(format!("output spk too long ({} > 512)", script.len()));
    }

    buffer.extend_from_slice(&value.to_le_bytes());
    buffer.extend_from_slice(&script_version.to_le_bytes());
    push_spk_len(buffer, script.len());
    buffer.extend_from_slice(&script);
    Ok(())
}

struct InputFields {
    previous_tx_id: [u8; 32],
    previous_index: u32,
    amount: u64,
    sequence: u64,
    sig_op_count: u8,
    script_version: u16,
    script_public_key: Vec<u8>,
    redeem_script: Option<Vec<u8>>,
    partial_signatures: Map<String, Value>,
}

impl InputFields {
    fn parse(object: &Map<String, Value>) -> Result<Self, String> {
        let (amount, script_version, script_public_key) = parse_utxo_fields(object)?;
        let (previous_tx_id, previous_index) = parse_outpoint_fields(object)?;
        Ok(Self {
            previous_tx_id,
            previous_index,
            amount,
            sequence: parse_optional_exact(object, "sequence", 0)?,
            sig_op_count: object
                .get("sigOpCount")
                .and_then(Value::as_u64)
                .unwrap_or(1) as u8,
            script_version,
            script_public_key,
            redeem_script: parse_redeem_script(object)?,
            partial_signatures: object
                .get("partialSigs")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default(),
        })
    }
}

fn parse_utxo_fields(object: &Map<String, Value>) -> Result<(u64, u16, Vec<u8>), String> {
    let utxo = object
        .get("utxoEntry")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing utxoEntry".to_string())?;
    let amount = parse_exact_u64(
        utxo.get("amount")
            .ok_or_else(|| "missing amount".to_string())?,
        "amount",
    )?;
    let script_public_key = utxo
        .get("scriptPublicKey")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing scriptPublicKey".to_string())?;
    let (script_version, script_public_key) = parse_spk_hex(script_public_key)?;
    if script_public_key.len() > 512 {
        return Err(format!(
            "spk too long for compact KSPT ({} > 512)",
            script_public_key.len()
        ));
    }
    Ok((amount, script_version, script_public_key))
}

fn parse_outpoint_fields(object: &Map<String, Value>) -> Result<([u8; 32], u32), String> {
    let outpoint = object
        .get("previousOutpoint")
        .and_then(Value::as_object)
        .ok_or_else(|| "missing previousOutpoint".to_string())?;
    let transaction_id = outpoint
        .get("transactionId")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing transactionId".to_string())?;
    let transaction_id = hex::decode(transaction_id).map_err(|e| format!("bad tx_id hex: {e}"))?;
    if transaction_id.len() != 32 {
        return Err("tx_id not 32 bytes".into());
    }
    let mut previous_tx_id = [0u8; 32];
    previous_tx_id.copy_from_slice(&transaction_id);
    let previous_index = outpoint
        .get("index")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing index".to_string())?;
    let previous_index =
        u32::try_from(previous_index).map_err(|_| "index exceeds u32".to_string())?;
    Ok((previous_tx_id, previous_index))
}

fn parse_optional_exact(
    object: &Map<String, Value>,
    field: &str,
    default: u64,
) -> Result<u64, String> {
    object
        .get(field)
        .map_or(Ok(default), |value| parse_exact_u64(value, field))
}

fn parse_redeem_script(object: &Map<String, Value>) -> Result<Option<Vec<u8>>, String> {
    match object.get("redeemScript").and_then(Value::as_str) {
        Some(value) => hex::decode(value)
            .map(Some)
            .map_err(|e| format!("redeem hex: {e}")),
        None => Ok(None),
    }
}

pub(crate) struct EncodedSignature {
    pub(crate) pubkey_position: u8,
    pub(crate) bytes: [u8; 64],
}

pub(crate) fn collect_signatures(
    script_public_key: &[u8],
    redeem_script: Option<&[u8]>,
    partial_signatures: &Map<String, Value>,
    mode: KsptEncodingMode,
) -> Result<Vec<EncodedSignature>, String> {
    if is_p2sh_script(script_public_key) {
        if let Some(redeem_script) = redeem_script {
            return collect_p2sh_signatures(redeem_script, partial_signatures, mode);
        }
    }
    collect_single_path_signature(partial_signatures, mode)
}

fn is_p2sh_script(script_public_key: &[u8]) -> bool {
    script_public_key.len() == 35
        && script_public_key.first() == Some(&0xAA)
        && script_public_key.get(1) == Some(&0x20)
        && script_public_key.get(34) == Some(&0x87)
}

fn collect_p2sh_signatures(
    redeem_script: &[u8],
    partial_signatures: &Map<String, Value>,
    mode: KsptEncodingMode,
) -> Result<Vec<EncodedSignature>, String> {
    if mode == KsptEncodingMode::Finalized && redeem_script.first() == Some(&0x63) {
        return collect_finalized_covenant_signature(redeem_script, partial_signatures);
    }
    if let Some((required, _)) = parse_multisig_redeem(redeem_script) {
        return collect_checked_multisig(redeem_script, partial_signatures, mode, required);
    }
    if mode == KsptEncodingMode::Relay {
        return Ok(Vec::new());
    }
    Err("redeem is not a valid M-of-N multisig".into())
}

fn collect_checked_multisig(
    redeem_script: &[u8],
    partial_signatures: &Map<String, Value>,
    mode: KsptEncodingMode,
    required: u8,
) -> Result<Vec<EncodedSignature>, String> {
    let signatures = collect_multisig_signatures(redeem_script, partial_signatures)?;
    if mode == KsptEncodingMode::Finalized && signatures.len() < required as usize {
        return Err(format!(
            "multisig not ready: {} sig(s) present, need {}",
            signatures.len(),
            required
        ));
    }
    Ok(signatures)
}

fn collect_single_path_signature(
    partial_signatures: &Map<String, Value>,
    mode: KsptEncodingMode,
) -> Result<Vec<EncodedSignature>, String> {
    match partial_signatures.iter().next() {
        Some((_, signature)) => Ok(vec![EncodedSignature {
            pubkey_position: 0,
            bytes: decode_signature(
                signature,
                "partial sig missing schnorr variant (ECDSA unsupported)",
            )?,
        }]),
        None if mode == KsptEncodingMode::Relay => Ok(Vec::new()),
        None => Err("input has no signature".into()),
    }
}

pub(crate) fn collect_finalized_covenant_signature(
    redeem_script: &[u8],
    partial_signatures: &Map<String, Value>,
) -> Result<Vec<EncodedSignature>, String> {
    let (public_key, signature) = partial_signatures
        .iter()
        .next()
        .ok_or_else(|| "covenant input has no signature".to_string())?;
    let xonly_public_key = if public_key.len() == 66 {
        &public_key[2..]
    } else {
        public_key.as_str()
    };
    let owner_public_key = if redeem_script.len() >= 34 && redeem_script[1] == 0x20 {
        Some(hex::encode(&redeem_script[2..34]))
    } else {
        None
    };
    let pubkey_position = u8::from(owner_public_key.as_deref() != Some(xonly_public_key));
    Ok(vec![EncodedSignature {
        pubkey_position,
        bytes: decode_signature(signature, "partial sig missing schnorr variant")?,
    }])
}

fn collect_multisig_signatures(
    redeem_script: &[u8],
    partial_signatures: &Map<String, Value>,
) -> Result<Vec<EncodedSignature>, String> {
    let mut signatures = Vec::with_capacity(partial_signatures.len());
    for (public_key, signature) in partial_signatures {
        if public_key.len() != 66 {
            continue;
        }
        let pubkey_position = find_pubkey_position_in_redeem(redeem_script, public_key)
            .ok_or_else(|| format!("pubkey not in redeem: {}", public_key))?;
        signatures.push(EncodedSignature {
            pubkey_position,
            bytes: decode_signature(
                signature,
                "partial sig missing schnorr variant (ECDSA unsupported)",
            )?,
        });
    }
    signatures.sort_by_key(|signature| signature.pubkey_position);
    Ok(signatures)
}

fn decode_signature(value: &Value, missing_message: &str) -> Result<[u8; 64], String> {
    let signature_hex = value
        .get("schnorr")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_message.to_string())?;
    if signature_hex.len() != 128 {
        return Err(format!("bad sig length: {}", signature_hex.len()));
    }
    let signature = hex::decode(signature_hex).map_err(|e| format!("sig hex: {}", e))?;
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&signature);
    Ok(bytes)
}

/// SPK length, extended encoding: len <= 254 -> 1 byte; len >= 255 -> 0xFF + u16 LE.
fn push_spk_len(buffer: &mut Vec<u8>, len: usize) {
    if len <= 254 {
        buffer.push(len as u8);
    } else {
        buffer.push(0xFF);
        buffer.extend_from_slice(&(len as u16).to_le_bytes());
    }
}

#[cfg(test)]
#[path = "encoder/unit-tests/mod.rs"]
mod unit_tests;
