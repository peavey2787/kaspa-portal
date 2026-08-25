// Kaspa Portal — partial PSKB to KSPT relay
// License: GPL-3.0

use serde_json::{Map, Value};

use super::{encode_compact_kspt_input, encode_output_kspt, KsptEncodingMode};
use crate::primitives::NetworkId;
use crate::transaction::interchange::pskt::exact_json::parse_exact_u64;
use crate::transaction::interchange::pskt::review::parse_spk_hex;
use crate::transaction::interchange::pskt::scripts::compute_genesis_covenant_id;
use crate::transaction::interchange::pskt::wire::{decode_root, pskt_from_root};

pub fn relay_pskb_as_kspt_hex_for_network(wire_hex: &str, network: &str) -> Result<String, String> {
    let (format, root) = decode_root(wire_hex)?;
    relay_decoded_root(&root, format, network)
}

fn relay_decoded_root(
    root: &Value,
    format: crate::transaction::interchange::pskt::model::PsktFormat,
    network: &str,
) -> Result<String, String> {
    pskt_from_root(root, format).and_then(|pskt| relay_pskt_value(pskt, network))
}

fn relay_pskt_value(pskt: &Value, network: &str) -> Result<String, String> {
    pskt.as_object()
        .ok_or("PSKT not object".to_string())
        .and_then(|document| relay_document(document, network))
}

fn relay_document(document: &Map<String, Value>, network: &str) -> Result<String, String> {
    relay_sections(document, network).and_then(|sections| {
        encode_relay_document(
            sections.global,
            sections.inputs,
            sections.outputs,
            sections.network_code,
        )
    })
}

struct RelaySections<'a> {
    global: &'a Map<String, Value>,
    inputs: &'a [Value],
    outputs: &'a [Value],
    network_code: u8,
}

fn relay_sections<'a>(
    document: &'a Map<String, Value>,
    network: &str,
) -> Result<RelaySections<'a>, String> {
    global_field(document).and_then(|global| {
        array_field(document, "inputs").and_then(|inputs| {
            array_field(document, "outputs").and_then(|outputs| {
                validate_counts(inputs, outputs).and_then(|()| {
                    parse_network_code(network).map(|network_code| RelaySections {
                        global,
                        inputs,
                        outputs,
                        network_code,
                    })
                })
            })
        })
    })
}

fn global_field(document: &Map<String, Value>) -> Result<&Map<String, Value>, String> {
    document
        .get("global")
        .and_then(Value::as_object)
        .ok_or("missing global".to_string())
}

fn encode_relay_document(
    global: &Map<String, Value>,
    inputs: &[Value],
    outputs: &[Value],
    network_code: u8,
) -> Result<String, String> {
    encode_transaction(global, inputs, outputs).and_then(|mut buffer| {
        append_network(&mut buffer, network_code);
        append_ms45_hints(&mut buffer, inputs, outputs);
        append_stealth_tweak(&mut buffer, inputs);
        append_derived_covenant_binding(&mut buffer, inputs, outputs);
        append_explicit_covenant_bindings(&mut buffer, outputs).map(|()| {
            append_derivation_hints(&mut buffer, outputs);
            hex::encode(buffer)
        })
    })
}

const MAX_TX_VERSION: u16 = 1;

#[derive(Debug)]
struct GlobalEncodingFields {
    tx_version: u16,
    locktime: u64,
    subnetwork_id: [u8; 20],
    gas: u64,
    payload: Vec<u8>,
}

fn encode_transaction(
    global: &Map<String, Value>,
    inputs: &[Value],
    outputs: &[Value],
) -> Result<Vec<u8>, String> {
    let fields = parse_global_encoding_fields(global)?;
    let mut buffer = encode_transaction_header(&fields, inputs.len(), outputs.len())?;
    encode_inputs(&mut buffer, inputs)?;
    encode_outputs(&mut buffer, outputs)?;
    Ok(buffer)
}

fn parse_global_encoding_fields(
    global: &Map<String, Value>,
) -> Result<GlobalEncodingFields, String> {
    let tx_version = global
        .get("txVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| "missing txVersion".to_string())?;
    let tx_version = u16::try_from(tx_version).map_err(|_| "txVersion exceeds u16".to_string())?;
    if tx_version > MAX_TX_VERSION {
        return Err(format!("unsupported txVersion: {tx_version}"));
    }
    Ok(GlobalEncodingFields {
        tx_version,
        locktime: optional_exact_u64(global, "fallbackLockTime")?,
        subnetwork_id: crate::transaction::interchange::pskt::wire::decode_subnetwork_id(global)?,
        gas: optional_exact_u64(global, "gas")?,
        payload: decode_payload(global),
    })
}

fn optional_exact_u64(global: &Map<String, Value>, key: &str) -> Result<u64, String> {
    match global.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(value) => parse_exact_u64(value, key),
    }
}

fn decode_payload(global: &Map<String, Value>) -> Vec<u8> {
    global
        .get("txPayload")
        .and_then(Value::as_str)
        .and_then(|value| hex::decode(value).ok())
        .unwrap_or_default()
}

fn encode_transaction_header(
    fields: &GlobalEncodingFields,
    input_count: usize,
    output_count: usize,
) -> Result<Vec<u8>, String> {
    let input_count = u32::try_from(input_count).map_err(|_| "too many inputs".to_string())?;
    let output_count = u8::try_from(output_count).map_err(|_| "too many outputs".to_string())?;
    let payload_length = u16::try_from(fields.payload.len())
        .map_err(|_| "transaction payload is too large".to_string())?;
    let mut buffer = Vec::with_capacity(512);
    buffer.extend_from_slice(b"KSPT");
    buffer.push(0x01);
    buffer.push(0x00);
    buffer.extend_from_slice(&fields.tx_version.to_le_bytes());
    buffer.extend_from_slice(&input_count.to_le_bytes());
    buffer.push(output_count);
    buffer.extend_from_slice(&fields.locktime.to_le_bytes());
    buffer.extend_from_slice(&fields.subnetwork_id);
    buffer.extend_from_slice(&fields.gas.to_le_bytes());
    buffer.extend_from_slice(&payload_length.to_le_bytes());
    buffer.extend_from_slice(&fields.payload);
    Ok(buffer)
}

fn encode_inputs(buffer: &mut Vec<u8>, inputs: &[Value]) -> Result<(), String> {
    for (index, input) in inputs.iter().enumerate() {
        encode_compact_kspt_input(buffer, input, KsptEncodingMode::Relay)
            .map_err(|error| format!("input[{}]: {}", index, error))?;
    }
    Ok(())
}

fn encode_outputs(buffer: &mut Vec<u8>, outputs: &[Value]) -> Result<(), String> {
    for (index, output) in outputs.iter().enumerate() {
        encode_output_kspt(buffer, output)
            .map_err(|error| format!("output[{}]: {}", index, error))?;
    }
    Ok(())
}

fn parse_network_code(network: &str) -> Result<u8, String> {
    match NetworkId::parse(network).map_err(|_| format!("unsupported network: {network}"))? {
        NetworkId::Mainnet => Ok(1),
        NetworkId::Testnet(_) => Ok(2),
        NetworkId::Devnet => Ok(3),
        NetworkId::Simnet => Ok(4),
    }
}

fn append_network(buffer: &mut Vec<u8>, network_code: u8) {
    buffer.push(b'N');
    buffer.push(network_code);
}

fn append_derivation_hints(buffer: &mut Vec<u8>, outputs: &[Value]) {
    for (output_index, output) in outputs.iter().enumerate() {
        let Some(hint) = output
            .get("proprietaries")
            .and_then(|value| value.get("kaspaPortalDerivation"))
            .and_then(Value::as_object)
        else {
            continue;
        };
        let Some(branch) = hint
            .get("branch")
            .and_then(Value::as_u64)
            .and_then(|v| u8::try_from(v).ok())
        else {
            continue;
        };
        if branch > 1 {
            continue;
        }
        let Some(index) = hint.get("index").and_then(|value| match value {
            Value::String(text) => text.parse::<u32>().ok(),
            Value::Number(number) => number.as_u64().and_then(|v| u32::try_from(v).ok()),
            _ => None,
        }) else {
            continue;
        };
        let Ok(output_index) = u8::try_from(output_index) else {
            continue;
        };
        buffer.push(b'D');
        buffer.push(output_index);
        buffer.push(branch);
        buffer.extend_from_slice(&index.to_le_bytes());
    }
}

fn parse_ms45_derivation(value: &Value) -> Option<(u32, u32, u32)> {
    let map = value.as_object()?;
    map.values().find_map(parse_ms45_derivation_entry)
}

fn parse_ms45_derivation_entry(entry: &Value) -> Option<(u32, u32, u32)> {
    let path = entry.get("derivationPath")?.as_str()?;
    let tail = path.strip_prefix("m/45'/111111'/0'/")?;
    parse_ms45_soft_tail(tail)
}

fn parse_ms45_soft_tail(tail: &str) -> Option<(u32, u32, u32)> {
    let mut components = tail.split('/');
    let cosigner = parse_soft_path_component(components.next()?)?;
    let chain = parse_soft_path_component(components.next()?)?;
    let index = parse_soft_path_component(components.next()?)?;
    if chain > 1 || components.next().is_some() {
        return None;
    }
    Some((cosigner, chain, index))
}

fn parse_soft_path_component(text: &str) -> Option<u32> {
    if text.ends_with('\'') {
        return None;
    }
    let value = text.parse::<u32>().ok()?;
    (value < 0x8000_0000).then_some(value)
}

fn append_ms45_hints(buffer: &mut Vec<u8>, inputs: &[Value], outputs: &[Value]) {
    for (input_index, input) in inputs.iter().enumerate() {
        let Some(hint) = input
            .get("bip32Derivations")
            .and_then(parse_ms45_derivation)
        else {
            continue;
        };
        let Ok(index) = u8::try_from(input_index) else {
            continue;
        };
        append_ms45_hint(buffer, b'I', index, hint);
    }
    for (output_index, output) in outputs.iter().enumerate() {
        let Some(hint) = output
            .get("bip32Derivations")
            .and_then(parse_ms45_derivation)
        else {
            continue;
        };
        let Ok(index) = u8::try_from(output_index) else {
            continue;
        };
        append_ms45_hint(buffer, b'O', index, hint);
    }
}

fn append_ms45_hint(buffer: &mut Vec<u8>, marker: u8, index: u8, hint: (u32, u32, u32)) {
    buffer.push(marker);
    buffer.push(index);
    buffer.extend_from_slice(&hint.0.to_le_bytes());
    buffer.extend_from_slice(&hint.1.to_le_bytes());
    buffer.extend_from_slice(&hint.2.to_le_bytes());
}

fn append_stealth_tweak(buffer: &mut Vec<u8>, inputs: &[Value]) {
    let tweak = inputs.iter().find_map(|input| {
        input
            .as_object()
            .and_then(|value| value.get("proprietaries"))
            .and_then(Value::as_object)
            .and_then(|values| values.get("stealthTweak"))
            .and_then(Value::as_str)
            .and_then(|value| hex::decode(value).ok())
            .filter(|bytes| bytes.len() == 32)
    });
    if let Some(tweak) = tweak {
        buffer.push(0x53);
        buffer.extend_from_slice(&tweak);
    }
}

fn append_derived_covenant_binding(buffer: &mut Vec<u8>, inputs: &[Value], outputs: &[Value]) {
    let persistent = inputs.iter().any(|input| {
        input
            .get("proprietaries")
            .and_then(|value| value.get("persistentVault"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    });
    let explicit = outputs
        .first()
        .and_then(|output| output.get("covenantBinding"))
        .is_some_and(|binding| !binding.is_null());
    if !persistent || explicit {
        return;
    }
    let Some((previous_tx_id, previous_index)) = first_outpoint(inputs) else {
        return;
    };
    let Some((value, script_version, script)) = first_output(outputs) else {
        return;
    };

    let covenant_id = compute_genesis_covenant_id(
        &previous_tx_id,
        previous_index,
        0,
        value,
        script_version,
        &script,
    );
    append_covenant_binding(buffer, 0, 0, &covenant_id);
}

fn append_explicit_covenant_bindings(
    buffer: &mut Vec<u8>,
    outputs: &[Value],
) -> Result<(), String> {
    for (index, output) in outputs.iter().enumerate() {
        let Some(binding) = output
            .get("covenantBinding")
            .filter(|binding| !binding.is_null())
            .and_then(Value::as_object)
        else {
            continue;
        };
        let authorizing_input = binding
            .get("authorizingInput")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                format!("output[{index}] covenant binding is missing authorizingInput")
            })?;
        let authorizing_input = u16::try_from(authorizing_input)
            .map_err(|_| format!("output[{index}] covenant authorizing input exceeds u16"))?;
        let covenant_id = binding
            .get("covenantId")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("output[{index}] covenant binding is missing covenantId"))?;
        let covenant_id = hex::decode(covenant_id)
            .map_err(|_| format!("output[{index}] covenant id is not hex"))?;
        if covenant_id.len() != 32 {
            return Err(format!("output[{index}] covenant id must be 32 bytes"));
        }
        let output_index = u8::try_from(index).map_err(|_| "too many outputs".to_string())?;
        append_covenant_binding(buffer, output_index, authorizing_input, &covenant_id);
    }
    Ok(())
}

pub(crate) fn first_outpoint(inputs: &[Value]) -> Option<([u8; 32], u32)> {
    let outpoint = inputs
        .first()?
        .as_object()?
        .get("previousOutpoint")?
        .as_object()?;
    let transaction_id = outpoint
        .get("transactionId")?
        .as_str()
        .and_then(|value| hex::decode(value).ok())?;
    if transaction_id.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&transaction_id);
    let index = outpoint
        .get("index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())?;
    Some((id, index))
}

fn first_output(outputs: &[Value]) -> Option<(u64, u16, Vec<u8>)> {
    let output = outputs.first()?.as_object()?;
    let value = parse_exact_u64(output.get("amount")?, "amount").ok()?;
    let script = output
        .get("scriptPublicKey")
        .and_then(Value::as_str)
        .unwrap_or("");
    let (version, script) = parse_spk_hex(script).ok()?;
    Some((value, version, script))
}

fn append_covenant_binding(
    buffer: &mut Vec<u8>,
    output_index: u8,
    authorizing_input: u16,
    covenant_id: &[u8],
) {
    buffer.push(0x43);
    buffer.push(output_index);
    buffer.extend_from_slice(&authorizing_input.to_le_bytes());
    buffer.extend_from_slice(covenant_id);
}

fn array_field<'a>(document: &'a Map<String, Value>, key: &str) -> Result<&'a [Value], String> {
    document
        .get(key)
        .and_then(Value::as_array)
        .map(|values| values.as_slice())
        .ok_or_else(|| format!("missing {}", key))
}

fn validate_counts(inputs: &[Value], outputs: &[Value]) -> Result<(), String> {
    u32::try_from(inputs.len()).map_err(|_| "too many inputs".to_string())?;
    u8::try_from(outputs.len()).map_err(|_| "too many outputs".to_string())?;
    Ok(())
}

#[cfg(test)]
#[path = "relay/unit-tests/mod.rs"]
mod unit_tests;
