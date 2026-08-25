use crate::{
    network::codec::primitives::WireReader,
    transaction::consensus::{
        ConsensusInput, ConsensusOutput, ConsensusTransaction, InputEncoding,
    },
};

const COMPACT_KSPT_V1: u8 = 0x01;
const COMPLETE_FLAG: u8 = 0x01;

struct SignedKsptGlobal {
    tx_version: u16,
    input_count: usize,
    output_count: usize,
    locktime: u64,
    subnetwork_id: [u8; 20],
    gas: u64,
    payload: Vec<u8>,
}

pub fn decode_signed_kspt(signed_hex: &str) -> Result<ConsensusTransaction, String> {
    let bytes = decode_signed_envelope(signed_hex)?;
    let mut reader = WireReader::new(&bytes[6..]);
    let global = decode_signed_global(&mut reader)?;
    let inputs = decode_signed_inputs(&mut reader, global.input_count)?;
    let mut outputs = decode_signed_outputs(&mut reader, global.output_count)?;
    decode_trailers(&mut reader, global.input_count, &mut outputs)?;
    Ok(ConsensusTransaction {
        tx_version: global.tx_version,
        input_encoding: InputEncoding::Compact,
        inputs,
        outputs,
        locktime: global.locktime,
        subnetwork_id: global.subnetwork_id,
        gas: global.gas,
        payload: global.payload,
    })
}

fn decode_signed_envelope(signed_hex: &str) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(signed_hex).map_err(|error| format!("Invalid hex: {error}"))?;
    if bytes.len() < 6 || &bytes[..4] != b"KSPT" {
        return Err("Not a compact KSPT (missing header)".into());
    }
    let format_version = bytes[4];
    if format_version != COMPACT_KSPT_V1 {
        return Err(format!("Unsupported compact KSPT version {format_version}"));
    }
    if bytes[5] != COMPLETE_FLAG {
        return Err("Compact KSPT is not fully signed".into());
    }
    Ok(bytes)
}

fn decode_signed_global(reader: &mut WireReader<'_>) -> Result<SignedKsptGlobal, String> {
    let tx_version = reader.read_u16().map_err(wire_error)?;
    let input_count = decode_signed_input_count(reader)?;
    let output_count = usize::from(reader.read_u8().map_err(wire_error)?);
    let locktime = reader.read_u64().map_err(wire_error)?;
    let subnetwork_id = decode_signed_subnetwork_id(reader)?;
    let gas = reader.read_u64().map_err(wire_error)?;
    let payload = decode_signed_payload(reader)?;
    Ok(SignedKsptGlobal {
        tx_version,
        input_count,
        output_count,
        locktime,
        subnetwork_id,
        gas,
        payload,
    })
}

fn decode_signed_input_count(reader: &mut WireReader<'_>) -> Result<usize, String> {
    let count = reader.read_u32().map_err(wire_error)?;
    match usize::try_from(count) {
        Ok(count) => Ok(count),
        Err(_) => Err("KSPT input count is too large".to_string()),
    }
}

fn decode_signed_subnetwork_id(reader: &mut WireReader<'_>) -> Result<[u8; 20], String> {
    let encoded = reader.read_exact(20).map_err(wire_error)?;
    let mut subnetwork_id = [0u8; 20];
    subnetwork_id.copy_from_slice(encoded);
    Ok(subnetwork_id)
}

fn decode_signed_payload(reader: &mut WireReader<'_>) -> Result<Vec<u8>, String> {
    let payload_length = usize::from(reader.read_u16().map_err(wire_error)?);
    match reader.read_exact(payload_length) {
        Ok(payload) => Ok(payload.to_vec()),
        Err(_) => Err("KSPT truncated at payload".to_string()),
    }
}

fn decode_signed_inputs(
    reader: &mut WireReader<'_>,
    input_count: usize,
) -> Result<Vec<ConsensusInput>, String> {
    let mut inputs = Vec::new();
    inputs
        .try_reserve(input_count)
        .map_err(|_| "KSPT input count exceeds available memory".to_string())?;
    for _ in 0..input_count {
        inputs.push(decode_input(reader)?);
    }
    Ok(inputs)
}

fn decode_signed_outputs(
    reader: &mut WireReader<'_>,
    output_count: usize,
) -> Result<Vec<ConsensusOutput>, String> {
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(decode_output(reader)?);
    }
    Ok(outputs)
}

fn decode_input(reader: &mut WireReader<'_>) -> Result<ConsensusInput, String> {
    let (prev_tx_id, prev_index) = decode_outpoint(reader)?;
    reader.read_u64().map_err(wire_error)?;
    let sequence = reader.read_u64().map_err(wire_error)?;
    let sig_op_count = reader.read_u8().map_err(wire_error)?;
    reader.read_u16().map_err(wire_error)?;
    let script_public_key = decode_input_script_public_key(reader)?;
    let sig_script = decode_compact_signature_script(reader, &script_public_key)?;
    Ok(ConsensusInput {
        prev_tx_id,
        prev_index,
        sig_script,
        sequence,
        sig_op_count,
    })
}

fn decode_outpoint(reader: &mut WireReader<'_>) -> Result<([u8; 32], u32), String> {
    let prev_tx_id = reader
        .read_exact(32)
        .map_err(|_| "KSPT truncated at input".to_string())?
        .try_into()
        .map_err(|_| "KSPT invalid transaction id".to_string())?;
    let prev_index = reader.read_u32().map_err(wire_error)?;
    Ok((prev_tx_id, prev_index))
}

fn decode_input_script_public_key(reader: &mut WireReader<'_>) -> Result<Vec<u8>, String> {
    let script_length = read_compact_script_length(reader)?;
    reader
        .read_exact(script_length)
        .map(Vec::from)
        .map_err(|_| "KSPT truncated at script public key".to_string())
}

fn decode_compact_signature_script(
    reader: &mut WireReader<'_>,
    script_public_key: &[u8],
) -> Result<Vec<u8>, String> {
    let signature_count = usize::from(reader.read_u8().map_err(wire_error)?);
    if signature_count == 0 {
        return Err("Input has no signatures".into());
    }
    if is_p2sh(script_public_key) || is_multisig(script_public_key) {
        decode_script_signatures(reader, signature_count, is_p2sh(script_public_key))
    } else {
        decode_p2pk_signature(reader, signature_count)
    }
}

pub(super) fn decode_script_signatures(
    reader: &mut WireReader<'_>,
    signature_count: usize,
    p2sh: bool,
) -> Result<Vec<u8>, String> {
    let mut signatures = read_script_signature_records(reader, signature_count)?;
    signatures.sort_by_key(|signature| signature.0);
    let redeem_script = read_redeem_script(reader)?;
    let threshold = signature_threshold(redeem_script.as_deref(), signatures.len());
    let mut result = emit_script_signatures(&signatures, threshold)?;
    append_redeem_if_needed(&mut result, redeem_script.as_deref(), p2sh)?;
    Ok(result)
}

fn read_script_signature_records(
    reader: &mut WireReader<'_>,
    signature_count: usize,
) -> Result<Vec<(u8, Vec<u8>)>, String> {
    let mut signatures = Vec::with_capacity(signature_count);
    for _ in 0..signature_count {
        signatures.push(read_script_signature_record(reader)?);
    }
    Ok(signatures)
}

fn read_script_signature_record(reader: &mut WireReader<'_>) -> Result<(u8, Vec<u8>), String> {
    let public_key_position = reader.read_u8().map_err(wire_error)?;
    let sighash_type = reader.read_u8().map_err(wire_error)?;
    let signature = reader.read_exact(64).map_err(wire_error)?;
    let mut data = Vec::with_capacity(65);
    data.extend_from_slice(signature);
    data.push(sighash_type);
    Ok((public_key_position, data))
}

fn read_redeem_script(reader: &mut WireReader<'_>) -> Result<Option<Vec<u8>>, String> {
    let redeem_length = usize::from(reader.read_u16().map_err(wire_error)?);
    if redeem_length == 0 {
        Ok(None)
    } else {
        reader
            .read_exact(redeem_length)
            .map(|script| Some(script.to_vec()))
            .map_err(wire_error)
    }
}

fn signature_threshold(redeem_script: Option<&[u8]>, signature_count: usize) -> usize {
    redeem_script
        .and_then(|script| script.first().copied())
        .filter(|opcode| (0x51..=0x60).contains(opcode))
        .map_or(signature_count, |opcode| usize::from(opcode - 0x50))
}

fn emit_script_signatures(
    signatures: &[(u8, Vec<u8>)],
    threshold: usize,
) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    for (_, signature) in signatures.iter().take(threshold) {
        result.push(u8::try_from(signature.len()).map_err(|_| "signature too long".to_string())?);
        result.extend_from_slice(signature);
    }
    Ok(result)
}

fn append_redeem_if_needed(
    result: &mut Vec<u8>,
    redeem_script: Option<&[u8]>,
    p2sh: bool,
) -> Result<(), String> {
    if p2sh {
        if let Some(redeem_script) = redeem_script {
            crate::transaction::interchange::pskt::push_redeem_script(result, redeem_script)?;
        }
    }
    Ok(())
}

fn decode_p2pk_signature(
    reader: &mut WireReader<'_>,
    signature_count: usize,
) -> Result<Vec<u8>, String> {
    reader.read_u8().map_err(wire_error)?;
    let sighash_type = reader.read_u8().map_err(wire_error)?;
    let signature = reader.read_exact(64).map_err(wire_error)?;
    let extra_signatures = signature_count.saturating_sub(1);
    reader
        .read_exact(66usize.saturating_mul(extra_signatures))
        .map_err(wire_error)?;
    let redeem_length = usize::from(reader.read_u16().map_err(wire_error)?);
    reader.read_exact(redeem_length).map_err(wire_error)?;

    let mut result = Vec::with_capacity(66);
    result.push(65);
    result.extend_from_slice(signature);
    result.push(sighash_type);
    Ok(result)
}

fn read_compact_script_length(reader: &mut WireReader<'_>) -> Result<usize, String> {
    let first = reader.read_u8().map_err(wire_error)?;
    if first == 0xff {
        Ok(usize::from(reader.read_u16().map_err(wire_error)?))
    } else {
        Ok(usize::from(first))
    }
}

fn decode_output(reader: &mut WireReader<'_>) -> Result<ConsensusOutput, String> {
    let value = reader.read_u64().map_err(wire_error)?;
    let spk_version = reader.read_u16().map_err(wire_error)?;
    let script_length = read_compact_script_length(reader)?;
    let spk_script = reader
        .read_exact(script_length)
        .map_err(wire_error)?
        .to_vec();
    Ok(ConsensusOutput {
        value,
        spk_version,
        spk_script,
        covenant: None,
    })
}

struct TrailerState {
    saw_stealth: bool,
    saw_network: bool,
    derivation_outputs: Vec<bool>,
}

impl TrailerState {
    fn new(output_count: usize) -> Self {
        Self {
            saw_stealth: false,
            saw_network: false,
            derivation_outputs: vec![false; output_count],
        }
    }
}

pub(crate) fn decode_trailers(
    reader: &mut WireReader<'_>,
    input_count: usize,
    outputs: &mut [ConsensusOutput],
) -> Result<(), String> {
    let mut state = TrailerState::new(outputs.len());
    while !reader.remaining().is_empty() {
        let before_remaining = reader.remaining().len();
        decode_next_trailer(reader, input_count, outputs, &mut state)?;
        require_signed_trailer_progress(before_remaining, reader.remaining().len())?;
    }
    if !state.saw_network {
        return Err("compact KSPT v1 is missing its network trailer".into());
    }
    Ok(())
}

pub(crate) fn require_signed_trailer_progress(
    before_remaining: usize,
    after_remaining: usize,
) -> Result<(), String> {
    crate::primitives::bytes::strict_forward_progress(before_remaining, after_remaining)
        .then_some(())
        .ok_or_else(|| "compact KSPT trailer made no forward progress".to_string())
}

fn decode_next_trailer(
    reader: &mut WireReader<'_>,
    input_count: usize,
    outputs: &mut [ConsensusOutput],
    state: &mut TrailerState,
) -> Result<(), String> {
    match reader.remaining().first().copied() {
        Some(b'N') => decode_network_trailer(reader, state),
        Some(b'D') => decode_derivation_trailer(reader, outputs.len(), state),
        Some(b'S') => decode_stealth_trailer(reader, state),
        Some(b'C') => decode_covenant_trailer(reader, input_count, outputs),
        _ => Err("invalid compact KSPT trailer".into()),
    }
}

fn decode_network_trailer(
    reader: &mut WireReader<'_>,
    state: &mut TrailerState,
) -> Result<(), String> {
    reader
        .read_exact(2)
        .map_err(wire_error)
        .and_then(|record| accept_network_record(record, state))
}

fn accept_network_record(record: &[u8], state: &mut TrailerState) -> Result<(), String> {
    let valid = !state.saw_network && matches!(record.get(1), Some(1..=4));
    valid
        .then_some(())
        .ok_or("invalid compact KSPT network trailer".to_string())
        .map(|()| {
            state.saw_network = true;
        })
}

fn decode_derivation_trailer(
    reader: &mut WireReader<'_>,
    output_count: usize,
    state: &mut TrailerState,
) -> Result<(), String> {
    reader
        .read_exact(7)
        .map_err(wire_error)
        .and_then(|record| accept_derivation_record(record, output_count, state))
}

fn accept_derivation_record(
    record: &[u8],
    output_count: usize,
    state: &mut TrailerState,
) -> Result<(), String> {
    let output_index = usize::from(record[1]);
    let branch = record[2];
    valid_derivation_slot(output_index, branch, output_count, state)
        .then_some(())
        .ok_or_else(|| "invalid compact KSPT derivation trailer".to_string())
        .map(|()| state.derivation_outputs[output_index] = true)
}

fn valid_derivation_slot(
    output_index: usize,
    branch: u8,
    output_count: usize,
    state: &TrailerState,
) -> bool {
    matches!(
        (
            output_index < output_count,
            branch <= 1,
            state.derivation_outputs.get(output_index)
        ),
        (true, true, Some(false))
    )
}

fn decode_stealth_trailer(
    reader: &mut WireReader<'_>,
    state: &mut TrailerState,
) -> Result<(), String> {
    if state.saw_stealth {
        return Err("invalid compact KSPT trailer".into());
    }
    reader.read_u8().map_err(wire_error)?;
    reader.read_exact(32).map_err(wire_error)?;
    state.saw_stealth = true;
    Ok(())
}

fn decode_covenant_trailer(
    reader: &mut WireReader<'_>,
    input_count: usize,
    outputs: &mut [ConsensusOutput],
) -> Result<(), String> {
    reader.read_u8().map_err(wire_error)?;
    let output_index = usize::from(reader.read_u8().map_err(wire_error)?);
    let authorizing_input = reader.read_u16().map_err(wire_error)?;
    let Some(output) = outputs.get_mut(output_index) else {
        return Err("invalid compact KSPT covenant trailer".into());
    };
    if usize::from(authorizing_input) >= input_count {
        return Err("invalid compact KSPT covenant trailer".into());
    }
    if output.covenant.is_some() {
        return Err("invalid compact KSPT covenant trailer".into());
    }
    let covenant_id = reader
        .read_exact(32)
        .map_err(wire_error)?
        .try_into()
        .map_err(|_| "invalid covenant id".to_string())?;
    output.covenant = Some((authorizing_input, covenant_id));
    Ok(())
}

fn is_p2sh(script: &[u8]) -> bool {
    script.len() == 35 && script[0] == 0xaa && script[1] == 0x20 && script[34] == 0x87
}

fn is_multisig(script: &[u8]) -> bool {
    script.len() >= 37
        && script.last() == Some(&0xae)
        && script
            .first()
            .is_some_and(|opcode| (0x51..=0x55).contains(opcode))
}

fn wire_error(error: impl core::fmt::Display) -> String {
    error.to_string()
}
