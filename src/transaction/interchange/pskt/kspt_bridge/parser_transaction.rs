use super::KsptReader;
use crate::transaction::interchange::pskt::model::{
    CompactKsptInput, CompactKsptOutput, CompactKsptSignature, CompactKsptTransaction,
};

const KSPT_V1: u8 = 0x01;
const MAX_SIGNATURES_PER_INPUT: usize = 5;
const MIN_INPUT_WIRE_BYTES: usize = 59;

pub(crate) fn parse_compact_kspt_transaction(
    data: &[u8],
) -> Result<CompactKsptTransaction, String> {
    let mut reader = KsptReader::new(data);
    let global = parse_global(&mut reader)?;
    validate_input_capacity(&reader, global.input_count)?;
    let mut inputs = parse_inputs(&mut reader, global.input_count)?;
    let mut outputs = parse_outputs(&mut reader, global.output_count)?;
    let (network, stealth_tweak) = consume_trailers(&mut reader, &mut inputs, &mut outputs)?;
    Ok(global.into_transaction(inputs, outputs, network, stealth_tweak))
}

struct CompactGlobal {
    format_version: u8,
    flags: u8,
    version: u16,
    input_count: usize,
    output_count: usize,
    locktime: u64,
    subnetwork_id: [u8; 20],
    gas: u64,
    payload: Vec<u8>,
}

impl CompactGlobal {
    fn into_transaction(
        self,
        inputs: Vec<CompactKsptInput>,
        outputs: Vec<CompactKsptOutput>,
        network: u8,
        stealth_tweak: Option<[u8; 32]>,
    ) -> CompactKsptTransaction {
        CompactKsptTransaction {
            format_version: self.format_version,
            flags: self.flags,
            version: self.version,
            locktime: self.locktime,
            subnetwork_id: self.subnetwork_id,
            gas: self.gas,
            payload: self.payload,
            network,
            inputs,
            outputs,
            stealth_tweak,
        }
    }
}

fn parse_global(reader: &mut KsptReader<'_>) -> Result<CompactGlobal, String> {
    let (format_version, flags) = parse_header(reader)?;
    let version = reader.u16_le()?;
    let input_count = parse_input_count(reader)?;
    let output_count = usize::from(reader.u8()?);
    let locktime = reader.u64_le()?;
    let subnetwork_id = read_array::<20>(reader)?;
    let gas = reader.u64_le()?;
    let payload = read_u16_sized_bytes(reader)?;
    Ok(CompactGlobal {
        format_version,
        flags,
        version,
        input_count,
        output_count,
        locktime,
        subnetwork_id,
        gas,
        payload,
    })
}

fn validate_input_capacity(reader: &KsptReader<'_>, input_count: usize) -> Result<(), String> {
    let minimum_bytes = input_count
        .checked_mul(MIN_INPUT_WIRE_BYTES)
        .ok_or("compact KSPT input count exceeds remaining wire capacity".to_string())?;
    (minimum_bytes <= reader.remaining())
        .then_some(())
        .ok_or("compact KSPT input count exceeds remaining wire capacity".to_string())
}

fn parse_header(reader: &mut KsptReader<'_>) -> Result<(u8, u8), String> {
    if reader.bytes(4)? != b"KSPT" {
        return Err("not a KSPT blob".into());
    }
    let format_version = reader.u8()?;
    if format_version != KSPT_V1 {
        return Err(format!(
            "unsupported compact KSPT version: 0x{format_version:02x}"
        ));
    }
    Ok((format_version, reader.u8()?))
}

fn parse_input_count(reader: &mut KsptReader<'_>) -> Result<usize, String> {
    reader.u32_le().and_then(|value| {
        usize::try_from(value).map_err(|_| "input count is too large".to_string())
    })
}

fn parse_inputs(
    reader: &mut KsptReader<'_>,
    count: usize,
) -> Result<Vec<CompactKsptInput>, String> {
    let mut inputs = Vec::new();
    for _ in 0..count {
        inputs.push(parse_input(reader)?);
    }
    Ok(inputs)
}

fn parse_input(reader: &mut KsptReader<'_>) -> Result<CompactKsptInput, String> {
    let previous_tx_id = read_array::<32>(reader)?;
    let previous_index = reader.u32_le()?;
    let amount = reader.u64_le()?;
    let sequence = reader.u64_le()?;
    let sig_op_count = reader.u8()?;
    let script_version = reader.u16_le()?;
    let script = read_compact_script(reader)?;
    let signatures = parse_signatures(reader)?;
    let redeem_script = read_u16_sized_bytes(reader)?;
    Ok(CompactKsptInput {
        previous_tx_id,
        previous_index,
        amount,
        sequence,
        sig_op_count,
        script_version,
        script,
        signatures,
        redeem_script,
        ms45_derivation: None,
    })
}

fn parse_signatures(reader: &mut KsptReader<'_>) -> Result<Vec<CompactKsptSignature>, String> {
    let count = usize::from(reader.u8()?);
    if count > MAX_SIGNATURES_PER_INPUT {
        return Err("compact KSPT has too many signatures for one input".into());
    }
    let mut signatures = Vec::with_capacity(count);
    let mut seen = [false; 256];
    for _ in 0..count {
        let pubkey_pos = reader.u8()?;
        if seen[usize::from(pubkey_pos)] {
            return Err("compact KSPT repeats a signature public-key position".into());
        }
        seen[usize::from(pubkey_pos)] = true;
        let sighash_type = reader.u8()?;
        if !matches!(sighash_type, 0x01 | 0x02 | 0x04 | 0x81 | 0x82 | 0x84) {
            return Err("compact KSPT contains an invalid sighash type".into());
        }
        signatures.push(CompactKsptSignature {
            pubkey_pos,
            sighash_type,
            signature: read_array::<64>(reader)?,
        });
    }
    Ok(signatures)
}

fn parse_outputs(
    reader: &mut KsptReader<'_>,
    count: usize,
) -> Result<Vec<CompactKsptOutput>, String> {
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        outputs.push(CompactKsptOutput {
            value: reader.u64_le()?,
            script_version: reader.u16_le()?,
            script: read_compact_script(reader)?,
            covenant: None,
            derivation: None,
            ms45_derivation: None,
        });
    }
    Ok(outputs)
}

fn read_compact_script(reader: &mut KsptReader<'_>) -> Result<Vec<u8>, String> {
    let length = reader.compact_script_len()?;
    Ok(reader.bytes(length)?.to_vec())
}

fn read_u16_sized_bytes(reader: &mut KsptReader<'_>) -> Result<Vec<u8>, String> {
    let length = usize::from(reader.u16_le()?);
    Ok(reader.bytes(length)?.to_vec())
}

fn read_array<const N: usize>(reader: &mut KsptReader<'_>) -> Result<[u8; N], String> {
    reader
        .bytes(N)?
        .try_into()
        .map_err(|_| "compact KSPT fixed field is truncated".to_string())
}

struct TrailerState {
    saw_network: bool,
    saw_stealth: bool,
    derivation_outputs: Vec<bool>,
    ms45_inputs: Vec<bool>,
    ms45_outputs: Vec<bool>,
    covenant_outputs: Vec<bool>,
    network: Option<u8>,
    stealth_tweak: Option<[u8; 32]>,
}

impl TrailerState {
    fn new(input_count: usize, output_count: usize) -> Self {
        Self {
            saw_network: false,
            saw_stealth: false,
            derivation_outputs: vec![false; output_count],
            ms45_inputs: vec![false; input_count],
            ms45_outputs: vec![false; output_count],
            covenant_outputs: vec![false; output_count],
            network: None,
            stealth_tweak: None,
        }
    }
}

fn consume_trailers(
    reader: &mut KsptReader<'_>,
    inputs: &mut [CompactKsptInput],
    outputs: &mut [CompactKsptOutput],
) -> Result<(u8, Option<[u8; 32]>), String> {
    let input_count = inputs.len();
    let mut state = TrailerState::new(input_count, outputs.len());
    while reader.remaining() != 0 {
        let before_remaining = reader.remaining();
        consume_next_trailer(reader, inputs, outputs, &mut state)?;
        require_compact_trailer_progress(before_remaining, reader.remaining())?;
    }
    let network = require_network(&state)?;
    Ok((network, state.stealth_tweak))
}

pub(crate) fn require_compact_trailer_progress(
    before_remaining: usize,
    after_remaining: usize,
) -> Result<(), String> {
    crate::primitives::bytes::strict_forward_progress(before_remaining, after_remaining)
        .then_some(())
        .ok_or("compact KSPT trailer made no forward progress".to_string())
}

fn consume_next_trailer(
    reader: &mut KsptReader<'_>,
    inputs: &mut [CompactKsptInput],
    outputs: &mut [CompactKsptOutput],
    state: &mut TrailerState,
) -> Result<(), String> {
    match reader.peek() {
        Some(b'N') => consume_network(reader, state),
        Some(b'D') => consume_derivation(reader, outputs, state),
        Some(b'I') => consume_ms45_input(reader, inputs, state),
        Some(b'O') => consume_ms45_output(reader, outputs, state),
        Some(b'S') => consume_stealth(reader, state),
        Some(b'C') => consume_covenant(reader, inputs.len(), outputs, state),
        _ => Err("invalid compact KSPT trailer".into()),
    }
}

fn require_network(state: &TrailerState) -> Result<u8, String> {
    state
        .network
        .ok_or("compact KSPT v1 is missing its network trailer".to_string())
}

fn consume_network(reader: &mut KsptReader<'_>, state: &mut TrailerState) -> Result<(), String> {
    reader.u8()?;
    let network = reader.u8()?;
    if state.saw_network || !matches!(network, 1..=4) {
        return Err("invalid compact KSPT network trailer".into());
    }
    state.saw_network = true;
    state.network = Some(network);
    Ok(())
}

fn consume_derivation(
    reader: &mut KsptReader<'_>,
    outputs: &mut [CompactKsptOutput],
    state: &mut TrailerState,
) -> Result<(), String> {
    reader.u8()?;
    let output_index = usize::from(reader.u8()?);
    let branch = reader.u8()?;
    let index = reader.u32_le()?;
    let Some(seen) = state.derivation_outputs.get_mut(output_index) else {
        return Err("invalid compact KSPT derivation trailer".into());
    };
    if *seen || branch > 1 {
        return Err("invalid compact KSPT derivation trailer".into());
    }
    *seen = true;
    let Some(output) = outputs.get_mut(output_index) else {
        return Err("invalid compact KSPT derivation trailer".into());
    };
    output.derivation = Some((branch, index));
    Ok(())
}

fn read_ms45_hint(reader: &mut KsptReader<'_>) -> Result<(u32, u32, u32), String> {
    let cosigner = reader.u32_le()?;
    let chain = reader.u32_le()?;
    let index = reader.u32_le()?;
    if chain > 1 || cosigner >= 0x8000_0000 || index >= 0x8000_0000 {
        return Err("invalid compact KSPT multisig derivation trailer".into());
    }
    Ok((cosigner, chain, index))
}

fn consume_ms45_input(
    reader: &mut KsptReader<'_>,
    inputs: &mut [CompactKsptInput],
    state: &mut TrailerState,
) -> Result<(), String> {
    reader.u8()?;
    let input_index = usize::from(reader.u8()?);
    let Some(seen) = state.ms45_inputs.get_mut(input_index) else {
        return Err("invalid compact KSPT multisig input trailer".into());
    };
    if *seen {
        return Err("duplicate compact KSPT multisig input trailer".into());
    }
    let hint = read_ms45_hint(reader)?;
    let Some(input) = inputs.get_mut(input_index) else {
        return Err("invalid compact KSPT multisig input trailer".into());
    };
    input.ms45_derivation = Some(hint);
    *seen = true;
    Ok(())
}

fn consume_ms45_output(
    reader: &mut KsptReader<'_>,
    outputs: &mut [CompactKsptOutput],
    state: &mut TrailerState,
) -> Result<(), String> {
    reader.u8()?;
    let output_index = usize::from(reader.u8()?);
    let Some(seen) = state.ms45_outputs.get_mut(output_index) else {
        return Err("invalid compact KSPT multisig output trailer".into());
    };
    if *seen {
        return Err("duplicate compact KSPT multisig output trailer".into());
    }
    let hint = read_ms45_hint(reader)?;
    let Some(output) = outputs.get_mut(output_index) else {
        return Err("invalid compact KSPT multisig output trailer".into());
    };
    output.ms45_derivation = Some(hint);
    *seen = true;
    Ok(())
}

fn consume_stealth(reader: &mut KsptReader<'_>, state: &mut TrailerState) -> Result<(), String> {
    reader.u8()?;
    if state.saw_stealth {
        return Err("invalid compact KSPT trailer".into());
    }
    state.stealth_tweak = Some(read_array::<32>(reader)?);
    state.saw_stealth = true;
    Ok(())
}

fn consume_covenant(
    reader: &mut KsptReader<'_>,
    input_count: usize,
    outputs: &mut [CompactKsptOutput],
    state: &mut TrailerState,
) -> Result<(), String> {
    reader.u8()?;
    let output_index = usize::from(reader.u8()?);
    let authorizing_input = reader.u16_le()?;
    if usize::from(authorizing_input) >= input_count {
        return Err("invalid compact KSPT covenant trailer".into());
    }
    let Some(output) = outputs.get_mut(output_index) else {
        return Err("invalid compact KSPT covenant trailer".into());
    };
    let Some(seen) = state.covenant_outputs.get_mut(output_index) else {
        return Err("invalid compact KSPT covenant trailer".into());
    };
    if *seen {
        return Err("invalid compact KSPT covenant trailer".into());
    }
    output.covenant = Some((authorizing_input, read_array::<32>(reader)?));
    *seen = true;
    Ok(())
}
