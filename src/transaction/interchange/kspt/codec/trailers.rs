use crate::{
    primitives::address::KaspaNetwork,
    transaction::model::{Transaction, MAX_OUTPUTS},
};

use super::super::{
    error::PsktError,
    format::{
        COVENANT_TRAILER_MARKER, DERIVATION_TRAILER_MARKER, MS45_INPUT_TRAILER_MARKER,
        MS45_OUTPUT_TRAILER_MARKER, NETWORK_TRAILER_MARKER, STEALTH_TRAILER_MARKER,
    },
};
use super::io::{ByteReader, ByteWriter};

pub(super) fn write_trailers(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
) -> Result<(), PsktError> {
    write_network(writer, tx)?;
    write_stealth(writer, tx)?;
    for input_index in 0..tx.num_inputs {
        write_ms45_input(writer, tx, input_index)?;
    }
    for output_index in 0..tx.num_outputs {
        write_output_trailers(writer, tx, output_index)?;
    }
    Ok(())
}

fn write_network(writer: &mut ByteWriter<'_>, tx: &Transaction) -> Result<(), PsktError> {
    if tx.network == KaspaNetwork::Unknown {
        return Err(PsktError::InvalidModel);
    }
    writer.write_u8(NETWORK_TRAILER_MARKER)?;
    writer.write_u8(tx.network as u8)
}

fn write_stealth(writer: &mut ByteWriter<'_>, tx: &Transaction) -> Result<(), PsktError> {
    if !tx.has_stealth_tweak {
        return Ok(());
    }
    writer.write_u8(STEALTH_TRAILER_MARKER)?;
    writer.write_bytes(&tx.stealth_tweak)
}

fn write_output_trailers(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
    output_index: usize,
) -> Result<(), PsktError> {
    write_derivation_trailer(writer, tx, output_index)?;
    write_ms45_output(writer, tx, output_index)?;
    write_covenant_trailer(writer, tx, output_index)
}

fn write_ms45_input(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
    input_index: usize,
) -> Result<(), PsktError> {
    let hint = tx.inputs[input_index].ms45_hint;
    if !hint.present {
        return Ok(());
    }
    write_ms45_record(writer, MS45_INPUT_TRAILER_MARKER, input_index, hint)
}

fn write_ms45_output(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
    output_index: usize,
) -> Result<(), PsktError> {
    let hint = tx.outputs[output_index].ms45_hint;
    if !hint.present {
        return Ok(());
    }
    write_ms45_record(writer, MS45_OUTPUT_TRAILER_MARKER, output_index, hint)
}

fn write_ms45_record(
    writer: &mut ByteWriter<'_>,
    marker: u8,
    index: usize,
    hint: crate::transaction::model::Ms45Hint,
) -> Result<(), PsktError> {
    if index > u8::MAX as usize
        || hint.chain > 1
        || hint.cosigner >= 0x8000_0000
        || hint.index >= 0x8000_0000
    {
        return Err(PsktError::InvalidModel);
    }
    writer
        .write_u8(marker)
        .and_then(|()| writer.write_u8(index as u8))
        .and_then(|()| writer.write_u32_le(hint.cosigner))
        .and_then(|()| writer.write_u32_le(hint.chain))
        .and_then(|()| writer.write_u32_le(hint.index))
}

fn write_derivation_trailer(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
    output_index: usize,
) -> Result<(), PsktError> {
    if !tx.outputs[output_index].has_derivation_hint {
        return Ok(());
    }
    write_derivation_record(writer, tx, output_index)
}

fn write_derivation_record(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
    output_index: usize,
) -> Result<(), PsktError> {
    let output = &tx.outputs[output_index];
    writer
        .write_u8(DERIVATION_TRAILER_MARKER)
        .and_then(|()| writer.write_u8(output_index as u8))
        .and_then(|()| writer.write_u8(output.derivation_branch))
        .and_then(|()| writer.write_u32_le(output.derivation_index))
}

fn write_covenant_trailer(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
    output_index: usize,
) -> Result<(), PsktError> {
    if !tx.outputs[output_index].has_covenant {
        return Ok(());
    }
    write_covenant_record(writer, tx, output_index)
}

fn write_covenant_record(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
    output_index: usize,
) -> Result<(), PsktError> {
    let output = &tx.outputs[output_index];
    writer
        .write_u8(COVENANT_TRAILER_MARKER)
        .and_then(|()| writer.write_u8(output_index as u8))
        .and_then(|()| writer.write_u16_le(output.covenant_auth_input))
        .and_then(|()| writer.write_bytes(&output.covenant_id))
}

struct TrailerState {
    saw_stealth: bool,
    saw_network: bool,
    saw_covenant: [bool; MAX_OUTPUTS],
    saw_derivation: [bool; MAX_OUTPUTS],
    saw_ms45_input: [bool; 256],
    saw_ms45_output: [bool; MAX_OUTPUTS],
}

impl TrailerState {
    const fn new() -> Self {
        Self {
            saw_stealth: false,
            saw_network: false,
            saw_covenant: [false; MAX_OUTPUTS],
            saw_derivation: [false; MAX_OUTPUTS],
            saw_ms45_input: [false; 256],
            saw_ms45_output: [false; MAX_OUTPUTS],
        }
    }
}

pub(super) fn read_trailers(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
) -> Result<(), PsktError> {
    let mut state = TrailerState::new();
    while reader.remaining() != 0 {
        let before_remaining = reader.remaining();
        read_next_trailer(reader, tx, &mut state)?;
        require_trailer_progress(before_remaining, reader.remaining())?;
    }
    if !state.saw_network {
        return Err(PsktError::InvalidTrailer);
    }
    Ok(())
}

pub(crate) fn require_trailer_progress(
    before_remaining: usize,
    after_remaining: usize,
) -> Result<(), PsktError> {
    crate::primitives::bytes::strict_forward_progress(before_remaining, after_remaining)
        .then_some(())
        .ok_or(PsktError::InvalidTrailer)
}

fn read_next_trailer(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    state: &mut TrailerState,
) -> Result<(), PsktError> {
    match reader.peek_u8() {
        Some(NETWORK_TRAILER_MARKER) => read_network(reader, tx, state),
        Some(DERIVATION_TRAILER_MARKER) => read_derivation(reader, tx, state),
        Some(MS45_INPUT_TRAILER_MARKER) => read_ms45_input(reader, tx, state),
        Some(MS45_OUTPUT_TRAILER_MARKER) => read_ms45_output(reader, tx, state),
        Some(STEALTH_TRAILER_MARKER) => read_stealth(reader, tx, state),
        Some(COVENANT_TRAILER_MARKER) => read_covenant(reader, tx, state),
        _ => Err(PsktError::TrailingData),
    }
}

fn read_network(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    state: &mut TrailerState,
) -> Result<(), PsktError> {
    if state.saw_network {
        return Err(PsktError::InvalidTrailer);
    }
    reader.read_u8()?;
    tx.network = KaspaNetwork::from_wire(reader.read_u8()?).ok_or(PsktError::InvalidTrailer)?;
    state.saw_network = true;
    Ok(())
}

fn read_derivation(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    state: &mut TrailerState,
) -> Result<(), PsktError> {
    reader.read_u8()?;
    let output_index = reader.read_u8()? as usize;
    let branch = reader.read_u8()?;
    let index = reader.read_u32_le()?;
    if output_index >= tx.num_outputs || output_index >= MAX_OUTPUTS || branch > 1 {
        return Err(PsktError::InvalidTrailer);
    }
    if state.saw_derivation[output_index] {
        return Err(PsktError::InvalidTrailer);
    }
    let output = &mut tx.outputs[output_index];
    output.has_derivation_hint = true;
    output.derivation_branch = branch;
    output.derivation_index = index;
    state.saw_derivation[output_index] = true;
    Ok(())
}

fn read_ms45_input(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    state: &mut TrailerState,
) -> Result<(), PsktError> {
    reader.read_u8()?;
    let index = reader.read_u8()? as usize;
    if index >= tx.num_inputs || index >= state.saw_ms45_input.len() || state.saw_ms45_input[index]
    {
        return Err(PsktError::InvalidTrailer);
    }
    let hint = read_ms45_body(reader)?;
    tx.inputs[index].ms45_hint = hint;
    state.saw_ms45_input[index] = true;
    Ok(())
}

fn read_ms45_output(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    state: &mut TrailerState,
) -> Result<(), PsktError> {
    reader.read_u8()?;
    let index = reader.read_u8()? as usize;
    if index >= tx.num_outputs || index >= MAX_OUTPUTS || state.saw_ms45_output[index] {
        return Err(PsktError::InvalidTrailer);
    }
    let hint = read_ms45_body(reader)?;
    tx.outputs[index].ms45_hint = hint;
    state.saw_ms45_output[index] = true;
    Ok(())
}

fn read_ms45_body(
    reader: &mut ByteReader<'_>,
) -> Result<crate::transaction::model::Ms45Hint, PsktError> {
    let cosigner = reader.read_u32_le()?;
    let chain = reader.read_u32_le()?;
    let index = reader.read_u32_le()?;
    if chain > 1 || cosigner >= 0x8000_0000 || index >= 0x8000_0000 {
        return Err(PsktError::InvalidTrailer);
    }
    Ok(crate::transaction::model::Ms45Hint {
        present: true,
        cosigner,
        chain,
        index,
    })
}

fn read_stealth(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    state: &mut TrailerState,
) -> Result<(), PsktError> {
    if state.saw_stealth {
        return Err(PsktError::InvalidTrailer);
    }
    reader.read_u8()?;
    tx.stealth_tweak.copy_from_slice(reader.read_bytes(32)?);
    tx.has_stealth_tweak = true;
    state.saw_stealth = true;
    Ok(())
}

fn read_covenant(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    state: &mut TrailerState,
) -> Result<(), PsktError> {
    reader.read_u8()?;
    let output_index = reader.read_u8()? as usize;
    let authorizing_input = reader.read_u16_le()?;
    if output_index >= tx.num_outputs
        || output_index >= MAX_OUTPUTS
        || authorizing_input as usize >= tx.num_inputs
    {
        return Err(PsktError::InvalidTrailer);
    }
    if state.saw_covenant[output_index] {
        return Err(PsktError::InvalidTrailer);
    }
    let covenant_id = reader.read_bytes(32)?;
    let output = &mut tx.outputs[output_index];
    output.has_covenant = true;
    output.covenant_auth_input = authorizing_input;
    output.covenant_id.copy_from_slice(covenant_id);
    state.saw_covenant[output_index] = true;
    Ok(())
}
