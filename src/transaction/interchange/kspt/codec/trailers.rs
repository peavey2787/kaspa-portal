//! Canonical KSPT trailers. Trailer kinds appear in a fixed rank order,
//! positions within a kind strictly increase, and every value is validated
//! before it reaches the transaction model.

use crate::{
    primitives::address::KaspaNetwork,
    transaction::model::{Ms45Hint, Transaction},
};

use super::super::{
    error::PsktError,
    format::{
        COVENANT_EXECUTION_TRAILER_MARKER, COVENANT_TRAILER_MARKER, DERIVATION_TRAILER_MARKER,
        INPUT_DERIVATION_TRAILER_MARKER, MS45_INPUT_TRAILER_MARKER, MS45_OUTPUT_TRAILER_MARKER,
        NETWORK_TRAILER_MARKER, STEALTH_TRAILER_MARKER,
    },
};
use super::io::{ByteReader, ByteWriter};

const HARDENED_LIMIT: u32 = 0x8000_0000;
const TRAILER_KINDS: usize = 8;

const fn valid_derivation(branch: u8, index: u32) -> bool {
    branch <= 1 && index < HARDENED_LIMIT
}

const fn valid_ms45(hint: Ms45Hint) -> bool {
    hint.chain <= 1 && hint.cosigner < HARDENED_LIMIT && hint.index < HARDENED_LIMIT
}

const fn valid_covenant_execution(mask: u16, true_mask: u16) -> bool {
    true_mask & !mask == 0
}

fn position(index: usize) -> Result<u8, PsktError> {
    u8::try_from(index).map_err(|_| PsktError::InvalidModel)
}

pub(super) fn write_trailers(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
) -> Result<(), PsktError> {
    write_network(writer, tx)?;
    write_ms45_hints(writer, tx)?;
    write_stealth(writer, tx)?;
    write_covenants(writer, tx)?;
    write_covenant_executions(writer, tx)?;
    write_derivations(writer, tx)
}

fn write_network(writer: &mut ByteWriter<'_>, tx: &Transaction) -> Result<(), PsktError> {
    if tx.network == KaspaNetwork::Unknown {
        return Err(PsktError::InvalidModel);
    }
    writer.write_u8(NETWORK_TRAILER_MARKER)?;
    writer.write_u8(tx.network as u8)
}

fn write_ms45_hints(writer: &mut ByteWriter<'_>, tx: &Transaction) -> Result<(), PsktError> {
    for (index, input) in tx.inputs[..tx.num_inputs].iter().enumerate() {
        if input.ms45_hint.present {
            write_ms45(writer, MS45_INPUT_TRAILER_MARKER, index, input.ms45_hint)?;
        }
    }
    for (index, output) in tx.outputs[..tx.num_outputs].iter().enumerate() {
        if output.ms45_hint.present {
            write_ms45(writer, MS45_OUTPUT_TRAILER_MARKER, index, output.ms45_hint)?;
        }
    }
    Ok(())
}

fn write_ms45(
    writer: &mut ByteWriter<'_>,
    marker: u8,
    index: usize,
    hint: Ms45Hint,
) -> Result<(), PsktError> {
    if !valid_ms45(hint) {
        return Err(PsktError::InvalidModel);
    }
    writer.write_u8(marker)?;
    writer.write_u8(position(index)?)?;
    writer.write_u32_le(hint.cosigner)?;
    writer.write_u32_le(hint.chain)?;
    writer.write_u32_le(hint.index)
}

fn write_stealth(writer: &mut ByteWriter<'_>, tx: &Transaction) -> Result<(), PsktError> {
    if !tx.has_stealth_tweak {
        return Ok(());
    }
    writer.write_u8(STEALTH_TRAILER_MARKER)?;
    writer.write_bytes(&tx.stealth_tweak)
}

fn write_covenants(writer: &mut ByteWriter<'_>, tx: &Transaction) -> Result<(), PsktError> {
    for (index, output) in tx.outputs[..tx.num_outputs].iter().enumerate() {
        if !output.has_covenant {
            continue;
        }
        writer.write_u8(COVENANT_TRAILER_MARKER)?;
        writer.write_u8(position(index)?)?;
        writer.write_u16_le(output.covenant_auth_input)?;
        writer.write_bytes(&output.covenant_id)?;
    }
    Ok(())
}

fn write_covenant_executions(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
) -> Result<(), PsktError> {
    for (index, input) in tx.inputs[..tx.num_inputs].iter().enumerate() {
        if !input.covenant_execution_present {
            continue;
        }
        let mask = input.covenant_execution_mask;
        let true_mask = input.covenant_execution_true_mask;
        if !valid_covenant_execution(mask, true_mask) {
            return Err(PsktError::InvalidModel);
        }
        writer.write_u8(COVENANT_EXECUTION_TRAILER_MARKER)?;
        writer.write_u8(position(index)?)?;
        writer.write_u16_le(mask)?;
        writer.write_u16_le(true_mask)?;
    }
    Ok(())
}

fn write_derivations(writer: &mut ByteWriter<'_>, tx: &Transaction) -> Result<(), PsktError> {
    for (index, input) in tx.inputs[..tx.num_inputs].iter().enumerate() {
        if input.has_derivation_hint {
            let value = (input.derivation_branch, input.derivation_index);
            write_derivation(writer, INPUT_DERIVATION_TRAILER_MARKER, index, value)?;
        }
    }
    for (index, output) in tx.outputs[..tx.num_outputs].iter().enumerate() {
        if output.has_derivation_hint {
            let value = (output.derivation_branch, output.derivation_index);
            write_derivation(writer, DERIVATION_TRAILER_MARKER, index, value)?;
        }
    }
    Ok(())
}

fn write_derivation(
    writer: &mut ByteWriter<'_>,
    marker: u8,
    index: usize,
    (branch, address_index): (u8, u32),
) -> Result<(), PsktError> {
    if !valid_derivation(branch, address_index) {
        return Err(PsktError::InvalidModel);
    }
    writer.write_u8(marker)?;
    writer.write_u8(position(index)?)?;
    writer.write_u8(branch)?;
    writer.write_u32_le(address_index)
}

const fn marker_rank(marker: u8) -> Option<u8> {
    match marker {
        NETWORK_TRAILER_MARKER => Some(0),
        MS45_INPUT_TRAILER_MARKER => Some(1),
        MS45_OUTPUT_TRAILER_MARKER => Some(2),
        STEALTH_TRAILER_MARKER => Some(3),
        COVENANT_TRAILER_MARKER => Some(4),
        COVENANT_EXECUTION_TRAILER_MARKER => Some(5),
        INPUT_DERIVATION_TRAILER_MARKER => Some(6),
        DERIVATION_TRAILER_MARKER => Some(7),
        _ => None,
    }
}

struct TrailerState {
    saw_network: bool,
    saw_stealth: bool,
    last_rank: u8,
    /// Last position seen for each positional trailer kind, indexed by rank.
    last_position: [Option<u8>; TRAILER_KINDS],
}

impl TrailerState {
    const fn new() -> Self {
        Self {
            saw_network: false,
            saw_stealth: false,
            last_rank: 0,
            last_position: [None; TRAILER_KINDS],
        }
    }

    /// The network trailer comes first and kinds never go back in rank.
    fn enter(&mut self, marker: u8) -> Result<u8, PsktError> {
        let rank = marker_rank(marker).ok_or(PsktError::TrailingData)?;
        if (!self.saw_network && marker != NETWORK_TRAILER_MARKER) || rank < self.last_rank {
            return Err(PsktError::InvalidTrailer);
        }
        self.last_rank = rank;
        Ok(rank)
    }

    /// Positions within one kind strictly increase, which also rules out duplicates.
    fn advance(&mut self, rank: u8, position: u8, bound: usize) -> Result<usize, PsktError> {
        let last = &mut self.last_position[usize::from(rank)];
        if last.is_some_and(|prior| position <= prior) || usize::from(position) >= bound {
            return Err(PsktError::InvalidTrailer);
        }
        *last = Some(position);
        Ok(usize::from(position))
    }
}

pub(super) fn read_trailers(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
) -> Result<(), PsktError> {
    let mut state = TrailerState::new();
    while let Some(marker) = reader.peek_u8() {
        let before_remaining = reader.remaining();
        let rank = state.enter(marker)?;
        reader.read_u8()?;
        read_trailer(marker, rank, reader, tx, &mut state)?;
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

fn read_trailer(
    marker: u8,
    rank: u8,
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    state: &mut TrailerState,
) -> Result<(), PsktError> {
    match marker {
        NETWORK_TRAILER_MARKER => read_network(reader, tx, state),
        STEALTH_TRAILER_MARKER => read_stealth(reader, tx, state),
        MS45_INPUT_TRAILER_MARKER => {
            let index = state.advance(rank, reader.read_u8()?, tx.num_inputs)?;
            tx.inputs[index].ms45_hint = read_ms45_body(reader)?;
            Ok(())
        }
        MS45_OUTPUT_TRAILER_MARKER => {
            let index = state.advance(rank, reader.read_u8()?, tx.num_outputs)?;
            tx.outputs[index].ms45_hint = read_ms45_body(reader)?;
            Ok(())
        }
        COVENANT_TRAILER_MARKER => {
            let index = state.advance(rank, reader.read_u8()?, tx.num_outputs)?;
            read_covenant(reader, tx, index)
        }
        COVENANT_EXECUTION_TRAILER_MARKER => {
            let index = state.advance(rank, reader.read_u8()?, tx.num_inputs)?;
            read_covenant_execution(reader, tx, index)
        }
        _ => read_derivation(marker, rank, reader, tx, state),
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
    tx.network = KaspaNetwork::from_wire(reader.read_u8()?).ok_or(PsktError::InvalidTrailer)?;
    state.saw_network = true;
    Ok(())
}

fn read_stealth(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    state: &mut TrailerState,
) -> Result<(), PsktError> {
    if state.saw_stealth {
        return Err(PsktError::InvalidTrailer);
    }
    tx.stealth_tweak.copy_from_slice(reader.read_bytes(32)?);
    tx.has_stealth_tweak = true;
    state.saw_stealth = true;
    Ok(())
}

fn read_ms45_body(reader: &mut ByteReader<'_>) -> Result<Ms45Hint, PsktError> {
    let hint = Ms45Hint {
        present: true,
        cosigner: reader.read_u32_le()?,
        chain: reader.read_u32_le()?,
        index: reader.read_u32_le()?,
    };
    if !valid_ms45(hint) {
        return Err(PsktError::InvalidTrailer);
    }
    Ok(hint)
}

fn read_covenant(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    output_index: usize,
) -> Result<(), PsktError> {
    let authorizing_input = reader.read_u16_le()?;
    if usize::from(authorizing_input) >= tx.num_inputs {
        return Err(PsktError::InvalidTrailer);
    }
    let covenant_id = reader.read_bytes(32)?;
    let output = &mut tx.outputs[output_index];
    output.has_covenant = true;
    output.covenant_auth_input = authorizing_input;
    output.covenant_id.copy_from_slice(covenant_id);
    Ok(())
}

fn read_covenant_execution(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    input_index: usize,
) -> Result<(), PsktError> {
    let mask = reader.read_u16_le()?;
    let true_mask = reader.read_u16_le()?;
    if !valid_covenant_execution(mask, true_mask) {
        return Err(PsktError::InvalidTrailer);
    }
    let input = &mut tx.inputs[input_index];
    input.covenant_execution_present = true;
    input.covenant_execution_mask = mask;
    input.covenant_execution_true_mask = true_mask;
    Ok(())
}

fn read_derivation(
    marker: u8,
    rank: u8,
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    state: &mut TrailerState,
) -> Result<(), PsktError> {
    let is_input = marker == INPUT_DERIVATION_TRAILER_MARKER;
    let bound = if is_input {
        tx.num_inputs
    } else {
        tx.num_outputs
    };
    let index = state.advance(rank, reader.read_u8()?, bound)?;
    let branch = reader.read_u8()?;
    let address_index = reader.read_u32_le()?;
    if !valid_derivation(branch, address_index) {
        return Err(PsktError::InvalidTrailer);
    }
    if is_input {
        let input = &mut tx.inputs[index];
        input.has_derivation_hint = true;
        input.derivation_branch = branch;
        input.derivation_index = address_index;
    } else {
        let output = &mut tx.outputs[index];
        output.has_derivation_hint = true;
        output.derivation_branch = branch;
        output.derivation_index = address_index;
    }
    Ok(())
}
