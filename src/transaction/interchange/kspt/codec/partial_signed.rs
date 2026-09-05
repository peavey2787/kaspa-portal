use crate::transaction::model::{SigHashType, Transaction, MAX_SIGS_PER_INPUT};

use super::super::{
    error::PsktError,
    format::{
        FLAG_SIGNED_OR_COMPLETE, KSPT_MAGIC, KSPT_VERSION_CURRENT, PARTIAL_SIGNED_ALLOWED_FLAGS,
    },
    signing::is_fully_signed,
    validation::{checked_redeem_bytes, validate_partial_signed},
};
use super::{
    common::{
        read_base_input, read_global, read_output, write_base_input, write_global, write_output,
    },
    io::{ByteReader, ByteWriter},
    trailers::{read_trailers, write_trailers},
};

/// Serialize a partial or complete compact KSPT version-1 envelope.
pub fn serialize_compact_kspt(tx: &Transaction, output: &mut [u8]) -> Result<usize, PsktError> {
    validate_partial_signed(tx)?;
    let mut writer = ByteWriter::new(output);
    write_compact_header(&mut writer, tx)?;
    write_global(&mut writer, tx)?;
    write_compact_inputs(&mut writer, tx)?;
    write_compact_outputs(&mut writer, tx)?;
    write_trailers(&mut writer, tx)?;
    Ok(writer.written())
}

fn write_compact_header(writer: &mut ByteWriter<'_>, tx: &Transaction) -> Result<(), PsktError> {
    writer.write_bytes(&KSPT_MAGIC)?;
    writer.write_u8(KSPT_VERSION_CURRENT)?;
    let flags = if is_fully_signed(tx) {
        FLAG_SIGNED_OR_COMPLETE
    } else {
        0
    };
    writer.write_u8(flags)
}

fn write_compact_inputs(writer: &mut ByteWriter<'_>, tx: &Transaction) -> Result<(), PsktError> {
    for input_index in 0..tx.num_inputs {
        write_compact_input(writer, tx, input_index)?;
    }
    Ok(())
}

fn write_compact_input(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
    input_index: usize,
) -> Result<(), PsktError> {
    write_base_input(writer, tx, input_index)?;
    let input = &tx.inputs[input_index];
    writer.write_u8(input.sig_count)?;
    for slot in &input.sigs[..input.sig_count as usize] {
        writer.write_u8(slot.pubkey_pos)?;
        writer.write_u8(slot.sighash_type)?;
        writer.write_bytes(&slot.signature)?;
    }
    let redeem = checked_redeem_bytes(tx, input_index)?;
    writer.write_u16_le(redeem.len() as u16)?;
    writer.write_bytes(redeem)
}

fn write_compact_outputs(writer: &mut ByteWriter<'_>, tx: &Transaction) -> Result<(), PsktError> {
    for output_index in 0..tx.num_outputs {
        write_output(writer, tx, output_index)?;
    }
    Ok(())
}

fn read_compact_header(reader: &mut ByteReader<'_>) -> Result<bool, PsktError> {
    if reader.read_bytes(4)? != KSPT_MAGIC {
        return Err(PsktError::InvalidMagic);
    }
    if reader.read_u8()? != KSPT_VERSION_CURRENT {
        return Err(PsktError::UnsupportedVersion);
    }
    let flags = reader.read_u8()?;
    if flags & !PARTIAL_SIGNED_ALLOWED_FLAGS != 0 {
        return Err(PsktError::InvalidFlags);
    }
    Ok(flags & FLAG_SIGNED_OR_COMPLETE != 0)
}

fn read_signature_slot(
    reader: &mut ByteReader<'_>,
    slot: &mut crate::transaction::model::InputSig,
    seen_positions: &mut [bool; 256],
) -> Result<(), PsktError> {
    let pubkey_position = reader.read_u8()?;
    let position = pubkey_position as usize;
    if seen_positions[position] {
        return Err(PsktError::InvalidSignatureState);
    }
    seen_positions[position] = true;
    let sighash_type = reader.read_u8()?;
    if SigHashType::from_byte(sighash_type).is_none() {
        return Err(PsktError::InvalidSigHashType);
    }
    slot.pubkey_pos = pubkey_position;
    slot.sighash_type = sighash_type;
    slot.signature.copy_from_slice(reader.read_bytes(64)?);
    slot.present = true;
    Ok(())
}

fn read_signature_slots(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    input_index: usize,
) -> Result<(), PsktError> {
    let signature_count = reader.read_u8()? as usize;
    if signature_count > MAX_SIGS_PER_INPUT {
        return Err(PsktError::TooManySignatures);
    }
    let mut seen_positions = [false; 256];
    for slot_index in 0..signature_count {
        read_signature_slot(
            reader,
            &mut tx.inputs[input_index].sigs[slot_index],
            &mut seen_positions,
        )?;
    }
    let input = &mut tx.inputs[input_index];
    input.sig_count = signature_count as u8;
    if let Some(first) = input.sigs[..signature_count].first() {
        input.sighash_type = first.sighash_type;
    }
    Ok(())
}

fn read_redeem_script(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    input_index: usize,
) -> Result<(), PsktError> {
    let redeem_len = reader.read_u16_le()? as usize;
    if redeem_len == 0 {
        return Ok(());
    }
    let redeem = reader.read_bytes(redeem_len)?;
    tx.store_redeem(input_index, redeem)
        .map_err(|_| PsktError::ScriptTooLong)
}

fn read_compact_input(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    input_index: usize,
) -> Result<(), PsktError> {
    let required_slots = input_index.checked_add(1).ok_or(PsktError::TooManyInputs)?;
    tx.ensure_input_slots(required_slots)
        .map_err(|_| PsktError::TooManyInputs)?;
    read_base_input(reader, tx, input_index)?;
    read_signature_slots(reader, tx, input_index)?;
    read_redeem_script(reader, tx, input_index)
}

fn read_compact_body(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
) -> Result<(usize, usize), PsktError> {
    let (num_inputs, num_outputs) = read_global(reader, tx)?;
    for input_index in 0..num_inputs {
        read_compact_input(reader, tx, input_index)?;
    }
    for output_index in 0..num_outputs {
        read_output(reader, tx, output_index)?;
    }
    Ok((num_inputs, num_outputs))
}

/// Parse a compact partial-signed KSPT version-1 envelope.
pub fn parse_compact_kspt(data: &[u8], tx: &mut Transaction) -> Result<(), PsktError> {
    tx.clear();
    let mut reader = ByteReader::new(data);
    let declared_complete = read_compact_header(&mut reader)?;
    let (num_inputs, num_outputs) = read_compact_body(&mut reader, tx)?;
    tx.num_inputs = num_inputs;
    tx.num_outputs = num_outputs;
    read_trailers(&mut reader, tx)?;
    reader.finish()?;
    if declared_complete != is_fully_signed(tx) {
        return Err(PsktError::InvalidSignatureState);
    }
    validate_partial_signed(tx)
}

/// Serialize a compact KSPT into a dynamically sized buffer. This is the
/// preferred API for firmware/browser flows where input count is not bounded.
pub fn serialize_compact_kspt_vec(tx: &Transaction) -> Result<alloc::vec::Vec<u8>, PsktError> {
    let capacity = 1024usize
        .saturating_add(tx.num_inputs.saturating_mul(192))
        .saturating_add(tx.num_outputs.saturating_mul(640))
        .saturating_add(tx.payload.len())
        .saturating_add(tx.redeem_pool_used);
    serialize_compact_vec_with_capacity(tx, capacity)
}

fn serialize_compact_vec_with_capacity(
    tx: &Transaction,
    capacity: usize,
) -> Result<alloc::vec::Vec<u8>, PsktError> {
    let mut output = alloc::vec![0u8; capacity];
    serialize_compact_kspt(tx, &mut output)
        .map(|length| {
            output.truncate(length);
            output
        })
        .or_else(|error| retry_compact_vec(tx, capacity, error))
}

fn retry_compact_vec(
    tx: &Transaction,
    capacity: usize,
    error: PsktError,
) -> Result<alloc::vec::Vec<u8>, PsktError> {
    if error != PsktError::OutputBufferTooSmall {
        return Err(error);
    }
    capacity
        .checked_mul(2)
        .ok_or(PsktError::OutputBufferTooSmall)
        .and_then(|next| serialize_compact_vec_with_capacity(tx, next))
}

#[cfg(test)]
#[path = "partial_signed/unit-tests/mod.rs"]
mod unit_tests;
