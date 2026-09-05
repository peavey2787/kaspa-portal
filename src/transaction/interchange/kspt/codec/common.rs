use crate::transaction::model::{Transaction, MAX_OUTPUTS, MAX_PAYLOAD_SIZE, MAX_SCRIPT_SIZE};

use super::super::error::PsktError;
use super::io::{ByteReader, ByteWriter};

fn read_global_counts(reader: &mut ByteReader<'_>) -> Result<(u16, usize, usize), PsktError> {
    let version = reader.read_u16_le()?;
    let num_inputs =
        usize::try_from(reader.read_u32_le()?).map_err(|_| PsktError::TooManyInputs)?;
    let num_outputs = reader.read_u8()? as usize;
    Ok((version, num_inputs, num_outputs))
}

fn validate_global_counts(num_inputs: usize, num_outputs: usize) -> Result<(), PsktError> {
    if num_inputs == 0 {
        return Err(PsktError::NoInputs);
    }
    if num_outputs == 0 {
        return Err(PsktError::NoOutputs);
    }
    if num_outputs > MAX_OUTPUTS {
        return Err(PsktError::TooManyOutputs);
    }
    Ok(())
}

fn read_global_tail(reader: &mut ByteReader<'_>, tx: &mut Transaction) -> Result<(), PsktError> {
    tx.locktime = reader.read_u64_le()?;
    tx.subnetwork_id.copy_from_slice(reader.read_bytes(20)?);
    tx.gas = reader.read_u64_le()?;
    let payload_len = reader.read_u16_le()? as usize;
    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(PsktError::PayloadTooLong);
    }
    tx.payload.clear();
    if payload_len != 0 {
        tx.payload
            .extend_from_slice(reader.read_bytes(payload_len)?);
    }
    Ok(())
}

pub(super) fn read_global(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
) -> Result<(usize, usize), PsktError> {
    let (version, num_inputs, num_outputs) = read_global_counts(reader)?;
    validate_global_counts(num_inputs, num_outputs)?;
    tx.version = version;
    read_global_tail(reader, tx)?;
    Ok((num_inputs, num_outputs))
}

pub(super) fn write_global(writer: &mut ByteWriter<'_>, tx: &Transaction) -> Result<(), PsktError> {
    writer.write_u16_le(tx.version)?;
    write_input_count(writer, tx.num_inputs)?;
    writer.write_u8(tx.num_outputs as u8)?;
    writer.write_u64_le(tx.locktime)?;
    writer.write_bytes(&tx.subnetwork_id)?;
    writer.write_u64_le(tx.gas)?;
    let payload_len = u16::try_from(tx.payload.len()).map_err(|_| PsktError::PayloadTooLong)?;
    writer.write_u16_le(payload_len)?;
    writer.write_bytes(&tx.payload)
}

fn write_input_count(writer: &mut ByteWriter<'_>, count: usize) -> Result<(), PsktError> {
    u32::try_from(count)
        .map_err(|_| PsktError::TooManyInputs)
        .and_then(|count| writer.write_u32_le(count))
}

pub(super) fn read_base_input(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    input_index: usize,
) -> Result<(), PsktError> {
    let input = &mut tx.inputs[input_index];
    input.previous_outpoint.transaction_id = reader.read_hash256()?;
    input.previous_outpoint.index = reader.read_u32_le()?;
    input.utxo_entry.amount = reader.read_u64_le()?;
    input.sequence = reader.read_u64_le()?;
    input.sig_op_count = reader.read_u8()?;
    input.utxo_entry.script_public_key.version = reader.read_u16_le()?;
    let script_len = reader.read_spk_len()?;
    if script_len > MAX_SCRIPT_SIZE {
        return Err(PsktError::ScriptTooLong);
    }
    input.utxo_entry.script_public_key.script_len = script_len;
    input.utxo_entry.script_public_key.script[..script_len]
        .copy_from_slice(reader.read_bytes(script_len)?);
    Ok(())
}

pub(super) fn write_base_input(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
    input_index: usize,
) -> Result<(), PsktError> {
    let input = &tx.inputs[input_index];
    writer.write_bytes(&input.previous_outpoint.transaction_id)?;
    writer.write_bytes(&input.previous_outpoint.index.to_le_bytes())?;
    writer.write_u64_le(input.utxo_entry.amount)?;
    writer.write_u64_le(input.sequence)?;
    writer.write_u8(input.sig_op_count)?;
    writer.write_u16_le(input.utxo_entry.script_public_key.version)?;
    writer.write_spk_len(input.utxo_entry.script_public_key.script_len)?;
    writer.write_bytes(input.utxo_entry.script_public_key.script_bytes())
}

pub(super) fn read_output(
    reader: &mut ByteReader<'_>,
    tx: &mut Transaction,
    output_index: usize,
) -> Result<(), PsktError> {
    let output = &mut tx.outputs[output_index];
    output.value = reader.read_u64_le()?;
    output.script_public_key.version = reader.read_u16_le()?;
    let script_len = reader.read_spk_len()?;
    if script_len > MAX_SCRIPT_SIZE {
        return Err(PsktError::ScriptTooLong);
    }
    output.script_public_key.script_len = script_len;
    output.script_public_key.script[..script_len].copy_from_slice(reader.read_bytes(script_len)?);
    Ok(())
}

pub(super) fn write_output(
    writer: &mut ByteWriter<'_>,
    tx: &Transaction,
    output_index: usize,
) -> Result<(), PsktError> {
    let output = &tx.outputs[output_index];
    writer.write_u64_le(output.value)?;
    writer.write_u16_le(output.script_public_key.version)?;
    writer.write_spk_len(output.script_public_key.script_len)?;
    writer.write_bytes(output.script_public_key.script_bytes())
}
