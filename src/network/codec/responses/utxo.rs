use super::envelope::{require_consumed, response_body};
use crate::{
    network::{codec::primitives::WireReader, error::NetworkError},
    primitives::utxo::UtxoEntry,
};

/// 16 MiB.
const MAX_BLOB_BYTES: usize = 16_777_216;
const MAX_UTXOS: usize = 1_000_000;
const RESPONSE: &str = "GetUtxosByAddressesResponse";
/// Outpoint version (1) + transaction id (32) + output index (4).
const OUTPOINT_BYTES: usize = 37;
/// The only script version Portal's transaction builder signs for.
const SPENDABLE_SCRIPT_VERSION: u16 = 0;

pub(crate) fn decode_entries(entries_blob: &[u8]) -> Result<Vec<UtxoEntry>, NetworkError> {
    let mut reader = WireReader::new(entries_blob);
    let count = usize::try_from(reader.read_u32()?).map_err(|_| NetworkError::InvalidLength)?;
    if count > MAX_UTXOS {
        return Err(NetworkError::InvalidLength);
    }
    // The count is untrusted: reserve a bounded amount, grow as entries parse.
    let mut entries = Vec::with_capacity(count.min(4096));
    for index_in_response in 0..count {
        let entry_blob = reader.read_bytes(MAX_BLOB_BYTES)?;
        entries.push(decode_entry(entry_blob, index_in_response)?);
    }
    require_consumed(&reader, "UTXO entry list")?;
    Ok(entries)
}

pub fn decode(data: &[u8]) -> Result<Vec<UtxoEntry>, NetworkError> {
    let mut response = response_body(data, MAX_BLOB_BYTES, RESPONSE)?;
    decode_entries(response.read_bytes(MAX_BLOB_BYTES)?)
}

fn decode_entry(data: &[u8], index_in_response: usize) -> Result<UtxoEntry, NetworkError> {
    let mut reader = WireReader::new(data);
    skip_entry_metadata(&mut reader)?;
    let (tx_id, index) = decode_outpoint(&mut reader, index_in_response)?;
    let (amount, script_public_key, block_daa_score, covenant_id) =
        decode_utxo(&mut reader, index_in_response)?;
    Ok(UtxoEntry {
        tx_id,
        index,
        amount,
        script_public_key,
        block_daa_score,
        covenant_id,
    })
}

fn skip_entry_metadata(reader: &mut WireReader<'_>) -> Result<(), NetworkError> {
    reader.read_u8()?;
    let metadata_tag = reader.read_u8()?;
    if metadata_tag == 1 {
        skip_present_entry_metadata(reader)?;
    }
    Ok(())
}

fn skip_present_entry_metadata(reader: &mut WireReader<'_>) -> Result<(), NetworkError> {
    reader.read_u8()?;
    reader.read_u8()?;
    reader.read_bytes(MAX_BLOB_BYTES)?;
    Ok(())
}

fn decode_outpoint(
    reader: &mut WireReader<'_>,
    index_in_response: usize,
) -> Result<(String, u32), NetworkError> {
    let outpoint = reader.read_bytes(MAX_BLOB_BYTES)?;
    let [_version, tx_id @ .., i0, i1, i2, i3] = <[u8; OUTPOINT_BYTES]>::try_from(outpoint)
        .map_err(|_| {
            NetworkError::InvalidEncoding(format!(
                "entry {index_in_response}: outpoint {} bytes",
                outpoint.len()
            ))
        })?;
    Ok((hex::encode(tx_id), u32::from_le_bytes([i0, i1, i2, i3])))
}

fn decode_utxo(
    reader: &mut WireReader<'_>,
    index_in_response: usize,
) -> Result<(u64, Vec<u8>, u64, Option<String>), NetworkError> {
    let utxo_blob = reader.read_bytes(MAX_BLOB_BYTES)?;
    let mut utxo_reader = WireReader::new(utxo_blob);
    let version = utxo_reader.read_u8()?;
    let amount = utxo_reader.read_u64()?;
    // `UtxoEntry` carries no script version because every input is signed as
    // version 0; any other version is refused rather than relabelled.
    let script_version = utxo_reader.read_u16()?;
    if script_version != SPENDABLE_SCRIPT_VERSION {
        return Err(NetworkError::InvalidEncoding(format!(
            "entry {index_in_response}: script version {script_version} is not spendable"
        )));
    }
    let script_public_key = utxo_reader.read_bytes(MAX_BLOB_BYTES)?.to_vec();
    let block_daa_score = utxo_reader.read_u64()?;
    utxo_reader.read_bool()?;
    let covenant_id = decode_covenant_id(&mut utxo_reader, version)?;
    Ok((amount, script_public_key, block_daa_score, covenant_id))
}

fn decode_covenant_id(
    reader: &mut WireReader<'_>,
    version: u8,
) -> Result<Option<String>, NetworkError> {
    if version <= 1 || reader.read_u8()? != 1 {
        return Ok(None);
    }
    Ok(Some(hex::encode(reader.read_exact(32)?)))
}
