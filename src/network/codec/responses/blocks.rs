//! `GetBlocksResponse(v1)`: `Vec<RpcHash>` then `serialize!(Vec<RpcBlock>)`.

use crate::network::{
    codec::primitives::WireReader,
    error::NetworkError,
    wrpc::block_added::{decode_rpc_block, OwnedBlockAddedNotification},
};

/// Kaspa wRPC success payloads start with this marker before the
/// length-prefixed `Serializable` response (see the UTXO response vector).
const RESPONSE_PRESENT: u8 = 1;
const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;
/// A node answers one bounded page of the DAG past `low_hash`.
const MAX_BLOCKS: usize = 100_000;

pub fn decode(data: &[u8]) -> Result<Vec<OwnedBlockAddedNotification>, NetworkError> {
    let mut reader = WireReader::new(data);
    if reader.read_u8()? != RESPONSE_PRESENT {
        return Err(NetworkError::InvalidEncoding(
            "GetBlocks response is missing its payload marker".into(),
        ));
    }
    let response = reader.read_bytes(MAX_BLOB_BYTES)?;
    require_empty(&reader)?;
    let mut response = WireReader::new(response);
    response.read_u16()?;
    let hashes = bounded_count(&mut response)?;
    let hash_bytes = hashes.checked_mul(32).ok_or(NetworkError::InvalidLength)?;
    response.read_exact(hash_bytes)?;
    let blocks = response.read_bytes(MAX_BLOB_BYTES)?;
    require_empty(&response)?;

    let mut reader = WireReader::new(blocks);
    let count = bounded_count(&mut reader)?;
    let mut decoded = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let block = reader.read_bytes(MAX_BLOB_BYTES)?;
        decoded.push(decode_rpc_block(block)?.into());
    }
    require_empty(&reader)?;
    Ok(decoded)
}

fn bounded_count(reader: &mut WireReader<'_>) -> Result<usize, NetworkError> {
    let count = usize::try_from(reader.read_u32()?).map_err(|_| NetworkError::InvalidLength)?;
    if count > MAX_BLOCKS {
        return Err(NetworkError::InvalidLength);
    }
    Ok(count)
}

fn require_empty(reader: &WireReader<'_>) -> Result<(), NetworkError> {
    if reader.remaining().is_empty() {
        Ok(())
    } else {
        Err(NetworkError::InvalidEncoding(
            "trailing bytes after GetBlocksResponse".into(),
        ))
    }
}
