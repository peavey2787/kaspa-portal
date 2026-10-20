//! `GetBlocksResponse(v1)`: `Vec<RpcHash>` then `serialize!(Vec<RpcBlock>)`.

use super::envelope::{require_consumed, response_body};
use crate::network::{
    codec::primitives::WireReader,
    error::NetworkError,
    wrpc::block_added::{decode_rpc_block, OwnedBlockAddedNotification},
};

const RESPONSE: &str = "GetBlocksResponse";
/// 64 MiB.
const MAX_BLOB_BYTES: usize = 67_108_864;
/// A node answers one bounded page of the DAG past `low_hash`.
const MAX_BLOCKS: usize = 100_000;

pub fn decode(data: &[u8]) -> Result<Vec<OwnedBlockAddedNotification>, NetworkError> {
    let mut response = response_body(data, MAX_BLOB_BYTES, RESPONSE)?;
    let hashes = bounded_count(&mut response)?;
    let hash_bytes = hashes.checked_mul(32).ok_or(NetworkError::InvalidLength)?;
    response.read_exact(hash_bytes)?;
    let blocks = response.read_bytes(MAX_BLOB_BYTES)?;
    require_consumed(&response, RESPONSE)?;

    let mut reader = WireReader::new(blocks);
    let count = bounded_count(&mut reader)?;
    let mut decoded = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let block = reader.read_bytes(MAX_BLOB_BYTES)?;
        decoded.push(decode_rpc_block(block)?.into());
    }
    require_consumed(&reader, RESPONSE)?;
    Ok(decoded)
}

fn bounded_count(reader: &mut WireReader<'_>) -> Result<usize, NetworkError> {
    let count = usize::try_from(reader.read_u32()?).map_err(|_| NetworkError::InvalidLength)?;
    if count > MAX_BLOCKS {
        return Err(NetworkError::InvalidLength);
    }
    Ok(count)
}
