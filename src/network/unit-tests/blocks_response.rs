use super::block_added::rpc_block;
use crate::network::{
    codec::{primitives::WireWriter, requests, responses::blocks},
    error::NetworkError,
};

/// A `GetBlocks` success payload exactly as `client.call` returns it.
fn response(hashes: &[[u8; 32]], rpc_blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut blocks = WireWriter::new();
    blocks.write_u32(rpc_blocks.len() as u32);
    for block in rpc_blocks {
        blocks.write_bytes(block).expect("RpcBlock payload");
    }
    let mut inner = WireWriter::new();
    inner.write_u16(1); // GetBlocksResponse serializer version
    inner.write_u32(hashes.len() as u32);
    for hash in hashes {
        inner.write_raw(hash);
    }
    inner
        .write_bytes(&blocks.into_vec())
        .expect("blocks payload");
    let mut outer = WireWriter::new();
    outer.write_u8(1); // payload marker
    outer
        .write_bytes(&inner.into_vec())
        .expect("response payload");
    outer.into_vec()
}

#[test]
fn get_blocks_request_asks_for_blocks_and_transactions_past_low_hash() {
    let low = [0xab; 32];
    let encoded = requests::block::encode_get_blocks(&low);
    let mut expected = vec![1, 0, 1];
    expected.extend_from_slice(&low);
    expected.extend_from_slice(&[1, 1]);
    assert_eq!(encoded, expected);
}

#[test]
fn get_blocks_response_decodes_every_block_and_payload() {
    let first = rpc_block([1; 32], 10, [7; 32], b"carrier-one");
    let second = rpc_block([2; 32], 11, [8; 32], b"carrier-two");
    let decoded = blocks::decode(&response(&[[1; 32], [2; 32]], &[first, second]))
        .expect("GetBlocks response decodes");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].block_hash, hex::encode([1u8; 32]));
    assert_eq!(decoded[1].daa_score, 11);
    assert_eq!(decoded[1].transactions[0].payload, b"carrier-two");
    assert_eq!(
        decoded[0].transactions[0].transaction_id.as_deref(),
        Some(hex::encode([7u8; 32]).as_str())
    );
}

#[test]
fn get_blocks_response_with_no_new_blocks_is_empty() {
    assert!(blocks::decode(&response(&[], &[]))
        .expect("empty page")
        .is_empty());
}

#[test]
fn get_blocks_response_rejects_trailing_bytes_and_truncation() {
    let mut trailing = response(&[[1; 32]], &[rpc_block([1; 32], 1, [2; 32], b"x")]);
    trailing.push(0);
    assert!(blocks::decode(&trailing).is_err());

    let full = response(&[[1; 32]], &[rpc_block([1; 32], 1, [2; 32], b"x")]);
    assert!(blocks::decode(&full[..full.len() - 3]).is_err());
}

#[test]
fn get_blocks_response_rejects_unbounded_counts() {
    let mut inner = WireWriter::new();
    inner.write_u16(1);
    inner.write_u32(u32::MAX);
    let mut outer = WireWriter::new();
    outer.write_u8(1);
    outer.write_bytes(&inner.into_vec()).expect("payload");
    assert!(matches!(
        blocks::decode(&outer.into_vec()),
        Err(NetworkError::InvalidLength)
    ));
}

#[test]
fn get_blocks_response_requires_the_payload_marker() {
    let mut unmarked = response(&[], &[]);
    unmarked[0] = 0;
    assert!(blocks::decode(&unmarked).is_err());
    assert!(blocks::decode(&[]).is_err());
}
