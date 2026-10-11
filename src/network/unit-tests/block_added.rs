use crate::network::{
    codec::primitives::WireWriter,
    wrpc::block_added::{self, BLOCK_ADDED_NOTIFICATION_OPERATION},
};

fn payload(value: &[u8]) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_bytes(value).expect("test payload length");
    writer.into_vec()
}

fn rpc_header(block_hash: [u8; 32], daa_score: u64) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_u16(1); // RpcHeader serializer version
    writer.write_raw(&block_hash);
    writer.write_u16(0); // consensus header version
    writer.write_u32(0); // no parent levels
    writer.write_raw(&[0x11; 32]); // hash merkle root
    writer.write_raw(&[0x22; 32]); // accepted-id merkle root
    writer.write_raw(&[0x33; 32]); // UTXO commitment
    writer.write_u64(1234); // timestamp
    writer.write_u32(0x1d00ffff); // bits
    writer.write_u64(9); // nonce
    writer.write_u64(daa_score);
    writer.write_raw(&[0x44; 24]); // blue work
    writer.write_u64(77); // blue score
    writer.write_raw(&[0x55; 32]); // pruning point
    writer.into_vec()
}

fn rpc_transaction(transaction_id: [u8; 32], app_payload: &[u8]) -> Vec<u8> {
    let mut verbose = WireWriter::new();
    verbose.write_u8(1); // RpcTransactionVerboseData serializer version
    verbose.write_raw(&transaction_id);
    verbose.write_raw(&[0x66; 32]); // transaction hash
    verbose.write_u64(123); // compute mass
    verbose.write_raw(&[0x77; 32]); // containing block hash
    verbose.write_u64(456); // block time

    let mut optional_verbose = WireWriter::new();
    optional_verbose.write_u8(1); // Some
    optional_verbose
        .write_bytes(&verbose.into_vec())
        .expect("verbose payload");

    let mut writer = WireWriter::new();
    writer.write_u16(1); // RpcTransaction serializer version
    writer.write_u16(0); // transaction version
    writer.write_bytes(&[]).expect("inputs payload");
    writer.write_bytes(&[]).expect("outputs payload");
    writer.write_u64(0); // lock time
    writer.write_raw(&[0; 20]); // subnetwork id
    writer.write_u64(0); // gas
    writer
        .write_bytes(app_payload)
        .expect("application payload");
    writer.write_u64(0); // storage mass
    writer
        .write_bytes(&optional_verbose.into_vec())
        .expect("optional verbose payload");
    writer.into_vec()
}

/// One `RpcBlock(v1)` carrying a single transaction.
pub(super) fn rpc_block(
    block_hash: [u8; 32],
    daa_score: u64,
    txid: [u8; 32],
    app: &[u8],
) -> Vec<u8> {
    let tx = rpc_transaction(txid, app);

    let mut transactions = WireWriter::new();
    transactions.write_u32(1);
    transactions.write_bytes(&tx).expect("transaction payload");

    let mut block = WireWriter::new();
    block.write_u16(1); // RpcBlock serializer version
    block
        .write_bytes(&rpc_header(block_hash, daa_score))
        .expect("header payload");
    block
        .write_bytes(&transactions.into_vec())
        .expect("transactions payload");
    block.write_bytes(&[0]).expect("None block verbose payload");
    block.into_vec()
}

fn block_added_frame(block_hash: [u8; 32], daa_score: u64, txid: [u8; 32], app: &[u8]) -> Vec<u8> {
    let block = rpc_block(block_hash, daa_score, txid, app);

    let mut block_added = WireWriter::new();
    block_added.write_u16(1); // BlockAddedNotification serializer version
    block_added.write_bytes(&block).expect("RpcBlock payload");

    let mut notification = WireWriter::new();
    notification.write_u16(1); // Notification serializer version
    notification.write_u16(0); // Notification::BlockAdded
    notification
        .write_bytes(&block_added.into_vec())
        .expect("BlockAdded payload");

    let mut frame = WireWriter::new();
    frame.write_u8(0); // no request id
    frame.write_u8(0xff); // server notification
    frame.write_u8(1); // operation is Some
    frame.write_u8(BLOCK_ADDED_NOTIFICATION_OPERATION);
    frame.write_raw(&payload(&notification.into_vec()));
    frame.into_vec()
}

#[test]
fn block_added_decoder_extracts_identity_and_transaction_payload() {
    let block_hash = [0x6a; 32];
    let txid = [0x7b; 32];
    let app_payload = vec![0xa5; 60 * 1024];
    let frame = block_added_frame(block_hash, 456_789, txid, &app_payload);

    let decoded = block_added::decode(&frame)
        .expect("valid BlockAdded notification")
        .expect("BlockAdded operation");
    assert_eq!(decoded.block_hash, hex::encode(block_hash));
    assert_eq!(decoded.daa_score, 456_789);
    assert_eq!(decoded.transactions.len(), 1);
    let expected_txid = hex::encode(txid);
    assert_eq!(
        decoded.transactions[0].transaction_id.as_deref(),
        Some(expected_txid.as_str())
    );
    assert_eq!(decoded.transactions[0].payload, app_payload.as_slice());
}

#[test]
fn block_added_decoder_ignores_other_notification_operations() {
    let frame = [0, 0xff, 1, 61];
    assert!(block_added::decode(&frame)
        .expect("other notification should be accepted")
        .is_none());
}

#[test]
fn block_added_decoder_rejects_rpc_response_frames() {
    let mut frame = WireWriter::new();
    frame.write_u8(1);
    frame.write_u64(7);
    frame.write_u8(0);
    frame.write_u8(1);
    frame.write_u8(BLOCK_ADDED_NOTIFICATION_OPERATION);
    assert!(block_added::decode(&frame.into_vec()).is_err());
}

/// An `RpcHeader(v1)` whose `parents_by_level` section is `parents`.
fn rpc_header_with_parents(parents: &[u8]) -> Vec<u8> {
    let standard = rpc_header([0x6a; 32], 5);
    // Replace the empty parent-level count (after version, hash, header version).
    let mut header = standard[..36].to_vec();
    header.extend_from_slice(parents);
    header.extend_from_slice(&standard[40..]);
    header
}

fn block_from(header: &[u8], transactions: &[u8], trailing: &[u8]) -> Vec<u8> {
    let mut block = WireWriter::new();
    block.write_u16(1);
    block.write_bytes(header).expect("header payload");
    block
        .write_bytes(transactions)
        .expect("transactions payload");
    block.write_bytes(&[0]).expect("block verbose payload");
    block.write_raw(trailing);
    block.into_vec()
}

fn transactions_with_count(count: u32, items: &[Vec<u8>], trailing: &[u8]) -> Vec<u8> {
    let mut writer = WireWriter::new();
    writer.write_u32(count);
    for item in items {
        writer.write_bytes(item).expect("transaction payload");
    }
    writer.write_raw(trailing);
    writer.into_vec()
}

fn decode_error(block: &[u8]) -> String {
    block_added::decode_rpc_block(block)
        .expect_err("malformed block")
        .to_string()
}

#[test]
fn every_nested_record_must_be_consumed_exactly() {
    let header = rpc_header([0x6a; 32], 5);
    let tx = rpc_transaction([0x7b; 32], b"app");
    let one = transactions_with_count(1, std::slice::from_ref(&tx), &[]);
    assert!(block_added::decode_rpc_block(&block_from(&header, &one, &[])).is_ok());
    assert!(decode_error(&block_from(&header, &one, &[0])).contains("after RpcBlock"));
    assert!(decode_error(&block_from(
        &header,
        &transactions_with_count(1, std::slice::from_ref(&tx), &[0]),
        &[]
    ))
    .contains("after Vec<RpcTransaction>"));
    let mut long_header = header.clone();
    long_header.push(0);
    assert!(decode_error(&block_from(&long_header, &one, &[])).contains("after RpcHeader"));
    let mut long_tx = tx;
    long_tx.push(0);
    assert!(decode_error(&block_from(
        &header,
        &transactions_with_count(1, &[long_tx], &[]),
        &[]
    ))
    .contains("after RpcTransaction"));
}

#[test]
fn transaction_and_parent_counts_are_bounded_exactly() {
    let header = rpc_header([0x6a; 32], 5);
    let at_limit = decode_error(&block_from(
        &header,
        &transactions_with_count(1_000_000, &[], &[]),
        &[],
    ));
    assert!(
        !at_limit.contains("transaction count exceeds"),
        "{at_limit}"
    );
    assert!(decode_error(&block_from(
        &header,
        &transactions_with_count(1_000_001, &[], &[]),
        &[]
    ))
    .contains("transaction count exceeds safety bound"));

    let levels = |count: u32| rpc_header_with_parents(&count.to_le_bytes());
    let empty = transactions_with_count(0, &[], &[]);
    let at_limit = decode_error(&block_from(&levels(1024), &empty, &[]));
    assert!(
        !at_limit.contains("parent-level count exceeds"),
        "{at_limit}"
    );
    assert!(decode_error(&block_from(&levels(1025), &empty, &[]))
        .contains("parent-level count exceeds safety bound"));

    let one_level = |parents: u32, hashes: usize| {
        let mut section = 1u32.to_le_bytes().to_vec();
        section.extend_from_slice(&parents.to_le_bytes());
        section.extend_from_slice(&vec![0x99; 32 * hashes]);
        rpc_header_with_parents(&section)
    };
    let two_parents = block_from(&one_level(2, 2), &empty, &[]);
    let decoded =
        block_added::decode_rpc_block(&two_parents).expect("two parent hashes are skipped exactly");
    assert_eq!(decoded.daa_score, 5);
    let at_limit = decode_error(&block_from(&one_level(65_536, 0), &empty, &[]));
    assert!(!at_limit.contains("parent count exceeds"), "{at_limit}");
    assert!(
        decode_error(&block_from(&one_level(65_537, 0), &empty, &[]))
            .contains("parent count exceeds safety bound")
    );
}

#[test]
fn large_payloads_decode_and_malformed_verbose_data_yields_no_id() {
    let header = rpc_header([0x6a; 32], 5);
    let big = vec![0x5a; 1_100_000];
    let block = block_from(
        &header,
        &transactions_with_count(1, &[rpc_transaction([1; 32], &big)], &[]),
        &[],
    );
    let decoded = block_added::decode_rpc_block(&block).expect("large payload");
    assert_eq!(decoded.transactions[0].payload.len(), big.len());

    // Rewrite the optional verbose section of a transaction.
    let with_verbose = |optional: &[u8]| {
        let standard = rpc_transaction([2; 32], b"x");
        let verbose_start = standard.len() - (4 + 1 + 4 + 1 + 32 + 32 + 8 + 32 + 8);
        let mut tx = standard[..verbose_start].to_vec();
        let mut writer = WireWriter::new();
        writer.write_bytes(optional).expect("optional verbose");
        tx.extend_from_slice(&writer.into_vec());
        let block = block_from(&header, &transactions_with_count(1, &[tx], &[]), &[]);
        block_added::decode_rpc_block(&block)
            .expect("block")
            .transactions[0]
            .transaction_id
            .clone()
    };
    let verbose = |version: u8, extra: &[u8]| {
        let mut body = vec![version];
        body.extend_from_slice(&[3; 32]);
        body.extend_from_slice(&[0; 32 + 8 + 32 + 8]);
        body.extend_from_slice(extra);
        let mut writer = WireWriter::new();
        writer.write_u8(1);
        writer.write_bytes(&body).expect("verbose body");
        writer.into_vec()
    };
    assert_eq!(with_verbose(&verbose(1, &[])), Some(hex::encode([3; 32])));
    assert_eq!(with_verbose(&[0]), None);
    assert_eq!(with_verbose(&[2]), None);
    assert_eq!(with_verbose(&verbose(2, &[])), None);
    assert_eq!(with_verbose(&verbose(1, &[0])), None);
    let mut trailing = verbose(1, &[]);
    trailing.push(0);
    assert_eq!(with_verbose(&trailing), None);
}
