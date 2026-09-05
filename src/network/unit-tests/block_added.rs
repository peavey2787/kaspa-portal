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

fn block_added_frame(block_hash: [u8; 32], daa_score: u64, txid: [u8; 32], app: &[u8]) -> Vec<u8> {
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

    let mut block_added = WireWriter::new();
    block_added.write_u16(1); // BlockAddedNotification serializer version
    block_added
        .write_bytes(&block.into_vec())
        .expect("RpcBlock payload");

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
