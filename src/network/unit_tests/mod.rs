mod block_added;
mod blocks_response;
mod dag;
mod error;
mod fee_response;
mod notification;
mod queries;
mod request;
mod resolver;
mod response;
mod transport;
mod utxo_response;

#[test]
fn wrpc_operation_codes_cover_every_known_and_unknown_value() {
    use super::wrpc::operation::Operation;

    for operation in [
        Operation::Subscribe,
        Operation::GetSink,
        Operation::SubmitTransaction,
        Operation::GetBlock,
        Operation::GetBlocks,
        Operation::GetBlockDagInfo,
        Operation::GetUtxosByAddresses,
        Operation::GetFeeEstimate,
    ] {
        assert_eq!(Operation::from_code(operation.code()), Some(operation));
    }
    for unknown in [
        0u8, 1, 4, 119, 121, 124, 127, 130, 132, 134, 136, 146, 148, 255,
    ] {
        assert_eq!(Operation::from_code(unknown), None);
    }
}

#[test]
fn wire_reader_covers_bool_length_and_truncation_boundaries() {
    use super::codec::primitives::WireReader;

    let mut bools = WireReader::new(&[0, 1, 2]);
    assert!(!bools.read_bool().unwrap());
    assert!(bools.read_bool().unwrap());
    crate::test_support::assert_err(
        &bools.read_bool(),
        r#"InvalidEncoding("invalid bool tag 2")"#,
    );

    let mut bounded = WireReader::new(&[3, 0, 0, 0, 0xaa, 0xbb, 0xcc]);
    assert_eq!(bounded.read_bytes(3).unwrap(), &[0xaa, 0xbb, 0xcc]);

    let mut too_large = WireReader::new(&[4, 0, 0, 0, 1, 2, 3, 4]);
    crate::test_support::assert_err(&too_large.read_bytes(3), "InvalidLength");

    let mut truncated = WireReader::new(&[4, 0, 0, 0, 1, 2]);
    crate::test_support::assert_err(&truncated.read_bytes(4), "TruncatedPayload");
}
