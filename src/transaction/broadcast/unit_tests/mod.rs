use crate::{
    network::codec::responses::submission,
    transaction::broadcast::encoder,
    transaction::consensus::{
        ConsensusInput, ConsensusOutput, ConsensusTransaction, InputEncoding,
    },
};

#[test]
fn consensus_submission_encoding_is_stable() {
    let transaction = ConsensusTransaction {
        tx_version: 1,
        input_encoding: InputEncoding::Budgeted,
        inputs: vec![ConsensusInput {
            prev_tx_id: [0x11; 32],
            prev_index: 2,
            sig_script: vec![0xaa, 0xbb],
            sequence: 3,
            sig_op_count: 1,
        }],
        outputs: vec![ConsensusOutput {
            value: 4,
            spk_version: 0,
            spk_script: vec![0x51],
            covenant: None,
        }],
        locktime: 5,
        subnetwork_id: [0; 20],
        gas: 0,
        payload: Vec::new(),
        storage_mass: 0,
    };

    let encoded =
        encoder::encode_submit_request(&transaction, false).expect("transaction should encode");
    assert_eq!(encoded.len(), 173);
    assert_eq!(u32::from_le_bytes(encoded[2..6].try_into().unwrap()), 166);
    assert_eq!(
        hex::encode(encoded),
        concat!(
            "0100a600000001000100480000000100000040000000022500000001",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "0200000002000000aabb03000000000000000001000000000a001d000000",
            "0100000015000000010400000000000000000001000000510100000000",
            "0500000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000010000000000"
        )
    );

    let mut committed = transaction.clone();
    committed.storage_mass = 10_111;
    let committed = encoder::encode_submit_request(&committed, false)
        .expect("storage-mass transaction should encode");
    let mass_start = committed.len() - 14;
    assert_eq!(
        u64::from_le_bytes(committed[mass_start..mass_start + 8].try_into().unwrap()),
        10_111,
    );
}

#[test]
fn submission_encoder_covers_compact_version_zero_budget_and_covenant_paths() {
    fn transaction(
        version: u16,
        encoding: InputEncoding,
        covenant: Option<(u16, [u8; 32])>,
    ) -> ConsensusTransaction {
        ConsensusTransaction {
            tx_version: version,
            input_encoding: encoding,
            inputs: vec![ConsensusInput {
                prev_tx_id: [0x21; 32],
                prev_index: 1,
                sig_script: vec![0x51],
                sequence: 2,
                sig_op_count: 3,
            }],
            outputs: vec![ConsensusOutput {
                value: 4,
                spk_version: 0,
                spk_script: vec![0x51],
                covenant,
            }],
            locktime: 5,
            subnetwork_id: [0; 20],
            gas: 0,
            payload: vec![0xaa],
            storage_mass: 0,
        }
    }

    let compact = encoder::encode_submit_request(
        &transaction(1, InputEncoding::Compact, Some((0, [0x77; 32]))),
        true,
    )
    .expect("compact covenant transaction");
    assert_eq!(compact.last(), Some(&1));

    let version_zero_budget =
        encoder::encode_submit_request(&transaction(0, InputEncoding::Budgeted, None), false)
            .expect("version-zero budget transaction");
    assert_eq!(version_zero_budget.last(), Some(&0));
    assert_ne!(compact, version_zero_budget);
}

#[test]
fn submission_response_vector_is_stable() {
    let mut response = vec![1];
    response.extend_from_slice(&34u32.to_le_bytes());
    response.extend_from_slice(&[0, 0]);
    response.extend_from_slice(&[0x44; 32]);

    assert_eq!(
        submission::decode(&response).expect("response should decode"),
        "44".repeat(32)
    );
}

#[test]
fn tagged_submission_errors_cover_declared_truncated_and_default_messages() {
    use crate::network::codec::responses::submission;

    let mut tagged = vec![0];
    tagged.extend_from_slice(&5u32.to_le_bytes());
    tagged.extend_from_slice(b"denied");
    assert!(submission::decode(&tagged)
        .unwrap_err()
        .to_string()
        .contains("denie"));

    assert!(submission::decode(&[0])
        .unwrap_err()
        .to_string()
        .contains("transaction rejected"));
}

#[test]
fn tagged_error_decoder_covers_full_truncated_and_default_payloads_directly() {
    use crate::network::codec::responses::submission::decode_tagged_error;

    let mut exact = vec![0];
    exact.extend_from_slice(&6u32.to_le_bytes());
    exact.extend_from_slice(b"denied");
    assert_eq!(decode_tagged_error(&exact), "denied");

    let mut truncated = vec![0];
    truncated.extend_from_slice(&100u32.to_le_bytes());
    truncated.extend_from_slice(b"short");
    assert_eq!(decode_tagged_error(&truncated), "short");
    assert_eq!(decode_tagged_error(&[0]), "transaction rejected by node");
}

#[test]
fn submission_decoder_covers_empty_text_errors_and_all_unwrap_shapes() {
    assert!(submission::decode(&[])
        .unwrap_err()
        .to_string()
        .contains("empty"));
    assert!(submission::decode(b"Error: denied")
        .unwrap_err()
        .to_string()
        .contains("Error: denied"));

    let mut wrapped_error = vec![1];
    wrapped_error.extend_from_slice(&5u32.to_le_bytes());
    wrapped_error.extend_from_slice(b"error");
    crate::test_support::assert_err(
        &submission::decode(&wrapped_error),
        r#"RemoteError("error")"#,
    );

    let mut two_bytes = vec![1];
    two_bytes.extend_from_slice(&2u32.to_le_bytes());
    two_bytes.extend_from_slice(&[0xaa, 0xbb]);
    assert_eq!(submission::decode(&two_bytes).unwrap(), "aabb");

    assert_eq!(submission::decode(&[1]).unwrap(), "broadcast_ok");

    // Non-tagged success wrappers start their length field at byte zero.
    let mut untagged = 2u32.to_le_bytes().to_vec();
    untagged.extend_from_slice(&[0xcc, 0xdd]);
    assert_eq!(submission::decode(&untagged).unwrap(), "ccdd");
}

#[test]
fn submission_error_decoder_strips_borsh_prefix_and_keeps_full_node_reason() {
    let reason = "Rejected transaction deadbeef: transaction has 400000 fees which is under the required amount of 421800 for compute mass 4218";
    let mut response = vec![1, 0xff, 0x00, 0x81, 0x00];
    response.extend_from_slice(reason.as_bytes());
    let error = submission::decode(&response)
        .expect_err("node rejection")
        .to_string();
    assert!(error.contains(reason));
    assert!(!error.contains('\u{fffd}'));
}

#[test]
fn submission_unwrap_reads_the_declared_length_after_the_tag() {
    use crate::network::codec::responses::submission::decode_tagged_error;

    // Five bytes cannot hold a tag, length and body: returned whole.
    assert_eq!(submission::decode(&[1, 2, 3, 4, 5]).unwrap(), "0102030405");
    // Tagged: the length is bytes 1..5, the body follows and is clipped to it.
    let mut tagged = vec![1];
    tagged.extend_from_slice(&3u32.to_le_bytes());
    tagged.extend_from_slice(&[0xa1, 0xa2, 0xa3, 0xa4]);
    assert_eq!(submission::decode(&tagged).unwrap(), "a1a2a3");
    // Untagged: the length is bytes 0..4.
    let mut untagged = 3u32.to_le_bytes().to_vec();
    untagged.extend_from_slice(&[0xb1, 0xb2, 0xb3, 0xb4]);
    assert_eq!(submission::decode(&untagged).unwrap(), "b1b2b3");
    // A tagged error needs a body byte beyond its length field.
    assert_eq!(
        decode_tagged_error(&[0, 1, 0, 0, 0]),
        "transaction rejected by node"
    );
    assert_eq!(decode_tagged_error(&[0, 1, 0, 0, 0, b'x']), "x");
}

#[test]
fn a_replacement_request_is_the_submit_request_without_its_orphan_flag() {
    let transaction = ConsensusTransaction {
        tx_version: 0,
        input_encoding: InputEncoding::Budgeted,
        inputs: Vec::new(),
        outputs: Vec::new(),
        locktime: 0,
        subnetwork_id: [0; 20],
        gas: 0,
        payload: vec![0x5a; 3],
        storage_mass: 0,
    };
    let replacement =
        encoder::encode_replacement_request(&transaction).expect("replacement should encode");
    for allow_orphan in [false, true] {
        let submit = encoder::encode_submit_request(&transaction, allow_orphan)
            .expect("submission should encode");
        assert_eq!(submit[..submit.len() - 1], replacement[..]);
        assert_eq!(submit.last(), Some(&u8::from(allow_orphan)));
    }
}

#[test]
fn a_replacement_response_yields_only_the_new_transaction_id() {
    // The replaced transaction follows the id; its payload text must not be
    // read as a node error.
    let mut body = vec![1, 0];
    body.extend_from_slice(&[0x55; 32]);
    body.extend_from_slice(b"Rejected transaction error: payload text");
    let mut response = vec![1];
    response.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
    response.extend_from_slice(&body);
    assert_eq!(
        submission::decode_replacement(&response).expect("replacement id"),
        "55".repeat(32)
    );

    let mut rejected = vec![0];
    rejected.extend_from_slice(&9u32.to_le_bytes());
    rejected.extend_from_slice(b"fee rate low");
    assert_eq!(
        submission::decode_replacement(&rejected)
            .unwrap_err()
            .to_string(),
        crate::network::error::NetworkError::RemoteError("fee rate ".into()).to_string()
    );
    assert_eq!(
        submission::decode_replacement(&[]).unwrap_err().to_string(),
        crate::network::error::NetworkError::UnexpectedResponse(
            "empty transaction replacement response".into()
        )
        .to_string()
    );
    let mut short = vec![1];
    short.extend_from_slice(&33u32.to_le_bytes());
    short.extend_from_slice(&[0x66; 33]);
    assert_eq!(
        submission::decode_replacement(&short)
            .unwrap_err()
            .to_string(),
        crate::network::error::NetworkError::UnexpectedResponse(
            "transaction replacement response holds no transaction id".into()
        )
        .to_string()
    );
}

#[test]
fn only_transaction_submissions_are_never_retried() {
    use crate::network::wrpc::operation::Operation;

    assert!(Operation::SubmitTransaction.is_submission());
    assert!(Operation::SubmitTransactionReplacement.is_submission());
    for operation in [
        Operation::Subscribe,
        Operation::GetBlock,
        Operation::GetBlocks,
        Operation::GetBlockDagInfo,
        Operation::GetUtxosByAddresses,
        Operation::GetFeeEstimate,
    ] {
        assert!(!operation.is_submission(), "{operation:?}");
    }
}
