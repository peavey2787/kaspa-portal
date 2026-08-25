use crate::{
    network::codec::primitives::WireReader,
    transaction::consensus::{
        signed_kspt::{decode_signed_kspt, decode_trailers, require_signed_trailer_progress},
        InputEncoding,
    },
};

const SIGNED_COMPACT_KSPT: &str = "4b53505401010000010000000100000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111010000006400000000000000000000000000000001000022204444444444444444444444444444444444444444444444444444444444444444ac0100012222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222200005a00000000000000000022205555555555555555555555555555555555555555555555555555555555555555ac4e01";

#[test]
fn signed_compact_kspt_decodes_to_consensus_transaction() {
    let transaction = decode_signed_kspt(SIGNED_COMPACT_KSPT).expect("KSPT should decode");
    assert_eq!(transaction.tx_version, 0);
    assert_eq!(transaction.input_encoding, InputEncoding::Compact);
    assert_eq!(transaction.inputs.len(), 1);
    assert_eq!(transaction.outputs.len(), 1);
    assert_eq!(transaction.inputs[0].prev_tx_id, [0x11; 32]);
    assert_eq!(transaction.inputs[0].prev_index, 1);
    assert_eq!(transaction.inputs[0].sig_script.len(), 66);
    assert_eq!(transaction.inputs[0].sig_script[0], 65);
    assert_eq!(transaction.inputs[0].sig_script[65], 1);
    assert_eq!(transaction.outputs[0].value, 90);
}

#[test]
fn non_v1_kspt_versions_are_rejected() {
    for unsupported in [0u8, 2u8, 3u8, 4u8, u8::MAX] {
        let mut bytes = hex::decode(SIGNED_COMPACT_KSPT).unwrap();
        bytes[4] = unsupported;
        assert!(decode_signed_kspt(&hex::encode(bytes)).is_err());
    }
}

#[test]
fn compact_trailers_cover_stealth_covenants_and_rejections() {
    use crate::transaction::consensus::ConsensusOutput;

    fn output() -> ConsensusOutput {
        ConsensusOutput {
            value: 1,
            spk_version: 0,
            spk_script: vec![0x51],
            covenant: None,
        }
    }

    let mut outputs = vec![output()];
    let mut valid = vec![b'N', 1, b'S'];
    valid.extend_from_slice(&[0x11; 32]);
    valid.push(b'C');
    valid.push(0);
    valid.extend_from_slice(&0u16.to_le_bytes());
    valid.extend_from_slice(&[0x22; 32]);
    decode_trailers(&mut WireReader::new(&valid), 1, &mut outputs).unwrap();
    assert_eq!(outputs[0].covenant, Some((0, [0x22; 32])));

    let invalid_cases = [
        vec![b'S'],
        {
            let mut value = vec![b'S'];
            value.extend_from_slice(&[0; 32]);
            value.push(b'S');
            value.extend_from_slice(&[0; 32]);
            value
        },
        {
            let mut value = vec![b'C', 1];
            value.extend_from_slice(&0u16.to_le_bytes());
            value.extend_from_slice(&[0; 32]);
            value
        },
        {
            let mut value = vec![b'C', 0];
            value.extend_from_slice(&1u16.to_le_bytes());
            value.extend_from_slice(&[0; 32]);
            value
        },
        vec![b'X'],
    ];
    for invalid in invalid_cases {
        let mut outputs = vec![output()];
        assert!(decode_trailers(&mut WireReader::new(&invalid), 1, &mut outputs).is_err());
    }

    let mut invalid_authorizer = vec![b'C', 0];
    invalid_authorizer.extend_from_slice(&1u16.to_le_bytes());
    invalid_authorizer.extend_from_slice(&[0x5a; 32]);
    let mut outputs = vec![output()];
    assert_eq!(
        decode_trailers(&mut WireReader::new(&invalid_authorizer), 1, &mut outputs),
        Err("invalid compact KSPT covenant trailer".to_string()),
    );
    assert_eq!(outputs[0].covenant, None);

    let mut duplicate = vec![b'C', 0];
    duplicate.extend_from_slice(&0u16.to_le_bytes());
    duplicate.extend_from_slice(&[0x33; 32]);
    duplicate.push(b'C');
    duplicate.push(0);
    duplicate.extend_from_slice(&0u16.to_le_bytes());
    duplicate.extend_from_slice(&[0x44; 32]);
    let mut outputs = vec![output()];
    assert!(decode_trailers(&mut WireReader::new(&duplicate), 1, &mut outputs).is_err());
}

#[test]
fn script_signature_decoder_orders_signers_honors_threshold_and_pushes_redeem() {
    use crate::transaction::consensus::signed_kspt::decode_script_signatures;

    fn encoded_signature(position: u8, sighash: u8, byte: u8) -> Vec<u8> {
        let mut encoded = vec![position, sighash];
        encoded.extend_from_slice(&[byte; 64]);
        encoded
    }

    let redeem = vec![0x52, 0x20, 0x11, 0xae];
    let mut encoded = encoded_signature(2, 1, 0x33);
    encoded.extend_from_slice(&encoded_signature(0, 1, 0x11));
    encoded.extend_from_slice(&encoded_signature(1, 2, 0x22));
    encoded.extend_from_slice(&(redeem.len() as u16).to_le_bytes());
    encoded.extend_from_slice(&redeem);

    let script = decode_script_signatures(&mut WireReader::new(&encoded), 3, true)
        .expect("ordered threshold script");
    assert_eq!(script[0], 65);
    assert_eq!(script[1], 0x11);
    assert_eq!(script[65], 1);
    assert_eq!(script[66], 65);
    assert_eq!(script[67], 0x22);
    assert_eq!(script[131], 2);
    assert_eq!(script[132], redeem.len() as u8);
    assert_eq!(&script[133..], redeem.as_slice());

    let mut no_redeem = encoded_signature(1, 1, 0x44);
    no_redeem.extend_from_slice(&encoded_signature(0, 1, 0x55));
    no_redeem.extend_from_slice(&0u16.to_le_bytes());
    let multisig = decode_script_signatures(&mut WireReader::new(&no_redeem), 2, false)
        .expect("multisig signatures");
    assert_eq!(multisig.len(), 132);
    assert_eq!(multisig[1], 0x55);
    assert_eq!(multisig[67], 0x44);
}

#[test]
fn script_signature_decoder_rejects_truncated_signatures_and_redeems() {
    use crate::transaction::consensus::signed_kspt::decode_script_signatures;

    assert!(decode_script_signatures(&mut WireReader::new(&[0, 1]), 1, false).is_err());

    let mut missing_redeem = vec![0, 1];
    missing_redeem.extend_from_slice(&[0x66; 64]);
    missing_redeem.extend_from_slice(&4u16.to_le_bytes());
    missing_redeem.extend_from_slice(&[0x51, 0xae]);
    assert!(decode_script_signatures(&mut WireReader::new(&missing_redeem), 1, true,).is_err());
}

fn compact_one_input(script_public_key: &[u8], signature_count: u8, redeem: &[u8]) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"KSPT");
    bytes.push(1);
    bytes.push(1);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 20]);
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());

    bytes.extend_from_slice(&[0x31; 32]);
    bytes.extend_from_slice(&7u32.to_le_bytes());
    bytes.extend_from_slice(&99u64.to_le_bytes());
    bytes.extend_from_slice(&11u64.to_le_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.push(script_public_key.len() as u8);
    bytes.extend_from_slice(script_public_key);
    bytes.push(signature_count);
    for position in 0..signature_count {
        bytes.push(position);
        bytes.push(position.saturating_add(1));
        bytes.extend_from_slice(&[0x40u8.saturating_add(position); 64]);
    }
    bytes.extend_from_slice(&(redeem.len() as u16).to_le_bytes());
    bytes.extend_from_slice(redeem);
    bytes.extend_from_slice(&[b'N', 1]);
    hex::encode(bytes)
}

fn p2sh_spk() -> Vec<u8> {
    let mut script = vec![0xaa, 0x20];
    script.extend_from_slice(&[0x55; 32]);
    script.push(0x87);
    script
}

fn two_of_two_script() -> Vec<u8> {
    let mut script = vec![0x52, 0x20];
    script.extend_from_slice(&[0x11; 32]);
    script.push(0x20);
    script.extend_from_slice(&[0x22; 32]);
    script.extend_from_slice(&[0x52, 0xae]);
    script
}

#[test]
fn signed_kspt_script_classification_and_extra_signature_boundaries_are_exact() {
    let p2pk = {
        let mut script = vec![0x20];
        script.extend_from_slice(&[0x44; 32]);
        script.push(0xac);
        script
    };
    for count in [2u8, 3] {
        let tx = decode_signed_kspt(&compact_one_input(&p2pk, count, &[]))
            .expect("P2PK with redundant compact signatures");
        assert_eq!(tx.inputs[0].sig_script.len(), 66);
        assert_eq!(tx.inputs[0].sig_script[1], 0x40);
        assert_eq!(tx.inputs[0].sig_script[65], 1);
    }

    let p2sh = p2sh_spk();
    let redeem = vec![0x51, 0x20, 0x11, 0xae];
    let tx =
        decode_signed_kspt(&compact_one_input(&p2sh, 1, &redeem)).expect("P2SH signature route");
    assert!(tx.inputs[0].sig_script.ends_with(&redeem));
    assert!(tx.inputs[0].sig_script.len() > 66);

    let multisig = two_of_two_script();
    let tx = decode_signed_kspt(&compact_one_input(&multisig, 2, &[]))
        .expect("multisig signature route");
    assert_eq!(tx.inputs[0].sig_script.len(), 132);
    assert_eq!(tx.inputs[0].sig_script[1], 0x40);
    assert_eq!(tx.inputs[0].sig_script[67], 0x41);

    for index in [0usize, 1, 34] {
        let mut malformed = p2sh.clone();
        malformed[index] ^= 1;
        let tx = decode_signed_kspt(&compact_one_input(&malformed, 2, &[]))
            .expect("near-P2SH must route as P2PK");
        assert_eq!(tx.inputs[0].sig_script.len(), 66, "P2SH byte {index}");
    }
    let tx = decode_signed_kspt(&compact_one_input(&p2sh[..34], 2, &[]))
        .expect("short P2SH must route as P2PK");
    assert_eq!(tx.inputs[0].sig_script.len(), 66);

    let mut wrong_last = multisig.clone();
    *wrong_last.last_mut().unwrap() = 0xad;
    let tx = decode_signed_kspt(&compact_one_input(&wrong_last, 2, &[]))
        .expect("near-multisig last opcode must route as P2PK");
    assert_eq!(tx.inputs[0].sig_script.len(), 66);
    let mut wrong_first = multisig.clone();
    wrong_first[0] = 0x50;
    let tx = decode_signed_kspt(&compact_one_input(&wrong_first, 2, &[]))
        .expect("near-multisig threshold must route as P2PK");
    assert_eq!(tx.inputs[0].sig_script.len(), 66);
    let tx = decode_signed_kspt(&compact_one_input(&multisig[..36], 2, &[]))
        .expect("short multisig must route as P2PK");
    assert_eq!(tx.inputs[0].sig_script.len(), 66);
}

#[test]
fn signed_kspt_global_fields_cover_payload_and_truncation_boundaries() {
    let mut bytes = hex::decode(SIGNED_COMPACT_KSPT).unwrap();
    // The compact-v1 global payload length is the final u16 before the first input.
    // Replace the zero-length payload with two bytes and keep the remaining transaction intact.
    let payload_len_offset = 6 + 2 + 4 + 1 + 8 + 20 + 8;
    bytes[payload_len_offset..payload_len_offset + 2].copy_from_slice(&2u16.to_le_bytes());
    bytes.splice(payload_len_offset + 2..payload_len_offset + 2, [0xaa, 0xbb]);
    let transaction = decode_signed_kspt(&hex::encode(bytes)).expect("non-empty payload KSPT");
    assert_eq!(transaction.payload, vec![0xaa, 0xbb]);

    let global_start = 6usize;
    for end in [
        global_start + 1,                  // tx version
        global_start + 2 + 3,              // input count
        global_start + 2 + 4 + 1 + 8 + 19, // subnetwork id
        payload_len_offset + 1,            // payload length
    ] {
        let bytes = hex::decode(SIGNED_COMPACT_KSPT).unwrap();
        assert!(decode_signed_kspt(&hex::encode(&bytes[..end])).is_err());
    }

    let mut truncated_payload = hex::decode(SIGNED_COMPACT_KSPT).unwrap();
    truncated_payload.truncate(payload_len_offset + 2);
    truncated_payload[payload_len_offset..payload_len_offset + 2]
        .copy_from_slice(&3u16.to_le_bytes());
    truncated_payload.extend_from_slice(&[0xaa, 0xbb]);
    assert_eq!(
        decode_signed_kspt(&hex::encode(truncated_payload)).unwrap_err(),
        "KSPT truncated at payload",
    );
}

#[test]
fn signed_kspt_exact_header_boundary_preserves_wire_error() {
    assert_eq!(
        decode_signed_kspt(&hex::encode(b"KSPT\x01\x01")).unwrap_err(),
        "truncated RPC payload",
    );
}

#[test]
fn signed_kspt_rejects_short_wrong_magic_incomplete_and_unsigned_inputs() {
    assert!(decode_signed_kspt("")
        .unwrap_err()
        .contains("missing header"));
    assert!(decode_signed_kspt(&hex::encode(b"NOPE\x01\x01"))
        .unwrap_err()
        .contains("missing header"));

    let mut incomplete = hex::decode(SIGNED_COMPACT_KSPT).unwrap();
    incomplete[5] = 0;
    assert_eq!(
        decode_signed_kspt(&hex::encode(incomplete)).unwrap_err(),
        "Compact KSPT is not fully signed"
    );

    let mut p2pk = vec![0x20];
    p2pk.extend_from_slice(&[0x44; 32]);
    p2pk.push(0xac);
    assert_eq!(
        decode_signed_kspt(&compact_one_input(&p2pk, 0, &[])).unwrap_err(),
        "Input has no signatures"
    );
}

#[test]
fn p2sh_compact_signature_without_redeem_does_not_append_one() {
    let p2sh = p2sh_spk();
    let tx = decode_signed_kspt(&compact_one_input(&p2sh, 1, &[]))
        .expect("P2SH compact signature without redeem");
    assert_eq!(tx.inputs[0].sig_script.len(), 66);
    assert_eq!(tx.inputs[0].sig_script[0], 65);
}

#[test]
fn signed_v1_trailers_cover_network_and_derivation_validation() {
    use crate::transaction::consensus::ConsensusOutput;

    fn output() -> ConsensusOutput {
        ConsensusOutput {
            value: 1,
            spk_version: 0,
            spk_script: vec![0x51],
            covenant: None,
        }
    }

    fn network(network: u8) -> Vec<u8> {
        vec![b'N', network]
    }

    fn derivation(output_index: u8, branch: u8, index: u32) -> Vec<u8> {
        let mut trailer = vec![b'D', output_index, branch];
        trailer.extend_from_slice(&index.to_le_bytes());
        trailer
    }

    for network_id in 1u8..=4 {
        let mut trailers = network(network_id);
        trailers.extend(derivation(0, 0, 7));
        trailers.extend(derivation(1, 1, u32::MAX));
        let mut outputs = vec![output(), output()];
        decode_trailers(&mut WireReader::new(&trailers), 1, &mut outputs)
            .expect("valid v1 trailers");
    }

    let mut outputs = vec![output()];
    assert_eq!(
        decode_trailers(&mut WireReader::new(&[]), 1, &mut outputs).unwrap_err(),
        "compact KSPT v1 is missing its network trailer",
    );

    for invalid_network in [0u8, 5u8, u8::MAX] {
        let trailers = network(invalid_network);
        let mut outputs = vec![output()];
        assert_eq!(
            decode_trailers(&mut WireReader::new(&trailers), 1, &mut outputs).unwrap_err(),
            "invalid compact KSPT network trailer",
        );
    }

    let mut duplicate_network = network(1);
    duplicate_network.extend(network(2));
    let mut outputs = vec![output()];
    assert_eq!(
        decode_trailers(&mut WireReader::new(&duplicate_network), 1, &mut outputs).unwrap_err(),
        "invalid compact KSPT network trailer",
    );

    for bad_derivation in [derivation(0, 2, 3), derivation(1, 0, 3)] {
        let mut trailers = network(1);
        trailers.extend(bad_derivation);
        let mut outputs = vec![output()];
        assert_eq!(
            decode_trailers(&mut WireReader::new(&trailers), 1, &mut outputs).unwrap_err(),
            "invalid compact KSPT derivation trailer",
        );
    }

    let mut duplicate_derivation = network(1);
    duplicate_derivation.extend(derivation(0, 0, 3));
    duplicate_derivation.extend(derivation(0, 1, 4));
    let mut outputs = vec![output()];
    assert_eq!(
        decode_trailers(&mut WireReader::new(&duplicate_derivation), 1, &mut outputs).unwrap_err(),
        "invalid compact KSPT derivation trailer",
    );
}

#[test]
fn signed_trailer_progress_is_strict() {
    assert_eq!(require_signed_trailer_progress(2, 1), Ok(()));
    assert_eq!(
        require_signed_trailer_progress(1, 1).unwrap_err(),
        "compact KSPT trailer made no forward progress",
    );
    assert!(require_signed_trailer_progress(1, 2).is_err());
}
