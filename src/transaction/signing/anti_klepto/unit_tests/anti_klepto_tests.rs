use super::*;

#[test]
fn message_detection_and_domain_hashes_are_exact() {
    let secret = [0x42u8; HASH_LEN];
    let tx = b"KSPT\x01example";
    let expected_commitment = [
        0x61, 0xbf, 0x94, 0xc3, 0xf1, 0xf9, 0x3c, 0xe1, 0xc8, 0x5d, 0xa6, 0xe0, 0x9f, 0x9c, 0xfb,
        0x7b, 0x0a, 0x46, 0x30, 0xeb, 0xf3, 0x13, 0x83, 0xb9, 0x22, 0x82, 0xcb, 0x2a, 0x1c, 0x17,
        0xb9, 0x36,
    ];
    let expected_digest = [
        0xd2, 0x57, 0xe3, 0xde, 0x24, 0x89, 0x6e, 0x7e, 0x7b, 0xeb, 0x56, 0xd1, 0x9b, 0xf8, 0xf3,
        0x13, 0xb9, 0xb1, 0xa8, 0x3d, 0x69, 0x74, 0x47, 0xeb, 0x3f, 0x21, 0x8a, 0xfc, 0x06, 0xc5,
        0x9d, 0x20,
    ];
    let expected_session = [
        0x7c, 0x48, 0x3d, 0x76, 0xdb, 0x4f, 0x19, 0xff, 0xad, 0x80, 0x49, 0xb4, 0x6f, 0xa4, 0x90,
        0xf7,
    ];

    assert_eq!(host_commitment(&secret), expected_commitment);
    assert_eq!(transaction_digest(tx), expected_digest);
    assert_eq!(
        session_id(&expected_commitment, &expected_digest),
        expected_session
    );
    assert!(verify_host_secret(&expected_commitment, &secret));
    assert!(!verify_host_secret(&expected_commitment, &[0x43; HASH_LEN]));

    let mut public_key = [0u8; 33];
    public_key[0] = 0x02;
    for (index, byte) in public_key[1..].iter_mut().enumerate() {
        *byte = (index + 1) as u8;
    }
    let mut nonce_point = [0u8; 33];
    nonce_point[0] = 0x02;
    for (index, byte) in nonce_point[1..].iter_mut().enumerate() {
        *byte = (index + 33) as u8;
    }
    assert_eq!(
        host_scalar_material(
            &expected_session,
            &secret,
            0x0102_0304,
            3,
            &public_key,
            &nonce_point
        ),
        [
            0x88, 0x14, 0xfd, 0x9c, 0xe6, 0xc2, 0x0a, 0x72, 0x0d, 0x79, 0xdc, 0x88, 0x33, 0xe7,
            0xdf, 0xa2, 0x28, 0xcb, 0xcb, 0xd6, 0xdb, 0x90, 0x04, 0x17, 0xb7, 0x3c, 0xf0, 0x6f,
            0x24, 0xa3, 0xd1, 0xd3,
        ],
    );

    let mut header = [0u8; HEADER_LEN];
    write_header(&mut header, MessageKind::Request, &expected_session).unwrap();
    assert!(is_message(&header));
    header[4] = VERSION - 1;
    assert!(!is_message(&header));
    assert!(!is_message(&header[..HEADER_LEN - 1]));
}

#[test]
fn request_round_trip_binds_session_digest_and_exact_length() {
    let secret = [7u8; HASH_LEN];
    let tx = b"abc";
    let mut encoded = [0u8; REQUEST_FIXED_LEN + 3];
    let length = encode_request(&secret, tx, &mut encoded).unwrap();
    assert_eq!(length, encoded.len());
    let parsed = parse_request(&encoded).unwrap();
    assert_eq!(parsed.transaction, tx);
    assert_eq!(parsed.host_commitment, host_commitment(&secret));
    assert_eq!(parsed.transaction_digest, transaction_digest(tx));

    let mut tampered_tx = encoded;
    tampered_tx[REQUEST_FIXED_LEN] ^= 1;
    assert_eq!(
        parse_request(&tampered_tx).unwrap_err(),
        WireError::TransactionMismatch
    );

    let mut tampered_session = encoded;
    tampered_session[6] ^= 1;
    assert_eq!(
        parse_request(&tampered_session).unwrap_err(),
        WireError::SessionMismatch
    );

    assert_eq!(
        parse_request(&encoded[..REQUEST_FIXED_LEN - 1]).unwrap_err(),
        WireError::Truncated
    );
    let mut short = [0u8; REQUEST_FIXED_LEN + 2];
    assert_eq!(
        encode_request(&secret, tx, &mut short),
        Err(WireError::OutputTooSmall)
    );
}

#[test]
fn commitment_round_trip_uses_u32_indices_and_counts() {
    let session = [3u8; SESSION_ID_LEN];
    let digest = [4u8; HASH_LEN];
    let records = [
        NonceCommitment {
            input_index: 0x0102_0304,
            signature_slot: 3,
            public_key: [5u8; 33],
            nonce_point: [6u8; 33],
        },
        NonceCommitment {
            input_index: u32::MAX,
            signature_slot: u8::MAX,
            public_key: [7u8; 33],
            nonce_point: [8u8; 33],
        },
    ];
    let mut encoded = vec![0u8; COMMITMENT_FIXED_LEN + records.len() * COMMITMENT_RECORD_LEN];
    assert_eq!(
        encode_commitment(&session, &digest, &records, &mut encoded),
        Ok(encoded.len())
    );
    let parsed = parse_commitment(&encoded).unwrap();
    assert_eq!(parsed.len(), 2);
    assert!(!parsed.is_empty());
    assert_eq!(parsed.record(0), Some(records[0]));
    assert_eq!(parsed.record(1), Some(records[1]));
    assert_eq!(parsed.record(2), None);

    assert_eq!(
        encode_commitment(&session, &digest, &[], &mut encoded),
        Err(WireError::TooManyProofs)
    );
    encoded[HEADER_LEN + HASH_LEN..COMMITMENT_FIXED_LEN].fill(0);
    assert_eq!(
        parse_commitment(&encoded).unwrap_err(),
        WireError::TooManyProofs
    );
}

#[test]
fn reveal_and_signed_round_trip_are_exact() {
    let session = [0x12u8; SESSION_ID_LEN];
    let secret = [0x34u8; HASH_LEN];
    let digest = [0x56u8; HASH_LEN];

    let mut reveal = [0u8; REVEAL_LEN];
    assert_eq!(
        encode_reveal(&session, &secret, &mut reveal),
        Ok(REVEAL_LEN)
    );
    assert_eq!(parse_reveal(&reveal), Ok((session, secret)));
    let mut long_reveal = [0u8; REVEAL_LEN + 1];
    long_reveal[..REVEAL_LEN].copy_from_slice(&reveal);
    assert_eq!(parse_reveal(&long_reveal), Err(WireError::InvalidLength));

    let proofs = [
        SignatureProof {
            input_index: 0x0102_0304,
            signature_slot: 3,
        },
        SignatureProof {
            input_index: u32::MAX,
            signature_slot: u8::MAX,
        },
    ];
    let tx = b"xyz";
    let required = SIGNED_FIXED_LEN + proofs.len() * SIGNATURE_PROOF_LEN + 4 + tx.len();
    let mut signed = vec![0u8; required];
    assert_eq!(
        encode_signed(&session, &digest, &proofs, tx, &mut signed),
        Ok(required)
    );
    let parsed = parse_signed(&signed).unwrap();
    assert_eq!(parsed.proof_count(), 2);
    assert_eq!(parsed.proof(0), Some(proofs[0]));
    assert_eq!(parsed.proof(1), Some(proofs[1]));
    assert_eq!(parsed.proof(2), None);
    assert_eq!(parsed.transaction, tx);
}

#[test]
fn header_rejects_noncanonical_versions_kinds_and_magic() {
    let session = [0x77u8; SESSION_ID_LEN];
    let mut header = [0u8; HEADER_LEN];
    write_header(&mut header, MessageKind::Reveal, &session).unwrap();
    assert_eq!(
        parse_header(&header, MessageKind::Reveal)
            .unwrap()
            .session_id,
        session
    );

    let mut old_version = header;
    old_version[4] = VERSION - 1;
    assert_eq!(
        parse_header(&old_version, MessageKind::Reveal),
        Err(WireError::UnsupportedVersion)
    );

    let mut bad_magic = header;
    bad_magic[0] ^= 1;
    assert_eq!(
        parse_header(&bad_magic, MessageKind::Reveal),
        Err(WireError::InvalidMagic)
    );

    let mut bad_kind = header;
    bad_kind[5] = 0xff;
    assert_eq!(
        parse_header(&bad_kind, MessageKind::Reveal),
        Err(WireError::WrongKind)
    );

    assert_eq!(
        parse_header(&header, MessageKind::Signed),
        Err(WireError::WrongKind)
    );
}
