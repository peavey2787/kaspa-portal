use kaspa_portal::transaction::signing::anti_klepto::protocol::{
    encode_request, encode_reveal, is_message, parse_request, parse_reveal, MessageKind,
    WireError, HASH_LEN, SESSION_ID_LEN, VERSION,
};

#[test]
fn non_v1_wire_is_rejected_everywhere() {
    let session = [0x11u8; SESSION_ID_LEN];
    let secret = [0x22u8; HASH_LEN];
    let mut reveal = vec![0u8; 4 + 1 + 1 + SESSION_ID_LEN + HASH_LEN];
    let length = encode_reveal(&session, &secret, &mut reveal).unwrap();
    reveal.truncate(length);
    assert!(is_message(&reveal));
    assert_eq!(reveal[4], VERSION);

    reveal[4] = 2;
    assert!(!is_message(&reveal));
    assert_eq!(parse_reveal(&reveal), Err(WireError::UnsupportedVersion));
}

#[test]
fn request_binding_rejects_transaction_and_session_tampering() {
    let secret = [0x33u8; HASH_LEN];
    let transaction = b"KSPT\x01canonical-v1";
    let mut encoded = vec![0u8; 512];
    let length = encode_request(&secret, transaction, &mut encoded).unwrap();
    encoded.truncate(length);

    let parsed = parse_request(&encoded).unwrap();
    assert_eq!(parsed.transaction, transaction);

    let mut transaction_tamper = encoded.clone();
    *transaction_tamper.last_mut().unwrap() ^= 1;
    assert_eq!(
        parse_request(&transaction_tamper).unwrap_err(),
        WireError::TransactionMismatch
    );

    let mut session_tamper = encoded;
    // magic(4) + version(1) + kind(1) => first session byte at offset 6.
    session_tamper[6] ^= 1;
    assert_eq!(
        parse_request(&session_tamper).unwrap_err(),
        WireError::SessionMismatch
    );
}

#[test]
fn public_wire_version_is_one() {
    let _ = MessageKind::Request;
    assert_eq!(VERSION, 1);
}
