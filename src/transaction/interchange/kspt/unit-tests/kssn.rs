use crate::transaction::model::SigHashType;

use super::super::{PsktError, SignedResponse};

#[test]
fn kssn_rejects_trailing_data() {
    let mut response = SignedResponse::new();
    response
        .add_signature(0, SigHashType::All, &[0x88; 64])
        .expect("add signature");
    let mut wire = [0u8; 256];
    let len = response.serialize(&mut wire).expect("serialize KSSN");
    wire[len] = 0xee;
    assert!(matches!(
        SignedResponse::parse(&wire[..len + 1]),
        Err(PsktError::TrailingData)
    ));
}

#[test]
fn kssn_builder_rejects_duplicate_input_indexes() {
    let mut response = SignedResponse::new();
    response
        .add_signature(0, SigHashType::All, &[0x11; 64])
        .expect("first signature");
    assert_eq!(
        response.add_signature(0, SigHashType::All, &[0x22; 64]),
        Err(PsktError::InvalidSignatureState)
    );

    let mut wire = [0u8; 256];
    assert!(response.serialize(&mut wire).is_ok());
    assert_eq!(response.signatures.len(), 1);
}

#[test]
fn kssn_parser_rejects_duplicate_input_indexes() {
    let mut response = SignedResponse::new();
    response
        .add_signature(0, SigHashType::All, &[0x11; 64])
        .expect("first signature");
    response
        .add_signature(1, SigHashType::All, &[0x22; 64])
        .expect("second signature");

    let mut wire = [0u8; 256];
    let len = response.serialize(&mut wire).expect("serialize KSSN");
    const V1_HEADER_LEN: usize = 4 + 1 + 4;
    const V1_RECORD_LEN: usize = 4 + 1 + 64;
    let second_input_index = V1_HEADER_LEN + V1_RECORD_LEN;
    wire[second_input_index..second_input_index + 4].fill(0);

    assert!(matches!(
        SignedResponse::parse(&wire[..len]),
        Err(PsktError::InvalidSignatureState)
    ));
}

#[test]
fn kssn_parser_rejects_non_v1_version() {
    let mut wire = [0u8; 4 + 1 + 4];
    wire[..4].copy_from_slice(b"KSSN");
    wire[4] = 2;
    wire[5..9].copy_from_slice(&0u32.to_le_bytes());

    assert_eq!(
        SignedResponse::parse(&wire).unwrap_err(),
        PsktError::UnsupportedVersion
    );
}
