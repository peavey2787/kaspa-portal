use super::*;
use crate::self_test::schnorr::run_schnorr_tests;
#[cfg(test)]
use alloc::string::ToString;

// Tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn schnorr_vectors_pass() {
    let (passed, total) = run_schnorr_tests();
    assert_eq!(passed, total);
}

#[test]
fn schnorr_accessors_errors_and_known_answer_are_covered() {
    let mut bytes = [0u8; 64];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let signature = SchnorrSignature { bytes };
    assert_eq!(signature.r_bytes(), &bytes[..32]);
    assert_eq!(signature.s_bytes(), &bytes[32..]);

    assert_eq!(
        SchnorrError::InvalidPrivateKey.to_string(),
        "invalid BIP340 private key"
    );
    assert_eq!(
        SchnorrError::SigningFailed.to_string(),
        "BIP340 signing failed"
    );
    assert_eq!(
        SchnorrError::InvalidSignature.to_string(),
        "invalid BIP340 public key or signature"
    );

    assert!(bip340_known_answer(&BIP340_VECTOR0_EXPECTED));

    let mut wrong_signature = BIP340_VECTOR0_EXPECTED;
    wrong_signature.signature[0] ^= 1;
    assert!(!bip340_known_answer(&wrong_signature));

    let mut wrong_public_key = BIP340_VECTOR0_EXPECTED;
    wrong_public_key.public_key_x[0] ^= 1;
    assert!(!bip340_known_answer(&wrong_public_key));
    assert_eq!(
        schnorr_sign(&[0u8; 32], &[0u8; 32]),
        Err(SchnorrError::InvalidPrivateKey)
    );
    assert_eq!(
        schnorr_verify(&[0u8; 32], &[0u8; 32], &signature),
        Err(SchnorrError::InvalidSignature)
    );
    assert!(!known_answer_matches(
        Err(SchnorrError::SigningFailed),
        &BIP340_VECTOR0_EXPECTED,
    ));
}
