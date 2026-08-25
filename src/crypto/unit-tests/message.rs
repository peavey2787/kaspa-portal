use super::{message_digest, sign_message_with_entropy};
use sha2::{Digest, Sha256};

fn raw_sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[test]
fn message_digest_is_domain_length_and_content_bound() {
    let base = message_digest(b"hello");
    let mut encoded = [0u8; 64];
    assert_eq!(
        crate::primitives::bytes::encode_lower_hex(&base, &mut encoded),
        Some(64)
    );
    assert_eq!(
        &encoded,
        b"a3b9eb6c9cab9479a263fe5377e8f0120bd0ad289035e6708fbd7c2e18cb5916"
    );
    assert_ne!(base, message_digest(b"hello!"));
    assert_ne!(base, message_digest(b"\0hello"));
    assert_ne!(base, raw_sha256(b"hello"));
}

#[test]
fn message_signature_verifies_only_against_domain_digest() {
    let private_key = [0x11u8; 32];
    let entropy = [0x22u8; 32];
    let signature = sign_message_with_entropy(&private_key, b"reviewed text", &entropy)
        .expect("domain-separated message signs");
    let public = k256::schnorr::SigningKey::from_bytes(&private_key)
        .expect("test key")
        .verifying_key()
        .to_bytes();
    let public: [u8; 32] = public.into();
    let digest = message_digest(b"reviewed text");
    assert!(crate::crypto::schnorr::schnorr_verify(&public, &digest, &signature).is_ok());
    let raw = raw_sha256(b"reviewed text");
    assert!(crate::crypto::schnorr::schnorr_verify(&public, &raw, &signature).is_err());
}
