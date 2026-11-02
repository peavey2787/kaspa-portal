use crate::contract::zk::proof::{
    crowdfund_generate_proof, crowdfund_trusted_setup, serialize_total, verify_proof,
};

const GROTH16_BN254_COMPRESSED_PROOF_LEN: usize = 128;
const BN254_FIELD_ELEMENT_LEN: usize = 32;

#[test]
fn a_crowdfund_proof_verifies_only_against_its_own_total() {
    let (proving_key, verifying_key) = crowdfund_trusted_setup().expect("setup");
    let (proof, public_input, total) =
        crowdfund_generate_proof(&proving_key, &[1_000, 2_500, 7]).expect("proof");

    assert_eq!(total, 3_507);
    assert_eq!(proof.len(), GROTH16_BN254_COMPRESSED_PROOF_LEN);
    assert_eq!(public_input.len(), BN254_FIELD_ELEMENT_LEN);
    assert_eq!(public_input, serialize_total(total).expect("total"));
    assert!(verify_proof(&verifying_key, &proof, &public_input).expect("verify"));

    let wrong_total = serialize_total(total + 1).expect("total");
    assert!(!verify_proof(&verifying_key, &proof, &wrong_total).expect("verify"));
}

#[test]
fn proof_generation_rejects_empty_oversized_and_overflowing_contributions() {
    let (proving_key, _) = crowdfund_trusted_setup().expect("setup");

    assert!(crowdfund_generate_proof(&proving_key, &[]).is_err());
    assert!(crowdfund_generate_proof(&proving_key, &[1; 9]).is_err());
    assert!(crowdfund_generate_proof(&proving_key, &[u64::MAX, 1]).is_err());
}

#[test]
fn malformed_key_and_proof_bytes_are_reported_not_trusted() {
    assert!(crowdfund_generate_proof(&[0xff; 4], &[1]).is_err());
    assert!(verify_proof(&[0xff; 4], &[], &[]).is_err());
}
