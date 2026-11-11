use crate::transaction::signing::anti_klepto::protocol::{NonceCommitment, SignatureProof};

use super::super::{
    anti_klepto::{
        added_signature_count, added_signatures_for_input, commitment_position_is_valid,
        expected_added_sighash, nonce_commitment_records, proof_records,
        pubkey_is_allowed_for_input, signing_pubkey_xonly, validate_proof_position,
        AntiKleptoVerifyError,
    },
    signature_state::set_single_signature,
};
use super::{set_p2sh, set_two_of_two_multisig, transaction};
use crate::transaction::model::{EmptySlot, InputSig, SigHashType, MAX_SIGS_PER_INPUT};

fn commitment(input_index: u32, signature_slot: u8) -> NonceCommitment {
    NonceCommitment {
        input_index,
        signature_slot,
        public_key: [0x02; 33],
        nonce_point: [0x02; 33],
    }
}

fn proof(input_index: u32, signature_slot: u8) -> SignatureProof {
    SignatureProof {
        input_index,
        signature_slot,
    }
}

fn signed_with_one_signature() -> crate::transaction::model::Transaction {
    let mut tx = transaction();
    set_single_signature(
        &mut tx.inputs[0],
        [0x44; 64],
        SigHashType::All.to_byte(),
        0,
        [0x02; 33],
    );
    tx
}

#[test]
fn anti_klepto_proof_position_dimensions_are_independently_enforced() {
    let signed = signed_with_one_signature();
    assert_eq!(
        validate_proof_position(&signed, &commitment(0, 0), &proof(0, 0)),
        Ok(())
    );

    // Commitment/input disagreement only; the proof's input and slot are valid.
    assert_eq!(
        validate_proof_position(&signed, &commitment(1, 0), &proof(0, 0)),
        Err(AntiKleptoVerifyError::InvalidProof),
    );
    // Commitment/slot disagreement only; the proof's input and slot are valid.
    assert_eq!(
        validate_proof_position(&signed, &commitment(0, 1), &proof(0, 0)),
        Err(AntiKleptoVerifyError::InvalidProof),
    );
    // Input range only: commitment and proof agree with each other.
    assert_eq!(
        validate_proof_position(&signed, &commitment(1, 0), &proof(1, 0)),
        Err(AntiKleptoVerifyError::InvalidProof),
    );
    // Signature-slot range only: commitment and proof agree with each other.
    assert_eq!(
        validate_proof_position(&signed, &commitment(0, 1), &proof(0, 1)),
        Err(AntiKleptoVerifyError::InvalidProof),
    );
}

#[test]
fn anti_klepto_expected_added_sighash_distinguishes_unsigned_and_partial_inputs() {
    let mut original = transaction();
    original.inputs[0].sighash_type = SigHashType::None.to_byte();
    assert_eq!(
        expected_added_sighash(&original, 0),
        SigHashType::All.to_byte()
    );

    set_single_signature(
        &mut original.inputs[0],
        [0x11; 64],
        SigHashType::None.to_byte(),
        0,
        [0x02; 33],
    );
    original.inputs[0].sighash_type = SigHashType::None.to_byte();
    assert_eq!(
        expected_added_sighash(&original, 0),
        SigHashType::None.to_byte()
    );
}

#[test]
fn anti_klepto_added_signature_count_is_exact_across_zero_one_and_multiple_inputs() {
    let original = transaction();
    let signed_same = transaction();
    assert_eq!(added_signature_count(&original, &signed_same), Ok(0));

    let mut signed_one = transaction();
    set_single_signature(
        &mut signed_one.inputs[0],
        [0x21; 64],
        SigHashType::All.to_byte(),
        0,
        [0x02; 33],
    );
    assert_eq!(added_signature_count(&original, &signed_one), Ok(1));

    let mut original_two = transaction();
    original_two.ensure_input_slots(2).unwrap();
    original_two.num_inputs = 2;
    original_two.inputs[1] = original_two.inputs[0].clone();
    let mut signed_two = transaction();
    signed_two.ensure_input_slots(2).unwrap();
    signed_two.num_inputs = 2;
    signed_two.inputs[1] = signed_two.inputs[0].clone();
    for input_index in 0..2 {
        set_single_signature(
            &mut signed_two.inputs[input_index],
            [0x30 + u8::try_from(input_index).unwrap(); 64],
            SigHashType::All.to_byte(),
            0,
            [0x02; 33],
        );
    }
    assert_eq!(added_signature_count(&original_two, &signed_two), Ok(2));

    signed_two.num_inputs = 1;
    assert_eq!(
        added_signature_count(&original_two, &signed_two),
        Err(AntiKleptoVerifyError::TransactionMismatch),
    );
}

fn transaction_with_signatures(
    count: usize,
    sighash: SigHashType,
) -> crate::transaction::model::Transaction {
    let mut tx = transaction();
    for position in (0..=u8::MAX).take(count) {
        assert!(tx.inputs[0].sigs.push(InputSig {
            sighash_type: sighash.to_byte(),
            pubkey_pos: position,
            ..InputSig::EMPTY
        }));
    }
    tx.inputs[0].sighash_type = sighash.to_byte();
    tx
}

#[test]
fn anti_klepto_per_input_signature_count_rejects_regression_and_reaches_capacity() {
    let original = transaction_with_signatures(1, SigHashType::None);
    let same = transaction_with_signatures(1, SigHashType::None);
    assert_eq!(added_signatures_for_input(&original, &same, 0), Ok(0));

    let one_added = transaction_with_signatures(2, SigHashType::None);
    assert_eq!(added_signatures_for_input(&original, &one_added, 0), Ok(1));

    let regression = transaction();
    assert_eq!(
        added_signatures_for_input(&original, &regression, 0),
        Err(AntiKleptoVerifyError::TransactionMismatch),
    );

    let full = transaction_with_signatures(MAX_SIGS_PER_INPUT, SigHashType::All);
    assert_eq!(
        added_signatures_for_input(&transaction(), &full, 0),
        Ok(MAX_SIGS_PER_INPUT)
    );
}

#[test]
fn anti_klepto_key_authorization_distinguishes_multisig_covenant_and_missing_keys() {
    let first = [0x11u8; 32];
    let second = [0x22u8; 32];
    let absent = [0x33u8; 32];

    let mut multisig = transaction();
    set_two_of_two_multisig(&mut multisig, &first, &second);
    assert_eq!(pubkey_is_allowed_for_input(&multisig, 0, &first), Ok(true));
    assert_eq!(pubkey_is_allowed_for_input(&multisig, 0, &second), Ok(true));
    assert_eq!(
        pubkey_is_allowed_for_input(&multisig, 0, &absent),
        Ok(false)
    );
    assert_eq!(signing_pubkey_xonly(&multisig, 0, 0), Ok(first));
    assert_eq!(signing_pubkey_xonly(&multisig, 0, 1), Ok(second));
    assert_eq!(
        signing_pubkey_xonly(&multisig, 0, 2),
        Err(AntiKleptoVerifyError::InvalidPublicKey)
    );

    let covenant_key = [0x44u8; 32];
    let mut redeem = [0u8; 34];
    redeem[0] = 0x20;
    redeem[1..33].copy_from_slice(&covenant_key);
    redeem[33] = 0xac;
    let mut covenant = transaction();
    set_p2sh(&mut covenant, &redeem);
    covenant.inputs[0].covenant_execution = Some(crate::transaction::model::CovenantExecution {
        supplied_mask: 0,
        supplied_true_mask: 0,
    });
    assert_eq!(
        pubkey_is_allowed_for_input(&covenant, 0, &covenant_key),
        Ok(true)
    );
    assert_eq!(
        pubkey_is_allowed_for_input(&covenant, 0, &absent),
        Ok(false)
    );
    assert_eq!(signing_pubkey_xonly(&covenant, 0, 0), Ok(covenant_key));
    assert_eq!(
        signing_pubkey_xonly(&covenant, 0, 1),
        Err(AntiKleptoVerifyError::InvalidPublicKey)
    );
}

#[test]
fn anti_klepto_commitment_position_requires_unused_in_range_signature_slot() {
    let tx = transaction_with_signatures(1, SigHashType::All);

    assert!(!commitment_position_is_valid(&tx, 0, 0));
    assert!(commitment_position_is_valid(&tx, 0, 1));
    assert!(commitment_position_is_valid(&tx, 0, MAX_SIGS_PER_INPUT - 1));
    assert!(!commitment_position_is_valid(&tx, 0, MAX_SIGS_PER_INPUT));
    assert!(!commitment_position_is_valid(&tx, 1, 1));
}

#[test]
fn anti_klepto_record_generation_preserves_absolute_signature_slots() {
    let mut tx = transaction();
    for slot in 0..3u8 {
        let mut pubkey_compressed = [0x02; 33];
        pubkey_compressed[1] = 0x20 + slot;
        assert!(tx.inputs[0].sigs.push(InputSig {
            signature: [0x40 + slot; 64],
            pubkey_compressed,
            ..InputSig::EMPTY
        }));
    }
    let initial = [1u8];

    let commitments = nonce_commitment_records(&tx, &initial).expect("commitment records");
    assert_eq!(commitments.len(), 2);
    assert_eq!(commitments[0].signature_slot, 1);
    assert_eq!(commitments[1].signature_slot, 2);

    let proofs = proof_records(&tx, &initial).expect("proof records");
    assert_eq!(proofs.len(), 2);
    assert_eq!(proofs[0].signature_slot, 1);
    assert_eq!(proofs[1].signature_slot, 2);
}
