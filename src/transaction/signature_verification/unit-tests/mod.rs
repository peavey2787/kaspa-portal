use alloc::vec::Vec;

use super::*;
use crate::transaction::model::{Transaction, OP_1, OP_CHECKMULTISIG, OP_CHECKSIG, OP_DATA_32};

fn compressed(key: [u8; 32]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 0x02;
    out[1..].copy_from_slice(&key);
    out
}

fn one_input() -> Transaction {
    let mut tx = Transaction::try_new().expect("transaction storage");
    tx.num_inputs = 1;
    tx
}

#[test]
fn pskt_key_position_covers_p2pk_multisig_unknown_and_binding_failures() {
    let key = [0x31; 32];
    let mut tx = one_input();
    let script = &mut tx.inputs[0].utxo_entry.script_public_key;
    script.script[0] = OP_DATA_32;
    script.script[1..33].copy_from_slice(&key);
    script.script[33] = OP_CHECKSIG;
    script.script_len = 34;

    assert_eq!(position_for_pskt_key(&tx, 0, &compressed(key)), Ok(0));
    assert_eq!(
        position_for_pskt_key(&tx, 0, &compressed([0x32; 32])),
        Err(SignatureValidationError::InvalidBinding)
    );
    let mut invalid_prefix = compressed(key);
    invalid_prefix[0] = 0x04;
    assert_eq!(
        position_for_pskt_key(&tx, 0, &invalid_prefix),
        Err(SignatureValidationError::InvalidBinding)
    );

    let mut multisig = one_input();
    let script = &mut multisig.inputs[0].utxo_entry.script_public_key;
    script.script[0] = OP_1;
    script.script[1] = OP_DATA_32;
    script.script[2..34].copy_from_slice(&key);
    script.script[34] = OP_1;
    script.script[35] = OP_CHECKMULTISIG;
    script.script_len = 36;
    assert_eq!(position_for_pskt_key(&multisig, 0, &compressed(key)), Ok(0));
    assert_eq!(
        position_for_pskt_key(&multisig, 0, &compressed([0x33; 32])),
        Err(SignatureValidationError::InvalidBinding)
    );

    let mut unknown = one_input();
    unknown.inputs[0].utxo_entry.script_public_key.script[0] = 0xff;
    unknown.inputs[0].utxo_entry.script_public_key.script_len = 1;
    assert_eq!(
        position_for_pskt_key(&unknown, 0, &compressed(key)),
        Err(SignatureValidationError::InvalidBinding)
    );
}

fn covenant_input(owner: [u8; 32], beneficiary: [u8; 32]) -> Transaction {
    let mut tx = one_input();
    let script = &mut tx.inputs[0].utxo_entry.script_public_key;
    script.script[0] = 0xaa;
    script.script[1] = OP_DATA_32;
    script.script[2..34].fill(0x55);
    script.script[34] = 0x87;
    script.script_len = 35;

    let mut redeem = Vec::new();
    redeem.extend_from_slice(&[0x63, OP_DATA_32]);
    redeem.extend_from_slice(&owner);
    redeem.extend_from_slice(&[OP_CHECKSIG, 0x67, OP_DATA_32]);
    redeem.extend_from_slice(&beneficiary);
    redeem.extend_from_slice(&[OP_CHECKSIG, 0x68]);
    tx.inputs[0].redeem_script[..redeem.len()].copy_from_slice(&redeem);
    tx.inputs[0].redeem_script_len = redeem.len();
    tx.inputs[0].covenant_execution_present = true;
    tx.inputs[0].covenant_execution_mask = 1;
    tx.inputs[0].covenant_execution_true_mask = 1;
    tx
}

#[test]
fn covenant_pskt_key_position_and_execution_binding_cover_all_fail_closed_paths() {
    let owner = [0x41; 32];
    let beneficiary = [0x42; 32];
    let mut tx = covenant_input(owner, beneficiary);

    assert_eq!(position_for_pskt_key(&tx, 0, &compressed(owner)), Ok(0));
    assert_eq!(
        position_for_pskt_key(&tx, 0, &compressed(beneficiary)),
        Err(SignatureValidationError::InvalidBinding)
    );
    assert_eq!(
        validate_covenant_execution_binding(&tx.inputs[0], 1),
        Ok(())
    );

    tx.inputs[0].covenant_execution_true_mask = 0;
    assert_eq!(
        position_for_pskt_key(&tx, 0, &compressed(beneficiary)),
        Ok(1)
    );

    tx.inputs[0].covenant_execution_present = false;
    assert_eq!(
        validate_covenant_execution_binding(&tx.inputs[0], 1),
        Err(SignatureValidationError::InvalidBinding)
    );

    tx.inputs[0].covenant_execution_present = true;
    tx.inputs[0].covenant_execution_mask = 1;
    tx.inputs[0].covenant_execution_true_mask = 2;
    assert_eq!(
        validate_covenant_execution_binding(&tx.inputs[0], 1),
        Err(SignatureValidationError::InvalidBinding)
    );

    tx.inputs[0].covenant_execution_true_mask = 0;
    tx.inputs[0].covenant_execution_mask = 3;
    assert_eq!(
        validate_covenant_execution_binding(&tx.inputs[0], 1),
        Err(SignatureValidationError::InvalidBinding)
    );

    assert_eq!(
        position_for_covenant_key(&tx, 1, &owner),
        Err(SignatureValidationError::InvalidModel)
    );

    tx.inputs[0].covenant_execution_mask = 1;
    tx.inputs[0].redeem_script[0] = 0x63;
    tx.inputs[0].redeem_script_len = 1;
    assert_eq!(
        position_for_covenant_key(&tx, 0, &owner),
        Err(SignatureValidationError::InvalidBinding)
    );
}

const SIGHASH_ALL: u8 = 0x01;

fn xonly(marker: u8) -> [u8; 32] {
    crate::transaction::interchange::pskt::pipeline::test_support::xonly(marker)
}

/// One input locked by `threshold`-of-`keys.len()` multisig over test signers.
fn multisig_input(keys: &[u8], threshold: u8) -> Transaction {
    let mut tx = one_input();
    let script =
        crate::transaction::interchange::pskt::pipeline::test_support::multisig(keys, threshold);
    let spk = &mut tx.inputs[0].utxo_entry.script_public_key;
    spk.script[..script.len()].copy_from_slice(&script);
    spk.script_len = script.len();
    tx.inputs[0].sighash_type = SIGHASH_ALL;
    tx
}

fn signature(tx: &Transaction, marker: u8) -> [u8; 64] {
    let message = calculate_sighash(tx, 0, SigHashType::All);
    crate::crypto::schnorr::schnorr_sign(&[marker; 32], &message)
        .expect("test signature")
        .bytes
}

/// Attach compact KSPT signatures from `(marker, position)` signers.
fn with_kspt_sigs(mut tx: Transaction, signers: &[(u8, u8)]) -> Transaction {
    for (slot, (marker, position)) in signers.iter().enumerate() {
        tx.inputs[0].sigs[slot] = crate::transaction::model::InputSig {
            signature: signature(&tx, *marker),
            sighash_type: SIGHASH_ALL,
            pubkey_pos: *position,
            present: true,
            pubkey_compressed: [0; 33],
        };
    }
    tx.inputs[0].sig_count = signers.len() as u8;
    tx
}

/// Attach standard PSKT partial signatures from `markers`.
fn with_pskt_sigs(mut tx: Transaction, markers: &[u8]) -> Transaction {
    for (slot, marker) in markers.iter().enumerate() {
        tx.inputs[0].incoming_partial_sigs[slot] = crate::transaction::model::IncomingPartialSig {
            pubkey: compressed(xonly(*marker)),
            signature: signature(&tx, *marker),
            present: true,
        };
    }
    tx.inputs[0].incoming_partial_sigs_count = markers.len() as u8;
    tx
}

#[test]
fn kspt_status_counts_only_verified_signatures_up_to_the_threshold() {
    let unsigned = || multisig_input(&[1, 2, 3], 2);
    assert_eq!(kspt_status(&unsigned()), (0, 2));
    let partial = with_kspt_sigs(unsigned(), &[(1, 0)]);
    assert_eq!(kspt_status(&partial), (1, 2));
    assert!(!kspt_is_fully_signed(&partial));
    let complete = with_kspt_sigs(unsigned(), &[(1, 0), (3, 2)]);
    assert_eq!(kspt_status(&complete), (2, 2));
    assert!(kspt_is_fully_signed(&complete));
    // More valid signatures than the threshold are not counted as progress.
    let excess = with_kspt_sigs(unsigned(), &[(1, 0), (2, 1), (3, 2)]);
    assert_eq!(kspt_status(&excess), (0, 2));
    assert!(!kspt_is_fully_signed(&excess));
    // A signature bound to another signer's position fails verification.
    let misbound = with_kspt_sigs(unsigned(), &[(1, 1)]);
    assert_eq!(
        verified_count(&misbound, 0, SignatureSource::Kspt),
        Err(SignatureValidationError::InvalidSignature)
    );
    let duplicate = with_kspt_sigs(unsigned(), &[(1, 0), (1, 0)]);
    assert_eq!(
        verified_count(&duplicate, 0, SignatureSource::Kspt),
        Err(SignatureValidationError::DuplicateBinding)
    );
    assert_eq!(kspt_status(&duplicate), (0, 2));
}

#[test]
fn signature_slot_counts_are_bounded_by_the_input_capacity() {
    let keys = [1, 2, 3, 4, 5];
    let all: Vec<(u8, u8)> = keys.iter().zip(0u8..).map(|(k, p)| (*k, p)).collect();
    let full = || with_kspt_sigs(multisig_input(&keys, 5), &all);
    assert_eq!(kspt_status(&full()), (5, 5));
    assert!(kspt_is_fully_signed(&full()));
    let mut overdeclared = full();
    overdeclared.inputs[0].sig_count = MAX_SIGS_PER_INPUT as u8 + 1;
    assert_eq!(
        verified_count(&overdeclared, 0, SignatureSource::Kspt),
        Err(SignatureValidationError::InvalidModel)
    );
    assert_eq!(kspt_status(&overdeclared), (0, 5));
    assert!(!kspt_is_fully_signed(&overdeclared));

    let pskt_full = || with_pskt_sigs(multisig_input(&keys, 5), &keys);
    assert_eq!(pskt_status(&pskt_full()), (5, 5));
    let mut pskt_overdeclared = pskt_full();
    pskt_overdeclared.inputs[0].incoming_partial_sigs_count = MAX_SIGS_PER_INPUT as u8 + 1;
    assert_eq!(
        verified_count(&pskt_overdeclared, 0, SignatureSource::StandardPskt),
        Err(SignatureValidationError::InvalidModel)
    );
}

#[test]
fn pskt_status_requires_sighash_all_only_when_signatures_are_present() {
    let signed = with_pskt_sigs(multisig_input(&[1, 2], 2), &[2, 1]);
    assert_eq!(pskt_status(&signed), (2, 2));
    let mut wrong_sighash = signed;
    wrong_sighash.inputs[0].sighash_type = 0x02;
    assert_eq!(
        verified_count(&wrong_sighash, 0, SignatureSource::StandardPskt),
        Err(SignatureValidationError::InvalidSighash)
    );
    let mut empty_other_sighash = multisig_input(&[1, 2], 2);
    empty_other_sighash.inputs[0].sighash_type = 0x02;
    assert_eq!(
        verified_count(&empty_other_sighash, 0, SignatureSource::StandardPskt),
        Ok(0)
    );
    let duplicate = with_pskt_sigs(multisig_input(&[1, 2], 2), &[1, 1]);
    assert_eq!(
        verified_count(&duplicate, 0, SignatureSource::StandardPskt),
        Err(SignatureValidationError::DuplicateBinding)
    );
}

#[test]
fn status_is_empty_for_missing_or_out_of_range_inputs() {
    let complete = || with_kspt_sigs(multisig_input(&[1], 1), &[(1, 0)]);
    assert_eq!(kspt_status(&complete()), (1, 1));
    let mut none = complete();
    none.num_inputs = 0;
    assert_eq!(kspt_status(&none), (0, 0));
    assert!(!kspt_is_fully_signed(&none));
    let mut beyond = complete();
    beyond.num_inputs = beyond.inputs.len() + 1;
    assert_eq!(pskt_status(&beyond), (0, 0));
    assert!(!kspt_is_fully_signed(&beyond));
}

/// A P2SH covenant input whose redeem script is `redeem`, with no branch
/// selectors.
fn unbranched_covenant(redeem: &[u8]) -> Transaction {
    let mut tx = covenant_input([0; 32], [0; 32]);
    tx.inputs[0].redeem_script[..redeem.len()].copy_from_slice(redeem);
    tx.inputs[0].redeem_script_len = redeem.len();
    tx.inputs[0].covenant_execution_mask = 0;
    tx.inputs[0].covenant_execution_true_mask = 0;
    tx
}

#[test]
fn covenant_inputs_require_every_active_execution_key() {
    let mut redeem = alloc::vec![OP_DATA_32];
    redeem.extend_from_slice(&xonly(1));
    redeem.extend_from_slice(&[0xad, OP_DATA_32]);
    redeem.extend_from_slice(&xonly(2));
    redeem.push(OP_CHECKSIG);
    let two_keys = unbranched_covenant(&redeem);
    assert_eq!(required_for_input(&two_keys, 0), Some(2));

    // A covenant with no signing key cannot be declared complete.
    let keyless = unbranched_covenant(&[OP_1]);
    assert_eq!(required_for_input(&keyless, 0), None);
    assert_eq!(kspt_status(&keyless), (0, 1));
}

#[test]
fn covenant_signatures_must_match_the_selected_execution_branch() {
    let owner = 1;
    let beneficiary = 2;
    let covenant = || {
        let mut tx = covenant_input(xonly(owner), xonly(beneficiary));
        tx.inputs[0].sighash_type = SIGHASH_ALL;
        tx
    };
    let owner_signed = with_kspt_sigs(covenant(), &[(owner, 0)]);
    assert_eq!(kspt_status(&owner_signed), (1, 1));
    // The beneficiary key is on the unselected branch.
    let beneficiary_signed = with_kspt_sigs(covenant(), &[(beneficiary, 1)]);
    assert_eq!(
        verified_count(&beneficiary_signed, 0, SignatureSource::Kspt),
        Err(SignatureValidationError::InvalidBinding)
    );
    let mut absent = owner_signed;
    absent.inputs[0].covenant_execution_present = false;
    assert_eq!(
        covenant_position_matches_execution(&absent, 0, 0),
        Err(SignatureValidationError::InvalidBinding)
    );
    assert_eq!(
        covenant_position_matches_execution(&covenant(), 0, 7),
        Err(SignatureValidationError::InvalidBinding)
    );
}

#[test]
fn p2pk_positions_require_the_exact_pay_to_pubkey_script() {
    let p2pk = || {
        let mut tx = one_input();
        let spk = &mut tx.inputs[0].utxo_entry.script_public_key;
        spk.script[0] = OP_DATA_32;
        spk.script[1..33].copy_from_slice(&xonly(1));
        spk.script[33] = OP_CHECKSIG;
        spk.script_len = 34;
        tx
    };
    let tx = p2pk();
    assert_eq!(p2pk_xonly_for_position(&tx, 0, 0), Ok(xonly(1)));
    assert_eq!(
        p2pk_xonly_for_position(&tx, 0, 1),
        Err(SignatureValidationError::InvalidBinding)
    );
    for (index, byte) in [(0, 0x21), (33, OP_CHECKMULTISIG)] {
        let mut altered = p2pk();
        altered.inputs[0].utxo_entry.script_public_key.script[index] = byte;
        assert_eq!(
            p2pk_xonly_for_position(&altered, 0, 0),
            Err(SignatureValidationError::InvalidBinding)
        );
    }
    let mut longer = tx;
    longer.inputs[0].utxo_entry.script_public_key.script_len = 35;
    assert_eq!(
        p2pk_xonly_for_position(&longer, 0, 0),
        Err(SignatureValidationError::InvalidBinding)
    );
}
