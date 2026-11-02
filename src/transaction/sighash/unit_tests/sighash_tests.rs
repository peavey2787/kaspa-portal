use super::*;
use crate::self_test::sighash::run_sighash_tests;

// Tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn sighash_vectors_pass() {
    let (passed, total) = run_sighash_tests();
    assert_eq!(passed, total);
}

#[test]
fn input_aux_randomness_binds_message_input_and_entropy() {
    use super::signing::input_aux_rand;

    let sighash = [0x3C; 32];
    let changed_sighash = [0xC3; 32];
    let first = input_aux_rand(&[0xA5; 32], &sighash, 0);
    let second = input_aux_rand(&[0xA5; 32], &sighash, 1);
    let different_entropy = input_aux_rand(&[0x5A; 32], &sighash, 0);
    let different_message = input_aux_rand(&[0xA5; 32], &changed_sighash, 0);
    assert_ne!(first, second);
    assert_ne!(first, different_entropy);
    assert_ne!(first, different_message);
}

#[test]
fn component_hashes_cover_all_sighash_and_covenant_payload_branches() {
    use super::components::{
        outputs_hash, payload_hash, previous_outputs_hash, sequences_hash, sig_op_counts_hash,
    };

    let mut tx = Transaction::try_new().expect("transaction storage");
    tx.version = 1;
    tx.num_inputs = 2;
    tx.num_outputs = 2;
    for index in 0..2 {
        tx.inputs[index].previous_outpoint.transaction_id = [index as u8 + 1; 32];
        tx.inputs[index].previous_outpoint.index = index as u32;
        tx.inputs[index].sequence = 10 + index as u64;
        tx.inputs[index].sig_op_count = index as u8 + 1;
        tx.inputs[index].utxo_entry.amount = 100 + index as u64;
        tx.outputs[index].value = 90 + index as u64;
        tx.outputs[index].script_public_key.script[0] = 0x20;
        tx.outputs[index].script_public_key.script[1..33].fill(0x30 + index as u8);
        tx.outputs[index].script_public_key.script[33] = 0xac;
        tx.outputs[index].script_public_key.script_len = 34;
    }
    tx.outputs[0].has_covenant = true;
    tx.outputs[0].covenant_auth_input = 1;
    tx.outputs[0].covenant_id = [0x77; 32];

    assert_ne!(previous_outputs_hash(&tx, SigHashType::All), [0; 32]);
    assert_eq!(
        previous_outputs_hash(&tx, SigHashType::AllAnyOneCanPay),
        [0; 32]
    );
    assert_ne!(sequences_hash(&tx, SigHashType::All), [0; 32]);
    for sighash in [
        SigHashType::None,
        SigHashType::Single,
        SigHashType::AllAnyOneCanPay,
    ] {
        assert_eq!(sequences_hash(&tx, sighash), [0; 32]);
    }
    assert_ne!(sig_op_counts_hash(&tx, SigHashType::All), [0; 32]);
    assert_eq!(
        sig_op_counts_hash(&tx, SigHashType::AllAnyOneCanPay),
        [0; 32]
    );

    let all = outputs_hash(&tx, SigHashType::All, 0);
    let single_zero = outputs_hash(&tx, SigHashType::Single, 0);
    let single_one = outputs_hash(&tx, SigHashType::Single, 1);
    assert_ne!(all, [0; 32]);
    assert_ne!(single_zero, single_one);
    assert_eq!(outputs_hash(&tx, SigHashType::None, 0), [0; 32]);
    assert_eq!(outputs_hash(&tx, SigHashType::Single, 2), [0; 32]);

    tx.outputs[0].has_covenant = false;
    assert_ne!(outputs_hash(&tx, SigHashType::All, 0), all);

    assert_eq!(
        payload_hash(&Transaction::try_new().expect("transaction storage")),
        [0; 32]
    );
    tx.payload = b"KSP".to_vec();
    assert_ne!(payload_hash(&tx), [0; 32]);
    tx.payload.clear();
    tx.subnetwork_id = [1; 20];
    assert_ne!(payload_hash(&tx), [0; 32]);
}

#[test]
fn final_sighash_binds_every_serialized_field_and_version_zero_sigops_only() {
    fn fixture(version: u16) -> Transaction {
        let mut tx = Transaction::try_new().expect("transaction storage");
        tx.version = version;
        tx.num_inputs = 1;
        tx.num_outputs = 1;
        tx.inputs[0].previous_outpoint.transaction_id = [0x11; 32];
        tx.inputs[0].previous_outpoint.index = 3;
        tx.inputs[0].sequence = 7;
        tx.inputs[0].sig_op_count = 2;
        tx.inputs[0].utxo_entry.amount = 123_456_789;
        tx.inputs[0].utxo_entry.script_public_key.version = 4;
        tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20;
        tx.inputs[0].utxo_entry.script_public_key.script[1..33].fill(0x22);
        tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xac;
        tx.inputs[0].utxo_entry.script_public_key.script_len = 34;
        tx.outputs[0].value = 120_000_000;
        tx.outputs[0].script_public_key.version = 5;
        tx.outputs[0].script_public_key.script[0] = 0x20;
        tx.outputs[0].script_public_key.script[1..33].fill(0x33);
        tx.outputs[0].script_public_key.script[33] = 0xac;
        tx.outputs[0].script_public_key.script_len = 34;
        tx.locktime = 9;
        tx.subnetwork_id = [0x44; 20];
        tx.gas = 10;
        tx.payload = b"abc".to_vec();
        tx
    }

    fn digest(tx: &Transaction) -> [u8; 32] {
        calculate_sighash(tx, 0, SigHashType::All)
    }

    let baseline_tx = fixture(0);
    let baseline = digest(&baseline_tx);

    macro_rules! differs {
        ($name:literal, $edit:expr) => {{
            let mut changed = fixture(0);
            $edit(&mut changed);
            assert_ne!(digest(&changed), baseline, $name);
        }};
    }

    differs!("version", |tx: &mut Transaction| tx.version = 1);
    differs!("previous tx id", |tx: &mut Transaction| tx.inputs[0]
        .previous_outpoint
        .transaction_id[0] ^=
        1);
    differs!("previous index", |tx: &mut Transaction| tx.inputs[0]
        .previous_outpoint
        .index += 1);
    differs!("script version", |tx: &mut Transaction| tx.inputs[0]
        .utxo_entry
        .script_public_key
        .version += 1);
    differs!("script bytes", |tx: &mut Transaction| tx.inputs[0]
        .utxo_entry
        .script_public_key
        .script[1] ^= 1);
    differs!("amount", |tx: &mut Transaction| tx.inputs[0]
        .utxo_entry
        .amount += 1);
    differs!("sequence", |tx: &mut Transaction| tx.inputs[0].sequence +=
        1);
    differs!("version-zero sigop", |tx: &mut Transaction| tx.inputs[0]
        .sig_op_count +=
        1);
    differs!("output", |tx: &mut Transaction| tx.outputs[0].value += 1);
    differs!("locktime", |tx: &mut Transaction| tx.locktime += 1);
    differs!("subnetwork", |tx: &mut Transaction| tx.subnetwork_id[0] ^=
        1);
    differs!("gas", |tx: &mut Transaction| tx.gas += 1);
    differs!("payload", |tx: &mut Transaction| tx.payload[1] ^= 1);
    assert_ne!(
        calculate_sighash(&baseline_tx, 0, SigHashType::None),
        baseline,
        "sighash type"
    );

    let version_one = fixture(1);
    let version_one_digest = digest(&version_one);
    let mut changed_sigop = fixture(1);
    changed_sigop.inputs[0].sig_op_count += 1;
    assert_eq!(
        digest(&changed_sigop),
        version_one_digest,
        "version 1 excludes sig-op count from the final digest",
    );

    let version_two = fixture(2);
    let version_two_digest = digest(&version_two);
    let mut changed_v2_sigop = fixture(2);
    changed_v2_sigop.inputs[0].sig_op_count += 1;
    assert_eq!(
        digest(&changed_v2_sigop),
        version_two_digest,
        "every non-zero version excludes version-zero sig-op fields",
    );
}

#[path = "vectors.rs"]
mod vectors;
