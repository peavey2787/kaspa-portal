use crate::transaction::{
    interchange::pskt::standard::{move_ksp_sigs_to_pskt, pskt_signature_status, PskError},
    model::{EmptySlot, IncomingPartialSig, InputSig, Transaction, MAX_SIGS_PER_INPUT},
};

fn ksp_signature(pubkey_compressed: [u8; 33], signature: [u8; 64]) -> InputSig {
    InputSig {
        signature,
        pubkey_compressed,
        ..InputSig::EMPTY
    }
}

fn p2pk_transaction() -> Transaction {
    let mut transaction = Transaction::try_new().expect("transaction test allocation");
    transaction.num_inputs = 1;
    let script = &mut transaction.inputs[0].utxo_entry.script_public_key;
    script.script[0] = 0x20;
    script.script[1..33].fill(0x11);
    script.script[33] = 0xac;
    script.script_len = 34;
    transaction
}

#[test]
fn pskt_signature_merge_preserves_existing_entries_deduplicates_and_sorts() {
    let mut transaction = p2pk_transaction();
    let input = &mut transaction.inputs[0];

    input
        .incoming_partial_sigs
        .replace_with(IncomingPartialSig {
            pubkey: [0x03; 33],
            signature: [0x33; 64],
        });
    for (pubkey, signature) in [
        ([0u8; 33], [0u8; 64]),
        ([0x03; 33], [0x33; 64]),
        ([0x02; 33], [0x22; 64]),
        ([0x04; 33], [0x44; 64]),
    ] {
        assert!(input.sigs.push(ksp_signature(pubkey, signature)));
    }

    move_ksp_sigs_to_pskt(&mut transaction).expect("merge signatures");

    let input = &transaction.inputs[0];
    assert_eq!(input.incoming_partial_sigs.len(), 3);
    assert_eq!(input.incoming_partial_sigs[0].pubkey, [0x02; 33]);
    assert_eq!(input.incoming_partial_sigs[1].pubkey, [0x03; 33]);
    assert_eq!(input.incoming_partial_sigs[2].pubkey, [0x04; 33]);
    assert_eq!(input.incoming_partial_sigs[1].signature, [0x33; 64]);

    move_ksp_sigs_to_pskt(&mut transaction).expect("merge signatures");
    assert_eq!(transaction.inputs[0].incoming_partial_sigs.len(), 3);
}

#[test]
fn pskt_signature_merge_rejects_conflicting_existing_signature() {
    let mut transaction = p2pk_transaction();
    let input = &mut transaction.inputs[0];
    input
        .incoming_partial_sigs
        .replace_with(IncomingPartialSig {
            pubkey: [0x03; 33],
            signature: [0x11; 64],
        });
    input
        .sigs
        .replace_with(ksp_signature([0x03; 33], [0x22; 64]));

    assert_eq!(
        move_ksp_sigs_to_pskt(&mut transaction),
        Err(PskError::SignatureConflict)
    );
    assert_eq!(
        transaction.inputs[0].incoming_partial_sigs[0].signature,
        [0x11; 64]
    );
}

#[test]
fn pskt_signature_merge_stops_at_fixed_capacity() {
    let mut transaction = p2pk_transaction();
    let input = &mut transaction.inputs[0];
    for marker in 1..=0xff_u8 {
        if !input.incoming_partial_sigs.push(IncomingPartialSig {
            pubkey: [marker; 33],
            ..IncomingPartialSig::EMPTY
        }) {
            break;
        }
    }
    input
        .sigs
        .replace_with(ksp_signature([0xff; 33], [0u8; 64]));

    assert_eq!(
        move_ksp_sigs_to_pskt(&mut transaction),
        Err(PskError::TooManyPartialSigs)
    );
    assert_eq!(
        transaction.inputs[0].incoming_partial_sigs.len(),
        MAX_SIGS_PER_INPUT
    );
}

#[test]
fn pskt_signature_status_counts_only_valid_bound_signatures() {
    use crate::{
        transaction::{model::SigHashType, sighash},
        wallet::derivation::bip32::compressed_pubkey_from_raw_key,
    };

    let private_key = [0x21; 32];
    let compressed = compressed_pubkey_from_raw_key(&private_key).expect("public key");
    let mut p2pk = p2pk_transaction();
    p2pk.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&compressed[1..33]);
    p2pk.inputs[0].sighash_type = SigHashType::All.to_byte();
    let signature =
        sighash::sign_input(&p2pk, 0, &private_key, SigHashType::All).expect("valid signature");
    p2pk.inputs[0]
        .incoming_partial_sigs
        .replace_with(IncomingPartialSig {
            pubkey: compressed,
            signature: signature.bytes,
        });
    assert_eq!(pskt_signature_status(&p2pk), (1, 1));

    p2pk.inputs[0].incoming_partial_sigs[0].signature[0] ^= 1;
    assert_eq!(pskt_signature_status(&p2pk), (0, 1));
}

#[test]
fn pskt_signature_status_rejects_unbound_or_generic_covenant_completion() {
    let mut unknown = Transaction::try_new().expect("transaction test allocation");
    unknown.num_inputs = 1;
    assert_eq!(pskt_signature_status(&unknown), (0, 1));

    let mut p2sh = Transaction::try_new().expect("transaction test allocation");
    p2sh.num_inputs = 1;
    let script = &mut p2sh.inputs[0].utxo_entry.script_public_key;
    script.script[0] = 0xaa;
    script.script[1] = 0x20;
    script.script[2..34].fill(0x44);
    script.script[34] = 0x87;
    script.script_len = 35;
    assert_eq!(pskt_signature_status(&p2sh), (0, 1));
}
