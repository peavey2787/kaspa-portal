//! Power-on known-answer self-test, shared with the unit tests.

use crate::transaction::{model::*, sighash::*};

/// Test: Keyed Blake2b produces different output than unkeyed.
fn test_keyed_differs() -> bool {
    let data = b"test data for keyed hash check";

    // Unkeyed
    let plain = blake2b_hash(data);

    // Keyed with signing hash domain key
    let mut h = KaspaBlake2b::new();
    h.update(data);
    let keyed = h.finalize();

    // They MUST differ — if they're the same, keying is not working
    plain != keyed
}

/// Test: basic sighash computation for a single-input transaction.
fn test_sighash_basic() -> bool {
    // Create a simple transaction: 1 input, 1 output
    let Ok(mut tx) = Transaction::try_new() else {
        return false;
    };
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 1;

    // Input: UTXO with 5 KAS (500_000_000 sompi)
    tx.inputs[0].previous_outpoint.transaction_id = [0xAA; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 500_000_000;
    // Script P2PK: OP_DATA_32 <pubkey_x> OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20; // OP_DATA_32
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xBB; 32]);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC; // OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Output: send 4.99 KAS
    tx.outputs[0].value = 499_000_000;
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xCC; 32]);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    // Compute sighash
    let sighash = calculate_sighash(&tx, 0, SigHashType::All);

    // The sighash must not be all zeros
    let all_zero = sighash.iter().all(|&b| b == 0);
    if all_zero {
        return false;
    }

    // Must be deterministic
    let sighash2 = calculate_sighash(&tx, 0, SigHashType::All);
    sighash == sighash2
}

/// Test: different inputs produce different sighashes.
fn test_sighash_different_inputs() -> bool {
    // Transaction with 2 inputs — each must have a different sighash
    let Ok(mut tx) = Transaction::try_new() else {
        return false;
    };
    tx.version = 0;
    tx.num_inputs = 2;
    tx.num_outputs = 1;

    // Input 0
    tx.inputs[0].previous_outpoint.transaction_id = [0x11; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = u64::MAX;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 100_000_000;
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xAA; 32]);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC;
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Input 1
    tx.inputs[1].previous_outpoint.transaction_id = [0x22; 32];
    tx.inputs[1].previous_outpoint.index = 1;
    tx.inputs[1].sequence = u64::MAX;
    tx.inputs[1].sig_op_count = 1;
    tx.inputs[1].utxo_entry.amount = 200_000_000;
    tx.inputs[1].utxo_entry.script_public_key.version = 0;
    tx.inputs[1].utxo_entry.script_public_key.script[0] = 0x20;
    tx.inputs[1].utxo_entry.script_public_key.script[1..33].copy_from_slice(&[0xBB; 32]);
    tx.inputs[1].utxo_entry.script_public_key.script[33] = 0xAC;
    tx.inputs[1].utxo_entry.script_public_key.script_len = 34;

    // Output
    tx.outputs[0].value = 290_000_000;
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xCC; 32]);
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    let sighash0 = calculate_sighash(&tx, 0, SigHashType::All);
    let sighash1 = calculate_sighash(&tx, 1, SigHashType::All);

    // Must differ (each input has different outpoint, amount, script)
    sighash0 != sighash1
}

/// Test: complete transaction signing pipeline.
fn test_sign_transaction_complete() -> bool {
    use crate::crypto::schnorr;
    use crate::wallet::derivation::bip32;
    use crate::wallet::mnemonic::bip39;

    // 1. Generate wallet
    let entropy = [0u8; 16];
    let mnemonic = bip39::mnemonic_from_entropy_12(&entropy);
    let seed = bip39::seed_from_mnemonic_12(&mnemonic, "");
    let key = match bip32::derive_path(&seed.bytes, bip32::KASPA_MAINNET_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let pubkey_x = match key.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // 2. Create transaction: 1 input (our UTXO), 1 output
    let Ok(mut tx) = Transaction::try_new() else {
        return false;
    };
    tx.version = 0;
    tx.num_inputs = 1;
    tx.num_outputs = 1;

    tx.inputs[0].previous_outpoint.transaction_id = [0x42; 32];
    tx.inputs[0].previous_outpoint.index = 0;
    tx.inputs[0].sequence = 0;
    tx.inputs[0].sig_op_count = 1;
    tx.inputs[0].utxo_entry.amount = 1_000_000_000; // 10 KAS

    // Script of the UTXO = P2PK with our pubkey
    tx.inputs[0].utxo_entry.script_public_key.version = 0;
    tx.inputs[0].utxo_entry.script_public_key.script[0] = 0x20; // OP_DATA_32
    tx.inputs[0].utxo_entry.script_public_key.script[1..33].copy_from_slice(&pubkey_x);
    tx.inputs[0].utxo_entry.script_public_key.script[33] = 0xAC; // OP_CHECKSIG
    tx.inputs[0].utxo_entry.script_public_key.script_len = 34;

    // Output: send to another destination
    tx.outputs[0].value = 999_000_000; // 9.99 KAS (fee = 0.01 KAS)
    tx.outputs[0].script_public_key.version = 0;
    tx.outputs[0].script_public_key.script[0] = 0x20;
    tx.outputs[0].script_public_key.script[1..33].copy_from_slice(&[0xFF; 32]); // destination
    tx.outputs[0].script_public_key.script[33] = 0xAC;
    tx.outputs[0].script_public_key.script_len = 34;

    // 3. Compute sighash
    let sighash = calculate_sighash(&tx, 0, SigHashType::All);

    // 4. Sign with Schnorr
    let sig = match schnorr::schnorr_sign(key.private_key_bytes(), &sighash) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 5. Verify signature
    schnorr::schnorr_verify(&pubkey_x, &sighash, &sig).is_ok()
}

/// Test: KAS amount formatting.
fn test_format_kas() -> bool {
    let mut buf = [0u8; 32];

    // 1.0 KAS = 100_000_000 sompi
    let len = Transaction::format_kas(100_000_000, &mut buf);
    if &buf[..len] != b"1.00" {
        return false;
    }

    // 10.5 KAS
    let len = Transaction::format_kas(1_050_000_000, &mut buf);
    if &buf[..len] != b"10.5" {
        return false;
    }

    // 0.001 KAS
    let len = Transaction::format_kas(100_000, &mut buf);
    if &buf[..len] != b"0.001" {
        return false;
    }

    true
}

/// Runs all sighash tests
/// Run all sighash test vectors.
pub fn run_sighash_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    if test_keyed_differs() {
        passed += 1;
    }
    if test_sighash_basic() {
        passed += 1;
    }
    if test_sighash_different_inputs() {
        passed += 1;
    }
    if test_sign_transaction_complete() {
        passed += 1;
    }
    if test_format_kas() {
        passed += 1;
    }

    (passed, total)
}
