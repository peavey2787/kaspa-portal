use super::*;

// ─── Tests ──────────────────────────────────────────────────────────

#[test]
fn bip85_vector_passes() {
    let (passed, total) = crate::self_test::bip85::run_bip85_tests();
    assert_eq!(passed, total);
}

#[test]
fn bip85_twenty_four_word_derivation_is_deterministic_and_indexed() {
    let seed = [0x35u8; 64];
    let first = derive_mnemonic_24(&seed, 0).expect("first child mnemonic");
    let repeated = derive_mnemonic_24(&seed, 0).expect("repeated child mnemonic");
    let second = derive_mnemonic_24(&seed, 1).expect("second child mnemonic");
    assert_eq!(first.indices, repeated.indices);
    assert_ne!(first.indices, second.indices);
    assert!(crate::wallet::mnemonic::bip39::validate_mnemonic_24(&first).is_ok());
}
