use super::*;
use crate::self_test::bip39::run_bip39_tests;

// Tests with official BIP39 vectors
// ═══════════════════════════════════════════════════════════════════════
//
// These tests use vectors from the official repository:
// https://github.com/trezor/python-mnemonic/blob/master/vectors.json
//
// To run: called from self_test or from an external test harness.

#[test]
fn bip39_vectors_pass() {
    let (passed, total) = run_bip39_tests();
    assert_eq!(passed, total);
}

#[test]
fn twenty_four_word_seed_derivation_wrapper_is_covered() {
    let mnemonic = mnemonic_from_entropy_24(&[0u8; 32]);
    let mut seed = seed_from_mnemonic_24(&mnemonic, "KaspaPortal");
    assert!(seed.bytes.iter().any(|byte| *byte != 0));
    seed.zeroize();
    assert_eq!(seed.bytes, [0u8; 64]);
}

#[test]
fn mnemonic_validation_rejects_checksum_bit_flips_and_word_index_overflow() {
    let mut twelve = mnemonic_from_entropy_12(&[0u8; 16]);
    twelve.indices[11] ^= 1;
    assert_eq!(
        validate_mnemonic_12(&twelve),
        Err(Bip39Error::InvalidChecksum)
    );

    let mut twenty_four = mnemonic_from_entropy_24(&[0u8; 32]);
    twenty_four.indices[23] ^= 1;
    assert_eq!(
        validate_mnemonic_24(&twenty_four),
        Err(Bip39Error::InvalidChecksum)
    );

    assert_eq!(index_to_word(2047), "zoo");
    assert_eq!(index_to_word(2048), "???");
}

#[test]
fn mnemonic_and_seed_zeroization_is_explicitly_observable() {
    let mut twelve = mnemonic_from_entropy_12(&[0x11u8; 16]);
    assert!(twelve.indices.iter().any(|value| *value != 0));
    twelve.zeroize();
    assert_eq!(twelve.indices, [0u16; 12]);

    let mut twenty_four = mnemonic_from_entropy_24(&[0x22u8; 32]);
    assert!(twenty_four.indices.iter().any(|value| *value != 0));
    twenty_four.zeroize();
    assert_eq!(twenty_four.indices, [0u16; 24]);

    let mut seed = Seed {
        bytes: [0x5au8; 64],
    };
    seed.zeroize();
    assert_eq!(seed.bytes, [0u8; 64]);
}

#[test]
fn word_lookup_comparison_covers_prefix_and_length_ordering() {
    assert_eq!(word_to_index("abandon"), Ok(0));
    assert_eq!(word_to_index("ability"), Ok(1));
    assert_eq!(word_to_index("zoo"), Ok(2047));
    assert_eq!(word_to_index("aban"), Err(Bip39Error::WordNotFound));
    assert_eq!(word_to_index("abandonx"), Err(Bip39Error::WordNotFound));
}

#[test]
fn checkpointed_seed_derivation_matches_normal_seed() {
    let mnemonic = mnemonic_from_entropy_12(&[0x42u8; 16]);
    let mut checkpoints = 0u32;
    let mut callback = || checkpoints += 1;
    let mut checkpointed =
        seed_from_mnemonic_12_with_checkpoint(&mnemonic, "KaspaPortal", &mut callback);
    let mut normal = seed_from_mnemonic_12(&mnemonic, "KaspaPortal");
    assert_eq!(checkpointed.bytes, normal.bytes);
    assert!(checkpoints >= 32);
    checkpointed.zeroize();
    normal.zeroize();
}

#[test]
fn resumable_seed_derivation_zero_budget_stays_not_started() {
    let mnemonic = mnemonic_from_entropy_12(&[0x33u8; 16]);
    let mut work = SeedDerivation::from_mnemonic_12(&mnemonic, "");
    assert_eq!(work.progress_percent(), 0);
    assert!(work.advance(0).is_none());
    assert_eq!(work.progress_percent(), 0);
    assert!(work.advance(1).is_none());
    assert_eq!(work.progress_percent(), 1);
}

#[test]
fn resumable_twenty_four_word_seed_matches_normal_seed() {
    let mnemonic = mnemonic_from_entropy_24(&[0x55u8; 32]);
    let mut work = SeedDerivation::from_mnemonic_24(&mnemonic, "KaspaPortal-24");
    assert!(work.advance(0).is_none());
    assert_eq!(work.progress_percent(), 0);
    let mut stepped = loop {
        if let Some(seed) = work.advance(17) {
            break seed;
        }
    };
    let mut normal = seed_from_mnemonic_24(&mnemonic, "KaspaPortal-24");
    assert_eq!(stepped.bytes, normal.bytes);
    assert_eq!(work.progress_percent(), 100);
    stepped.zeroize();
    normal.zeroize();
}

#[test]
fn resumable_seed_derivation_matches_normal_seed() {
    let mnemonic = mnemonic_from_entropy_12(&[0x24u8; 16]);
    let mut work = SeedDerivation::from_mnemonic_12(&mnemonic, "KaspaPortal");
    assert!(work.advance(8).is_none());
    assert!(work.progress_percent() > 0);
    let mut stepped = loop {
        if let Some(seed) = work.advance(8) {
            break seed;
        }
    };
    let mut normal = seed_from_mnemonic_12(&mnemonic, "KaspaPortal");
    assert_eq!(stepped.bytes, normal.bytes);
    assert_eq!(work.progress_percent(), 100);
    assert!(work.advance(8).is_none());
    stepped.zeroize();
    normal.zeroize();
}

#[test]
fn resumable_seed_progress_exact_boundaries_and_completion_wipe() {
    let mnemonic = mnemonic_from_entropy_12(&[0x61u8; 16]);
    let mut work = SeedDerivation::from_mnemonic_12(&mnemonic, "progress-boundary");

    assert!(work.advance(1).is_none());
    assert_eq!(work.progress_percent(), 1);
    assert!(work.advance(1023).is_none());
    assert_eq!(work.progress_percent(), 50);
    assert!(work.advance(1023).is_none());
    assert_eq!(work.progress_percent(), 99);
    let mut seed = work.advance(1).expect("round 2048 completes exactly");
    assert_eq!(work.progress_percent(), 100);
    assert!(work.sensitive_state_is_zeroized());
    assert!(work.advance(1).is_none());
    seed.zeroize();
}
