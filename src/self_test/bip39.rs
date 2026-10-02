//! Power-on known-answer self-test, shared with the unit tests.

use crate::wallet::mnemonic::bip39::*;

/// Test vector 1: entropy all zeros → "abandon" × 11 + "about"
/// Entropy: 00000000000000000000000000000000 (16 bytes)
/// Expected mnemonic: "abandon abandon abandon abandon abandon abandon
///                     abandon abandon abandon abandon abandon about"
/// BIP39 test: 12-word mnemonic from all-zero entropy.
fn test_vector_12_zeros() -> bool {
    let entropy = [0u8; 16];
    let mnemonic = mnemonic_from_entropy_12(&entropy);

    // "abandon" = index 0, "about" = index 3
    let expected: [u16; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];

    for (actual, expected) in mnemonic.indices.iter().zip(expected) {
        if *actual != expected {
            return false;
        }
    }

    // Validate roundtrip
    validate_mnemonic_12(&mnemonic).is_ok()
}

/// Test vector 2: entropy all ones → known mnemonic
/// Entropy: 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
/// Expected: "legal winner thank year wave sausage worth useful
///            legal winner thank yellow"
/// BIP39 test: 12-word mnemonic from 0x7F entropy.
fn test_vector_12_7f() -> bool {
    let entropy: [u8; 16] = [
        0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f,
        0x7f,
    ];
    let mnemonic = mnemonic_from_entropy_12(&entropy);

    // Verify first and last word
    let first_word = index_to_word(mnemonic.indices[0]);
    let last_word = index_to_word(mnemonic.indices[11]);

    if first_word != "legal" {
        return false;
    }
    if last_word != "yellow" {
        return false;
    }

    validate_mnemonic_12(&mnemonic).is_ok()
}

/// Test vector 3: 24-word mnemonic (256 bits entropy all zeros)
/// Entropy: 0000...0000 (32 bytes)
/// Expected: "abandon" × 23 + "art"
/// BIP39 test: 24-word mnemonic from all-zero entropy.
fn test_vector_24_zeros() -> bool {
    let entropy = [0u8; 32];
    let mnemonic = mnemonic_from_entropy_24(&entropy);

    // First 23 words should be "abandon" (index 0)
    for i in 0..23 {
        if mnemonic.indices[i] != 0 {
            return false;
        }
    }

    // Last word: "art" = index 104
    let last_word = index_to_word(mnemonic.indices[23]);
    if last_word != "art" {
        return false;
    }

    validate_mnemonic_24(&mnemonic).is_ok()
}

/// Test: seed derivation with known vector
/// Mnemonic: "abandon abandon abandon abandon abandon abandon
///            abandon abandon abandon abandon abandon about"
/// Passphrase: "TREZOR"
/// Expected seed (hex):
///   c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e7e24052f0b7c87c5
///   67a677d12fbc157e164023a3cf9b11f9c7cf61e3da79e1c6aba8e9e5c369c429
/// BIP39 test: seed derivation matches Trezor test vectors.
fn test_seed_derivation_trezor() -> bool {
    let entropy = [0u8; 16];
    let mnemonic = mnemonic_from_entropy_12(&entropy);
    let mut seed = seed_from_mnemonic_12(&mnemonic, "TREZOR");

    let expected: [u8; 64] = [
        0xc5, 0x52, 0x57, 0xc3, 0x60, 0xc0, 0x7c, 0x72, 0x02, 0x9a, 0xeb, 0xc1, 0xb5, 0x3c, 0x05,
        0xed, 0x03, 0x62, 0xad, 0xa3, 0x8e, 0xad, 0x3e, 0x3e, 0x9e, 0xfa, 0x37, 0x08, 0xe5, 0x34,
        0x95, 0x53, 0x1f, 0x09, 0xa6, 0x98, 0x75, 0x99, 0xd1, 0x82, 0x64, 0xc1, 0xe1, 0xc9, 0x2f,
        0x2c, 0xf1, 0x41, 0x63, 0x0c, 0x7a, 0x3c, 0x4a, 0xb7, 0xc8, 0x1b, 0x2f, 0x00, 0x16, 0x98,
        0xe7, 0x46, 0x3b, 0x04,
    ];

    let matches = seed.bytes == expected;
    seed.zeroize();
    matches
}

/// Test: word lookup (binary search)
fn test_word_lookup() -> bool {
    // Test first word
    if word_to_index("abandon") != Ok(0) {
        return false;
    }
    // Test last word
    if word_to_index("zoo") != Ok(2047) {
        return false;
    }
    // Test middle word
    if word_to_index("middle") != Ok(1122) {
        return false;
    }
    // Test nonexistent word
    if word_to_index("zzzzz") != Err(Bip39Error::WordNotFound) {
        return false;
    }
    true
}

/// Run all BIP39 tests.
/// Returns (passed, total).
pub fn run_bip39_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    if test_vector_12_zeros() {
        passed += 1;
    }
    if test_vector_12_7f() {
        passed += 1;
    }
    if test_vector_24_zeros() {
        passed += 1;
    }
    if test_seed_derivation_trezor() {
        passed += 1;
    }
    if test_word_lookup() {
        passed += 1;
    }

    (passed, total)
}
