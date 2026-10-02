//! Power-on known-answer self-test, shared with the unit tests.

use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};

use crate::wallet::derivation::{
    bip32::{
        constants::{BITCOIN_SEED, SECP256K1_ORDER},
        scalar::{is_less_than_order, is_zero, scalar_add_mod_n},
        *,
    },
    hmac::hmac_sha512,
};

/// Test vector 1: Master key from seed
/// BIP32 test vector 1: master key derivation.
fn test_vector1_master() -> bool {
    // Known seed (abandon×11 + about, no passphrase):
    let known_seed: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];

    let master = match master_key_from_seed(&known_seed) {
        Ok(m) => m,
        Err(_) => return false,
    };

    // Verify master key is valid (non-zero, < n)
    if is_zero(master.private_key_bytes()) {
        return false;
    }
    if !is_less_than_order(master.private_key_bytes()) {
        return false;
    }
    if master.depth != 0 {
        return false;
    }

    // Verify public key can be computed
    master.public_key_compressed().is_ok()
}

/// Test: BIP32 test vector 1 con seed hex 000102030405060708090a0b0c0d0e0f
/// We use HMAC-SHA512 directly to verify against the official test vector.
/// BIP32 test vector 1: official test vectors.
fn test_vector1_official() -> bool {
    // BIP32 Test Vector 1 seed (16 bytes — la spec dice que se pasa tal cual a HMAC)
    let seed_short: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    // I = HMAC-SHA512("Bitcoin seed", seed)
    let i = hmac_sha512(BITCOIN_SEED, &seed_short);

    // Expected master private key
    let expected_key: [u8; 32] = [
        0xe8, 0xf3, 0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x05, 0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93, 0xc9,
        0xc5, 0xb2, 0x14, 0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a, 0x14, 0x94, 0xb9, 0x17, 0xc8, 0x43,
        0x6b, 0x35,
    ];

    // Expected master chain code
    let expected_chain: [u8; 32] = [
        0x87, 0x3d, 0xff, 0x81, 0xc0, 0x2f, 0x52, 0x56, 0x23, 0xfd, 0x1f, 0xe5, 0x16, 0x7e, 0xac,
        0x3a, 0x55, 0xa0, 0x49, 0xde, 0x3d, 0x31, 0x4b, 0xb4, 0x2e, 0xe2, 0x27, 0xff, 0xed, 0x37,
        0xd5, 0x08,
    ];

    if i[..32] != expected_key {
        return false;
    }
    if i[32..] != expected_chain {
        return false;
    }

    // Verify public key derivation
    let sk: SecretKey = match SecretKey::from_slice(&expected_key) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let point = pk.to_encoded_point(true);
    let pk_bytes = point.as_bytes();

    // Expected compressed public key
    let expected_pub: [u8; 33] = [
        0x03, 0x39, 0xa3, 0x60, 0x13, 0x30, 0x15, 0x97, 0xda, 0xef, 0x41, 0xfb, 0xe5, 0x93, 0xa0,
        0x2c, 0xc5, 0x13, 0xd0, 0xb5, 0x55, 0x27, 0xec, 0x2d, 0xf1, 0x05, 0x0e, 0x2e, 0x8f, 0xf4,
        0x9c, 0x85, 0xc2,
    ];

    pk_bytes == expected_pub
}

/// Test: child derivation hardened (m/0')
/// BIP32 Test Vector 1, Chain m/0':
///   key:   edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
///   chain: 47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
/// BIP32 test vector 1: hardened child derivation.
fn test_vector1_child_hardened() -> bool {
    let seed_short: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    // Generate master key manually (16-byte seed, not 64)
    let i = hmac_sha512(BITCOIN_SEED, &seed_short);
    let mut master_key = [0u8; 32];
    let mut master_chain = [0u8; 32];
    master_key.copy_from_slice(&i[..32]);
    master_chain.copy_from_slice(&i[32..]);

    let master = ExtendedPrivKey::from_parts(master_key, master_chain, 0);

    // Derive m/0' (hardened)
    let child = match derive_child(&master, HARDENED_BIT) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let expected_child_key: [u8; 32] = [
        0xed, 0xb2, 0xe1, 0x4f, 0x9e, 0xe7, 0x7d, 0x26, 0xdd, 0x93, 0xb4, 0xec, 0xed, 0xe8, 0xd1,
        0x6e, 0xd4, 0x08, 0xce, 0x14, 0x9b, 0x6c, 0xd8, 0x0b, 0x07, 0x15, 0xa2, 0xd9, 0x11, 0xa0,
        0xaf, 0xea,
    ];

    let expected_child_chain: [u8; 32] = [
        0x47, 0xfd, 0xac, 0xbd, 0x0f, 0x10, 0x97, 0x04, 0x3b, 0x78, 0xc6, 0x3c, 0x20, 0xc3, 0x4e,
        0xf4, 0xed, 0x9a, 0x11, 0x1d, 0x98, 0x00, 0x47, 0xad, 0x16, 0x28, 0x2c, 0x7a, 0xe6, 0x23,
        0x61, 0x41,
    ];

    if *child.private_key_bytes() != expected_child_key {
        return false;
    }
    if *child.chain_code_bytes() != expected_child_chain {
        return false;
    }
    if child.depth != 1 {
        return false;
    }

    true
}

/// Test: Kaspa path derivation (m/44'/111111'/0'/0/0)
/// Verify that full Kaspa path derivation does not fail
/// and produces a valid key.
/// Kaspa-specific path derivation (m/44'/111111'/0').
fn test_kaspa_path_derivation() -> bool {
    // Use known seed (abandon×11 + about, no passphrase)
    let seed: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];

    // Derivar path completo de Kaspa mainnet
    let result = derive_path(&seed, KASPA_MAINNET_PATH);
    let key = match result {
        Ok(k) => k,
        Err(_) => return false,
    };

    // The key must be valid
    if is_zero(key.private_key_bytes()) {
        return false;
    }
    if !is_less_than_order(key.private_key_bytes()) {
        return false;
    }
    if key.depth != 5 {
        return false;
    }

    // Must be able to generate public key
    let pubkey = match key.public_key_compressed() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Compressed pubkey: 33 bytes, prefix 02 o 03
    if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
        return false;
    }

    // x-only pubkey (for Kaspa Schnorr): 32 bytes
    key.public_key_x_only().is_ok()
}

/// Test: modular arithmetic
fn test_scalar_arithmetic() -> bool {
    // Test 1: 1 + 1 = 2
    let one = {
        let mut a = [0u8; 32];
        a[31] = 1;
        a
    };
    let two = scalar_add_mod_n(&one, &one);
    if two[31] != 2 {
        return false;
    }

    // Test 2: (n-1) + 1 = 0 mod n
    let n_minus_1 = {
        let mut a = SECP256K1_ORDER;
        // Restar 1
        let mut borrow: i16 = 1;
        for i in (0..32).rev() {
            let diff = (a[i] as i16) - borrow;
            if diff < 0 {
                a[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                a[i] = diff as u8;
                borrow = 0;
            }
        }
        a
    };
    let should_be_zero = scalar_add_mod_n(&n_minus_1, &one);
    if !is_zero(&should_be_zero) {
        return false;
    }

    // Test 3: (n-1) + 2 = 1 mod n
    let two_val = {
        let mut a = [0u8; 32];
        a[31] = 2;
        a
    };
    let should_be_one = scalar_add_mod_n(&n_minus_1, &two_val);
    if should_be_one[31] != 1 {
        return false;
    }
    // Check rest is zero
    for byte in should_be_one.iter().take(31) {
        if *byte != 0 {
            return false;
        }
    }

    true
}

/// Test: Multi-address derivation — derive_path_for_index matches derive_path
/// Verifies that derive_path_for_index(seed, 0) == derive_path(seed, KASPA_MAINNET_PATH)
/// and that different indices produce different keys.
fn test_multi_address_derivation() -> bool {
    let seed: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];

    // 1. derive_path_for_index(seed, 0) must match KASPA_MAINNET_PATH
    let key_idx0 = match derive_path_for_index(&seed, 0) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let key_mainnet = match derive_path(&seed, KASPA_MAINNET_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if key_idx0.private_key_bytes() != key_mainnet.private_key_bytes() {
        return false;
    }

    // 2. derive_account_key + derive_address_key must match derive_path_for_index
    let acct = match derive_account_key(&seed) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let key_idx0_via_acct = match derive_address_key(&acct, 0) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if key_idx0_via_acct.private_key_bytes() != key_idx0.private_key_bytes() {
        return false;
    }

    // 3. Different indices produce different keys
    let key_idx1 = match derive_address_key(&acct, 1) {
        Ok(k) => k,
        Err(_) => return false,
    };
    if key_idx1.private_key_bytes() == key_idx0.private_key_bytes() {
        return false; // indices 0 and 1 must differ
    }

    // 4. find_address_index_for_pubkey works
    let pk0 = match key_idx0.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let pk1 = match key_idx1.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    if find_address_index_for_pubkey(&acct, &pk0) != Some((0, false)) {
        return false;
    }
    if find_address_index_for_pubkey(&acct, &pk1) != Some((1, false)) {
        return false;
    }

    // 5. Non-existent pubkey returns None
    let fake_pk = [0xFFu8; 32];
    if find_address_index_for_pubkey(&acct, &fake_pk).is_some() {
        return false;
    }

    true
}

/// Self-consistency: public-key child derivation must produce the same
/// pubkey as private-key child derivation at the same index.
///
/// Strategy — don't hard-code external BIP32 test vectors (typo risk).
/// Instead, derive an account-level private key (proven infrastructure),
/// export it to xpub, derive a child at index 5 via BOTH paths, and
/// verify pubkey + chain code + depth all match. Also verify that
/// hardened indices are correctly rejected on the public path (BIP32
/// public derivation is only defined for non-hardened indices).
fn test_derive_child_pub_consistency() -> bool {
    // Known seed (BIP39 "abandon × 11 + about" → BIP32 master seed bytes)
    let seed: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];
    // Account key at m/44'/111111'/0' (hardened, private-only)
    let acct = match derive_account_key(&seed) {
        Ok(k) => k,
        Err(_) => return false,
    };
    // Export as xpub for public-derivation path
    let acct_xpub = match acct.to_xpub() {
        Ok(x) => x,
        Err(_) => return false,
    };
    // Derive child at index 5 via BOTH paths — must agree
    let priv_child = match derive_child(&acct, 5) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let pub_child = match derive_child_pub(&acct_xpub, 5) {
        Ok(x) => x,
        Err(_) => return false,
    };
    // Compressed pubkey of private-derived must match the public-derived
    let priv_pk_compressed = match priv_child.public_key_compressed() {
        Ok(p) => p,
        Err(_) => return false,
    };
    if priv_pk_compressed != pub_child.pubkey {
        return false;
    }
    if *priv_child.chain_code_bytes() != pub_child.chain_code {
        return false;
    }
    if priv_child.depth != pub_child.depth {
        return false;
    }

    // Also verify index 0 agrees (edge case — first address)
    let priv0 = match derive_child(&acct, 0) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let pub0 = match derive_child_pub(&acct_xpub, 0) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let priv0_pk = match priv0.public_key_compressed() {
        Ok(p) => p,
        Err(_) => return false,
    };
    if priv0_pk != pub0.pubkey {
        return false;
    }
    if *priv0.chain_code_bytes() != pub0.chain_code {
        return false;
    }

    // Hardened indices MUST be rejected on the public path
    if derive_child_pub(&acct_xpub, 0x8000_0000).is_ok() {
        return false;
    }
    if derive_child_pub(&acct_xpub, HARDENED_BIT | 5).is_ok() {
        return false;
    }

    true
}

/// Run all BIP32 tests.
/// Returns (passed, total).
pub fn run_bip32_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 7u32;

    if test_vector1_master() {
        passed += 1;
    }
    if test_vector1_official() {
        passed += 1;
    }
    if test_vector1_child_hardened() {
        passed += 1;
    }
    if test_kaspa_path_derivation() {
        passed += 1;
    }
    if test_scalar_arithmetic() {
        passed += 1;
    }
    if test_multi_address_derivation() {
        passed += 1;
    }
    if test_derive_child_pub_consistency() {
        passed += 1;
    }

    (passed, total)
}
