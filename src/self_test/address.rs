//! Power-on known-answer self-test, shared with the unit tests.

use crate::primitives::address::{decode_address, encode_p2pk, MAX_ADDR_LEN};

/// The official rusty-kaspa address of the all-zero x-only key.
const ZERO_KEY_ADDRESS: &str =
    "kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e";

/// The official rusty-kaspa vector key and its address.
const VECTOR_KEY: [u8; 32] = [
    0x5f, 0xff, 0x3c, 0x4d, 0xa1, 0x8f, 0x45, 0xad, 0xcd, 0xd4, 0x99, 0xe4, 0x46, 0x11, 0xe9, 0xff,
    0xf1, 0x48, 0xba, 0x69, 0xdb, 0x3c, 0x4e, 0xa2, 0xdd, 0xd9, 0x55, 0xfc, 0x46, 0xa5, 0x95, 0x22,
];
const VECTOR_ADDRESS: &str = "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfj";

/// The first mainnet receive address (m/44'/111111'/0'/0/0) of the BIP39
/// "abandon ×11 about" mnemonic with no passphrase.
const ABANDON_RECEIVE_ADDRESS: &str =
    "kaspa:qqd6e65yefepe9wk0m9vuxdufxd80sphy67gwwd0vdaumzdt4tc9s3qt0lqeh";

/// Run the address encoding and decoding suite. Returns (passed, total).
pub fn run_address_tests() -> (u32, u32) {
    super::tally(&[
        encodes_to(&[0; 32], ZERO_KEY_ADDRESS),
        encodes_to(&VECTOR_KEY, VECTOR_ADDRESS),
        distinct_keys_encode_distinctly(),
        mnemonic_derives_known_address(),
        decode_round_trips(),
        decode_rejects_corrupted_checksum(),
    ])
}

fn encodes_to(pubkey: &[u8; 32], expected: &str) -> bool {
    let mut buf = [0u8; MAX_ADDR_LEN];
    let len = encode_p2pk(pubkey, &mut buf);
    buf[..len] == *expected.as_bytes()
}

fn distinct_keys_encode_distinctly() -> bool {
    let mut first = [0u8; MAX_ADDR_LEN];
    let mut second = [0u8; MAX_ADDR_LEN];
    let first_len = encode_p2pk(&[0x01; 32], &mut first);
    let second_len = encode_p2pk(&[0x02; 32], &mut second);
    first[..first_len] != second[..second_len]
}

/// The whole chain: entropy → mnemonic → seed → BIP32 path → address.
fn mnemonic_derives_known_address() -> bool {
    use crate::wallet::derivation::bip32;
    use crate::wallet::mnemonic::bip39;

    let mnemonic = bip39::mnemonic_from_entropy_12(&[0; 16]);
    let seed = bip39::seed_from_mnemonic_12(&mnemonic, "");
    bip32::derive_path(&seed.bytes, bip32::KASPA_MAINNET_PATH)
        .and_then(|key| key.public_key_x_only())
        .is_ok_and(|pubkey| encodes_to(&pubkey, ABANDON_RECEIVE_ADDRESS))
}

fn decode_round_trips() -> bool {
    decode_address(VECTOR_ADDRESS) == Ok((0x00, VECTOR_KEY))
}

/// `VECTOR_ADDRESS` with its last checksum character changed.
const CORRUPTED_VECTOR_ADDRESS: &str =
    "kaspa:qp0l70zd5x85ttwd6jv7g3s3a8llzj96d8dncn4zmhv4tlzx5k2jyqh70xmfk";

fn decode_rejects_corrupted_checksum() -> bool {
    decode_address(CORRUPTED_VECTOR_ADDRESS).is_err()
}
