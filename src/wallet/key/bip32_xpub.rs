//! Import standard account-level BIP32 `xpub` values into Kaspa Portal's
//! canonical account-key representation.
//!
//! This path exists solely for standards-compatible BIP32 interoperability.

use sha2::{Digest, Sha256};

use crate::wallet::key::account::{
    ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_PAYLOAD_LEN, ACCOUNT_KEY_VERSION,
};

const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAX_BASE58_BYTES: usize = 128;
const BIP32_XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip32XpubImportError {
    Empty,
    InvalidCharacter,
    Overflow,
    InvalidChecksum,
    InvalidPayload,
}

pub fn decode_bip32_xpub(
    encoded: &[u8],
    output: &mut [u8; ACCOUNT_KEY_PAYLOAD_LEN],
) -> Result<usize, Bip32XpubImportError> {
    decode_base58check(encoded, output)?;
    if !valid_account_xpub(output) {
        output.fill(0);
        return Err(Bip32XpubImportError::InvalidPayload);
    }
    output[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
    Ok(ACCOUNT_KEY_PAYLOAD_LEN)
}

fn valid_account_xpub(payload: &[u8; ACCOUNT_KEY_PAYLOAD_LEN]) -> bool {
    payload[..4] == BIP32_XPUB_VERSION
        && payload[4] == ACCOUNT_KEY_DEPTH
        && payload[9..13] == ACCOUNT_KEY_CHILD_INDEX.to_be_bytes()
        && matches!(payload[45], 0x02 | 0x03)
}

fn decode_base58check(
    encoded: &[u8],
    output: &mut [u8; ACCOUNT_KEY_PAYLOAD_LEN],
) -> Result<(), Bip32XpubImportError> {
    let mut decoded = [0u8; MAX_BASE58_BYTES];
    let decoded_len = decode_base58(encoded, &mut decoded)?;
    let expected_len = ACCOUNT_KEY_PAYLOAD_LEN + 4;
    if decoded_len != expected_len {
        return Err(Bip32XpubImportError::InvalidPayload);
    }
    let checksum: [u8; 32] =
        Sha256::digest(Sha256::digest(&decoded[..ACCOUNT_KEY_PAYLOAD_LEN])).into();
    if decoded[ACCOUNT_KEY_PAYLOAD_LEN..expected_len] != checksum[..4] {
        return Err(Bip32XpubImportError::InvalidChecksum);
    }
    output.copy_from_slice(&decoded[..ACCOUNT_KEY_PAYLOAD_LEN]);
    Ok(())
}

fn decode_base58(
    input: &[u8],
    output: &mut [u8; MAX_BASE58_BYTES],
) -> Result<usize, Bip32XpubImportError> {
    if input.is_empty() {
        return Err(Bip32XpubImportError::Empty);
    }
    let leading_zeroes = input.iter().take_while(|byte| **byte == b'1').count();
    let mut number = [0u8; MAX_BASE58_BYTES];
    let mut number_len = 0usize;
    for byte in input {
        let digit = alphabet_value(*byte).ok_or(Bip32XpubImportError::InvalidCharacter)?;
        number_len = mul_add_base58(&mut number, number_len, digit)?;
    }
    let total = leading_zeroes
        .checked_add(number_len)
        .ok_or(Bip32XpubImportError::Overflow)?;
    let target = output
        .get_mut(..total)
        .ok_or(Bip32XpubImportError::Overflow)?;
    target[..leading_zeroes].fill(0);
    target[leading_zeroes..].copy_from_slice(&number[..number_len]);
    Ok(total)
}

fn mul_add_base58(
    number: &mut [u8; MAX_BASE58_BYTES],
    mut number_len: usize,
    digit: u8,
) -> Result<usize, Bip32XpubImportError> {
    let mut carry = u32::from(digit);
    for index in (0..number_len).rev() {
        carry += u32::from(number[index]) * 58;
        number[index] = (carry & 0xff) as u8;
        carry >>= 8;
    }
    while carry != 0 {
        if number_len == MAX_BASE58_BYTES {
            return Err(Bip32XpubImportError::Overflow);
        }
        number.copy_within(0..number_len, 1);
        number[0] = (carry & 0xff) as u8;
        carry >>= 8;
        number_len += 1;
    }
    Ok(number_len)
}

fn alphabet_value(byte: u8) -> Option<u8> {
    BASE58_ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
}

#[cfg(test)]
#[path = "unit-tests/bip32_xpub.rs"]
mod unit_tests;
