//! Import account keys exported by other wallets into Kaspa Portal's canonical
//! account-key representation.
//!
//! Two Base58Check forms are accepted for interoperability: the `kpub…`
//! account key that rusty-kaspa wallets export, and a standard account-level
//! BIP32 `xpub`. Both are decode-only: Portal exports canonical `kpub1:` text.

use crate::wallet::key::{
    account::{
        ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_DEPTH, ACCOUNT_KEY_PAYLOAD_LEN, ACCOUNT_KEY_VERSION,
    },
    xpub::base58::{base58check_decode, Base58Error, MAX_BASE58_BYTES},
};

const BIP32_XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip32XpubImportError {
    Empty,
    InvalidCharacter,
    Overflow,
    InvalidChecksum,
    InvalidPayload,
}

impl From<Base58Error> for Bip32XpubImportError {
    fn from(error: Base58Error) -> Self {
        match error {
            Base58Error::Empty => Self::Empty,
            Base58Error::InvalidCharacter => Self::InvalidCharacter,
            Base58Error::Overflow => Self::Overflow,
            Base58Error::InvalidChecksum => Self::InvalidChecksum,
        }
    }
}

/// Decode an account-level BIP32 `xpub` (version `0488b21e`).
pub fn decode_bip32_xpub(
    encoded: &[u8],
    output: &mut [u8; ACCOUNT_KEY_PAYLOAD_LEN],
) -> Result<usize, Bip32XpubImportError> {
    decode_account_key(encoded, BIP32_XPUB_VERSION, output)
}

/// Decode a rusty-kaspa Base58Check `kpub…` account key (version `038f332e`).
pub fn decode_base58_kpub(
    encoded: &[u8],
    output: &mut [u8; ACCOUNT_KEY_PAYLOAD_LEN],
) -> Result<usize, Bip32XpubImportError> {
    decode_account_key(encoded, ACCOUNT_KEY_VERSION, output)
}

/// Decode a Base58Check account key carrying `version` and normalize it to
/// the canonical payload. The output is zeroed on every failure.
fn decode_account_key(
    encoded: &[u8],
    version: [u8; 4],
    output: &mut [u8; ACCOUNT_KEY_PAYLOAD_LEN],
) -> Result<usize, Bip32XpubImportError> {
    output.fill(0);
    let mut decoded = [0u8; MAX_BASE58_BYTES];
    let length = base58check_decode(encoded, &mut decoded)?;
    let result = match decoded.get(..length) {
        Some(payload)
            if payload.len() == ACCOUNT_KEY_PAYLOAD_LEN && is_account_key(payload, version) =>
        {
            output.copy_from_slice(payload);
            output[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
            Ok(ACCOUNT_KEY_PAYLOAD_LEN)
        }
        _ => Err(Bip32XpubImportError::InvalidPayload),
    };
    decoded.fill(0);
    result
}

fn is_account_key(payload: &[u8], version: [u8; 4]) -> bool {
    payload[..4] == version
        && payload[4] == ACCOUNT_KEY_DEPTH
        && payload[9..13] == ACCOUNT_KEY_CHILD_INDEX.to_be_bytes()
        && matches!(payload[45], 0x02 | 0x03)
}

#[cfg(test)]
#[path = "unit-tests/bip32_xpub.rs"]
mod unit_tests;
