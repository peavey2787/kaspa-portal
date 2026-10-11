//! Recognizers for the two standard locking scripts.

use super::opcode::{OP_BLAKE2B, OP_CHECKSIG, OP_DATA_32, OP_EQUAL};

/// The x-only key locked by a pay-to-pubkey script `<32-byte key> OP_CHECKSIG`.
#[must_use]
pub fn p2pk_xonly(script: &[u8]) -> Option<[u8; 32]> {
    match script {
        [OP_DATA_32, key @ .., OP_CHECKSIG] => key.try_into().ok(),
        _ => None,
    }
}

/// The redeem-script hash locked by `OP_BLAKE2B <32-byte hash> OP_EQUAL`.
#[must_use]
pub fn p2sh_hash(script: &[u8]) -> Option<[u8; 32]> {
    match script {
        [OP_BLAKE2B, OP_DATA_32, hash @ .., OP_EQUAL] => hash.try_into().ok(),
        _ => None,
    }
}
