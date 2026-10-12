//! The one codec for `OP_m <key>... OP_n OP_CHECKMULTISIG` redeem scripts.
//!
//! Each key is a 32-byte x-only Schnorr key pushed with `OP_DATA_32`; `m` and
//! `n` are small-integer opcodes (`OP_1`..`OP_16`) with `1 <= m <= n`. Callers
//! with a smaller capacity (an embedded signer) check [`MultisigScript::key_count`].

use super::opcode::{OP_1, OP_16, OP_CHECKMULTISIG, OP_DATA_32};

/// Most keys a small-integer opcode can declare.
pub const MAX_SCRIPT_KEYS: usize = 16;

const KEY_RECORD_LEN: usize = 33;

/// A parsed multisig redeem script, borrowing its key records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MultisigScript<'a> {
    threshold: u8,
    records: &'a [u8],
}

impl<'a> MultisigScript<'a> {
    /// Signatures required.
    #[must_use]
    pub const fn threshold(&self) -> u8 {
        self.threshold
    }

    /// Keys declared, which equals the keys present.
    #[must_use]
    pub const fn key_count(&self) -> u8 {
        (self.records.len() / KEY_RECORD_LEN) as u8
    }

    /// The key at `position`, in script order.
    #[must_use]
    pub fn key(&self, position: u8) -> Option<[u8; 32]> {
        let start = usize::from(position) * KEY_RECORD_LEN + 1;
        self.records.get(start..start + 32)?.try_into().ok()
    }

    /// The position of `key`, if the script names it.
    #[must_use]
    pub fn position_of(&self, key: &[u8; 32]) -> Option<u8> {
        self.keys()
            .position(|candidate| candidate == *key)
            .and_then(|position| u8::try_from(position).ok())
    }

    /// Every key, in script order.
    pub fn keys(&self) -> impl Iterator<Item = [u8; 32]> + 'a {
        self.records
            .as_chunks::<KEY_RECORD_LEN>()
            .0
            .iter()
            .map(|record| {
                let mut key = [0u8; 32];
                key.copy_from_slice(&record[1..]);
                key
            })
    }
}

fn small_int(opcode: u8) -> Option<u8> {
    (OP_1..=OP_16).contains(&opcode).then(|| opcode - OP_1 + 1)
}

/// Parse `script` as a canonical multisig redeem script.
#[must_use]
pub fn parse(script: &[u8]) -> Option<MultisigScript<'_>> {
    let (&first, rest) = script.split_first()?;
    let (&last, rest) = rest.split_last()?;
    let (&declared, records) = rest.split_last()?;
    let threshold = small_int(first)?;
    let count = small_int(declared)?;
    let canonical = last == OP_CHECKMULTISIG
        && threshold <= count
        && records.len() == usize::from(count) * KEY_RECORD_LEN
        && records
            .as_chunks::<KEY_RECORD_LEN>()
            .0
            .iter()
            .all(|record| record[0] == OP_DATA_32);
    canonical.then_some(MultisigScript { threshold, records })
}

/// Bytes [`encode`] writes for `key_count` keys.
#[must_use]
pub const fn encoded_len(key_count: usize) -> usize {
    key_count * KEY_RECORD_LEN + 3
}

/// Write the `threshold`-of-`keys` redeem script into `out`, returning its
/// length; `None` for an invalid threshold, key count or short buffer.
pub fn encode(threshold: u8, keys: &[[u8; 32]], out: &mut [u8]) -> Option<usize> {
    let count = u8::try_from(keys.len()).ok()?;
    let valid = threshold >= 1 && threshold <= count && keys.len() <= MAX_SCRIPT_KEYS;
    let length = encoded_len(keys.len());
    let out = out.get_mut(..length).filter(|_| valid)?;
    out[0] = OP_1 + threshold - 1;
    for (record, key) in out[1..].chunks_exact_mut(KEY_RECORD_LEN).zip(keys) {
        record[0] = OP_DATA_32;
        record[1..].copy_from_slice(key);
    }
    out[length - 2] = OP_1 + count - 1;
    out[length - 1] = OP_CHECKMULTISIG;
    Some(length)
}

#[cfg(test)]
#[path = "unit-tests/multisig_script.rs"]
mod unit_tests;
