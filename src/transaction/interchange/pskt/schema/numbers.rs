//! Canonical integer parsing for PSKT JSON.

use super::JS_MAX_SAFE_U64;

/// Parse a canonical decimal u64 string. This byte-level helper is shared by
/// serde-based host code and allocation-free Vault code.
pub fn parse_canonical_u64_bytes(bytes: &[u8]) -> Result<u64, JsonNumberError> {
    if bytes.is_empty()
        || !bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 1 && bytes[0] == b'0')
    {
        return Err(JsonNumberError::NonCanonical);
    }
    let mut value = 0u64;
    for &byte in bytes {
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(JsonNumberError::Overflow)?;
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonNumberError {
    NonCanonical,
    Overflow,
    UnsafeInteger,
}

#[must_use]
/// A JSON *number* integer is exact only within JavaScript's safe range;
/// standard PSKT JSON may carry integers as numbers, larger ones must be
/// decimal strings.
pub const fn json_number_is_exact_integer(value: u64) -> bool {
    value <= JS_MAX_SAFE_U64
}
