//! Strict lowercase hexadecimal conversion.

use super::super::PskError;
use crate::primitives::bytes::{decode_lower_hex, encode_lower_hex};

// ═══════════════════════════════════════════════════════════════════════
// Strict hex decoder
// ═══════════════════════════════════════════════════════════════════════

/// Strict lowercase-hex decoder.
///
/// Writes decoded bytes into `dst`, returns the number of bytes
/// written. Fails on:
///   - odd length `src` (can't form whole bytes)
///   - any character outside `0-9a-f` (uppercase, whitespace, `0x` prefix all rejected)
///   - `dst.len() < src.len() / 2`
///
/// No allocation. Single pass. Safe to call on the signing path — no
/// panics, no unwraps.
///
/// Example:
/// ```
/// use kaspa_portal::transaction::interchange::pskt::standard::hex_decode_strict;
///
/// let mut out = [0u8; 4];
/// let n = hex_decode_strict(b"deadbeef", &mut out).expect("valid lowercase hex");
/// assert_eq!(n, 4);
/// assert_eq!(&out[..n], &[0xde, 0xad, 0xbe, 0xef]);
/// ```
pub fn hex_decode_strict(src: &[u8], dst: &mut [u8]) -> Result<usize, PskError> {
    if src.len() & 1 != 0 {
        return Err(PskError::OddHexLength);
    }
    let need = src.len() / 2;
    if dst.len() < need {
        return Err(PskError::ScratchBufferTooSmall);
    }
    // Length and capacity are checked above, so only a bad digit can fail.
    decode_lower_hex(src, dst).ok_or(PskError::BadHexChar)
}

/// Encode bytes as lowercase hex into `dst`, returning the number of
/// ASCII chars written. Used by the serializer; defined here
/// because it's the natural inverse of `hex_decode_strict` and sharing
/// a file keeps both sides of the conversion in one review surface.
///
/// Fails with `OutputBufferTooSmall` if `dst.len() < src.len() * 2`.
pub fn hex_encode_lower(src: &[u8], dst: &mut [u8]) -> Result<usize, PskError> {
    encode_lower_hex(src, dst).ok_or(PskError::OutputBufferTooSmall)
}
