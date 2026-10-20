// Kaspa protocol implementation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Pure Base58 and Base58Check codec.

use sha2::{Digest, Sha256};

/// Bitcoin base58 alphabet
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// ─── Base58 Encoding ──────────────────────────────────────────────────

/// Most Base58 digits a [`MAX_BASE58_BYTES`] value needs:
/// ceil(128 * log58(256)) = ceil(174.80) = 175, reached by 128 bytes of 0xff.
const MAX_BASE58_CHARS: usize = 175;

/// Why bytes could not be written as Base58 text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Base58EncodeError {
    /// More than [`MAX_BASE58_BYTES`] to encode.
    InputTooLong,
    /// `out` cannot hold the whole encoding.
    BufferTooSmall,
}

/// Encode bytes as Base58 into `out`; returns the number of characters
/// written. Input longer than [`MAX_BASE58_BYTES`] and an `out` too small for
/// the whole encoding are refused, so the text is never silently cut short.
///
/// Leading zero bytes become '1' characters; the rest is the big-endian
/// integer's base-58 digits.
pub(crate) fn base58_encode(data: &[u8], out: &mut [u8]) -> Result<usize, Base58EncodeError> {
    if data.len() > MAX_BASE58_BYTES {
        return Err(Base58EncodeError::InputTooLong);
    }
    let leading_zeros = data.iter().take_while(|byte| **byte == 0).count();
    let mut number = [0u8; MAX_BASE58_BYTES];
    number[..data.len()].copy_from_slice(data);
    let mut digits = [0u8; MAX_BASE58_CHARS];
    let digit_count = base58_digits(&mut number[..data.len()], leading_zeros, &mut digits);
    let total = leading_zeros + digit_count;
    let result = out
        .get_mut(..total)
        .ok_or(Base58EncodeError::BufferTooSmall)
        .map(|target| {
            target[..leading_zeros].fill(b'1');
            for (slot, digit) in target[leading_zeros..]
                .iter_mut()
                .zip(digits[..digit_count].iter().rev())
            {
                *slot = *digit;
            }
            total
        });
    digits.fill(0);
    result
}

/// Divide `number` by 58 until it is zero, collecting the remainders as
/// least-significant-first digits. `number` is consumed (left all zero).
fn base58_digits(
    number: &mut [u8],
    mut start: usize,
    digits: &mut [u8; MAX_BASE58_CHARS],
) -> usize {
    let mut count = 0;
    while let Some(offset) = number[start..].iter().position(|byte| *byte != 0) {
        start += offset;
        let mut remainder = 0u32;
        for byte in &mut number[start..] {
            let value = (remainder << 8) | u32::from(*byte);
            *byte = (value / 58) as u8;
            remainder = value % 58;
        }
        digits[count] = BASE58_ALPHABET[remainder as usize];
        count += 1;
    }
    count
}

/// SHA256 double hash (SHA256d): SHA256(SHA256(data))
pub(crate) fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize()
    };
    let mut h = Sha256::new();
    h.update(first);
    let result: [u8; 32] = h.finalize().into();
    result
}

/// Base58Check encode: data + 4-byte SHA256d checksum → base58 string.
/// Returns the number of chars written to `out`.
pub(crate) fn base58check_encode(data: &[u8], out: &mut [u8]) -> Result<usize, Base58EncodeError> {
    let total_len = data
        .len()
        .checked_add(4)
        .filter(|length| *length <= MAX_BASE58_BYTES)
        .ok_or(Base58EncodeError::InputTooLong)?;
    let mut buf = [0u8; MAX_BASE58_BYTES];
    buf[..data.len()].copy_from_slice(data);
    buf[data.len()..total_len].copy_from_slice(&sha256d(data)[..4]);
    let result = base58_encode(&buf[..total_len], out);
    buf.fill(0);
    result
}

// ─── Base58 Decode ───────────────────────────────────────────────────

/// Largest decoded Base58 value accepted (account keys are 82 bytes).
pub(crate) const MAX_BASE58_BYTES: usize = 128;

/// Why Base58 or Base58Check text was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Base58Error {
    Empty,
    InvalidCharacter,
    Overflow,
    InvalidChecksum,
}

fn base58_char_value(byte: u8) -> Option<u8> {
    BASE58_ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as u8)
}

/// Base58 decode into `out`; returns the decoded length. Input that decodes to
/// more than [`MAX_BASE58_BYTES`] is rejected rather than truncated.
pub(crate) fn base58_decode(
    input: &[u8],
    out: &mut [u8; MAX_BASE58_BYTES],
) -> Result<usize, Base58Error> {
    if input.is_empty() {
        return Err(Base58Error::Empty);
    }
    let leading_zeroes = input.iter().take_while(|byte| **byte == b'1').count();
    let mut number = [0u8; MAX_BASE58_BYTES];
    let mut number_len = 0usize;
    for byte in input {
        let digit = base58_char_value(*byte).ok_or(Base58Error::InvalidCharacter)?;
        number_len = mul_add_base58(&mut number, number_len, digit)?;
    }
    let total = leading_zeroes
        .checked_add(number_len)
        .ok_or(Base58Error::Overflow)?;
    let target = out.get_mut(..total).ok_or(Base58Error::Overflow)?;
    target[..leading_zeroes].fill(0);
    target[leading_zeroes..].copy_from_slice(&number[..number_len]);
    Ok(total)
}

fn mul_add_base58(
    number: &mut [u8; MAX_BASE58_BYTES],
    mut number_len: usize,
    digit: u8,
) -> Result<usize, Base58Error> {
    let mut carry = u32::from(digit);
    for index in (0..number_len).rev() {
        carry += u32::from(number[index]) * 58;
        number[index] = (carry & 0xff) as u8;
        carry >>= 8;
    }
    while carry != 0 {
        if number_len == MAX_BASE58_BYTES {
            return Err(Base58Error::Overflow);
        }
        number.copy_within(0..number_len, 1);
        number[0] = (carry & 0xff) as u8;
        carry >>= 8;
        number_len += 1;
    }
    Ok(number_len)
}

/// Base58Check decode: verify the double-SHA256 checksum and return the
/// payload length written to `out`.
pub(crate) fn base58check_decode(
    input: &[u8],
    out: &mut [u8; MAX_BASE58_BYTES],
) -> Result<usize, Base58Error> {
    let mut raw = [0u8; MAX_BASE58_BYTES];
    let raw_len = base58_decode(input, &mut raw)?;
    let payload_len = raw_len.checked_sub(4).ok_or(Base58Error::InvalidChecksum)?;
    if payload_len == 0 || raw[payload_len..raw_len] != sha256d(&raw[..payload_len])[..4] {
        raw.fill(0);
        return Err(Base58Error::InvalidChecksum);
    }
    out[..payload_len].copy_from_slice(&raw[..payload_len]);
    raw.fill(0);
    Ok(payload_len)
}
