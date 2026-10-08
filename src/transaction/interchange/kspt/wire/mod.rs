//! Canonical compact KSPT v1 wire grammar.
//!
//! The grammar is allocation-free and model-agnostic: consumers adapt their
//! own transaction models through [`EncodeSource`] and [`DecodeSink`], so no
//! consumer owns KSPT field ordering, limits, or trailer parsing.

mod decode;
mod encode;
mod error;
pub(crate) mod io;
mod model;

pub use decode::{decode, validate, DecodeSink};
pub use encode::{encode, EncodeSource};
pub use error::{DecodeError, WireError};
pub use model::*;

/// Encode into a buffer that grows until the envelope fits.
pub fn encode_vec<S: EncodeSource>(
    source: &S,
    limits: Limits,
) -> Result<alloc::vec::Vec<u8>, WireError> {
    let global = source.global();
    let inputs = usize::try_from(global.input_count).map_err(|_| WireError::CountOverflow)?;
    let mut capacity = 1024usize
        .saturating_add(inputs.saturating_mul(192))
        .saturating_add(usize::from(global.output_count).saturating_mul(640))
        .saturating_add(global.payload.len());
    loop {
        let mut output = alloc::vec![0u8; capacity];
        match encode(source, &mut output, limits) {
            Ok(length) => {
                output.truncate(length);
                return Ok(output);
            }
            Err(WireError::OutputBufferTooSmall) => {
                capacity = capacity
                    .checked_mul(2)
                    .ok_or(WireError::OutputBufferTooSmall)?;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
