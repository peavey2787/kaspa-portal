use crate::transaction::model::{Transaction, MAX_OUTPUTS};

use super::super::{
    error::PsktError,
    signing::is_fully_signed,
    validation::validate_partial_signed,
    wire::{self, Limits, WireError, FLAG_SIGNED_OR_COMPLETE},
};
use super::{sink::TransactionSink, source::TransactionSource};

/// The transaction's configured capacity, expressed as grammar limits.
fn limits(tx: &Transaction) -> Limits {
    Limits::new(
        u32::try_from(tx.limits.max_inputs).unwrap_or(u32::MAX),
        MAX_OUTPUTS as u8,
        tx.limits.max_payload_bytes,
    )
}

/// Model fields the grammar rejects on encode are model inconsistencies.
fn encode_error(error: WireError) -> PsktError {
    match error {
        WireError::InvalidNetwork | WireError::InvalidTrailer | WireError::CountOverflow => {
            PsktError::InvalidModel
        }
        other => other.into(),
    }
}

/// Serialize a partial or complete compact KSPT version-1 envelope.
pub fn serialize_compact_kspt(tx: &Transaction, output: &mut [u8]) -> Result<usize, PsktError> {
    validate_partial_signed(tx)?;
    wire::encode(&TransactionSource(tx), output, limits(tx)).map_err(encode_error)
}

/// Parse a compact partial-signed KSPT version-1 envelope.
pub fn parse_compact_kspt(data: &[u8], tx: &mut Transaction) -> Result<(), PsktError> {
    tx.clear();
    let limits = limits(tx);
    let envelope =
        wire::decode(data, &mut TransactionSink(tx), limits).map_err(|error| match error {
            wire::DecodeError::Wire(error) => error.into(),
            wire::DecodeError::Sink(error) => error,
        })?;
    if (envelope.flags & FLAG_SIGNED_OR_COMPLETE != 0) != is_fully_signed(tx) {
        return Err(PsktError::InvalidSignatureState);
    }
    validate_partial_signed(tx)
}

/// Serialize a compact KSPT into a dynamically sized buffer. This is the
/// preferred API for firmware/browser flows where input count is not bounded.
pub fn serialize_compact_kspt_vec(tx: &Transaction) -> Result<alloc::vec::Vec<u8>, PsktError> {
    let capacity = 1024usize
        .saturating_add(tx.num_inputs.saturating_mul(192))
        .saturating_add(tx.num_outputs.saturating_mul(640))
        .saturating_add(tx.payload.len())
        .saturating_add(tx.redeem_pool_used);
    serialize_compact_vec_with_capacity(tx, capacity)
}

fn serialize_compact_vec_with_capacity(
    tx: &Transaction,
    capacity: usize,
) -> Result<alloc::vec::Vec<u8>, PsktError> {
    let mut output = alloc::vec![0u8; capacity];
    serialize_compact_kspt(tx, &mut output)
        .map(|length| {
            output.truncate(length);
            output
        })
        .or_else(|error| retry_compact_vec(tx, capacity, error))
}

fn retry_compact_vec(
    tx: &Transaction,
    capacity: usize,
    error: PsktError,
) -> Result<alloc::vec::Vec<u8>, PsktError> {
    if error != PsktError::OutputBufferTooSmall {
        return Err(error);
    }
    capacity
        .checked_mul(2)
        .ok_or(PsktError::OutputBufferTooSmall)
        .and_then(|next| serialize_compact_vec_with_capacity(tx, next))
}

#[cfg(test)]
#[path = "partial_signed/unit-tests/mod.rs"]
mod unit_tests;
