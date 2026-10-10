//! Central transaction mass and fee analysis.
//!
//! This module is the single source of truth used by public preflight analysis
//! and transaction planners. The constants mirror current Kaspa/Toccata mass
//! policy: compute/storage limits of 500,000 grams, transient limit of
//! 1,000,000 grams, 1 gram per estimated transaction byte, 10 grams per
//! script-public-key byte, 1,000 grams per signature operation, and 4 grams
//! per transient byte.

use serde::Serialize;

use crate::transaction::{
    consensus::ConsensusTransaction, interchange::pskt::pipeline::VerifiedTransaction,
};

pub const MASS_PER_TX_BYTE: u64 = 1;
pub const MASS_PER_SCRIPT_PUBLIC_KEY_BYTE: u64 = 10;
pub const MASS_PER_SIG_OP: u64 = 1_000;
pub const TRANSIENT_BYTE_TO_MASS_FACTOR: u64 = 4;
pub const STORAGE_MASS_PARAMETER: u64 = 1_000_000_000_000;
pub const MAX_COMPUTE_MASS: u64 = 500_000;
pub const MAX_STORAGE_MASS: u64 = 500_000;
pub const MAX_TRANSIENT_MASS: u64 = 1_000_000;
pub const MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM: u64 = 100;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionAnalysis {
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub estimated_serialized_bytes: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub compute_mass: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub transient_mass: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub normalized_transient_mass: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub storage_mass: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub normalized_mass: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub maximum_mass: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub fee_sompi: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub fee_mass: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub fee_rate_sompi_per_gram: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub minimum_fee_sompi: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub recommended_fee_rate_sompi_per_gram: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub recommended_fee_sompi: u64,
    pub compute_mass_valid: bool,
    pub transient_mass_valid: bool,
    pub storage_mass_valid: bool,
    pub mass_valid: bool,
    pub fee_sufficient: bool,
}

pub(crate) fn analyze_verified(
    verified: &VerifiedTransaction,
    recommended_fee_rate_sompi_per_gram: u64,
) -> Result<TransactionAnalysis, String> {
    let transaction = verified.to_consensus()?;
    let fee_sompi = verified.fee()?;

    let estimated_serialized_bytes = estimated_serialized_size(&transaction)?;
    let compute_mass = compute_mass(&transaction, estimated_serialized_bytes)?;
    let transient_mass = estimated_serialized_bytes
        .checked_mul(TRANSIENT_BYTE_TO_MASS_FACTOR)
        .ok_or_else(|| "transient mass overflow".to_string())?;
    let normalized_transient_mass =
        normalize_mass(transient_mass, MAX_COMPUTE_MASS, MAX_TRANSIENT_MASS)?;
    let storage_mass = transaction.storage_mass;
    let normalized_storage_mass = normalize_mass(storage_mass, MAX_COMPUTE_MASS, MAX_STORAGE_MASS)?;
    let normalized_mass = compute_mass
        .max(normalized_transient_mass)
        .max(normalized_storage_mass);
    let fee_mass = compute_mass.max(normalized_transient_mass);
    let minimum_fee_sompi = fee_mass
        .checked_mul(MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM)
        .ok_or_else(|| "minimum fee overflow".to_string())?;
    let recommended_rate =
        recommended_fee_rate_sompi_per_gram.max(MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM);
    let recommended_fee_sompi = fee_mass
        .checked_mul(recommended_rate)
        .ok_or_else(|| "recommended fee overflow".to_string())?;
    let fee_rate_sompi_per_gram = fee_sompi.checked_div(fee_mass).unwrap_or(0);
    let [compute_mass_valid, transient_mass_valid, storage_mass_valid, mass_valid] =
        mass_validity(compute_mass, transient_mass, storage_mass);

    Ok(TransactionAnalysis {
        estimated_serialized_bytes,
        compute_mass,
        transient_mass,
        normalized_transient_mass,
        storage_mass,
        normalized_mass,
        maximum_mass: MAX_COMPUTE_MASS,
        fee_sompi,
        fee_mass,
        fee_rate_sompi_per_gram,
        minimum_fee_sompi,
        recommended_fee_rate_sompi_per_gram: recommended_rate,
        recommended_fee_sompi,
        compute_mass_valid,
        transient_mass_valid,
        storage_mass_valid,
        mass_valid,
        fee_sufficient: fee_sompi >= recommended_fee_sompi,
    })
}

/// Whether compute, transient and storage mass are each within their limits,
/// followed by whether all three are.
fn mass_validity(compute_mass: u64, transient_mass: u64, storage_mass: u64) -> [bool; 4] {
    let compute = compute_mass <= MAX_COMPUTE_MASS;
    let transient = transient_mass <= MAX_TRANSIENT_MASS;
    let storage = storage_mass <= MAX_STORAGE_MASS;
    [compute, transient, storage, compute && transient && storage]
}

/// Final signed shape shared by every input of a planned transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SignedInputShape {
    pub(crate) signature_script_len: u64,
    pub(crate) sig_op_count: u8,
}

impl SignedInputShape {
    /// One Schnorr signature push spending a P2PK output.
    pub(crate) const P2PK: Self = Self {
        signature_script_len: 66,
        sig_op_count: 1,
    };
}

pub(crate) fn estimate_non_contextual_fee(
    input_count: usize,
    output_script_lengths: &[usize],
    payload_len: usize,
    fee_rate_sompi_per_gram: u64,
) -> Result<(u64, u64, u64), String> {
    estimate_non_contextual_fee_for_shape(
        SignedInputShape::P2PK,
        input_count,
        output_script_lengths,
        payload_len,
        fee_rate_sompi_per_gram,
    )
}

pub(crate) fn estimate_non_contextual_fee_for_shape(
    input_shape: SignedInputShape,
    input_count: usize,
    output_script_lengths: &[usize],
    payload_len: usize,
    fee_rate_sompi_per_gram: u64,
) -> Result<(u64, u64, u64), String> {
    let estimated_serialized_bytes = estimated_plan_size(
        input_shape.signature_script_len,
        input_count,
        output_script_lengths,
        payload_len,
    )?;
    let script_mass = output_script_lengths
        .iter()
        .try_fold(0u64, |total, length| {
            let length =
                u64::try_from(*length).map_err(|_| "script length exceeds u64".to_string())?;
            let script_bytes = 2u64
                .checked_add(length)
                .ok_or_else(|| "script mass overflow".to_string())?;
            let mass = script_bytes
                .checked_mul(MASS_PER_SCRIPT_PUBLIC_KEY_BYTE)
                .ok_or_else(|| "script mass overflow".to_string())?;
            total
                .checked_add(mass)
                .ok_or_else(|| "script mass overflow".to_string())
        })?;
    let input_count_u64 =
        u64::try_from(input_count).map_err(|_| "input count exceeds u64".to_string())?;
    let sig_op_mass = input_count_u64
        .checked_mul(u64::from(input_shape.sig_op_count))
        .and_then(|value| value.checked_mul(MASS_PER_SIG_OP))
        .ok_or_else(|| "signature-operation mass overflow".to_string())?;
    let compute = estimated_serialized_bytes
        .checked_mul(MASS_PER_TX_BYTE)
        .and_then(|value| value.checked_add(script_mass))
        .and_then(|value| value.checked_add(sig_op_mass))
        .ok_or_else(|| "compute mass overflow".to_string())?;
    let transient = estimated_serialized_bytes
        .checked_mul(TRANSIENT_BYTE_TO_MASS_FACTOR)
        .ok_or_else(|| "transient mass overflow".to_string())?;
    if compute > MAX_COMPUTE_MASS || transient > MAX_TRANSIENT_MASS {
        return Err("planned transaction exceeds Kaspa non-contextual mass limits".into());
    }
    let normalized_transient = normalize_mass(transient, MAX_COMPUTE_MASS, MAX_TRANSIENT_MASS)?;
    let fee_mass = compute.max(normalized_transient);
    let fee = fee_mass
        .checked_mul(fee_rate_sompi_per_gram.max(MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM))
        .ok_or_else(|| "fee estimate overflow".to_string())?;
    Ok((fee, compute, transient))
}

pub(crate) fn estimate_covenant_deposit_fee(
    payload_len: u64,
    tag_genesis: bool,
    input_count: u64,
) -> Result<u64, String> {
    const FEE_MARKUP_PERCENT: u64 = 115;
    const MINIMUM_FEE: u64 = 100_000;
    const BASE_TRANSACTION_BYTES: u64 = 46;
    const PER_P2PK_INPUT_BYTES: u64 = 45 + 66 + 4;
    const COVENANT_OUTPUT_BYTES: u64 = 35;
    const GENESIS_TAG_BYTES: u64 = 32;
    const CHANGE_OUTPUT_BYTES: u64 = 43;
    const FRAMING_BYTES: u64 = 10;
    const SCRIPT_PUBLIC_KEY_MASS: u64 = (35 + 34) * MASS_PER_SCRIPT_PUBLIC_KEY_BYTE;

    let input_bytes = input_count
        .checked_mul(PER_P2PK_INPUT_BYTES)
        .ok_or_else(|| "Covenant fee input-byte estimate overflow".to_string())?;
    let covenant_output_bytes = COVENANT_OUTPUT_BYTES
        .checked_add(if tag_genesis { GENESIS_TAG_BYTES } else { 0 })
        .ok_or_else(|| "Covenant fee output-byte estimate overflow".to_string())?;
    let estimated_transaction_bytes = BASE_TRANSACTION_BYTES
        .checked_add(input_bytes)
        .and_then(|value| value.checked_add(covenant_output_bytes))
        .and_then(|value| value.checked_add(CHANGE_OUTPUT_BYTES))
        .and_then(|value| value.checked_add(payload_len))
        .and_then(|value| value.checked_add(FRAMING_BYTES))
        .ok_or_else(|| "Covenant transaction-byte estimate overflow".to_string())?;
    let signature_operation_mass = input_count
        .checked_mul(MASS_PER_SIG_OP)
        .ok_or_else(|| "Covenant signature-operation mass overflow".to_string())?;
    let compute_mass = estimated_transaction_bytes
        .checked_mul(MASS_PER_TX_BYTE)
        .and_then(|value| value.checked_add(signature_operation_mass))
        .and_then(|value| value.checked_add(SCRIPT_PUBLIC_KEY_MASS))
        .ok_or_else(|| "Covenant compute-mass estimate overflow".to_string())?;
    let fee = compute_mass
        .checked_mul(MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM)
        .and_then(|value| value.checked_mul(FEE_MARKUP_PERCENT))
        .map(|value| value / 100)
        .ok_or_else(|| "Covenant fee estimate overflow".to_string())?;
    Ok(fee.max(MINIMUM_FEE))
}

fn estimated_serialized_size(transaction: &ConsensusTransaction) -> Result<u64, String> {
    let mut size = 2u64 + 8 + 8 + 8 + 20 + 8 + 32 + 8;
    for input in &transaction.inputs {
        let sig_len = u64::try_from(input.sig_script.len())
            .map_err(|_| "signature script length exceeds u64".to_string())?;
        size = size
            .checked_add(32 + 4 + 8 + sig_len + 8 + if transaction.tx_version >= 1 { 2 } else { 0 })
            .ok_or_else(|| "transaction size overflow".to_string())?;
    }
    for output in &transaction.outputs {
        let script_len = u64::try_from(output.spk_script.len())
            .map_err(|_| "script length exceeds u64".to_string())?;
        size = size
            .checked_add(8 + 2 + 8 + script_len)
            .ok_or_else(|| "transaction size overflow".to_string())?;
    }
    size.checked_add(
        u64::try_from(transaction.payload.len())
            .map_err(|_| "payload length exceeds u64".to_string())?,
    )
    .ok_or_else(|| "transaction size overflow".to_string())
}

fn estimated_plan_size(
    signature_script_len: u64,
    input_count: usize,
    output_script_lengths: &[usize],
    payload_len: usize,
) -> Result<u64, String> {
    const BASE_TRANSACTION_BYTES: u64 = 2 + 8 + 8 + 8 + 20 + 8 + 32 + 8;
    const INPUT_FIXED_BYTES: u64 = 32 + 4 + 8 + 8;
    const OUTPUT_FIXED_BYTES: u64 = 8 + 2 + 8;

    let input_count =
        u64::try_from(input_count).map_err(|_| "input count exceeds u64".to_string())?;
    let payload_len =
        u64::try_from(payload_len).map_err(|_| "payload length exceeds u64".to_string())?;
    let input_bytes = INPUT_FIXED_BYTES
        .checked_add(signature_script_len)
        .and_then(|value| value.checked_mul(input_count))
        .ok_or_else(|| "transaction size overflow".to_string())?;
    let mut size = BASE_TRANSACTION_BYTES
        .checked_add(payload_len)
        .and_then(|value| value.checked_add(input_bytes))
        .ok_or_else(|| "transaction size overflow".to_string())?;
    for script_len in output_script_lengths {
        let script_len =
            u64::try_from(*script_len).map_err(|_| "script length exceeds u64".to_string())?;
        let output_bytes = OUTPUT_FIXED_BYTES
            .checked_add(script_len)
            .ok_or_else(|| "transaction size overflow".to_string())?;
        size = size
            .checked_add(output_bytes)
            .ok_or_else(|| "transaction size overflow".to_string())?;
    }
    Ok(size)
}

fn compute_mass(transaction: &ConsensusTransaction, estimated_size: u64) -> Result<u64, String> {
    let script_mass = transaction.outputs.iter().try_fold(0u64, |total, output| {
        let script_len = u64::try_from(output.spk_script.len())
            .map_err(|_| "script length exceeds u64".to_string())?;
        let script_bytes = 2u64
            .checked_add(script_len)
            .ok_or_else(|| "script mass overflow".to_string())?;
        let mass = script_bytes
            .checked_mul(MASS_PER_SCRIPT_PUBLIC_KEY_BYTE)
            .ok_or_else(|| "script mass overflow".to_string())?;
        total
            .checked_add(mass)
            .ok_or_else(|| "script mass overflow".to_string())
    })?;
    let signature_mass = transaction.inputs.iter().try_fold(0u64, |total, input| {
        total
            .checked_add(u64::from(input.sig_op_count).saturating_mul(MASS_PER_SIG_OP))
            .ok_or_else(|| "signature-operation mass overflow".to_string())
    })?;
    estimated_size
        .checked_mul(MASS_PER_TX_BYTE)
        .and_then(|value| value.checked_add(script_mass))
        .and_then(|value| value.checked_add(signature_mass))
        .ok_or_else(|| "compute mass overflow".to_string())
}

fn normalize_mass(mass: u64, reference_limit: u64, dimension_limit: u64) -> Result<u64, String> {
    mass.checked_mul(reference_limit)
        .map(|value| value.div_ceil(dimension_limit))
        .ok_or_else(|| "mass normalization overflow".to_string())
}

#[cfg(test)]
#[path = "unit-tests/mass.rs"]
mod unit_tests;
