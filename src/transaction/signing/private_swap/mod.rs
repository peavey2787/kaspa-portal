//! Private Swap v1 claim validation for signers.

use alloc::vec::Vec;

pub use crate::contract::covenant::PRIVATE_SWAP_MAX_FEE_SOMPI;
use crate::transaction::{
    model::{SigHashType, Transaction},
    sighash::calculate_sighash,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateSwapScript {
    pub salt: [u8; 16],
    pub claimer_pubkey: [u8; 32],
    pub owner_pubkey: [u8; 32],
    /// The claim destination as the script commits to it: version then script.
    pub destination_spk: Vec<u8>,
    pub refund_locktime_daa: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateSwapError {
    InvalidScript,
    WrongClaimer,
    InvalidTransaction,
    InvalidSighash,
    WrongDestination,
    FeeTooHigh,
}

/// Recognize a canonical Private Swap redeem script.
pub fn parse_private_swap_script(script: &[u8]) -> Result<PrivateSwapScript, PrivateSwapError> {
    let fields = crate::contract::covenant::private_swap_script_fields(script)
        .ok_or(PrivateSwapError::InvalidScript)?;
    Ok(PrivateSwapScript {
        salt: fields.salt,
        claimer_pubkey: fields.claimer_pubkey,
        owner_pubkey: fields.owner_pubkey,
        destination_spk: fields.versioned_destination(),
        refund_locktime_daa: fields.refund_locktime_daa,
    })
}

pub fn private_swap_claim_sighash(
    tx: &Transaction,
    expected_claimer_pubkey: &[u8; 32],
) -> Result<([u8; 32], PrivateSwapScript), PrivateSwapError> {
    let sighash_type = validate_claim_transaction_shape(tx)?;
    let policy = validate_claim_policy(tx, expected_claimer_pubkey)?;
    validate_claim_output(tx, &policy)?;
    Ok((calculate_sighash(tx, 0, sighash_type), policy))
}

fn validate_claim_transaction_shape(tx: &Transaction) -> Result<SigHashType, PrivateSwapError> {
    if tx.num_inputs != 1 || tx.num_outputs != 1 || !tx.payload.is_empty() {
        return Err(PrivateSwapError::InvalidTransaction);
    }
    let input = &tx.inputs[0];
    if input.sig_count != 0 || input.incoming_partial_sigs_count != 0 {
        return Err(PrivateSwapError::InvalidTransaction);
    }
    // Compact KSPT carries sighash metadata with signature records, not as
    // a standalone field on an unsigned input. Private Swap claims must be
    // unsigned here, so a zero model byte is the canonical wire-round-trip
    // representation of the protocol default: SIGHASH_ALL. This mirrors the
    // watcher bridge's `expected_added_sighash` rule.
    let sighash_type = if input.sighash_type == 0 {
        SigHashType::All
    } else {
        SigHashType::from_byte(input.sighash_type).ok_or(PrivateSwapError::InvalidSighash)?
    };
    if sighash_type != SigHashType::All {
        Err(PrivateSwapError::InvalidSighash)
    } else {
        Ok(sighash_type)
    }
}

fn validate_claim_policy(
    tx: &Transaction,
    expected_claimer_pubkey: &[u8; 32],
) -> Result<PrivateSwapScript, PrivateSwapError> {
    let redeem = tx.redeem_bytes(0);
    if redeem.is_empty() {
        return Err(PrivateSwapError::InvalidScript);
    }
    let policy = parse_private_swap_script(redeem)?;
    if &policy.claimer_pubkey != expected_claimer_pubkey {
        Err(PrivateSwapError::WrongClaimer)
    } else {
        Ok(policy)
    }
}

fn validate_claim_output(
    tx: &Transaction,
    policy: &PrivateSwapScript,
) -> Result<(), PrivateSwapError> {
    let input = &tx.inputs[0];
    let output = &tx.outputs[0];
    let capacity = 2usize
        .checked_add(output.script_public_key.script_len)
        .ok_or(PrivateSwapError::InvalidScript)?;
    let mut actual_spk = Vec::new();
    actual_spk
        .try_reserve_exact(capacity)
        .map_err(|_| PrivateSwapError::InvalidScript)?;
    actual_spk.extend_from_slice(&output.script_public_key.version.to_le_bytes());
    actual_spk.extend_from_slice(output.script_public_key.script_bytes());
    if actual_spk != policy.destination_spk {
        return Err(PrivateSwapError::WrongDestination);
    }
    let fee = input
        .utxo_entry
        .amount
        .checked_sub(output.value)
        .ok_or(PrivateSwapError::InvalidTransaction)?;
    if fee > PRIVATE_SWAP_MAX_FEE_SOMPI {
        Err(PrivateSwapError::FeeTooHigh)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
