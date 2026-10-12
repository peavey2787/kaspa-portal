//! Private Swap v1 covenant: adaptor-signature claim + timed owner refund.
//!
//! The claim branch uses ordinary OP_CHECKSIG over the Kaspa transaction
//! sighash. The adaptor construction exists only off-chain, so no preimage or
//! shared hash appears on-chain. The claim transaction is constrained to one
//! input, one fixed destination output, and a bounded fee as defense in depth.
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

use super::covenant_ops::*;
use super::{push_data, push_int, push_pubkey};

pub const PRIVATE_SWAP_MAX_FEE_SOMPI: u64 = 500_000_000; // 5 KAS hard ceiling.

pub fn build_private_swap_script(
    owner_pubkey: &[u8; 32],
    claimer_pubkey: &[u8; 32],
    claimer_output_spk: &[u8],
    refund_locktime_daa: u64,
    salt: &[u8; 16],
) -> Result<Vec<u8>, String> {
    if refund_locktime_daa == 0 {
        return Err("Private Swap refund timeout must be nonzero".into());
    }
    if salt.iter().all(|byte| *byte == 0) {
        return Err("Private Swap salt must be nonzero".into());
    }
    if claimer_output_spk.len() < 3 || claimer_output_spk.len() > 73 {
        return Err("Private Swap destination script length is unsupported".into());
    }
    if owner_pubkey == claimer_pubkey {
        return Err("Private Swap owner and claimer keys must differ".into());
    }

    let destination_spk = versioned_destination(claimer_output_spk);
    let mut script = Vec::with_capacity(242 + claimer_output_spk.len());
    push_data(&mut script, salt);
    script.push(OP_DROP);

    // Adaptor claim. The final on-chain object is an ordinary transaction
    // Schnorr signature under the isolated per-swap claimer key.
    script.push(OP_IF);
    push_pubkey(&mut script, claimer_pubkey);
    script.push(OP_CHECKSIGVERIFY);
    script.push(OP_TX_INPUT_COUNT);
    push_int(&mut script, 1);
    script.push(OP_NUMEQUALVERIFY);
    script.push(OP_TX_OUTPUT_COUNT);
    push_int(&mut script, 1);
    script.push(OP_NUMEQUALVERIFY);
    push_int(&mut script, 0);
    script.push(OP_TX_OUTPUT_SPK);
    push_data(&mut script, &destination_spk);
    script.push(OP_EQUALVERIFY);
    append_claim_fee_bound(&mut script);
    script.push(OP_1);

    // Funding owner recovers after timeout using the ordinary wallet key.
    script.push(OP_ELSE);
    push_pubkey(&mut script, owner_pubkey);
    script.push(OP_CHECKSIGVERIFY);
    push_int(&mut script, refund_locktime_daa);
    script.push(OP_CHECKLOCKTIMEVERIFY);
    script.push(OP_1);
    script.push(OP_ENDIF);
    Ok(script)
}

fn append_claim_fee_bound(script: &mut Vec<u8>) {
    push_int(script, 0);
    script.push(OP_TX_INPUT_AMOUNT);
    script.push(OP_DUP);
    push_int(script, 0);
    script.push(OP_TX_OUTPUT_AMOUNT);
    script.push(OP_GREATERTHANOREQUAL);
    script.push(OP_VERIFY);
    push_int(script, 0);
    script.push(OP_TX_OUTPUT_AMOUNT);
    script.push(OP_SUB);
    push_int(script, PRIVATE_SWAP_MAX_FEE_SOMPI);
    script.push(OP_LESSTHANOREQUAL);
    script.push(OP_VERIFY);
}

#[cfg(test)]
#[path = "private_swap/unit-tests/mod.rs"]
mod unit_tests;

/// The fields of a canonical Private Swap script.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateSwapFields {
    pub owner_pubkey: [u8; 32],
    pub claimer_pubkey: [u8; 32],
    /// The claim destination, without its two-byte script version.
    pub claimer_output_spk: Vec<u8>,
    pub refund_locktime_daa: u64,
    pub salt: [u8; 16],
}

impl PrivateSwapFields {
    /// The destination as the claim branch commits to it: script version 0
    /// then the script.
    #[must_use]
    pub fn versioned_destination(&self) -> Vec<u8> {
        versioned_destination(&self.claimer_output_spk)
    }
}

fn versioned_destination(script: &[u8]) -> Vec<u8> {
    let mut versioned = Vec::with_capacity(2 + script.len());
    versioned.extend_from_slice(&[0x00, 0x00]);
    versioned.extend_from_slice(script);
    versioned
}

/// Recognize `script` as exactly what [`build_private_swap_script`] builds.
#[must_use]
pub fn private_swap_script_fields(script: &[u8]) -> Option<PrivateSwapFields> {
    let elements = crate::contract::script::complete_elements(script)?;
    let push32 = |index: usize| elements.get(index)?.data.try_into().ok();
    let fields = PrivateSwapFields {
        salt: elements.first()?.data.try_into().ok()?,
        claimer_pubkey: push32(3)?,
        claimer_output_spk: elements.get(13)?.data.get(2..)?.to_vec(),
        owner_pubkey: push32(30)?,
        refund_locktime_daa: crate::contract::script::element_integer(elements.get(32)?)?,
    };
    let rebuilt = build_private_swap_script(
        &fields.owner_pubkey,
        &fields.claimer_pubkey,
        &fields.claimer_output_spk,
        fields.refund_locktime_daa,
        &fields.salt,
    )
    .ok()?;
    (rebuilt == script).then_some(fields)
}
