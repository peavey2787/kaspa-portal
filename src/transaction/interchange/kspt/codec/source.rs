//! [`EncodeSource`] view of a validated [`Transaction`].

use crate::transaction::model::{Ms45Hint, Transaction};

use super::super::{
    signing::is_fully_signed,
    validation::checked_redeem_bytes,
    wire::{
        Covenant, CovenantExecution, Derivation, EncodeSource, Global, Input, Ms45Derivation,
        Output, Signature, FLAG_SIGNED_OR_COMPLETE,
    },
};

/// Encodes a transaction that already passed `validate_partial_signed`.
pub(super) struct TransactionSource<'a>(pub(super) &'a Transaction);

const fn ms45(hint: Ms45Hint) -> Option<Ms45Derivation> {
    if !hint.present {
        return None;
    }
    Some(Ms45Derivation {
        cosigner: hint.cosigner,
        chain: hint.chain,
        index: hint.index,
    })
}

const fn derivation(present: bool, branch: u8, index: u32) -> Option<Derivation> {
    if !present {
        return None;
    }
    Some(Derivation { branch, index })
}

impl EncodeSource for TransactionSource<'_> {
    fn global(&self) -> Global<'_> {
        let tx = self.0;
        Global {
            flags: if is_fully_signed(tx) {
                FLAG_SIGNED_OR_COMPLETE
            } else {
                0
            },
            version: tx.version,
            // Validation bounds both counts by the transaction limits.
            input_count: tx.num_inputs as u32,
            output_count: tx.num_outputs as u8,
            locktime: tx.locktime,
            subnetwork_id: tx.subnetwork_id,
            gas: tx.gas,
            payload: &tx.payload,
        }
    }

    fn input(&self, index: usize) -> Input<'_> {
        let input = &self.0.inputs[index];
        Input {
            previous_tx_id: input.previous_outpoint.transaction_id,
            previous_index: input.previous_outpoint.index,
            amount: input.utxo_entry.amount,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
            script_version: input.utxo_entry.script_public_key.version,
            script: input.utxo_entry.script_public_key.script_bytes(),
        }
    }

    fn signature_count(&self, input: usize) -> usize {
        usize::from(self.0.inputs[input].sig_count)
    }

    fn signature(&self, input: usize, slot: usize) -> Signature {
        let slot = &self.0.inputs[input].sigs[slot];
        Signature {
            position: slot.pubkey_pos,
            sighash: slot.sighash_type,
            bytes: slot.signature,
        }
    }

    fn redeem(&self, input: usize) -> &[u8] {
        // Validation already proved every redeem reference in bounds.
        checked_redeem_bytes(self.0, input).unwrap_or(&[])
    }

    fn output(&self, index: usize) -> Output<'_> {
        let output = &self.0.outputs[index];
        Output {
            amount: output.value,
            script_version: output.script_public_key.version,
            script: output.script_public_key.script_bytes(),
        }
    }

    fn network(&self) -> u8 {
        self.0.network as u8
    }

    fn stealth(&self) -> Option<[u8; 32]> {
        self.0.has_stealth_tweak.then_some(self.0.stealth_tweak)
    }

    fn input_derivation(&self, index: usize) -> Option<Derivation> {
        let input = &self.0.inputs[index];
        derivation(
            input.has_derivation_hint,
            input.derivation_branch,
            input.derivation_index,
        )
    }

    fn output_derivation(&self, index: usize) -> Option<Derivation> {
        let output = &self.0.outputs[index];
        derivation(
            output.has_derivation_hint,
            output.derivation_branch,
            output.derivation_index,
        )
    }

    fn input_ms45(&self, index: usize) -> Option<Ms45Derivation> {
        ms45(self.0.inputs[index].ms45_hint)
    }

    fn output_ms45(&self, index: usize) -> Option<Ms45Derivation> {
        ms45(self.0.outputs[index].ms45_hint)
    }

    fn covenant(&self, index: usize) -> Option<Covenant> {
        let output = &self.0.outputs[index];
        output.has_covenant.then_some(Covenant {
            authorizing_input: output.covenant_auth_input,
            id: output.covenant_id,
        })
    }

    fn covenant_execution(&self, index: usize) -> Option<CovenantExecution> {
        let input = &self.0.inputs[index];
        input
            .covenant_execution_present
            .then_some(CovenantExecution {
                supplied_mask: input.covenant_execution_mask,
                supplied_true_mask: input.covenant_execution_true_mask,
            })
    }
}
