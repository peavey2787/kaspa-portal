//! [`EncodeSource`] view of a validated [`Transaction`].

use crate::transaction::model::Transaction;

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
            // Validation bounds both counts by the transaction limits, and the
            // encoder rejects a saturated count.
            input_count: u32::try_from(tx.num_inputs).unwrap_or(u32::MAX),
            output_count: u8::try_from(tx.num_outputs).unwrap_or(u8::MAX),
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
        self.0.inputs[input].sigs.len()
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
        self.0.stealth_tweak
    }

    fn input_derivation(&self, index: usize) -> Option<Derivation> {
        self.0.inputs[index].derivation_hint
    }

    fn output_derivation(&self, index: usize) -> Option<Derivation> {
        self.0.outputs[index].derivation_hint
    }

    fn input_ms45(&self, index: usize) -> Option<Ms45Derivation> {
        self.0.inputs[index].ms45_hint
    }

    fn output_ms45(&self, index: usize) -> Option<Ms45Derivation> {
        self.0.outputs[index].ms45_hint
    }

    fn covenant(&self, index: usize) -> Option<Covenant> {
        self.0.outputs[index].covenant
    }

    fn covenant_execution(&self, index: usize) -> Option<CovenantExecution> {
        self.0.inputs[index].covenant_execution
    }
}
