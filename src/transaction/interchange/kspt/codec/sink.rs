//! [`DecodeSink`] that fills a [`Transaction`] and applies Portal's
//! SIGHASH_ALL-only signing policy on top of the shared grammar.

use crate::{
    primitives::address::KaspaNetwork,
    transaction::model::{Ms45Hint, SigHashType, Transaction, TransactionStorageError},
};

use super::super::{
    error::PsktError,
    wire::{
        CovenantExecution, DecodeSink, Derivation, Global, Input, Ms45Derivation, Output, Signature,
    },
};

pub(super) struct TransactionSink<'a>(pub(super) &'a mut Transaction);

const fn ms45_hint(value: Ms45Derivation) -> Ms45Hint {
    Ms45Hint {
        present: true,
        cosigner: value.cosigner,
        chain: value.chain,
        index: value.index,
    }
}

fn payload_error(error: TransactionStorageError) -> PsktError {
    match error {
        TransactionStorageError::PayloadTooLarge => PsktError::PayloadTooLong,
        _ => PsktError::StorageExhausted,
    }
}

impl DecodeSink for TransactionSink<'_> {
    type Error = PsktError;

    fn global(&mut self, value: Global<'_>) -> Result<(), PsktError> {
        if value.input_count == 0 {
            return Err(PsktError::NoInputs);
        }
        if value.output_count == 0 {
            return Err(PsktError::NoOutputs);
        }
        let tx = &mut *self.0;
        let inputs = usize::try_from(value.input_count).map_err(|_| PsktError::TooManyInputs)?;
        tx.ensure_input_slots(inputs)
            .map_err(|_| PsktError::TooManyInputs)?;
        tx.num_inputs = inputs;
        tx.num_outputs = usize::from(value.output_count);
        tx.version = value.version;
        tx.locktime = value.locktime;
        tx.subnetwork_id = value.subnetwork_id;
        tx.gas = value.gas;
        tx.set_payload(value.payload).map_err(payload_error)
    }

    fn input(
        &mut self,
        index: u32,
        value: Input<'_>,
        signature_count: u8,
    ) -> Result<(), PsktError> {
        let input = &mut self.0.inputs[index as usize];
        input.previous_outpoint.transaction_id = value.previous_tx_id;
        input.previous_outpoint.index = value.previous_index;
        input.utxo_entry.amount = value.amount;
        input.sequence = value.sequence;
        input.sig_op_count = value.sig_op_count;
        let script = &mut input.utxo_entry.script_public_key;
        script.version = value.script_version;
        script.script_len = value.script.len();
        script.script[..value.script.len()].copy_from_slice(value.script);
        input.sig_count = signature_count;
        // KSPT carries the project-wide SIGHASH_ALL policy implicitly for
        // unsigned inputs; signature records repeat it when present.
        input.sighash_type = SigHashType::All.to_byte();
        Ok(())
    }

    fn signature(&mut self, input: u32, slot: u8, value: Signature) -> Result<(), PsktError> {
        if value.sighash != SigHashType::All.to_byte() {
            return Err(PsktError::InvalidSigHashType);
        }
        let slot = &mut self.0.inputs[input as usize].sigs[usize::from(slot)];
        slot.pubkey_pos = value.position;
        slot.sighash_type = value.sighash;
        slot.signature = value.bytes;
        slot.present = true;
        Ok(())
    }

    fn redeem(&mut self, input: u32, value: &[u8]) -> Result<(), PsktError> {
        if value.is_empty() {
            return Ok(());
        }
        self.0
            .store_redeem(input as usize, value)
            .map_err(|_| PsktError::ScriptTooLong)
    }

    fn output(&mut self, index: u8, value: Output<'_>) -> Result<(), PsktError> {
        let output = &mut self.0.outputs[usize::from(index)];
        output.value = value.amount;
        let script = &mut output.script_public_key;
        script.version = value.script_version;
        script.script_len = value.script.len();
        script.script[..value.script.len()].copy_from_slice(value.script);
        Ok(())
    }

    fn network(&mut self, code: u8) -> Result<(), PsktError> {
        self.0.network = KaspaNetwork::from_wire(code).ok_or(PsktError::InvalidTrailer)?;
        Ok(())
    }

    fn stealth(&mut self, tweak: [u8; 32]) -> Result<(), PsktError> {
        self.0.stealth_tweak = tweak;
        self.0.has_stealth_tweak = true;
        Ok(())
    }

    fn input_derivation(&mut self, input: u8, value: Derivation) -> Result<(), PsktError> {
        let input = &mut self.0.inputs[usize::from(input)];
        input.has_derivation_hint = true;
        input.derivation_branch = value.branch;
        input.derivation_index = value.index;
        Ok(())
    }

    fn output_derivation(&mut self, output: u8, value: Derivation) -> Result<(), PsktError> {
        let output = &mut self.0.outputs[usize::from(output)];
        output.has_derivation_hint = true;
        output.derivation_branch = value.branch;
        output.derivation_index = value.index;
        Ok(())
    }

    fn input_ms45(&mut self, input: u8, value: Ms45Derivation) -> Result<(), PsktError> {
        self.0.inputs[usize::from(input)].ms45_hint = ms45_hint(value);
        Ok(())
    }

    fn output_ms45(&mut self, output: u8, value: Ms45Derivation) -> Result<(), PsktError> {
        self.0.outputs[usize::from(output)].ms45_hint = ms45_hint(value);
        Ok(())
    }

    fn covenant(
        &mut self,
        output: u8,
        authorizing_input: u16,
        id: [u8; 32],
    ) -> Result<(), PsktError> {
        let output = &mut self.0.outputs[usize::from(output)];
        output.has_covenant = true;
        output.covenant_auth_input = authorizing_input;
        output.covenant_id = id;
        Ok(())
    }

    fn covenant_execution(&mut self, input: u8, value: CovenantExecution) -> Result<(), PsktError> {
        let input = &mut self.0.inputs[usize::from(input)];
        input.covenant_execution_present = true;
        input.covenant_execution_mask = value.supplied_mask;
        input.covenant_execution_true_mask = value.supplied_true_mask;
        Ok(())
    }
}
