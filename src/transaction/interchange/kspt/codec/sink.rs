//! [`DecodeSink`] that fills a [`Transaction`] and applies Portal's
//! SIGHASH_ALL-only signing policy on top of the shared grammar.

use crate::{
    primitives::address::KaspaNetwork,
    transaction::model::{Covenant, InputSig, SigHashType, Transaction},
};

use super::super::{
    error::PsktError,
    wire::{
        CovenantExecution, DecodeSink, Derivation, Global, Input, Ms45Derivation, Output, Signature,
    },
};

pub(super) struct TransactionSink<'a>(pub(super) &'a mut Transaction);

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
        // The grammar limit is the model's own, so only allocation can fail.
        tx.set_payload(value.payload)
            .map_err(|_| PsktError::StorageExhausted)
    }

    fn input(
        &mut self,
        index: u32,
        value: Input<'_>,
        _signature_count: u8,
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
        input.sigs.clear();
        // KSPT carries the project-wide SIGHASH_ALL policy implicitly for
        // unsigned inputs; signature records repeat it when present.
        input.sighash_type = SigHashType::All.to_byte();
        Ok(())
    }

    /// The grammar delivers an input's records in slot order and never more
    /// than the model holds, so each one is the next slot.
    fn signature(&mut self, input: u32, _slot: u8, value: Signature) -> Result<(), PsktError> {
        if value.sighash != SigHashType::All.to_byte() {
            return Err(PsktError::InvalidSigHashType);
        }
        let added = self.0.inputs[input as usize].sigs.push(InputSig {
            signature: value.bytes,
            sighash_type: value.sighash,
            pubkey_pos: value.position,
            pubkey_compressed: [0u8; 33],
        });
        if added {
            Ok(())
        } else {
            Err(PsktError::TooManySignatures)
        }
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
        self.0.stealth_tweak = Some(tweak);
        Ok(())
    }

    fn input_derivation(&mut self, input: u8, value: Derivation) -> Result<(), PsktError> {
        self.0.inputs[usize::from(input)].derivation_hint = Some(value);
        Ok(())
    }

    fn output_derivation(&mut self, output: u8, value: Derivation) -> Result<(), PsktError> {
        self.0.outputs[usize::from(output)].derivation_hint = Some(value);
        Ok(())
    }

    fn input_ms45(&mut self, input: u8, value: Ms45Derivation) -> Result<(), PsktError> {
        self.0.inputs[usize::from(input)].ms45_hint = Some(value);
        Ok(())
    }

    fn output_ms45(&mut self, output: u8, value: Ms45Derivation) -> Result<(), PsktError> {
        self.0.outputs[usize::from(output)].ms45_hint = Some(value);
        Ok(())
    }

    fn covenant(
        &mut self,
        output: u8,
        authorizing_input: u16,
        id: [u8; 32],
    ) -> Result<(), PsktError> {
        self.0.outputs[usize::from(output)].covenant = Some(Covenant {
            authorizing_input,
            id,
        });
        Ok(())
    }

    fn covenant_execution(&mut self, input: u8, value: CovenantExecution) -> Result<(), PsktError> {
        self.0.inputs[usize::from(input)].covenant_execution = Some(value);
        Ok(())
    }
}
