//! Consensus transaction materialization from the exact typed authorization
//! result. Like the JSON finalizer, nothing here reads PSKT or KSPT source.

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::transaction::consensus::{
    ConsensusInput, ConsensusOutput, ConsensusTransaction, InputEncoding, SpentUtxo,
};

use super::verified::VerifiedTransaction;

impl VerifiedTransaction {
    /// The broadcastable consensus transaction, with its KIP-9 storage mass.
    pub fn to_consensus(&self) -> Result<ConsensusTransaction, String> {
        let inputs = self
            .inputs()
            .iter()
            .map(|input| {
                Ok(ConsensusInput {
                    prev_tx_id: *input.previous_tx_id(),
                    prev_index: input.previous_index(),
                    sig_script: input.witness().materialize_signature_script()?,
                    sequence: input.sequence(),
                    sig_op_count: input.sig_op_count(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let outputs = self
            .outputs()
            .iter()
            .map(|output| ConsensusOutput {
                value: output.amount(),
                spk_version: output.script_version(),
                spk_script: output.script_public_key().to_vec(),
                covenant: output.covenant(),
            })
            .collect::<Vec<_>>();
        let spent = self
            .inputs()
            .iter()
            .map(|input| {
                (
                    input.amount(),
                    input.script_public_key().len(),
                    input.has_covenant_id(),
                )
            })
            .collect::<Vec<SpentUtxo>>();
        let storage_mass = ConsensusTransaction::storage_mass_for(&spent, &outputs)?;
        Ok(ConsensusTransaction {
            tx_version: self.version(),
            input_encoding: InputEncoding::Budgeted,
            inputs,
            outputs,
            locktime: self.locktime(),
            subnetwork_id: *self.subnetwork_id(),
            gas: self.gas(),
            payload: self.payload().to_vec(),
            storage_mass,
        })
    }

    /// The fee the authorized transaction pays: spent amounts minus outputs.
    pub fn fee(&self) -> Result<u64, String> {
        let spent = checked_total(self.inputs().iter().map(|input| input.amount()), "input")?;
        let created = checked_total(
            self.outputs().iter().map(|output| output.amount()),
            "output",
        )?;
        spent
            .checked_sub(created)
            .ok_or_else(|| "transaction outputs exceed inputs".to_string())
    }
}

fn checked_total(mut amounts: impl Iterator<Item = u64>, kind: &str) -> Result<u64, String> {
    amounts.try_fold(0u64, |total, amount| {
        total
            .checked_add(amount)
            .ok_or_else(|| format!("{kind} amount total overflow"))
    })
}
