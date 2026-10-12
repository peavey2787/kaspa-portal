//! Kaspa SIGHASH_ALL digest of a compact KSPT transaction, computed by the
//! signer's single sighash implementation.

use super::Transaction;
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::transaction::{
    model::SigHashType,
    sighash::{calculate_sighash, SighashInput, SighashOutput, SighashSource},
};

impl SighashSource for Transaction {
    fn version(&self) -> u16 {
        self.version
    }
    fn input_count(&self) -> usize {
        self.inputs.len()
    }
    fn input(&self, index: usize) -> SighashInput<'_> {
        let input = &self.inputs[index];
        SighashInput {
            transaction_id: &input.tx_id,
            index: input.index,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
            script_version: input.script_version,
            script: &input.script,
            amount: input.amount,
        }
    }
    fn output_count(&self) -> usize {
        self.outputs.len()
    }
    fn output(&self, index: usize) -> SighashOutput<'_> {
        let output = &self.outputs[index];
        SighashOutput {
            value: output.amount,
            script_version: output.script_version,
            script: &output.script,
            covenant: output
                .covenant
                .as_ref()
                .map(|(authorizing_input, id)| (*authorizing_input, id)),
        }
    }
    fn locktime(&self) -> u64 {
        self.locktime
    }
    fn subnetwork_id(&self) -> &[u8; 20] {
        &self.subnetwork
    }
    fn gas(&self) -> u64 {
        self.gas
    }
    fn payload(&self) -> &[u8] {
        &self.payload
    }
}

pub(crate) fn sighash_all(
    transaction: &Transaction,
    input_index: usize,
) -> Result<[u8; 32], String> {
    if input_index >= transaction.inputs.len() {
        return Err("sighash input index out of range".to_string());
    }
    Ok(calculate_sighash(
        transaction,
        input_index,
        SigHashType::All,
    ))
}
