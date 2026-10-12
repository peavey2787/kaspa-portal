// Kaspa protocol implementation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Read-only view of the transaction fields a Kaspa sighash commits to, so one
// digest implementation serves every transaction representation.

use crate::transaction::model::{Hash256, Transaction};

/// The previous output and spending fields of one input.
#[derive(Clone, Copy, Debug)]
pub struct SighashInput<'a> {
    pub transaction_id: &'a Hash256,
    pub index: u32,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub script_version: u16,
    pub script: &'a [u8],
    pub amount: u64,
}

/// One output, with its KIP-20 covenant binding when present.
#[derive(Clone, Copy, Debug)]
pub struct SighashOutput<'a> {
    pub value: u64,
    pub script_version: u16,
    pub script: &'a [u8],
    pub covenant: Option<(u16, &'a Hash256)>,
}

/// A transaction whose signature hash can be computed.
pub trait SighashSource {
    fn version(&self) -> u16;
    fn input_count(&self) -> usize;
    fn input(&self, index: usize) -> SighashInput<'_>;
    fn output_count(&self) -> usize;
    fn output(&self, index: usize) -> SighashOutput<'_>;
    fn locktime(&self) -> u64;
    fn subnetwork_id(&self) -> &[u8; 20];
    fn gas(&self) -> u64;
    fn payload(&self) -> &[u8];
}

impl SighashSource for Transaction {
    fn version(&self) -> u16 {
        self.version
    }
    fn input_count(&self) -> usize {
        self.num_inputs
    }
    fn input(&self, index: usize) -> SighashInput<'_> {
        let input = &self.inputs()[index];
        SighashInput {
            transaction_id: &input.previous_outpoint.transaction_id,
            index: input.previous_outpoint.index,
            sequence: input.sequence,
            sig_op_count: input.sig_op_count,
            script_version: input.utxo_entry.script_public_key.version,
            script: input.utxo_entry.script_public_key.script_bytes(),
            amount: input.utxo_entry.amount,
        }
    }
    fn output_count(&self) -> usize {
        self.num_outputs
    }
    fn output(&self, index: usize) -> SighashOutput<'_> {
        let output = &self.outputs()[index];
        SighashOutput {
            value: output.value,
            script_version: output.script_public_key.version,
            script: output.script_public_key.script_bytes(),
            covenant: output
                .has_covenant
                .then_some((output.covenant_auth_input, &output.covenant_id)),
        }
    }
    fn locktime(&self) -> u64 {
        self.locktime
    }
    fn subnetwork_id(&self) -> &[u8; 20] {
        &self.subnetwork_id
    }
    fn gas(&self) -> u64 {
        self.gas
    }
    fn payload(&self) -> &[u8] {
        &self.payload
    }
}
