#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use serde::Serialize;

use crate::contract::covenant::identity::{
    verify_genesis, AuthorizedOutput, CovenantGenesis, CovenantProofError, GenesisOutpoint,
};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusInput {
    pub prev_tx_id: [u8; 32],
    pub prev_index: u32,
    pub sig_script: Vec<u8>,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub sequence: u64,
    pub sig_op_count: u8,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusOutput {
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub value: u64,
    pub spk_version: u16,
    pub spk_script: Vec<u8>,
    pub covenant: Option<(u16, [u8; 32])>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputEncoding {
    Compact,
    Budgeted,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusTransaction {
    pub tx_version: u16,
    pub input_encoding: InputEncoding,
    pub inputs: Vec<ConsensusInput>,
    pub outputs: Vec<ConsensusOutput>,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub locktime: u64,
    pub subnetwork_id: [u8; 20],
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub gas: u64,
    pub payload: Vec<u8>,
    /// KIP-9 storage-mass commitment submitted to kaspad.
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub storage_mass: u64,
}

/// `(amount, script public key length, has covenant id)` of a spent UTXO.
pub type SpentUtxo = (u64, usize, bool);

impl ConsensusTransaction {
    /// Extracts the genesis group bound to `claimed` from this genesis
    /// transaction and verifies it. Every output bound to the ID must name the
    /// same authorizing input.
    pub fn covenant_genesis(
        &self,
        claimed: &[u8; 32],
    ) -> Result<CovenantGenesis<'_>, CovenantProofError> {
        let mut authorizing_input = None;
        let mut outputs = Vec::new();
        for (index, output) in self.outputs.iter().enumerate() {
            let Some((input, _)) = output.covenant.filter(|(_, id)| id == claimed) else {
                continue;
            };
            if *authorizing_input.get_or_insert(input) != input {
                return Err(CovenantProofError::MixedAuthorizingInputs);
            }
            outputs.push(AuthorizedOutput {
                index: u32::try_from(index).map_err(|_| CovenantProofError::OutputsNotOrdered)?,
                value: output.value,
                spk_version: output.spk_version,
                spk_script: &output.spk_script,
            });
        }
        let authorizing_input = authorizing_input.ok_or(CovenantProofError::NoAuthorizedOutputs)?;
        let input = self
            .inputs
            .get(usize::from(authorizing_input))
            .ok_or(CovenantProofError::NoSuchInput(authorizing_input))?;
        let outpoint = GenesisOutpoint {
            transaction_id: input.prev_tx_id,
            index: input.prev_index,
        };
        verify_genesis(claimed, outpoint, &outputs)?;
        Ok(CovenantGenesis {
            covenant_id: *claimed,
            outpoint,
            authorizing_input,
            outputs,
        })
    }

    /// KIP-9 storage mass for spending `inputs` into `outputs`.
    pub fn storage_mass_for(
        inputs: &[SpentUtxo],
        outputs: &[ConsensusOutput],
    ) -> Result<u64, String> {
        use crate::transaction::builder::planning::amounts::{
            storage_mass_estimate, utxo_plurality,
        };
        let input_cells = inputs
            .iter()
            .map(|&(amount, script_len, covenant)| (amount, utxo_plurality(script_len, covenant)))
            .collect::<Vec<_>>();
        let output_cells = outputs
            .iter()
            .map(|output| {
                (
                    output.value,
                    utxo_plurality(output.spk_script.len(), output.covenant.is_some()),
                )
            })
            .collect::<Vec<_>>();
        storage_mass_estimate(&input_cells, &output_cells)
    }
}

#[cfg(test)]
#[path = "unit-tests/model.rs"]
mod unit_tests;
