use serde::Serialize;

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
}
