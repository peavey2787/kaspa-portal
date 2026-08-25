use serde::{Deserialize, Serialize};

/// Spendable transaction output returned by a Kaspa node.
///
/// This wire/value type sits below `network`, `chain`, `wallet`, and
/// `transaction` so RPC decoding never depends upward on chain services.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub tx_id: String,
    pub index: u32,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub block_daa_score: u64,
    /// On-chain covenant id for covenant-tagged outputs.
    #[serde(default)]
    pub covenant_id: Option<String>,
}

#[cfg(test)]
#[path = "utxo/unit-tests/mod.rs"]
mod unit_tests;
