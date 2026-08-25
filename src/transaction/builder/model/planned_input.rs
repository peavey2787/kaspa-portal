use crate::chain::utxo::UtxoEntry;
use serde_json::Value;

/// A transaction input after coin selection and policy resolution.
#[derive(Clone, Debug)]
pub struct PlannedInput {
    pub utxo: UtxoEntry,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub redeem_script: Option<Vec<u8>>,
    pub bip32_derivations: Option<Value>,
}

impl PlannedInput {
    #[must_use]
    pub fn p2pk(utxo: UtxoEntry) -> Self {
        Self {
            utxo,
            sequence: 0,
            sig_op_count: 1,
            redeem_script: None,
            bip32_derivations: None,
        }
    }

    #[must_use]
    pub fn p2sh_multisig(utxo: UtxoEntry, redeem_script: &[u8], sig_op_count: u8) -> Self {
        Self {
            utxo,
            sequence: 0,
            sig_op_count,
            redeem_script: Some(redeem_script.to_vec()),
            bip32_derivations: None,
        }
    }

    #[must_use]
    pub fn with_bip32_derivations(mut self, derivations: Value) -> Self {
        self.bip32_derivations = Some(derivations);
        self
    }
}
