use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::chain::utxo::UtxoEntry;

/// Typed input description for browser-compatible PSKB planning.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PskbInputPlan {
    pub utxo: UtxoEntry,
    pub source_script_public_key: Vec<u8>,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub sequence: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub block_daa_score: u64,
    pub sig_op_count: u8,
    pub minimum_signatures: u8,
    pub redeem_script: Option<Vec<u8>>,
    pub proprietaries: Value,
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    pub min_time: Option<u64>,
}

/// Signing and metadata policy for one covenant PSKB input.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CovenantInputPolicy {
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub sequence: u64,
    pub sig_op_count: u8,
    pub minimum_signatures: u8,
    pub proprietaries: Value,
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    pub min_time: Option<u64>,
}

impl PskbInputPlan {
    #[must_use]
    pub fn covenant(
        utxo: UtxoEntry,
        source_script_public_key: &[u8],
        redeem_script: &[u8],
        policy: CovenantInputPolicy,
    ) -> Self {
        Self {
            utxo,
            source_script_public_key: source_script_public_key.to_vec(),
            sequence: policy.sequence,
            block_daa_score: 0,
            sig_op_count: policy.sig_op_count,
            minimum_signatures: policy.minimum_signatures,
            redeem_script: Some(redeem_script.to_vec()),
            proprietaries: policy.proprietaries,
            min_time: policy.min_time,
        }
    }

    #[must_use]
    pub fn p2pk(utxo: UtxoEntry, source_script_public_key: &[u8], proprietaries: Value) -> Self {
        Self {
            utxo,
            source_script_public_key: source_script_public_key.to_vec(),
            sequence: 0,
            block_daa_score: 0,
            sig_op_count: 1,
            minimum_signatures: 1,
            redeem_script: None,
            proprietaries,
            min_time: Some(0),
        }
    }
}

/// Typed output description. `covenant_binding_field == None` omits the field;
/// `Some(Value::Null)` emits an explicit null binding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PskbOutputPlan {
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub covenant_binding_field: Option<Value>,
    pub proprietaries: Value,
}

impl PskbOutputPlan {
    #[must_use]
    pub fn plain(amount: u64, script_public_key: &[u8]) -> Self {
        Self {
            amount,
            script_public_key: script_public_key.to_vec(),
            covenant_binding_field: None,
            proprietaries: Value::Array(Vec::new()),
        }
    }

    #[must_use]
    pub fn with_binding_field(mut self, covenant_binding: Value) -> Self {
        self.covenant_binding_field = Some(covenant_binding);
        self
    }
}

/// Global PSKB metadata used by contract, oracle, ZK and privacy planners.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PskbGlobalPlan {
    pub tx_version: u16,
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    pub fallback_lock_time: Option<u64>,
    pub covenant_branch: Option<Value>,
    pub proprietaries: Value,
    pub transaction_payload: Option<Vec<u8>>,
}

impl PskbGlobalPlan {
    #[must_use]
    pub fn standard() -> Self {
        Self {
            tx_version: 0,
            fallback_lock_time: None,
            covenant_branch: None,
            proprietaries: Value::Array(Vec::new()),
            transaction_payload: None,
        }
    }

    #[must_use]
    pub fn with_branch(mut self, branch: impl Into<Value>) -> Self {
        self.covenant_branch = Some(branch.into());
        self
    }

    #[must_use]
    pub fn with_lock_time(mut self, lock_time: u64) -> Self {
        self.fallback_lock_time = Some(lock_time);
        self
    }
}

/// Complete typed plan for the browser PSKB wire envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PskbPlan {
    pub global: PskbGlobalPlan,
    pub inputs: Vec<PskbInputPlan>,
    pub outputs: Vec<PskbOutputPlan>,
}
