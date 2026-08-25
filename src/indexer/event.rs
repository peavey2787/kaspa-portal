use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexedTransaction {
    pub txid: String,
    pub block_hash: Option<String>,
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    pub daa_score: Option<u64>,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub observed_at_ms: u64,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub payload: Vec<u8>,
    #[serde(default)]
    pub raw: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexedBlock {
    pub hash: String,
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    pub daa_score: Option<u64>,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub observed_at_ms: u64,
    #[serde(default)]
    pub txids: Vec<String>,
    #[serde(default)]
    pub raw: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexedMatch {
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub matcher_id: u64,
    pub txid: String,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub observed_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IndexerEvent {
    Transaction {
        txid: String,
    },
    Block {
        hash: String,
    },
    Match {
        #[serde(with = "crate::primitives::serialization::decimal_u64")]
        matcher_id: u64,
        txid: String,
    },
    Evicted {
        eviction_kind: String,
        id: String,
    },
    Reconciled {
        removed_blocks: usize,
        accepted_blocks: usize,
    },
    Checkpoint {
        #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
        virtual_daa_score: Option<u64>,
        block_hash: Option<String>,
    },
}
