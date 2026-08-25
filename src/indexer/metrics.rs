use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexerMetrics {
    /// Retained records, not merely observed stream items.
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub transactions: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub blocks: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub matches: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub transactions_observed: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub blocks_observed: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub matches_observed: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub duplicate_transactions: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub cache_hits: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub cache_misses: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub evictions: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub ttl_evictions: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub size_evictions: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub rejected_records: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexerHealth {
    pub running: bool,
    pub scanner_healthy: bool,
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    pub last_block_at_ms: Option<u64>,
    pub transaction_count: usize,
    pub block_count: usize,
    pub match_count: usize,
    pub matcher_count: usize,
}
