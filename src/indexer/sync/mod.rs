use serde::{Deserialize, Serialize};

use crate::indexer::scanner::BlockBatch;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncCheckpoint {
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    pub virtual_daa_score: Option<u64>,
    pub block_hash: Option<String>,
}

impl SyncCheckpoint {
    pub fn validate(&self) -> Result<(), String> {
        if self
            .block_hash
            .as_ref()
            .is_some_and(|hash| hash.trim().is_empty())
        {
            return Err("checkpoint block hash cannot be empty".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncReport {
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub transactions_added: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub blocks_added: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub matches_added: u64,
    pub checkpoint: SyncCheckpoint,
}

/// Accepted-chain change delivered by a node after a virtual-chain update.
/// Removed block hashes are applied first; accepted blocks are then ingested in
/// ascending accepted-chain order.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VirtualChainDelta {
    #[serde(default)]
    pub removed_block_hashes: Vec<String>,
    #[serde(default)]
    pub accepted: Vec<BlockBatch>,
    pub checkpoint: SyncCheckpoint,
}

impl VirtualChainDelta {
    pub fn validate(&self) -> Result<(), String> {
        self.checkpoint.validate()?;
        if self
            .removed_block_hashes
            .iter()
            .any(|hash| hash.trim().is_empty())
        {
            return Err("virtual-chain delta contains an empty removed block hash".into());
        }
        if self.removed_block_hashes.len() > 100_000 || self.accepted.len() > 100_000 {
            return Err("virtual-chain delta exceeds hard safety bound".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReconciliationReport {
    pub removed_blocks: usize,
    pub removed_transactions: usize,
    pub removed_matches: usize,
    pub added_blocks: usize,
    pub added_transactions: usize,
    pub added_matches: usize,
    pub checkpoint: SyncCheckpoint,
}
