use crate::primitives::{BlockHash, DaaScore};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub hash: BlockHash,
    pub daa_score: DaaScore,
    pub timestamp: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transaction_ids: Vec<crate::primitives::TxId>,
}
