use serde::{Deserialize, Serialize};

use crate::indexer::{
    event::{IndexedBlock, IndexedMatch, IndexedTransaction},
    matcher::Matcher,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockBatch {
    pub block: IndexedBlock,
    #[serde(default)]
    pub transactions: Vec<IndexedTransaction>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockScanReport {
    pub block_hash: String,
    pub transactions_scanned: usize,
    pub matches: Vec<IndexedMatch>,
}

pub fn scan(transaction: &IndexedTransaction, matchers: &[Matcher]) -> Vec<IndexedMatch> {
    matchers
        .iter()
        .filter(|matcher| matcher.rule.matches(transaction))
        .map(|matcher| IndexedMatch {
            matcher_id: matcher.id,
            txid: transaction.txid.clone(),
            observed_at_ms: transaction.observed_at_ms,
        })
        .collect()
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
