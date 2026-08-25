use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::indexer::{
    config::IndexerConfig,
    event::{IndexedBlock, IndexedMatch, IndexedTransaction},
};

use super::IndexStore;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IndexerSnapshot {
    pub transactions: Vec<IndexedTransaction>,
    pub blocks: Vec<IndexedBlock>,
    pub matches: Vec<IndexedMatch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreEviction {
    pub kind: &'static str,
    pub id: String,
}

#[derive(Clone)]
pub struct MemoryStore {
    config: IndexerConfig,
    tx: HashMap<String, IndexedTransaction>,
    tx_order: VecDeque<String>,
    blocks: HashMap<String, IndexedBlock>,
    block_order: VecDeque<String>,
    matches: VecDeque<IndexedMatch>,
    pending_evictions: Vec<StoreEviction>,
}

impl MemoryStore {
    pub fn new(config: IndexerConfig) -> Self {
        Self {
            config,
            tx: HashMap::new(),
            tx_order: VecDeque::new(),
            blocks: HashMap::new(),
            block_order: VecDeque::new(),
            matches: VecDeque::new(),
            pending_evictions: Vec::new(),
        }
    }

    pub fn snapshot(&self) -> IndexerSnapshot {
        IndexerSnapshot {
            transactions: self.transactions(),
            blocks: self.blocks(),
            matches: self.matches(),
        }
    }

    pub fn restore(config: IndexerConfig, snapshot: IndexerSnapshot) -> Self {
        let mut store = Self::new(config);
        for value in snapshot.transactions {
            store.insert_transaction(value);
        }
        for value in snapshot.blocks {
            store.insert_block(value);
        }
        for value in snapshot.matches {
            store.insert_match(value);
        }
        store.pending_evictions.clear();
        store
    }

    pub fn purge_expired(&mut self, now_ms: u64) -> Vec<String> {
        let ttl = self.config.transaction_ttl_ms;
        if ttl == 0 {
            return Vec::new();
        }
        let mut expired = Vec::new();
        while let Some(id) = self.tx_order.front().cloned() {
            let Some(transaction) = self.tx.get(&id) else {
                self.tx_order.pop_front();
                continue;
            };
            if now_ms.saturating_sub(transaction.observed_at_ms) <= ttl {
                break;
            }
            self.tx_order.pop_front();
            self.tx.remove(&id);
            expired.push(id);
        }
        remove_matches_for_transactions(&mut self.matches, &expired);
        expired
    }

    pub fn remove_chain_blocks(
        &mut self,
        removed_hashes: &HashSet<String>,
    ) -> (usize, usize, usize) {
        if removed_hashes.is_empty() {
            return (0, 0, 0);
        }
        let before_blocks = self.blocks.len();
        let before_transactions = self.tx.len();
        let before_matches = self.matches.len();

        self.blocks.retain(|hash, _| !removed_hashes.contains(hash));
        self.block_order
            .retain(|hash| !removed_hashes.contains(hash));

        let removed_txids = self
            .tx
            .iter()
            .filter_map(|(txid, tx)| {
                tx.block_hash
                    .as_ref()
                    .filter(|hash| removed_hashes.contains(*hash))
                    .map(|_| txid.clone())
            })
            .collect::<HashSet<_>>();
        self.tx.retain(|txid, _| !removed_txids.contains(txid));
        self.tx_order.retain(|txid| !removed_txids.contains(txid));
        self.matches
            .retain(|item| !removed_txids.contains(&item.txid));

        (
            before_blocks - self.blocks.len(),
            before_transactions - self.tx.len(),
            before_matches - self.matches.len(),
        )
    }

    pub fn max_query_page(&self) -> usize {
        self.config.max_query_page
    }

    pub fn take_evictions(&mut self) -> Vec<StoreEviction> {
        core::mem::take(&mut self.pending_evictions)
    }

    fn trim_transactions(&mut self) {
        while self.tx.len() > self.config.max_transactions {
            let Some(id) = self.tx_order.pop_front() else {
                break;
            };
            self.tx.remove(&id);
            self.matches.retain(|value| value.txid != id);
            self.pending_evictions.push(StoreEviction {
                kind: "transaction_size",
                id,
            });
        }
    }

    fn trim_blocks(&mut self) {
        while self.blocks.len() > self.config.max_blocks {
            let Some(id) = self.block_order.pop_front() else {
                break;
            };
            self.blocks.remove(&id);
            self.pending_evictions.push(StoreEviction {
                kind: "block_size",
                id,
            });
        }
    }

    fn trim_matches(&mut self) {
        while self.matches.len() > self.config.max_matches {
            let Some(value) = self.matches.pop_front() else {
                break;
            };
            self.pending_evictions.push(StoreEviction {
                kind: "match_size",
                id: format!("{}:{}", value.matcher_id, value.txid),
            });
        }
    }
}

impl IndexStore for MemoryStore {
    fn insert_transaction(&mut self, value: IndexedTransaction) -> bool {
        if self.tx.contains_key(&value.txid) {
            return false;
        }
        let id = value.txid.clone();
        self.tx.insert(id.clone(), value);
        self.tx_order.push_back(id);
        self.trim_transactions();
        true
    }

    fn insert_block(&mut self, value: IndexedBlock) -> bool {
        let id = value.hash.clone();
        if self.blocks.contains_key(&id) {
            return false;
        }
        self.block_order.push_back(id.clone());
        self.blocks.insert(id, value);
        self.trim_blocks();
        true
    }

    fn insert_match(&mut self, value: IndexedMatch) {
        self.matches.push_back(value);
        self.trim_matches();
    }

    fn transaction(&self, txid: &str) -> Option<IndexedTransaction> {
        self.tx.get(txid).cloned()
    }

    fn transactions(&self) -> Vec<IndexedTransaction> {
        self.tx_order
            .iter()
            .filter_map(|id| self.tx.get(id).cloned())
            .collect()
    }

    fn blocks(&self) -> Vec<IndexedBlock> {
        self.block_order
            .iter()
            .filter_map(|id| self.blocks.get(id).cloned())
            .collect()
    }

    fn matches(&self) -> Vec<IndexedMatch> {
        self.matches.iter().cloned().collect()
    }

    fn counts(&self) -> (usize, usize, usize) {
        (self.tx.len(), self.blocks.len(), self.matches.len())
    }

    fn clear(&mut self) {
        self.tx.clear();
        self.tx_order.clear();
        self.blocks.clear();
        self.block_order.clear();
        self.matches.clear();
        self.pending_evictions.clear();
    }
}

fn remove_matches_for_transactions(matches: &mut VecDeque<IndexedMatch>, ids: &[String]) {
    if ids.is_empty() {
        return;
    }
    let ids: HashSet<&str> = ids.iter().map(String::as_str).collect();
    matches.retain(|value| !ids.contains(value.txid.as_str()));
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
