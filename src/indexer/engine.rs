use std::collections::{HashMap, HashSet};

use crate::indexer::{
    config::IndexerConfig,
    event::{IndexedBlock, IndexedMatch, IndexedTransaction, IndexerEvent},
    matcher::{MatchRule, Matcher},
    metrics::{IndexerHealth, IndexerMetrics},
    scanner,
    storage::{IndexStore, IndexerSnapshot, MemoryStore, PersistedIndexerState, RecentKeys},
    sync::{ReconciliationReport, SyncCheckpoint, SyncReport, VirtualChainDelta},
};

#[derive(Clone)]
pub struct IndexerEngine {
    config: IndexerConfig,
    store: MemoryStore,
    recent_txids: RecentKeys,
    matchers: HashMap<u64, Matcher>,
    next_matcher_id: u64,
    running: bool,
    last_block_at_ms: Option<u64>,
    metrics: IndexerMetrics,
    checkpoint: SyncCheckpoint,
    events: Vec<IndexerEvent>,
}

impl IndexerEngine {
    pub fn new(config: IndexerConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            store: MemoryStore::new(config.clone()),
            recent_txids: RecentKeys::new(config.dedupe_window),
            config,
            matchers: HashMap::new(),
            next_matcher_id: 1,
            running: false,
            last_block_at_ms: None,
            metrics: IndexerMetrics::default(),
            checkpoint: SyncCheckpoint::default(),
            events: Vec::new(),
        })
    }

    pub fn start(&mut self, now_ms: u64) {
        self.running = true;
        self.last_block_at_ms.get_or_insert(now_ms);
    }

    pub fn stop(&mut self) {
        self.running = false;
    }

    pub fn add_matcher(&mut self, rule: MatchRule) -> Result<u64, String> {
        rule.validate()?;
        if self.matchers.len() >= 4096 {
            return Err("matcher limit reached".into());
        }
        let id = self.next_matcher_id;
        self.next_matcher_id = self
            .next_matcher_id
            .checked_add(1)
            .ok_or("matcher id exhausted")?;
        self.matchers.insert(id, Matcher { id, rule });
        Ok(id)
    }

    pub fn remove_matcher(&mut self, id: u64) -> bool {
        self.matchers.remove(&id).is_some()
    }

    pub fn ingest_transaction(
        &mut self,
        tx: IndexedTransaction,
    ) -> Result<Vec<IndexedMatch>, String> {
        if let Err(error) = validate_transaction(&self.config, &tx) {
            self.metrics.rejected_records = self.metrics.rejected_records.saturating_add(1);
            return Err(error);
        }
        self.metrics.transactions_observed = self.metrics.transactions_observed.saturating_add(1);
        self.purge_expired(tx.observed_at_ms);
        if !self.recent_txids.observe(&tx.txid) {
            self.metrics.duplicate_transactions =
                self.metrics.duplicate_transactions.saturating_add(1);
            self.metrics.cache_hits = self.metrics.cache_hits.saturating_add(1);
            return Ok(Vec::new());
        }
        self.metrics.cache_misses = self.metrics.cache_misses.saturating_add(1);

        let matchers: Vec<Matcher> = self.matchers.values().cloned().collect();
        let matches = scanner::scan(&tx, &matchers);
        let is_match = !matches.is_empty();
        self.metrics.matches_observed = self
            .metrics
            .matches_observed
            .saturating_add(matches.len() as u64);

        self.retain_transaction(&tx, is_match);
        self.publish_matches(&matches);
        self.record_size_evictions();
        Ok(matches)
    }

    pub fn ingest_block(&mut self, block: IndexedBlock) -> Result<(), String> {
        if block.hash.trim().is_empty() {
            self.metrics.rejected_records = self.metrics.rejected_records.saturating_add(1);
            return Err("block hash cannot be empty".into());
        }
        self.metrics.blocks_observed = self.metrics.blocks_observed.saturating_add(1);
        self.purge_expired(block.observed_at_ms);
        self.last_block_at_ms = Some(block.observed_at_ms);
        let hash = block.hash.clone();
        if self.config.mode.retains_blocks() && self.store.insert_block(block) {
            self.metrics.blocks = self.metrics.blocks.saturating_add(1);
        }
        self.events.push(IndexerEvent::Block { hash });
        self.record_size_evictions();
        Ok(())
    }

    pub fn purge_expired(&mut self, now_ms: u64) {
        for id in self.store.purge_expired(now_ms) {
            self.metrics.evictions = self.metrics.evictions.saturating_add(1);
            self.metrics.ttl_evictions = self.metrics.ttl_evictions.saturating_add(1);
            self.events.push(IndexerEvent::Evicted {
                eviction_kind: "transaction_ttl".into(),
                id,
            });
        }
    }

    pub fn store(&self) -> &MemoryStore {
        &self.store
    }

    pub fn max_query_page(&self) -> usize {
        self.store.max_query_page()
    }

    pub fn metrics(&self) -> IndexerMetrics {
        self.metrics
    }

    pub fn health(&self, now_ms: u64) -> IndexerHealth {
        let (transaction_count, block_count, match_count) = self.store.counts();
        IndexerHealth {
            running: self.running,
            scanner_healthy: scanner_is_healthy(
                self.running,
                self.last_block_at_ms,
                now_ms,
                self.config.scanner_stale_after_ms,
            ),
            last_block_at_ms: self.last_block_at_ms,
            transaction_count,
            block_count,
            match_count,
            matcher_count: self.matchers.len(),
        }
    }

    pub fn snapshot(&self) -> IndexerSnapshot {
        self.store.snapshot()
    }

    pub fn checkpoint(&self) -> SyncCheckpoint {
        self.checkpoint.clone()
    }

    pub fn set_checkpoint(&mut self, checkpoint: SyncCheckpoint) -> Result<(), String> {
        checkpoint.validate()?;
        self.checkpoint = checkpoint.clone();
        self.events.push(IndexerEvent::Checkpoint {
            virtual_daa_score: checkpoint.virtual_daa_score,
            block_hash: checkpoint.block_hash,
        });
        Ok(())
    }

    pub fn persisted_state(&self) -> PersistedIndexerState {
        let mut matchers: Vec<_> = self.matchers.values().cloned().collect();
        matchers.sort_by_key(|matcher| matcher.id);
        PersistedIndexerState::new(self.snapshot(), self.checkpoint.clone(), matchers)
    }

    pub fn restore_state(&mut self, state: PersistedIndexerState) -> Result<(), String> {
        state.validate_schema().map_err(|error| error.to_string())?;
        state.checkpoint.validate()?;
        validate_matchers(&state.matchers)?;
        validate_snapshot(&self.config, &state.snapshot)?;

        self.store = MemoryStore::restore(self.config.clone(), state.snapshot);
        self.matchers = state
            .matchers
            .into_iter()
            .map(|matcher| (matcher.id, matcher))
            .collect();
        self.next_matcher_id = next_matcher_id(&self.matchers)?;
        self.checkpoint = state.checkpoint;
        self.rebuild_runtime_state();
        self.events.clear();
        Ok(())
    }

    pub fn apply_sync_batches(
        &mut self,
        batches: Vec<crate::indexer::scanner::BlockBatch>,
        checkpoint: SyncCheckpoint,
    ) -> Result<SyncReport, String> {
        checkpoint.validate()?;
        if batches.len() > 100_000 {
            return Err("sync batch count exceeds hard safety bound".into());
        }
        let before = self.store.counts();
        let mut matches_added = 0u64;
        for batch in batches {
            self.ingest_block(batch.block)?;
            for transaction in batch.transactions {
                matches_added = matches_added
                    .saturating_add(self.ingest_transaction(transaction)?.len() as u64);
            }
        }
        let after = self.store.counts();
        self.set_checkpoint(checkpoint.clone())?;
        Ok(SyncReport {
            transactions_added: after.0.saturating_sub(before.0) as u64,
            blocks_added: after.1.saturating_sub(before.1) as u64,
            matches_added,
            checkpoint,
        })
    }

    pub fn reconcile_virtual_chain(
        &mut self,
        delta: VirtualChainDelta,
    ) -> Result<ReconciliationReport, String> {
        delta.validate()?;
        let removed_hashes = delta
            .removed_block_hashes
            .into_iter()
            .collect::<HashSet<_>>();
        let (removed_blocks, removed_transactions, removed_matches) =
            self.store.remove_chain_blocks(&removed_hashes);
        self.metrics.blocks = self.metrics.blocks.saturating_sub(removed_blocks as u64);
        self.metrics.transactions = self
            .metrics
            .transactions
            .saturating_sub(removed_transactions as u64);
        self.metrics.matches = self.metrics.matches.saturating_sub(removed_matches as u64);
        self.rebuild_recent_txids();

        let mut added_blocks = 0usize;
        let mut added_transactions = 0usize;
        let mut added_matches = 0usize;
        for batch in delta.accepted {
            let before = self.store.counts();
            self.ingest_block(batch.block)?;
            for transaction in batch.transactions {
                added_matches =
                    added_matches.saturating_add(self.ingest_transaction(transaction)?.len());
            }
            let after = self.store.counts();
            added_transactions =
                added_transactions.saturating_add(after.0.saturating_sub(before.0));
            added_blocks = added_blocks.saturating_add(after.1.saturating_sub(before.1));
        }

        let checkpoint = delta.checkpoint;
        self.set_checkpoint(checkpoint.clone())?;
        self.events.push(IndexerEvent::Reconciled {
            removed_blocks,
            accepted_blocks: added_blocks,
        });
        Ok(ReconciliationReport {
            removed_blocks,
            removed_transactions,
            removed_matches,
            added_blocks,
            added_transactions,
            added_matches,
            checkpoint,
        })
    }

    pub fn restore_snapshot(&mut self, snapshot: IndexerSnapshot) -> Result<(), String> {
        validate_snapshot(&self.config, &snapshot)?;
        self.store = MemoryStore::restore(self.config.clone(), snapshot);
        self.rebuild_runtime_state();
        self.events.clear();
        Ok(())
    }

    pub fn drain_events(&mut self) -> Vec<IndexerEvent> {
        core::mem::take(&mut self.events)
    }

    pub fn clear(&mut self) {
        self.store.clear();
        self.recent_txids.clear();
        self.events.clear();
        self.metrics = IndexerMetrics::default();
        self.checkpoint = SyncCheckpoint::default();
        self.last_block_at_ms = None;
    }

    fn rebuild_runtime_state(&mut self) {
        self.rebuild_recent_txids();
        let (transactions, blocks, matches) = self.store.counts();
        self.metrics = IndexerMetrics {
            transactions: transactions as u64,
            blocks: blocks as u64,
            matches: matches as u64,
            ..IndexerMetrics::default()
        };
        self.last_block_at_ms = self.store.blocks().last().map(|block| block.observed_at_ms);
    }

    fn rebuild_recent_txids(&mut self) {
        self.recent_txids.clear();
        for tx in self.store.transactions() {
            self.recent_txids.observe(&tx.txid);
        }
    }

    fn retain_transaction(&mut self, tx: &IndexedTransaction, is_match: bool) {
        if !self.config.mode.retains_transaction(is_match) {
            return;
        }
        if self.store.insert_transaction(tx.clone()) {
            self.metrics.transactions = self.metrics.transactions.saturating_add(1);
            self.events.push(IndexerEvent::Transaction {
                txid: tx.txid.clone(),
            });
        } else {
            self.metrics.duplicate_transactions =
                self.metrics.duplicate_transactions.saturating_add(1);
        }
    }

    fn publish_matches(&mut self, matches: &[IndexedMatch]) {
        for item in matches {
            if self.config.mode.retains_matches() {
                self.store.insert_match(item.clone());
                self.metrics.matches = self.metrics.matches.saturating_add(1);
            }
            self.events.push(IndexerEvent::Match {
                matcher_id: item.matcher_id,
                txid: item.txid.clone(),
            });
        }
    }

    fn record_size_evictions(&mut self) {
        for eviction in self.store.take_evictions() {
            self.metrics.evictions = self.metrics.evictions.saturating_add(1);
            self.metrics.size_evictions = self.metrics.size_evictions.saturating_add(1);
            self.events.push(IndexerEvent::Evicted {
                eviction_kind: eviction.kind.into(),
                id: eviction.id,
            });
        }
    }
}

fn validate_matchers(matchers: &[Matcher]) -> Result<(), String> {
    if matchers.len() > 4096 {
        return Err("persisted matcher count exceeds 4096".into());
    }
    let mut ids = HashSet::with_capacity(matchers.len());
    for matcher in matchers {
        matcher.rule.validate()?;
        if matcher.id == 0 || !ids.insert(matcher.id) {
            return Err("persisted matcher ids must be non-zero and unique".into());
        }
    }
    Ok(())
}

fn next_matcher_id(matchers: &HashMap<u64, Matcher>) -> Result<u64, String> {
    matchers
        .keys()
        .copied()
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| "matcher id exhausted".into())
}

fn scanner_is_healthy(
    running: bool,
    last_block_at_ms: Option<u64>,
    now_ms: u64,
    stale_after_ms: u64,
) -> bool {
    if !running {
        return true;
    }
    last_block_at_ms
        .map(|last| now_ms.saturating_sub(last) <= stale_after_ms)
        .unwrap_or(false)
}

fn validate_snapshot(config: &IndexerConfig, snapshot: &IndexerSnapshot) -> Result<(), String> {
    for tx in &snapshot.transactions {
        validate_transaction(config, tx)?;
    }
    if snapshot
        .blocks
        .iter()
        .any(|block| block.hash.trim().is_empty())
    {
        return Err("snapshot contains an empty block hash".into());
    }
    Ok(())
}

fn validate_transaction(config: &IndexerConfig, tx: &IndexedTransaction) -> Result<(), String> {
    if tx.txid.trim().is_empty() {
        return Err("transaction id cannot be empty".into());
    }
    if tx.payload.len() > config.max_payload_bytes {
        return Err("transaction payload exceeds configured bound".into());
    }
    if tx.addresses.len() > config.max_addresses_per_transaction {
        return Err("transaction address count exceeds configured bound".into());
    }
    if tx.addresses.iter().any(|address| address.len() > 256) {
        return Err("indexed address exceeds 256 bytes".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "unit-tests/engine.rs"]
mod unit_tests;
