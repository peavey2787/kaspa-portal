use std::sync::{Arc, Mutex};

use crate::{
    error::{Error, Result},
    indexer::{
        config::IndexerConfig,
        engine::IndexerEngine,
        event::{IndexedBlock, IndexedMatch, IndexedTransaction, IndexerEvent},
        matcher::MatchRule,
        metrics::{IndexerHealth, IndexerMetrics},
        query::{self, Page, PageRequest, TransactionQuery},
        scanner::{BlockBatch, BlockScanReport},
        storage::{IndexStore, IndexerPersistence, IndexerSnapshot, PersistedIndexerState},
        sync::{ReconciliationReport, SyncCheckpoint, SyncReport, VirtualChainDelta},
    },
};

#[derive(Clone)]
pub struct IndexerApi {
    inner: Arc<Mutex<IndexerEngine>>,
    now_ms: fn() -> core::result::Result<u64, String>,
}

impl IndexerApi {
    pub fn with_clock(
        config: IndexerConfig,
        now_ms: fn() -> core::result::Result<u64, String>,
    ) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(
                IndexerEngine::new(config).map_err(Error::Indexer)?,
            )),
            now_ms,
        })
    }

    fn with<T>(
        &self,
        action: impl FnOnce(&mut IndexerEngine) -> core::result::Result<T, String>,
    ) -> Result<T> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| Error::Indexer("indexer lock poisoned".into()))?;
        action(&mut guard).map_err(Error::Indexer)
    }

    fn with_atomic<T>(
        &self,
        action: impl FnOnce(&mut IndexerEngine) -> core::result::Result<T, String>,
    ) -> Result<T> {
        self.with(|engine| {
            let mut staged = engine.clone();
            let result = action(&mut staged)?;
            *engine = staged;
            Ok(result)
        })
    }

    fn with_fresh<T>(
        &self,
        action: impl FnOnce(&mut IndexerEngine) -> core::result::Result<T, String>,
    ) -> Result<T> {
        let now = (self.now_ms)().map_err(Error::Indexer)?;
        self.with(|engine| {
            engine.purge_expired(now);
            action(engine)
        })
    }

    pub fn start(&self) -> Result<()> {
        let now = (self.now_ms)().map_err(Error::Indexer)?;
        self.with(|engine| {
            engine.start(now);
            Ok(())
        })
    }

    pub fn stop(&self) -> Result<()> {
        self.with(|engine| {
            engine.stop();
            Ok(())
        })
    }

    pub fn watch_address(&self, address: impl Into<String>) -> Result<u64> {
        self.add_matcher(MatchRule::Address(address.into()))
    }

    pub fn watch_payload_prefix(&self, value: Vec<u8>) -> Result<u64> {
        self.add_matcher(MatchRule::PayloadPrefix(value))
    }

    pub fn watch_payload_contains(&self, value: Vec<u8>) -> Result<u64> {
        self.add_matcher(MatchRule::PayloadContains(value))
    }

    pub fn watch_payload_exact(&self, value: Vec<u8>) -> Result<u64> {
        self.add_matcher(MatchRule::PayloadExact(value))
    }

    pub fn watch_payload_suffix(&self, value: Vec<u8>) -> Result<u64> {
        self.add_matcher(MatchRule::PayloadSuffix(value))
    }

    pub fn add_matcher(&self, rule: MatchRule) -> Result<u64> {
        self.with(|engine| engine.add_matcher(rule))
    }

    pub fn remove_matcher(&self, id: u64) -> Result<bool> {
        self.with(|engine| Ok(engine.remove_matcher(id)))
    }

    pub fn ingest_transaction(&self, tx: IndexedTransaction) -> Result<Vec<IndexedMatch>> {
        self.with(|engine| engine.ingest_transaction(tx))
    }

    pub fn ingest_block(&self, block: IndexedBlock) -> Result<()> {
        self.with(|engine| engine.ingest_block(block))
    }

    pub fn ingest_block_batch(&self, batch: BlockBatch) -> Result<BlockScanReport> {
        self.with_atomic(|engine| {
            let block_hash = batch.block.hash.clone();
            let transactions_scanned = batch.transactions.len();
            engine.ingest_block(batch.block)?;
            let mut matches = Vec::new();
            for transaction in batch.transactions {
                matches.extend(engine.ingest_transaction(transaction)?);
            }
            Ok(BlockScanReport {
                block_hash,
                transactions_scanned,
                matches,
            })
        })
    }

    pub fn transaction(&self, txid: &str) -> Result<Option<IndexedTransaction>> {
        self.with_fresh(|engine| Ok(engine.store().transaction(txid)))
    }

    pub fn transactions(&self, query_value: TransactionQuery) -> Result<Page<IndexedTransaction>> {
        self.with_fresh(|engine| {
            let values = query::filter_transactions(engine.store().transactions(), &query_value);
            query::page(&values, query_value.page, engine.max_query_page())
        })
    }

    pub fn blocks(&self, page: PageRequest) -> Result<Page<IndexedBlock>> {
        self.with_fresh(|engine| {
            query::page(&engine.store().blocks(), page, engine.max_query_page())
        })
    }

    pub fn matches(&self, page: PageRequest) -> Result<Page<IndexedMatch>> {
        self.with_fresh(|engine| {
            query::page(&engine.store().matches(), page, engine.max_query_page())
        })
    }

    pub fn metrics(&self) -> Result<IndexerMetrics> {
        self.with_fresh(|engine| Ok(engine.metrics()))
    }

    pub fn health(&self) -> Result<IndexerHealth> {
        let now = (self.now_ms)().map_err(Error::Indexer)?;
        self.with(|engine| {
            engine.purge_expired(now);
            Ok(engine.health(now))
        })
    }

    pub fn snapshot(&self) -> Result<IndexerSnapshot> {
        self.with_fresh(|engine| Ok(engine.snapshot()))
    }

    pub fn restore_snapshot(&self, snapshot: IndexerSnapshot) -> Result<()> {
        self.with(|engine| engine.restore_snapshot(snapshot))
    }

    pub fn checkpoint(&self) -> Result<SyncCheckpoint> {
        self.with_fresh(|engine| Ok(engine.checkpoint()))
    }

    pub fn set_checkpoint(&self, checkpoint: SyncCheckpoint) -> Result<()> {
        self.with(|engine| engine.set_checkpoint(checkpoint))
    }

    pub fn persisted_state(&self) -> Result<PersistedIndexerState> {
        self.with_fresh(|engine| Ok(engine.persisted_state()))
    }

    pub fn restore_state(&self, state: PersistedIndexerState) -> Result<()> {
        self.with(|engine| engine.restore_state(state))
    }

    pub async fn save_to(&self, persistence: &impl IndexerPersistence) -> Result<()> {
        persistence.save_state(self.persisted_state()?).await
    }

    pub async fn restore_from(&self, persistence: &impl IndexerPersistence) -> Result<bool> {
        let Some(state) = persistence.load_state().await? else {
            return Ok(false);
        };
        self.restore_state(state)?;
        Ok(true)
    }

    pub async fn clear_persisted(&self, persistence: &impl IndexerPersistence) -> Result<()> {
        persistence.clear_state().await
    }

    pub fn apply_sync_batches(
        &self,
        batches: Vec<BlockBatch>,
        checkpoint: SyncCheckpoint,
    ) -> Result<SyncReport> {
        self.with_atomic(|engine| engine.apply_sync_batches(batches, checkpoint))
    }

    pub fn reconcile_virtual_chain(
        &self,
        delta: VirtualChainDelta,
    ) -> Result<ReconciliationReport> {
        self.with_atomic(|engine| engine.reconcile_virtual_chain(delta))
    }

    pub fn drain_events(&self) -> Result<Vec<IndexerEvent>> {
        self.with_fresh(|engine| Ok(engine.drain_events()))
    }

    pub fn clear(&self) -> Result<()> {
        self.with(|engine| {
            engine.clear();
            Ok(())
        })
    }
}

#[cfg(test)]
#[path = "unit-tests/facade.rs"]
mod unit_tests;
