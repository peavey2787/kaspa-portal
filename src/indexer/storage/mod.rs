mod dedupe;
mod memory;

pub use dedupe::RecentKeys;
pub use memory::{IndexerSnapshot, MemoryStore, StoreEviction};

use core::{future::Future, pin::Pin};
use serde::{Deserialize, Serialize};

use crate::{
    error::Result,
    indexer::{
        event::{IndexedBlock, IndexedMatch, IndexedTransaction},
        matcher::Matcher,
        sync::SyncCheckpoint,
    },
};

pub const INDEXER_STATE_SCHEMA: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedIndexerState {
    pub schema: u32,
    pub snapshot: IndexerSnapshot,
    pub checkpoint: SyncCheckpoint,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
}

impl PersistedIndexerState {
    pub fn new(
        snapshot: IndexerSnapshot,
        checkpoint: SyncCheckpoint,
        matchers: Vec<Matcher>,
    ) -> Self {
        Self {
            schema: INDEXER_STATE_SCHEMA,
            snapshot,
            checkpoint,
            matchers,
        }
    }

    pub fn validate_schema(&self) -> Result<()> {
        if self.schema == INDEXER_STATE_SCHEMA {
            Ok(())
        } else {
            Err(crate::error::Error::Storage(format!(
                "unsupported indexer state schema {} (expected {})",
                self.schema, INDEXER_STATE_SCHEMA
            )))
        }
    }
}

pub type PersistenceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

/// Platform-neutral durable storage contract for indexer state.
///
/// The core indexer only exchanges owned, versioned Rust data. Browser-specific
/// IndexedDB objects and native filesystem/database handles stay in platform
/// adapters and never leak into the engine.
pub trait IndexerPersistence {
    fn load_state(&self) -> PersistenceFuture<'_, Option<PersistedIndexerState>>;
    fn save_state(&self, state: PersistedIndexerState) -> PersistenceFuture<'_, ()>;
    fn clear_state(&self) -> PersistenceFuture<'_, ()>;
}

pub trait IndexStore {
    fn insert_transaction(&mut self, value: IndexedTransaction) -> bool;
    fn insert_block(&mut self, value: IndexedBlock) -> bool;
    fn insert_match(&mut self, value: IndexedMatch);
    fn transaction(&self, txid: &str) -> Option<IndexedTransaction>;
    fn transactions(&self) -> Vec<IndexedTransaction>;
    fn blocks(&self) -> Vec<IndexedBlock>;
    fn matches(&self) -> Vec<IndexedMatch>;
    fn counts(&self) -> (usize, usize, usize);
    fn clear(&mut self);
}
