pub mod config;
pub(crate) mod engine;
pub mod event;
pub mod facade;
pub mod matcher;
pub mod metrics;
pub mod query;
pub mod scanner;
pub mod storage;
pub mod sync;

pub use config::{IndexerConfig, IndexingMode};
pub use event::{IndexedBlock, IndexedMatch, IndexedTransaction, IndexerEvent};
pub use facade::IndexerApi;
pub use matcher::{MatchRule, Matcher};
pub use scanner::{BlockBatch, BlockScanReport};

pub use storage::{IndexerPersistence, PersistedIndexerState, INDEXER_STATE_SCHEMA};
pub use sync::{ReconciliationReport, SyncCheckpoint, SyncReport, VirtualChainDelta};
