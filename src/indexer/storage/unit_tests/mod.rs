use super::*;
use crate::indexer::storage::IndexStore;
use crate::indexer::{config::IndexerConfig, event::IndexedTransaction};

fn tx(id: &str) -> IndexedTransaction {
    IndexedTransaction {
        txid: id.into(),
        block_hash: None,
        daa_score: None,
        observed_at_ms: 0,
        addresses: vec![],
        payload: vec![],
        raw: serde_json::Value::Null,
    }
}

#[test]
fn deduplicates_txids() {
    let mut store = MemoryStore::new(IndexerConfig::default());
    assert!(store.insert_transaction(tx("x")));
    assert!(!store.insert_transaction(tx("x")));
}

#[test]
fn evicts_oldest_at_bound_and_reports_size_reason() {
    let config = IndexerConfig {
        max_transactions: 1,
        ..IndexerConfig::default()
    };
    let mut store = MemoryStore::new(config);
    store.insert_transaction(tx("a"));
    store.insert_transaction(tx("b"));
    assert!(store.transaction("a").is_none());
    assert!(store.transaction("b").is_some());
    let evictions = store.take_evictions();
    assert_eq!(evictions.len(), 1);
    assert_eq!(evictions[0].kind, "transaction_size");
    assert_eq!(evictions[0].id, "a");
}
