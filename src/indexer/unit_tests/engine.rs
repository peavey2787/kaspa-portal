use super::*;
use crate::indexer::{config::IndexingMode, event::IndexedTransaction};

fn tx(id: &str, payload: &[u8]) -> IndexedTransaction {
    IndexedTransaction {
        txid: id.into(),
        block_hash: None,
        daa_score: None,
        observed_at_ms: 100,
        addresses: vec![],
        payload: payload.to_vec(),
        raw: serde_json::Value::Null,
    }
}

#[test]
fn matches_mode_keeps_only_matching_transactions() {
    let config = IndexerConfig {
        mode: IndexingMode::Matches,
        ..IndexerConfig::default()
    };
    let mut engine = IndexerEngine::new(config).unwrap();
    engine
        .add_matcher(MatchRule::PayloadPrefix(b"yes".to_vec()))
        .unwrap();
    engine.ingest_transaction(tx("no", b"other")).unwrap();
    engine.ingest_transaction(tx("yes", b"yes-value")).unwrap();
    assert!(engine.store().transaction("no").is_none());
    assert!(engine.store().transaction("yes").is_some());
    assert_eq!(engine.store().matches().len(), 1);
}

#[test]
fn block_mode_does_not_retain_transactions() {
    let config = IndexerConfig {
        mode: IndexingMode::Blocks,
        ..IndexerConfig::default()
    };
    let mut engine = IndexerEngine::new(config).unwrap();
    engine.ingest_transaction(tx("x", b"data")).unwrap();
    assert!(engine.store().transaction("x").is_none());
}

#[test]
fn recent_cache_deduplicates_even_when_transactions_are_not_retained() {
    let config = IndexerConfig {
        mode: IndexingMode::Blocks,
        ..IndexerConfig::default()
    };
    let mut engine = IndexerEngine::new(config).unwrap();
    engine.ingest_transaction(tx("x", b"data")).unwrap();
    engine.ingest_transaction(tx("x", b"data")).unwrap();
    assert_eq!(engine.metrics().duplicate_transactions, 1);
}

#[test]
fn running_scanner_health_becomes_stale() {
    let config = IndexerConfig {
        scanner_stale_after_ms: 10,
        ..IndexerConfig::default()
    };
    let mut engine = IndexerEngine::new(config).unwrap();
    engine.start(100);
    assert!(engine.health(110).scanner_healthy);
    assert!(!engine.health(111).scanner_healthy);
}

fn block(hash: &str) -> crate::indexer::IndexedBlock {
    crate::indexer::IndexedBlock {
        hash: hash.into(),
        daa_score: Some(10),
        observed_at_ms: 100,
        txids: Vec::new(),
        raw: serde_json::Value::Null,
    }
}

#[test]
fn persisted_state_restores_matchers_and_checkpoint() {
    let mut engine = IndexerEngine::new(IndexerConfig::default()).unwrap();
    let matcher = engine
        .add_matcher(MatchRule::PayloadPrefix(b"kp".to_vec()))
        .unwrap();
    engine
        .set_checkpoint(crate::indexer::sync::SyncCheckpoint {
            virtual_daa_score: Some(42),
            block_hash: Some("block-42".into()),
        })
        .unwrap();
    let state = engine.persisted_state();

    let mut restored = IndexerEngine::new(IndexerConfig::default()).unwrap();
    restored.restore_state(state).unwrap();
    assert_eq!(restored.checkpoint().virtual_daa_score, Some(42));
    assert!(restored.remove_matcher(matcher));
}

#[test]
fn reconciliation_removes_orphans_before_accepted_chain() {
    use crate::indexer::{
        scanner::BlockBatch,
        sync::{SyncCheckpoint, VirtualChainDelta},
    };
    let mut engine = IndexerEngine::new(IndexerConfig::default()).unwrap();
    engine.ingest_block(block("old")).unwrap();
    let mut orphan_tx = tx("orphan", b"old");
    orphan_tx.block_hash = Some("old".into());
    engine.ingest_transaction(orphan_tx).unwrap();

    let mut accepted_tx = tx("accepted", b"new");
    accepted_tx.block_hash = Some("new".into());
    let report = engine
        .reconcile_virtual_chain(VirtualChainDelta {
            removed_block_hashes: vec!["old".into()],
            accepted: vec![BlockBatch {
                block: block("new"),
                transactions: vec![accepted_tx],
            }],
            checkpoint: SyncCheckpoint {
                virtual_daa_score: Some(11),
                block_hash: Some("new".into()),
            },
        })
        .unwrap();

    assert_eq!(report.removed_blocks, 1);
    assert_eq!(report.removed_transactions, 1);
    assert_eq!(report.added_blocks, 1);
    assert!(engine.store().transaction("orphan").is_none());
    assert!(engine.store().transaction("accepted").is_some());
    assert_eq!(engine.checkpoint().block_hash.as_deref(), Some("new"));
}
