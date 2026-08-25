use super::*;
use crate::indexer::{
    event::{IndexedBlock, IndexedTransaction},
    scanner::BlockBatch,
    sync::{SyncCheckpoint, VirtualChainDelta},
};

fn api() -> IndexerApi {
    IndexerApi::with_clock(IndexerConfig::default(), || Ok(100)).unwrap()
}

fn block(hash: &str) -> IndexedBlock {
    IndexedBlock {
        hash: hash.into(),
        daa_score: Some(10),
        observed_at_ms: 100,
        txids: Vec::new(),
        raw: serde_json::Value::Null,
    }
}

fn tx(txid: &str, block_hash: Option<&str>) -> IndexedTransaction {
    IndexedTransaction {
        txid: txid.into(),
        block_hash: block_hash.map(str::to_owned),
        daa_score: Some(10),
        observed_at_ms: 100,
        addresses: Vec::new(),
        payload: Vec::new(),
        raw: serde_json::Value::Null,
    }
}

#[test]
fn block_batch_is_atomic_when_a_transaction_is_invalid() {
    let indexer = api();
    let mut invalid = tx("", Some("new"));
    invalid.payload = vec![0x42; 4];
    let result = indexer.ingest_block_batch(BlockBatch {
        block: block("new"),
        transactions: vec![tx("ok", Some("new")), invalid],
    });
    assert!(result.is_err());
    assert_eq!(indexer.health().unwrap().block_count, 0);
    assert!(indexer.transaction("ok").unwrap().is_none());
}

#[test]
fn virtual_chain_reconciliation_rolls_back_on_invalid_accepted_batch() {
    let indexer = api();
    indexer.ingest_block(block("old")).unwrap();
    indexer
        .ingest_transaction(tx("old-tx", Some("old")))
        .unwrap();
    indexer
        .set_checkpoint(SyncCheckpoint {
            virtual_daa_score: Some(9),
            block_hash: Some("old".into()),
        })
        .unwrap();

    let delta = VirtualChainDelta {
        removed_block_hashes: vec!["old".into()],
        accepted: vec![BlockBatch {
            block: block("new"),
            transactions: vec![tx("", Some("new"))],
        }],
        checkpoint: SyncCheckpoint {
            virtual_daa_score: Some(10),
            block_hash: Some("new".into()),
        },
    };
    assert!(indexer.reconcile_virtual_chain(delta).is_err());
    assert!(indexer.transaction("old-tx").unwrap().is_some());
    assert_eq!(
        indexer.checkpoint().unwrap().block_hash.as_deref(),
        Some("old")
    );
    assert_eq!(indexer.health().unwrap().block_count, 1);
}
