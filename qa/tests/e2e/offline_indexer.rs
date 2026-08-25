use kaspa_portal::indexer::{
    query::{PageRequest, TransactionQuery},
    BlockBatch, IndexedBlock, IndexedTransaction, IndexerApi, IndexerConfig, MatchRule,
    SyncCheckpoint, VirtualChainDelta,
};
use serde_json::json;

fn block(hash: &str, score: u64) -> IndexedBlock {
    IndexedBlock {
        hash: hash.to_owned(),
        daa_score: Some(score),
        observed_at_ms: 100,
        txids: Vec::new(),
        raw: json!({"hash": hash, "daaScore": score.to_string()}),
    }
}

fn transaction(txid: &str, block_hash: Option<&str>, payload: &[u8]) -> IndexedTransaction {
    IndexedTransaction {
        txid: txid.to_owned(),
        block_hash: block_hash.map(str::to_owned),
        daa_score: Some(10),
        observed_at_ms: 100,
        addresses: vec!["kaspatest:e2e-address".into()],
        payload: payload.to_vec(),
        raw: json!({"transactionId": txid, "payload": hex::encode(payload)}),
    }
}

#[test]
#[ignore = "Pass 2 E2E: run through qa/scripts/run-e2e-rust"]
fn rust_offline_indexer() {
    let indexer = IndexerApi::with_clock(IndexerConfig::default(), || Ok(100))
        .expect("construct indexer");
    indexer.start().expect("start indexer");
    assert!(indexer.health().expect("health").running);

    let address_id = indexer
        .watch_address("kaspatest:e2e-address")
        .expect("address matcher");
    let prefix_id = indexer
        .watch_payload_prefix(b"portal".to_vec())
        .expect("prefix matcher");
    let contains_id = indexer
        .watch_payload_contains(b"e2e".to_vec())
        .expect("contains matcher");
    let exact_id = indexer
        .watch_payload_exact(b"portal-e2e-payload".to_vec())
        .expect("exact matcher");
    let suffix_id = indexer
        .watch_payload_suffix(b"payload".to_vec())
        .expect("suffix matcher");
    assert!(address_id < prefix_id && prefix_id < contains_id && contains_id < exact_id && exact_id < suffix_id);

    let generic_id = indexer
        .add_matcher(MatchRule::PayloadContains(b"remove-me".to_vec()))
        .expect("generic matcher");
    assert!(indexer.remove_matcher(generic_id).expect("remove matcher"));
    assert!(!indexer.remove_matcher(generic_id).expect("remove absent matcher"));

    let payload = b"portal-e2e-payload";
    let matches = indexer
        .ingest_transaction(transaction("tx-a", Some("block-a"), payload))
        .expect("ingest transaction");
    assert_eq!(matches.len(), 5);
    indexer.ingest_block(block("block-a", 10)).expect("ingest block");

    let report = indexer
        .ingest_block_batch(BlockBatch {
            block: block("block-b", 11),
            transactions: vec![transaction("tx-b", Some("block-b"), b"other")],
        })
        .expect("ingest block batch");
    assert_eq!(report.block_hash, "block-b");
    assert_eq!(report.transactions_scanned, 1);
    assert_eq!(report.matches.len(), 1);
    assert_eq!(report.matches[0].matcher_id, address_id);

    assert_eq!(
        indexer
            .transaction("tx-a")
            .expect("transaction lookup")
            .expect("stored transaction")
            .payload,
        payload
    );
    let tx_page = indexer
        .transactions(TransactionQuery {
            address: Some("kaspatest:e2e-address".into()),
            after_daa_score: Some(9),
            page: PageRequest { offset: 0, limit: 10 },
        })
        .expect("transaction query");
    assert_eq!(tx_page.total, 2);
    assert_eq!(indexer.blocks(PageRequest { offset: 0, limit: 10 }).expect("block page").total, 2);
    assert_eq!(
        indexer
            .matches(PageRequest { offset: 0, limit: 20 })
            .expect("match page")
            .total,
        6
    );

    let metrics = indexer.metrics().expect("metrics");
    assert_eq!(metrics.transactions, 2);
    assert_eq!(metrics.blocks, 2);
    assert_eq!(metrics.matches, 6);
    let health = indexer.health().expect("health after ingest");
    assert!(health.running);
    assert_eq!(health.transaction_count, 2);
    assert_eq!(health.matcher_count, 5);

    let snapshot = indexer.snapshot().expect("snapshot");
    assert_eq!(snapshot.transactions.len(), 2);
    indexer.clear().expect("clear before snapshot restore");
    assert!(indexer.transaction("tx-a").expect("post-clear lookup").is_none());
    indexer.restore_snapshot(snapshot).expect("restore snapshot");
    assert!(indexer.transaction("tx-a").expect("restored lookup").is_some());

    let checkpoint = SyncCheckpoint {
        virtual_daa_score: Some(11),
        block_hash: Some("block-b".into()),
    };
    indexer.set_checkpoint(checkpoint.clone()).expect("set checkpoint");
    assert_eq!(indexer.checkpoint().expect("checkpoint"), checkpoint);

    let state = indexer.persisted_state().expect("persisted state");
    indexer.clear().expect("clear before state restore");
    indexer.restore_state(state).expect("restore persisted state");
    assert_eq!(indexer.checkpoint().expect("restored checkpoint"), checkpoint);
    assert!(indexer.transaction("tx-a").expect("restored state lookup").is_some());

    let sync_checkpoint = SyncCheckpoint {
        virtual_daa_score: Some(12),
        block_hash: Some("block-c".into()),
    };
    let sync = indexer
        .apply_sync_batches(
            vec![BlockBatch {
                block: block("block-c", 12),
                transactions: vec![transaction("tx-c", Some("block-c"), b"sync")],
            }],
            sync_checkpoint.clone(),
        )
        .expect("apply sync batches");
    assert_eq!(sync.blocks_added, 1);
    assert_eq!(sync.transactions_added, 1);
    assert_eq!(sync.checkpoint, sync_checkpoint);

    let reconciliation = indexer
        .reconcile_virtual_chain(VirtualChainDelta {
            removed_block_hashes: vec!["block-c".into()],
            accepted: vec![BlockBatch {
                block: block("block-d", 13),
                transactions: vec![transaction("tx-d", Some("block-d"), b"reorg")],
            }],
            checkpoint: SyncCheckpoint {
                virtual_daa_score: Some(13),
                block_hash: Some("block-d".into()),
            },
        })
        .expect("virtual-chain reconciliation");
    assert_eq!(reconciliation.removed_blocks, 1);
    assert_eq!(reconciliation.removed_transactions, 1);
    assert_eq!(reconciliation.added_blocks, 1);
    assert_eq!(reconciliation.added_transactions, 1);
    assert!(indexer.transaction("tx-c").expect("removed tx lookup").is_none());
    assert!(indexer.transaction("tx-d").expect("accepted tx lookup").is_some());

    let events = indexer.drain_events().expect("drain events");
    assert!(!events.is_empty());
    assert!(indexer.drain_events().expect("second drain").is_empty());

    indexer.stop().expect("stop indexer");
    assert!(!indexer.health().expect("stopped health").running);
    indexer.clear().expect("final clear");
    let cleared = indexer.health().expect("cleared health");
    assert_eq!(cleared.transaction_count, 0);
    assert_eq!(cleared.block_count, 0);
    assert_eq!(cleared.match_count, 0);
}
