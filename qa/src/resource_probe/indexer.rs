use std::hint::black_box;

use kaspa_portal::indexer::{IndexedTransaction, IndexerApi, IndexerConfig};
use serde_json::json;

pub fn run(iteration: usize) -> Result<(), String> {
    let indexer = IndexerApi::with_clock(IndexerConfig::default(), || Ok(100))
        .map_err(|error| error.to_string())?;
    indexer.start().map_err(|error| error.to_string())?;
    indexer
        .watch_payload_contains(b"resource".to_vec())
        .map_err(|error| error.to_string())?;
    for item in 0..16usize {
        let txid = format!("resource-{iteration}-{item}");
        indexer
            .ingest_transaction(IndexedTransaction {
                txid,
                block_hash: None,
                daa_score: Some(item as u64),
                observed_at_ms: 100,
                addresses: vec!["kaspatest:resource".into()],
                payload: format!("resource-{item}").into_bytes(),
                raw: json!({"iteration": iteration, "item": item}),
            })
            .map_err(|error| error.to_string())?;
    }
    let snapshot = indexer.snapshot().map_err(|error| error.to_string())?;
    let metrics = indexer.metrics().map_err(|error| error.to_string())?;
    indexer.clear().map_err(|error| error.to_string())?;
    indexer
        .restore_snapshot(snapshot)
        .map_err(|error| error.to_string())?;
    let events = indexer.drain_events().map_err(|error| error.to_string())?;
    indexer.stop().map_err(|error| error.to_string())?;
    indexer.clear().map_err(|error| error.to_string())?;
    black_box((metrics.transactions, events.len()));
    Ok(())
}
