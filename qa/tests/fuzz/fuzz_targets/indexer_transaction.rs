#![no_main]
use libfuzzer_sys::fuzz_target;
use kaspa_portal::indexer::{IndexedTransaction, IndexerApi, IndexerConfig};
fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = serde_json::from_slice::<IndexedTransaction>(data) {
        if let Ok(indexer) = IndexerApi::with_clock(IndexerConfig::default(), || Ok(0)) { let _ = indexer.ingest_transaction(tx); }
    }
});
