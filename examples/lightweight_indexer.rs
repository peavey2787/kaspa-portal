use kaspa_portal::{indexer::event::IndexedTransaction, KaspaPortal, Result};

fn main() -> Result<()> {
    let portal = KaspaPortal::builder().build()?;
    let indexer = portal.indexer();
    indexer.start()?;
    indexer.watch_payload_prefix(b"KASPA".to_vec())?;
    indexer.ingest_transaction(IndexedTransaction {
        txid: "demo-tx".into(),
        block_hash: Some("demo-block".into()),
        daa_score: Some(42),
        observed_at_ms: 1,
        addresses: Vec::new(),
        payload: b"KASPA portal".to_vec(),
        raw: serde_json::Value::Null,
    })?;
    for event in indexer.drain_events()? {
        println!("{event:?}");
    }
    Ok(())
}
