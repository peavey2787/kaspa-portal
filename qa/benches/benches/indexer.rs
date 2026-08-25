use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kaspa_portal::indexer::{IndexedTransaction, IndexerApi, IndexerConfig};

fn indexer_benches(c: &mut Criterion) {
    c.bench_function("indexer/ingest_transaction", |b| {
        let indexer = IndexerApi::with_clock(IndexerConfig::default(), || Ok(0)).unwrap();
        let mut id = 0u64;
        b.iter(|| {
            id = id.wrapping_add(1);
            indexer.ingest_transaction(IndexedTransaction {
                txid: format!("{id:064x}"),
                block_hash: None,
                daa_score: Some(id),
                observed_at_ms: id,
                addresses: Vec::new(),
                payload: black_box(vec![0x42; 32]),
                raw: serde_json::Value::Null,
            }).unwrap()
        });
    });
}

criterion_group!(benches, indexer_benches);
criterion_main!(benches);
