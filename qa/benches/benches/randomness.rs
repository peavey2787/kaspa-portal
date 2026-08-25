use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kaspa_portal::randomness::extractor::{extract_and_fold, ExtractorConfig};

fn randomness_benches(c: &mut Criterion) {
    let evidence = vec![0x5au8; 4096];
    c.bench_function("randomness/extract_and_fold", |b| {
        b.iter(|| {
            extract_and_fold(
                black_box(&evidence),
                black_box(b"benchmark-context"),
                ExtractorConfig::default(),
            ).unwrap()
        })
    });
}

criterion_group!(benches, randomness_benches);
criterion_main!(benches);
