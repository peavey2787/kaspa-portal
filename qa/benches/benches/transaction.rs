use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use kaspa_portal::primitives::hash::blake2b_256;

fn transaction_benches(c: &mut Criterion) {
    let payload = vec![0x99u8; 4096];
    c.bench_function("transaction/blake2b_4k", |b| {
        b.iter(|| blake2b_256(black_box(&payload)))
    });
}

criterion_group!(benches, transaction_benches);
criterion_main!(benches);
