use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kaspa_portal::transaction::sighash::blake2b_hash;

fn transaction_benches(c: &mut Criterion) {
    let payload = vec![0x99u8; 4096];
    c.bench_function("transaction/blake2b_4k", |b| {
        b.iter(|| blake2b_hash(black_box(&payload)))
    });
}

criterion_group!(benches, transaction_benches);
criterion_main!(benches);
