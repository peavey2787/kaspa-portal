use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kaspa_portal::wallet::derivation::bip32::derive_account_key;

fn wallet_benches(c: &mut Criterion) {
    let seed = [0x24u8; 64];
    c.bench_function("wallet/derive_account_key", |b| {
        b.iter(|| derive_account_key(black_box(&seed)).unwrap())
    });
}

criterion_group!(benches, wallet_benches);
criterion_main!(benches);
