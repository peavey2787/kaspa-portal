use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kaspa_portal::primitives::address::{decode_address, encode_p2pk_address, validate_kaspa_address};

fn address_benches(c: &mut Criterion) {
    let pubkey = [0x42u8; 32];
    let address = encode_p2pk_address(&pubkey, "kaspa");
    c.bench_function("address/validate", |b| {
        b.iter(|| validate_kaspa_address(black_box(address.as_bytes())))
    });
    c.bench_function("address/decode", |b| {
        b.iter(|| decode_address(black_box(&address)).unwrap())
    });
}

criterion_group!(benches, address_benches);
criterion_main!(benches);
