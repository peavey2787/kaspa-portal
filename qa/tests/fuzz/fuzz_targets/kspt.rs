#![no_main]
use libfuzzer_sys::fuzz_target;
use kaspa_portal::transaction::{interchange::kspt::parse_compact_kspt, model::Transaction};

fuzz_target!(|data: &[u8]| {
    let mut transaction = Transaction::new();
    let _ = parse_compact_kspt(data, &mut transaction);
});
