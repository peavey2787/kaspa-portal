#![no_main]

use kaspa_portal::transaction::{
    interchange::pskt::{shared::PsktParsed, standard::parse_pskt},
    model::Transaction,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut scratch = vec![0u8; data.len().saturating_add(1)];
    let mut transaction = Transaction::new();
    let mut parsed = PsktParsed::empty();
    let _ = parse_pskt(data, &mut scratch, &mut transaction, &mut parsed);
});
