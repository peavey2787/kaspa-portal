#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let wire = hex::encode(data);
    let _ = kaspa_portal::transaction::consensus::decode_signed_kspt(&wire);
});
