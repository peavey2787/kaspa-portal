#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| { let _ = kaspa_portal::transaction::interchange::qr::parse_frame(data); });
