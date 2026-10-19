#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| kaspa_portal_fuzz::qr_frame(data));
