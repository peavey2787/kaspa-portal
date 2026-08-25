#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = kaspa_portal::network::wrpc::validate_response(data);
});
