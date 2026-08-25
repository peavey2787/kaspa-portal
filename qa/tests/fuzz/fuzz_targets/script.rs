#![no_main]

use kaspa_portal::contract::script::{extract_cltv_locktime, extract_csv_sequence};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = extract_cltv_locktime(data);
    let _ = extract_csv_sequence(data);
});
