#![no_main]
use kaspa_portal::transaction::interchange::{kspt::wire::Limits, pskt::pipeline};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(verified) = pipeline::verify_complete_kspt(data, Limits::grammar()) {
        let _ = verified.to_consensus();
    }
});
