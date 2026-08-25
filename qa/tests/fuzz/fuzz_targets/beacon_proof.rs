#![no_main]
use libfuzzer_sys::fuzz_target;
use kaspa_portal::randomness::beacon::{verify_result, BeaconResult};
fuzz_target!(|data: &[u8]| if let Ok(value) = serde_json::from_slice::<BeaconResult>(data) { let _ = verify_result(&value); });
