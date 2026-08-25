#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // PSKB/PSKT wire APIs accept hexadecimal text. Hex-encoding arbitrary
    // fuzzer bytes keeps every byte representable while still exercising the
    // full envelope detection, JSON/schema parser, and review path.
    let wire = hex::encode(data);
    let _ = kaspa_portal::transaction::interchange::pskt::parse_summary(&wire, "kaspa");
});
