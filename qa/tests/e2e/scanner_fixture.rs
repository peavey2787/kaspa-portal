//! A raw transaction carrying one scanner-visible preimage output.

pub fn raw_scanner_fixture(transaction_id: &[u8; 32], preimage: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(preimage.len() + 1);
    script.push(u8::try_from(preimage.len()).expect("small preimage"));
    script.extend_from_slice(preimage);
    let script_length = script.len().max(10);
    let mut raw = Vec::new();
    raw.extend_from_slice(&37u32.to_le_bytes());
    raw.push(1);
    raw.extend_from_slice(transaction_id);
    raw.extend_from_slice(&7u32.to_le_bytes());
    raw.extend_from_slice(
        &u32::try_from(script_length)
            .expect("small script")
            .to_le_bytes(),
    );
    raw.extend_from_slice(&script);
    raw.resize(raw.len() + script_length.saturating_sub(script.len()), 0);
    raw
}
