use sha2::{Digest, Sha256};

pub fn derive_positions(seed: &[u8], bit_len: usize, count: usize) -> Result<Vec<usize>, String> {
    validate_request(seed, bit_len, count)?;

    let mut positions = Vec::with_capacity(count);
    let mut counter = 0u32;
    while positions.len() < count {
        append_positions(seed, bit_len, count, counter, &mut positions);
        counter = counter.checked_add(1).ok_or("position counter exhausted")?;
    }
    Ok(positions)
}

fn validate_request(seed: &[u8], bit_len: usize, count: usize) -> Result<(), String> {
    if seed.is_empty() {
        return Err("position seed cannot be empty".into());
    }
    if bit_len == 0 {
        return Err("entropy bit length must be > 0".into());
    }
    if !(1..=4096).contains(&count) {
        return Err("position count must be 1..=4096".into());
    }
    Ok(())
}

fn append_positions(
    seed: &[u8],
    bit_len: usize,
    count: usize,
    counter: u32,
    positions: &mut Vec<usize>,
) {
    let mut hash = Sha256::new();
    hash.update(b"kaspa-portal/beacon/positions/v1\0");
    hash.update(seed);
    hash.update(counter.to_be_bytes());
    let digest = hash.finalize();

    for chunk in digest.chunks_exact(8) {
        if positions.len() == count {
            break;
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(chunk);
        positions.push((u64::from_be_bytes(bytes) % bit_len as u64) as usize);
    }
}
