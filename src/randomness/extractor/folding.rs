use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::derive_positions;

const MAX_CONTEXT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtractorConfig {
    pub positions: u16,
    pub folding_rounds: u8,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            positions: 256,
            folding_rounds: 3,
        }
    }
}

impl ExtractorConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(8..=4096).contains(&self.positions) {
            return Err("extractor positions must be 8..=4096".into());
        }
        if !(1..=16).contains(&self.folding_rounds) {
            return Err("folding rounds must be 1..=16".into());
        }
        Ok(())
    }
}

pub fn extract_and_fold(
    evidence: &[u8],
    context: &[u8],
    config: ExtractorConfig,
) -> Result<[u8; 32], String> {
    config.validate()?;
    validate_input(evidence, context)?;

    let bit_len = evidence
        .len()
        .checked_mul(8)
        .ok_or("evidence bit length overflow")?;
    let evidence_hash = Sha256::digest(evidence);
    let mut seed = initial_seed(&evidence_hash, context);
    let mut output = [0u8; 32];

    for round in 0..config.folding_rounds {
        output = fold_round(
            evidence,
            &evidence_hash,
            seed,
            bit_len,
            config.positions,
            round,
        )?;
        seed = output;
    }

    Ok(whiten(output, &evidence_hash, context))
}

fn validate_input(evidence: &[u8], context: &[u8]) -> Result<(), String> {
    if evidence.is_empty() {
        return Err("evidence cannot be empty".into());
    }
    if context.len() > MAX_CONTEXT_BYTES {
        return Err("beacon context exceeds 4096 bytes".into());
    }
    Ok(())
}

fn fold_round(
    evidence: &[u8],
    evidence_hash: &[u8],
    seed: [u8; 32],
    bit_len: usize,
    positions: u16,
    round: u8,
) -> Result<[u8; 32], String> {
    let positions = derive_positions(&seed, bit_len, positions as usize)?;
    let packed = extract_bits(evidence, &positions);

    let mut hash = Sha256::new();
    hash.update(b"kaspa-portal/beacon/fold/v1\0");
    hash.update([round]);
    hash.update(seed);
    hash.update((positions.len() as u32).to_be_bytes());
    hash.update(packed);
    hash.update(evidence_hash);
    Ok(hash.finalize().into())
}

fn initial_seed(evidence_hash: &[u8], context: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"kaspa-portal/beacon/seed/v1\0");
    hash.update(evidence_hash);
    hash.update(Sha256::digest(context));
    hash.finalize().into()
}

fn whiten(output: [u8; 32], evidence_hash: &[u8], context: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"kaspa-portal/beacon/whiten/v1\0");
    hash.update(output);
    hash.update(evidence_hash);
    hash.update(Sha256::digest(context));
    hash.finalize().into()
}

fn extract_bits(source: &[u8], positions: &[usize]) -> Vec<u8> {
    let mut output = vec![0u8; positions.len().div_ceil(8)];
    for (index, position) in positions.iter().copied().enumerate() {
        let bit = (source[position / 8] >> (7 - (position % 8))) & 1;
        output[index / 8] |= bit << (7 - (index % 8));
    }
    output
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
