use super::{math::gamma_q, normalize, NistResult};

pub fn linear_complexity(bits: &[u8], block_size: usize) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("linear_complexity", "invalid bits");
    };
    if block_size != 500 {
        return NistResult::not_applicable(
            "linear_complexity",
            "strict reference configuration requires M=500",
        );
    }
    let blocks = bits.len() / block_size;
    if blocks == 0 {
        return NistResult::not_applicable("linear_complexity", "insufficient bits");
    }
    let mut counts = [0usize; 7];
    let mu = 500.0 / 2.0 + 2.0 / 9.0;
    for block in bits.chunks_exact(block_size) {
        let complexity = berlekamp_massey(block) as f64;
        let t = complexity - mu + 2.0 / 9.0;
        counts[bin(t)] += 1;
    }
    let probabilities = [
        1.0 / 96.0,
        1.0 / 32.0,
        1.0 / 8.0,
        1.0 / 2.0,
        1.0 / 4.0,
        1.0 / 16.0,
        1.0 / 48.0,
    ];
    let chi_squared = counts
        .iter()
        .zip(probabilities)
        .map(|(count, p)| {
            let expected = p * blocks as f64;
            (*count as f64 - expected).powi(2) / expected
        })
        .sum::<f64>();
    NistResult::from_p(
        "linear_complexity",
        gamma_q(3.0, chi_squared / 2.0),
        chi_squared,
    )
}

fn berlekamp_massey(sequence: &[u8]) -> usize {
    let mut c = vec![0u8; sequence.len()];
    c[0] = 1;
    let mut b = c.clone();
    let mut length = 0usize;
    let mut last_update = -1isize;
    for n in 0..sequence.len() {
        let mut discrepancy = sequence[n];
        for i in 1..=length {
            discrepancy ^= c[i] & sequence[n - i];
        }
        if discrepancy == 0 {
            continue;
        }
        let previous = c.clone();
        let shift = (n as isize - last_update) as usize;
        for i in 0..sequence.len().saturating_sub(shift) {
            c[i + shift] ^= b[i];
        }
        if length <= n / 2 {
            length = n + 1 - length;
            b = previous;
            last_update = n as isize;
        }
    }
    length
}

fn bin(value: f64) -> usize {
    if value <= -2.5 {
        0
    } else if value <= -1.5 {
        1
    } else if value <= -0.5 {
        2
    } else if value <= 0.5 {
        3
    } else if value <= 1.5 {
        4
    } else if value <= 2.5 {
        5
    } else {
        6
    }
}
