use std::collections::HashMap;

use super::{
    math::{erfc, gamma_q},
    normalize, NistResult,
};

pub fn frequency_monobit(bits: &[u8]) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("frequency_monobit", "invalid bits");
    };
    if bits.is_empty() {
        return NistResult::not_applicable("frequency_monobit", "empty sequence");
    }
    let sum: i64 = bits.iter().map(|bit| if *bit == 1 { 1 } else { -1 }).sum();
    let statistic = sum.unsigned_abs() as f64 / (bits.len() as f64).sqrt();
    NistResult::from_p(
        "frequency_monobit",
        erfc(statistic / 2f64.sqrt()),
        statistic,
    )
}

pub fn block_frequency(bits: &[u8], block_size: usize) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("block_frequency", "invalid bits");
    };
    if block_size == 0 || bits.len() < block_size {
        return NistResult::not_applicable(
            "block_frequency",
            "insufficient bits or zero block size",
        );
    }
    let block_count = bits.len() / block_size;
    let sum = bits
        .chunks_exact(block_size)
        .map(|block| {
            let ratio = block.iter().filter(|bit| **bit == 1).count() as f64 / block_size as f64;
            (ratio - 0.5).powi(2)
        })
        .sum::<f64>();
    let chi_squared = 4.0 * block_size as f64 * sum;
    NistResult::from_p(
        "block_frequency",
        gamma_q(block_count as f64 / 2.0, chi_squared / 2.0),
        chi_squared,
    )
}

pub fn runs(bits: &[u8]) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("runs", "invalid bits");
    };
    let n = bits.len();
    if n < 2 {
        return NistResult::not_applicable("runs", "sequence too short");
    }
    let pi = bits.iter().filter(|bit| **bit == 1).count() as f64 / n as f64;
    if (pi - 0.5).abs() >= 2.0 / (n as f64).sqrt() {
        return NistResult::not_applicable("runs", "frequency prerequisite failed");
    }
    let count = 1 + bits.windows(2).filter(|pair| pair[0] != pair[1]).count();
    let expected = 2.0 * n as f64 * pi * (1.0 - pi);
    let denominator = 2.0 * (2.0 * n as f64).sqrt() * pi * (1.0 - pi);
    if denominator == 0.0 {
        return NistResult::not_applicable("runs", "degenerate run denominator");
    }
    let z = (count as f64 - expected).abs() / denominator;
    NistResult::from_p("runs", erfc(z), z)
}

pub fn longest_run_of_ones(bits: &[u8], block_size: usize) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("longest_run_of_ones", "invalid bits");
    };
    let Some((bins, probabilities)) = longest_run_parameters(block_size) else {
        return NistResult::not_applicable(
            "longest_run_of_ones",
            "supported block sizes are 8, 128, 512",
        );
    };
    let blocks = bits.len() / block_size;
    if blocks == 0 {
        return NistResult::not_applicable("longest_run_of_ones", "insufficient bits");
    }
    let mut counts = vec![0usize; bins.len()];
    for block in bits.chunks_exact(block_size) {
        let longest = longest_one_run(block);
        let index = bins
            .iter()
            .take(bins.len() - 1)
            .position(|limit| longest <= *limit)
            .unwrap_or(bins.len() - 1);
        counts[index] += 1;
    }
    let chi_squared = counts
        .iter()
        .zip(probabilities)
        .map(|(count, probability)| {
            let expected = probability * blocks as f64;
            (*count as f64 - expected).powi(2) / expected
        })
        .sum::<f64>();
    let degrees = (bins.len() - 1) as f64;
    NistResult::from_p(
        "longest_run_of_ones",
        gamma_q(degrees / 2.0, chi_squared / 2.0),
        chi_squared,
    )
}

pub fn serial(bits: &[u8], m: usize) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable(format!("serial_m{m}"), "invalid bits");
    };
    if bits.is_empty() || !(1..=16).contains(&m) {
        return NistResult::not_applicable(
            format!("serial_m{m}"),
            "invalid sequence or pattern size",
        );
    }
    let psi_m = psi2(&bits, m);
    let psi_m1 = psi2(&bits, m.saturating_sub(1));
    let psi_m2 = psi2(&bits, m.saturating_sub(2));
    let delta1 = psi_m - psi_m1;
    let delta2 = psi_m - 2.0 * psi_m1 + psi_m2;
    let p1 = gamma_q(2f64.powi(m as i32 - 1), delta1 / 2.0);
    let p2 = gamma_q(2f64.powi(m as i32 - 2), delta2 / 2.0);
    NistResult::from_many(format!("serial_m{m}"), vec![p1, p2], vec![delta1, delta2])
}

fn longest_run_parameters(block_size: usize) -> Option<(&'static [usize], &'static [f64])> {
    match block_size {
        8 => Some((&[1, 2, 3, 4], &[0.2148, 0.3672, 0.2305, 0.1875])),
        128 => Some((&[4, 5, 6, 7], &[0.1174, 0.2430, 0.2493, 0.3903])),
        512 => Some((
            &[10, 11, 12, 13, 14, 15, 16],
            &[0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727],
        )),
        _ => None,
    }
}

fn longest_one_run(bits: &[u8]) -> usize {
    let mut longest = 0usize;
    let mut current = 0usize;
    for bit in bits {
        current = if *bit == 1 { current + 1 } else { 0 };
        longest = longest.max(current);
    }
    longest
}

fn psi2(bits: &[u8], m: usize) -> f64 {
    if m == 0 {
        return 0.0;
    }
    let n = bits.len();
    let mut counts = HashMap::<u32, usize>::new();
    for start in 0..n {
        let mut value = 0u32;
        for offset in 0..m {
            value = (value << 1) | u32::from(bits[(start + offset) % n]);
        }
        *counts.entry(value).or_default() += 1;
    }
    let square_sum = counts.values().map(|count| count * count).sum::<usize>() as f64;
    square_sum * 2f64.powi(m as i32) / n as f64 - n as f64
}
