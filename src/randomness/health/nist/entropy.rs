use super::{math::gamma_q, normalize, NistResult};
use std::collections::HashMap;

pub fn approximate_entropy(bits: &[u8], m: usize) -> NistResult {
    let name = format!("approximate_entropy_m{m}");
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable(name, "invalid bits");
    };
    if bits.is_empty() || !(1..=16).contains(&m) {
        return NistResult::not_applicable(name, "invalid sequence or block size");
    }
    let ap_en = phi(&bits, m) - phi(&bits, m + 1);
    let chi_squared = 2.0 * bits.len() as f64 * (core::f64::consts::LN_2 - ap_en);
    let shape = 2f64.powi(m as i32 - 1);
    NistResult::from_p(name, gamma_q(shape, chi_squared / 2.0), chi_squared)
}

fn phi(bits: &[u8], m: usize) -> f64 {
    let n = bits.len();
    let mut counts = HashMap::<u32, usize>::new();
    for start in 0..n {
        let mut value = 0u32;
        for offset in 0..m {
            value = (value << 1) | u32::from(bits[(start + offset) % n]);
        }
        *counts.entry(value).or_default() += 1;
    }
    counts
        .values()
        .map(|count| {
            let ratio = *count as f64 / n as f64;
            ratio * ratio.ln()
        })
        .sum()
}
