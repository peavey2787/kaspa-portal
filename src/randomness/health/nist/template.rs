use super::{
    math::{erfc, gamma_q},
    normalize, NistResult,
};

pub fn non_overlapping_template(bits: &[u8], template: &[u8]) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("non_overlapping_template", "invalid bits");
    };
    let Some(template) = normalize(template) else {
        return NistResult::not_applicable("non_overlapping_template", "invalid template");
    };
    let m = template.len();
    if !(2..=25).contains(&m) {
        return NistResult::not_applicable(
            "non_overlapping_template",
            "template length must be 2..=25",
        );
    }
    let blocks = 16usize.max(64usize.min(bits.len() / (m + 1).max(1000)));
    let block_size = bits.len() / blocks;
    if block_size < m {
        return NistResult::not_applicable("non_overlapping_template", "insufficient bits");
    }
    let lambda = (block_size - m + 1) as f64 / 2f64.powi(m as i32);
    let counts: Vec<_> = (0..blocks)
        .map(|index| {
            count_non_overlapping(
                &bits[index * block_size..(index + 1) * block_size],
                &template,
            )
        })
        .collect();
    let chi_squared = counts
        .iter()
        .map(|count| (*count as f64 - lambda).powi(2) / lambda)
        .sum::<f64>();
    NistResult::from_p(
        "non_overlapping_template",
        gamma_q(blocks as f64 / 2.0, chi_squared / 2.0),
        chi_squared,
    )
}

pub fn overlapping_template(bits: &[u8], template: &[u8]) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("overlapping_template", "invalid bits");
    };
    let Some(template) = normalize(template) else {
        return NistResult::not_applicable("overlapping_template", "invalid template");
    };
    let m = template.len();
    if !(2..=25).contains(&m) || template.iter().any(|bit| *bit != 1) {
        return NistResult::not_applicable("overlapping_template", "template must be 2..=25 ones");
    }
    if bits.len() < m {
        return NistResult::not_applicable("overlapping_template", "insufficient bits");
    }
    let observed = bits
        .windows(m)
        .filter(|window| *window == template.as_slice())
        .count() as f64;
    let probability = 1.0 / 2f64.powi(m as i32);
    let mean = (bits.len() - m + 1) as f64 * probability;
    let variance = bits.len() as f64 * (probability - (2 * m - 1) as f64 * probability.powi(2));
    if variance <= 0.0 {
        return NistResult::from_p("overlapping_template", 1.0, 0.0);
    }
    let z = (observed - mean).abs() / (2f64.sqrt() * variance.sqrt());
    NistResult::from_p("overlapping_template", erfc(z), z)
}

fn count_non_overlapping(bits: &[u8], template: &[u8]) -> usize {
    let mut count = 0usize;
    let mut index = 0usize;
    while index + template.len() <= bits.len() {
        if &bits[index..index + template.len()] == template {
            count += 1;
            index += template.len();
        } else {
            index += 1;
        }
    }
    count
}
