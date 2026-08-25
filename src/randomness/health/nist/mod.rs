mod basic;
mod cumulative;
mod entropy;
mod excursions;
mod linear_complexity;
mod math;
mod matrix_rank;
mod maurer;
mod spectral;
mod template;

pub use basic::{block_frequency, frequency_monobit, longest_run_of_ones, runs, serial};
pub use cumulative::{cumulative_sums_backward, cumulative_sums_forward};
pub use entropy::approximate_entropy;
pub use excursions::{random_excursions, random_excursions_variant};
pub use linear_complexity::linear_complexity;
pub use matrix_rank::binary_matrix_rank;
pub use maurer::maurer_universal;
pub use spectral::spectral_dft;
pub use template::{non_overlapping_template, overlapping_template};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NistResult {
    pub name: String,
    pub p_value: Option<f64>,
    #[serde(default)]
    pub p_values: Vec<f64>,
    pub statistic: Option<f64>,
    #[serde(default)]
    pub statistics: Vec<f64>,
    pub threshold: f64,
    pub applicable: bool,
    pub passed: bool,
    pub note: Option<String>,
}

impl NistResult {
    pub(super) fn from_p(name: impl Into<String>, p_value: f64, statistic: f64) -> Self {
        let p_value = bounded_probability(p_value);
        Self {
            name: name.into(),
            p_value: Some(p_value),
            p_values: vec![p_value],
            statistic: Some(statistic),
            statistics: vec![statistic],
            threshold: 0.01,
            applicable: true,
            passed: p_value >= 0.01,
            note: None,
        }
    }

    pub(super) fn from_many(
        name: impl Into<String>,
        p_values: Vec<f64>,
        statistics: Vec<f64>,
    ) -> Self {
        let p_values: Vec<_> = p_values.into_iter().map(bounded_probability).collect();
        let p_value = p_values.iter().copied().reduce(f64::min);
        let statistic = statistics.first().copied();
        Self {
            name: name.into(),
            p_value,
            p_values,
            statistic,
            statistics,
            threshold: 0.01,
            applicable: true,
            passed: p_value.is_some_and(|value| value >= 0.01),
            note: None,
        }
    }

    pub(super) fn not_applicable(name: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            p_value: None,
            p_values: Vec::new(),
            statistic: None,
            statistics: Vec::new(),
            threshold: 0.01,
            applicable: false,
            passed: false,
            note: Some(note.into()),
        }
    }
}

fn bounded_probability(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

pub(super) fn normalize(bits: &[u8]) -> Option<Vec<u8>> {
    bits.iter().copied().map(normalize_bit).collect()
}

fn normalize_bit(value: u8) -> Option<u8> {
    match value {
        0 | b'0' => Some(0),
        1 | b'1' => Some(1),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NistSuite;

impl NistSuite {
    /// Fast health subset. Statistical tests cannot establish cryptographic
    /// unpredictability or replace source/proof verification.
    pub fn quick(bits: &[u8]) -> Vec<NistResult> {
        vec![
            frequency_monobit(bits),
            block_frequency(bits, 128),
            runs(bits),
            cumulative_sums_forward(bits),
        ]
    }

    /// Full 18-row suite matching the retained reference configuration.
    /// Applicability is reported separately from pass/fail.
    pub fn full(bits: &[u8]) -> Vec<NistResult> {
        vec![
            frequency_monobit(bits),
            block_frequency(bits, 128),
            runs(bits),
            longest_run_of_ones(bits, 128),
            binary_matrix_rank(bits, 32),
            spectral_dft(bits),
            non_overlapping_template(bits, b"000000001"),
            overlapping_template(bits, b"111111111"),
            maurer_universal(bits, 6),
            linear_complexity(bits, 500),
            serial(bits, 2),
            serial(bits, 3),
            approximate_entropy(bits, 2),
            approximate_entropy(bits, 3),
            cumulative_sums_forward(bits),
            cumulative_sums_backward(bits),
            random_excursions(bits),
            random_excursions_variant(bits),
        ]
    }
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
