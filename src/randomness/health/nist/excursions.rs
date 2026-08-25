use super::{
    math::{erfc, gamma_q},
    normalize, NistResult,
};

pub fn random_excursions(bits: &[u8]) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("random_excursions", "invalid bits");
    };
    let (walk, ends) = walk_cycles(&bits);
    if ends.len() < 500 {
        return NistResult::not_applicable("random_excursions", "insufficient cycles (J < 500)");
    }
    let states = [-4i32, -3, -2, -1, 1, 2, 3, 4];
    let mut statistics = Vec::with_capacity(states.len());
    let mut probabilities = Vec::with_capacity(states.len());
    for state in states {
        let visits = cycle_visits(&walk, &ends, state);
        let mut bins = [0usize; 6];
        for count in visits {
            bins[count.min(5)] += 1;
        }
        let expected_p = excursion_probabilities(state);
        let chi_squared = bins
            .iter()
            .zip(expected_p)
            .map(|(count, p)| {
                let expected = p * ends.len() as f64;
                (*count as f64 - expected).powi(2) / expected
            })
            .sum::<f64>();
        statistics.push(chi_squared);
        probabilities.push(gamma_q(2.5, chi_squared / 2.0));
    }
    NistResult::from_many("random_excursions", probabilities, statistics)
}

pub fn random_excursions_variant(bits: &[u8]) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("random_excursions_variant", "invalid bits");
    };
    let (walk, ends) = walk_cycles(&bits);
    if ends.len() < 500 {
        return NistResult::not_applicable(
            "random_excursions_variant",
            "insufficient cycles (J < 500)",
        );
    }
    let cycles = ends.len() as f64;
    let mut statistics = Vec::with_capacity(18);
    let mut probabilities = Vec::with_capacity(18);
    for state in (-9i32..=9).filter(|state| *state != 0) {
        let visits = walk.iter().skip(1).filter(|value| **value == state).count() as f64;
        let denominator = (2.0 * cycles * (4.0 * state.unsigned_abs() as f64 - 2.0)).sqrt();
        let statistic = (visits - cycles).abs() / denominator;
        statistics.push(statistic);
        probabilities.push(erfc(statistic));
    }
    NistResult::from_many("random_excursions_variant", probabilities, statistics)
}

fn excursion_probabilities(state: i32) -> [f64; 6] {
    let x = state.unsigned_abs() as f64;
    let q = 1.0 - 1.0 / (2.0 * x);
    let mut p = [0.0; 6];
    p[0] = q;
    for (k, probability) in p.iter_mut().enumerate().take(5).skip(1) {
        *probability = q.powi(k as i32 - 1) / (4.0 * x * x);
    }
    p[5] = q.powi(4) / (2.0 * x);
    p
}

fn walk_cycles(bits: &[u8]) -> (Vec<i32>, Vec<usize>) {
    let mut walk = Vec::with_capacity(bits.len() + 1);
    walk.push(0);
    let mut ends = Vec::new();
    let mut sum = 0i32;
    for (index, bit) in bits.iter().enumerate() {
        sum += if *bit == 1 { 1 } else { -1 };
        walk.push(sum);
        if sum == 0 {
            ends.push(index + 1);
        }
    }
    if sum != 0 {
        ends.push(bits.len());
    }
    (walk, ends)
}

fn cycle_visits(walk: &[i32], ends: &[usize], state: i32) -> Vec<usize> {
    let mut start = 0usize;
    ends.iter()
        .map(|end| {
            let count = walk[start + 1..=*end]
                .iter()
                .filter(|value| **value == state)
                .count();
            start = *end;
            count
        })
        .collect()
}
