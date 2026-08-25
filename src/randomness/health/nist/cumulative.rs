use super::{math::normal_cdf, normalize, NistResult};

pub fn cumulative_sums_forward(bits: &[u8]) -> NistResult {
    cumulative_sums(bits, false)
}
pub fn cumulative_sums_backward(bits: &[u8]) -> NistResult {
    cumulative_sums(bits, true)
}

fn cumulative_sums(bits: &[u8], backward: bool) -> NistResult {
    let name = if backward {
        "cumulative_sums_backward"
    } else {
        "cumulative_sums_forward"
    };
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable(name, "invalid bits");
    };
    if bits.is_empty() {
        return NistResult::not_applicable(name, "empty sequence");
    }
    let mut sum = 0i64;
    let mut z = 0i64;
    let iterator: Box<dyn Iterator<Item = &u8>> = if backward {
        Box::new(bits.iter().rev())
    } else {
        Box::new(bits.iter())
    };
    for bit in iterator {
        sum += if *bit == 1 { 1 } else { -1 };
        z = z.max(sum.abs());
    }
    let p = cusum_probability(bits.len(), z as usize);
    NistResult::from_p(name, p, z as f64)
}

fn cusum_probability(n: usize, z: usize) -> f64 {
    if z == 0 {
        return 1.0;
    }
    let n = n as f64;
    let z = z as f64;
    let sqrt_n = n.sqrt();
    let k1_start = ((-n / z + 1.0) / 4.0).ceil() as i64;
    let k1_end = ((n / z - 1.0) / 4.0).floor() as i64;
    let k2_start = ((-n / z - 3.0) / 4.0).ceil() as i64;
    let k2_end = k1_end;
    let sum1 = bounded_sum(k1_start, k1_end, |k| {
        normal_cdf((4.0 * k as f64 + 1.0) * z / sqrt_n)
            - normal_cdf((4.0 * k as f64 - 1.0) * z / sqrt_n)
    });
    let sum2 = bounded_sum(k2_start, k2_end, |k| {
        normal_cdf((4.0 * k as f64 + 3.0) * z / sqrt_n)
            - normal_cdf((4.0 * k as f64 + 1.0) * z / sqrt_n)
    });
    1.0 - sum1 + sum2
}

fn bounded_sum(start: i64, end: i64, term: impl Fn(i64) -> f64) -> f64 {
    if end < start {
        return 0.0;
    }
    let end = end.min(start.saturating_add(9_999));
    (start..=end).map(term).sum()
}
