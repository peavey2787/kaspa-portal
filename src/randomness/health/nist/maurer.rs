use super::{math::erfc, normalize, NistResult};

const MU: [f64; 11] = [
    5.2177052, 6.1962507, 7.1836656, 8.1764248, 9.1723243, 10.170032, 11.168765, 12.16807,
    13.167693, 14.167488, 15.167379,
];
const SIGMA: [f64; 11] = [
    2.954, 3.125, 3.238, 3.311, 3.356, 3.384, 3.401, 3.410, 3.416, 3.419, 3.421,
];

pub fn maurer_universal(bits: &[u8], block_size: usize) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("maurer_universal", "invalid bits");
    };
    if !(6..=16).contains(&block_size) {
        return NistResult::not_applicable("maurer_universal", "block size must be 6..=16");
    }
    let alphabet = 1usize << block_size;
    let warmup = 10 * alphabet;
    let total = bits.len() / block_size;
    let test_blocks = total.saturating_sub(warmup);
    if test_blocks < 1000 {
        return NistResult::not_applicable(
            "maurer_universal",
            "requires at least 1000 test blocks after initialization",
        );
    }
    let mut last = vec![0usize; alphabet];
    for index in 0..warmup {
        last[block_value(&bits, index * block_size, block_size)] = index;
    }
    let mut sum = 0.0;
    for index in warmup..total {
        let value = block_value(&bits, index * block_size, block_size);
        sum += ((index - last[value]) as f64).log2();
        last[value] = index;
    }
    let observed = sum / test_blocks as f64;
    let table_index = block_size - 6;
    let z = (observed - MU[table_index]).abs() / (2f64.sqrt() * SIGMA[table_index]);
    NistResult::from_p("maurer_universal", erfc(z), observed)
}

fn block_value(bits: &[u8], start: usize, length: usize) -> usize {
    bits[start..start + length]
        .iter()
        .fold(0usize, |value, bit| (value << 1) | usize::from(*bit))
}
