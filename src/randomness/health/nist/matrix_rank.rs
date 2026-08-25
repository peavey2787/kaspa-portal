use super::{math::gamma_q, normalize, NistResult};

pub fn binary_matrix_rank(bits: &[u8], size: usize) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("binary_matrix_rank", "invalid bits");
    };
    if size == 0 || size > 64 {
        return NistResult::not_applicable("binary_matrix_rank", "matrix size must be 1..=64");
    }
    let block_size = size.saturating_mul(size);
    let matrices = bits.len() / block_size;
    if matrices == 0 {
        return NistResult::not_applicable("binary_matrix_rank", "insufficient bits");
    }
    let mut counts = [0usize; 3];
    for block in bits.chunks_exact(block_size) {
        let rank = rank_gf2(block, size);
        if rank == size {
            counts[0] += 1;
        } else if rank + 1 == size {
            counts[1] += 1;
        } else {
            counts[2] += 1;
        }
    }
    let probabilities = [0.2888, 0.5776, 0.1336];
    let chi_squared = counts
        .iter()
        .zip(probabilities)
        .map(|(count, p)| {
            let expected = p * matrices as f64;
            (*count as f64 - expected).powi(2) / expected
        })
        .sum::<f64>();
    NistResult::from_p(
        "binary_matrix_rank",
        gamma_q(1.0, chi_squared / 2.0),
        chi_squared,
    )
}

fn rank_gf2(block: &[u8], size: usize) -> usize {
    let mut rows = vec![0u64; size];
    for row in 0..size {
        for column in 0..size {
            if block[row * size + column] == 1 {
                rows[row] |= 1u64 << column;
            }
        }
    }
    let mut rank = 0usize;
    for column in 0..size {
        let Some(pivot) = (rank..size).find(|row| rows[*row] & (1u64 << column) != 0) else {
            continue;
        };
        rows.swap(rank, pivot);
        let pivot_row = rows[rank];
        for row in rows.iter_mut().take(size).skip(rank + 1) {
            if *row & (1u64 << column) != 0 {
                *row ^= pivot_row;
            }
        }
        rank += 1;
        if rank == size {
            break;
        }
    }
    rank
}
