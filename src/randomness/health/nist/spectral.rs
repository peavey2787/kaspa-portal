use super::{math::erfc, normalize, NistResult};

pub fn spectral_dft(bits: &[u8]) -> NistResult {
    let Some(bits) = normalize(bits) else {
        return NistResult::not_applicable("spectral_dft", "invalid bits");
    };
    let n = bits.len();
    if n < 1000 {
        return NistResult::not_applicable(
            "spectral_dft",
            "NIST diagnostic requires at least 1000 bits",
        );
    }
    let mut re: Vec<f64> = bits
        .iter()
        .map(|bit| if *bit == 1 { 1.0 } else { -1.0 })
        .collect();
    let mut im = vec![0.0; n];
    if n.is_power_of_two() {
        fft_radix2(&mut re, &mut im);
    } else if n <= 16_384 {
        dft_in_place(&mut re, &mut im);
    } else {
        return NistResult::not_applicable(
            "spectral_dft",
            "non-power-of-two input above safe DFT bound",
        );
    }
    let threshold = (f64::ln(1.0 / 0.05) * n as f64).sqrt();
    let half = n / 2;
    let below = (1..half)
        .filter(|index| re[*index].hypot(im[*index]) < threshold)
        .count() as f64;
    let expected = 0.95 * n as f64 / 2.0;
    let variance = n as f64 * 0.95 * 0.05 / 4.0;
    let statistic = (below - expected) / variance.sqrt();
    NistResult::from_p(
        "spectral_dft",
        erfc(statistic.abs() / 2f64.sqrt()),
        statistic,
    )
}

fn fft_radix2(re: &mut [f64], im: &mut [f64]) {
    bit_reverse(re, im);
    let mut length = 2usize;
    while length <= re.len() {
        fft_stage(re, im, length);
        length <<= 1;
    }
}

fn bit_reverse(re: &mut [f64], im: &mut [f64]) {
    let mut j = 0usize;
    for i in 0..re.len() {
        if i < j {
            re.swap(i, j);
            im.swap(i, j);
        }
        let mut mask = re.len() >> 1;
        while mask != 0 && j & mask != 0 {
            j &= !mask;
            mask >>= 1;
        }
        j |= mask;
    }
}

fn fft_stage(re: &mut [f64], im: &mut [f64], length: usize) {
    let half = length / 2;
    let theta = -2.0 * core::f64::consts::PI / length as f64;
    let (wpi, wpr) = theta.sin_cos();
    for start in (0..re.len()).step_by(length) {
        let (mut wr, mut wi) = (1.0, 0.0);
        for offset in 0..half {
            let low = start + offset;
            let high = low + half;
            let tr = wr * re[high] - wi * im[high];
            let ti = wr * im[high] + wi * re[high];
            re[high] = re[low] - tr;
            im[high] = im[low] - ti;
            re[low] += tr;
            im[low] += ti;
            (wr, wi) = (wr * wpr - wi * wpi, wr * wpi + wi * wpr);
        }
    }
}

fn dft_in_place(re: &mut [f64], im: &mut [f64]) {
    let input = re.to_vec();
    for k in 0..re.len() {
        let mut real = 0.0;
        let mut imaginary = 0.0;
        let base = -2.0 * core::f64::consts::PI * k as f64 / re.len() as f64;
        for (t, value) in input.iter().enumerate() {
            real += value * (base * t as f64).cos();
            imaginary += value * (base * t as f64).sin();
        }
        re[k] = real;
        im[k] = imaginary;
    }
}
