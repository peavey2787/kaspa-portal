pub fn erfc(value: f64) -> f64 {
    let z = value.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let result = t
        * (-z * z - 1.26551223
            + t * (1.00002368
                + t * (0.37409196
                    + t * (0.09678418
                        + t * (-0.18628806
                            + t * (0.27886807
                                + t * (-1.13520398
                                    + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))))
            .exp();
    if value >= 0.0 {
        result
    } else {
        2.0 - result
    }
}

pub fn gamma_q(a: f64, x: f64) -> f64 {
    if a <= 0.0 || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return 1.0;
    }
    if x < a + 1.0 {
        1.0 - gamma_series(a, x)
    } else {
        gamma_cf(a, x)
    }
}

fn ln_gamma(x: f64) -> f64 {
    let coefficients = [
        76.18009172947146,
        -86.50532032941677,
        24.01409824083091,
        -1.231739572450155,
        0.001208650973866179,
        -0.000005395239384953,
    ];
    let tmp = x + 5.5;
    let tmp = (x + 0.5) * tmp.ln() - tmp;
    let mut series = 1.000000000190015;
    let mut y = x;
    for coefficient in coefficients {
        y += 1.0;
        series += coefficient / y;
    }
    tmp + (2.5066282746310005 * series / x).ln()
}

fn gamma_series(a: f64, x: f64) -> f64 {
    let log_gamma = ln_gamma(a);
    let mut ap = a;
    let mut sum = 1.0 / a;
    let mut delta = sum;
    for _ in 0..1000 {
        ap += 1.0;
        delta *= x / ap;
        sum += delta;
        if delta.abs() < sum.abs() * 3e-14 {
            break;
        }
    }
    sum * (-x + a * x.ln() - log_gamma).exp()
}

fn gamma_cf(a: f64, x: f64) -> f64 {
    let log_gamma = ln_gamma(a);
    let mut b = x + 1.0 - a;
    let mut c = 1.0 / 1e-300;
    let mut d = 1.0 / b;
    let mut h = d;
    for i in 1..=1000 {
        let an = -(i as f64) * ((i as f64) - a);
        b += 2.0;
        d = an * d + b;
        if d.abs() < 1e-300 {
            d = 1e-300;
        }
        c = b + an / c;
        if c.abs() < 1e-300 {
            c = 1e-300;
        }
        d = 1.0 / d;
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() < 3e-14 {
            break;
        }
    }
    (-x + a * x.ln() - log_gamma).exp() * h
}

pub fn normal_cdf(value: f64) -> f64 {
    0.5 * erfc(-value / 2f64.sqrt())
}
