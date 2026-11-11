use crate::primitives::numeric::{ceil_to_u64, saturating_f64_to_i64, saturating_f64_to_u64};

#[test]
fn saturating_conversions_drop_fractions_and_clamp_out_of_range_values() {
    assert_eq!(saturating_f64_to_u64(41.9), 41);
    assert_eq!(saturating_f64_to_u64(-3.0), 0);
    assert_eq!(saturating_f64_to_u64(f64::NAN), 0);
    assert_eq!(saturating_f64_to_u64(f64::INFINITY), u64::MAX);

    assert_eq!(saturating_f64_to_i64(-41.9), -41);
    assert_eq!(saturating_f64_to_i64(41.9), 41);
    assert_eq!(saturating_f64_to_i64(f64::NAN), 0);
    assert_eq!(saturating_f64_to_i64(f64::NEG_INFINITY), i64::MIN);
    assert_eq!(saturating_f64_to_i64(f64::INFINITY), i64::MAX);
}

#[test]
fn ceil_accepts_only_finite_positive_values_within_the_u64_range() {
    assert_eq!(ceil_to_u64(0.25), Some(1));
    assert_eq!(ceil_to_u64(7.0), Some(7));
    assert_eq!(ceil_to_u64(u64::MAX as f64), Some(u64::MAX));
    assert_eq!(ceil_to_u64(0.0), None);
    assert_eq!(ceil_to_u64(-1.0), None);
    assert_eq!(ceil_to_u64(f64::NAN), None);
    assert_eq!(ceil_to_u64(f64::INFINITY), None);
    assert_eq!(ceil_to_u64(u64::MAX as f64 * 2.0), None);
}
