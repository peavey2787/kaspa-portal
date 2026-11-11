//! Float-to-integer conversions with explicit, documented saturation.
//!
//! Fee rates, clocks and statistics arrive as `f64`. Every conversion to an
//! integer goes through this module so the rounding and clamping rules live in
//! one place.

/// `value` with its fractional part dropped, as a `u64`. NaN maps to zero and
/// out-of-range values clamp to the nearest bound.
#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    reason = "float-to-integer `as` saturates; the saturation is this function's contract"
)]
pub fn saturating_f64_to_u64(value: f64) -> u64 {
    value as u64
}

/// `value` with its fractional part dropped, as an `i64`. NaN maps to zero and
/// out-of-range values clamp to the nearest bound.
#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    reason = "float-to-integer `as` saturates; the saturation is this function's contract"
)]
pub fn saturating_f64_to_i64(value: f64) -> i64 {
    value as i64
}

/// `value` rounded up to a whole `u64`, or `None` unless it is finite, positive
/// and within the `u64` range.
#[must_use]
pub fn ceil_to_u64(value: f64) -> Option<u64> {
    let representable = value.is_finite() && value > 0.0 && value <= u64::MAX as f64;
    representable.then(|| saturating_f64_to_u64(value.ceil()))
}

#[cfg(test)]
#[path = "unit_tests/numeric.rs"]
mod unit_tests;
