pub fn now_ms() -> Result<u64, String> {
    let value = js_sys::Date::now();
    if !value.is_finite() || value < 0.0 || value > u64::MAX as f64 {
        return Err("browser clock returned an invalid timestamp".into());
    }
    Ok(crate::primitives::numeric::saturating_f64_to_u64(value))
}
