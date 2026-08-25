#[cfg(target_arch = "wasm32")]
pub fn u64_to_bigint(value: u64) -> js_sys::BigInt {
    js_sys::BigInt::from(value)
}

#[cfg(target_arch = "wasm32")]
pub fn bigint_to_u64(value: &js_sys::BigInt) -> Result<u64, String> {
    value
        .to_string(10)
        .map_err(|_| "BigInt conversion failed")?
        .as_string()
        .ok_or("BigInt conversion failed")?
        .parse::<u64>()
        .map_err(|_| "BigInt is outside u64 range".into())
}
