use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> Result<u64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system time is before Unix epoch".to_string())?;
    u64::try_from(duration.as_millis())
        .map_err(|_| "system time millisecond value overflowed u64".to_string())
}
