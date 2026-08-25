use core::{future::Future, pin::Pin};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CURBY_LATEST_RESULT_URL: &str =
    "https://random.colorado.edu/api/curbyq/round/latest/result";
pub const MIN_REFRESH_MS: u64 = 60_000;

pub type CurbyIoFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + 'a>>;

/// Platform adapter required by the public CURBy source.
///
/// Randomness logic owns validation, parsing, commitments, and rate limiting;
/// platform modules provide only the clock and HTTP fetch mechanics.
pub trait CurbyIo: Send + Sync {
    fn now_ms(&self) -> Result<u64, String>;
    fn fetch_text<'a>(&'a self, url: &'a str) -> CurbyIoFuture<'a, String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CurbyVerification {
    /// The public endpoint returned these bytes, but the CURBy protocol proof
    /// has not been independently verified by this process.
    RawApiUnverified,
    /// Evidence was supplied by a caller that independently verified CURBy's
    /// protocol proof before constructing the beacon input.
    ExternallyVerified,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CurbyEvidence {
    pub round: String,
    pub value: Vec<u8>,
    pub raw_response_hash: [u8; 32],
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub retrieved_at_ms: u64,
    pub verification: CurbyVerification,
}

impl CurbyEvidence {
    pub fn validate(&self) -> Result<(), String> {
        if self.round.is_empty() || self.round.len() > 256 {
            return Err("CURBy round identifier must be 1..=256 bytes".into());
        }
        if !(16..=4096).contains(&self.value.len()) {
            return Err("CURBy value must be 16..=4096 bytes".into());
        }
        if self.raw_response_hash.iter().all(|byte| *byte == 0) {
            return Err("CURBy raw-response commitment cannot be zero".into());
        }
        Ok(())
    }
}

#[derive(Default)]
struct CacheState {
    evidence: Option<CurbyEvidence>,
    last_attempt_ms: Option<u64>,
}

#[derive(Clone)]
pub struct CurbyClient {
    state: Arc<Mutex<CacheState>>,
    io: Arc<dyn CurbyIo>,
}

impl CurbyClient {
    pub fn new(io: Arc<dyn CurbyIo>) -> Self {
        Self {
            state: Arc::new(Mutex::new(CacheState::default())),
            io,
        }
    }

    /// Fetch the latest CURBy-Q value, while guaranteeing that this client
    /// initiates no more than one HTTP request per 60-second window.
    pub async fn latest(&self) -> Result<CurbyEvidence, String> {
        let now = self.io.now_ms()?;
        if let Some(cached) = self.reserve_or_cached(now)? {
            return Ok(cached);
        }

        let body = self.io.fetch_text(CURBY_LATEST_RESULT_URL).await?;
        let evidence = parse_response(&body, now)?;
        let mut guard = self.state.lock().map_err(|_| "CURBy cache lock poisoned")?;
        guard.evidence = Some(evidence.clone());
        Ok(evidence)
    }

    fn reserve_or_cached(&self, now: u64) -> Result<Option<CurbyEvidence>, String> {
        let mut guard = self.state.lock().map_err(|_| "CURBy cache lock poisoned")?;

        if let Some(cached) = guard.evidence.as_ref() {
            if now.saturating_sub(cached.retrieved_at_ms) < MIN_REFRESH_MS {
                return Ok(Some(cached.clone()));
            }
        }

        if let Some(last_attempt) = guard.last_attempt_ms {
            if now.saturating_sub(last_attempt) < MIN_REFRESH_MS {
                return guard.evidence.clone().map(Some).ok_or_else(|| {
                    "CURBy refresh already attempted within the one-minute rate limit".into()
                });
            }
        }

        // Reserve the refresh window before network I/O. This prevents two
        // concurrent callers from both issuing a request.
        guard.last_attempt_ms = Some(now);
        Ok(None)
    }
}

fn parse_response(body: &str, now: u64) -> Result<CurbyEvidence, String> {
    if body.len() > 1_048_576 {
        return Err("CURBy response exceeds 1 MiB".into());
    }
    let raw_response_hash = Sha256::digest(body.as_bytes()).into();
    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|error| format!("invalid CURBy DAG-JSON: {error}"))?;
    let round = find_round(&parsed).unwrap_or_else(|| "latest".into());
    let encoded = find_random_value(&parsed)
        .ok_or("CURBy response contained no supported randomness field")?;
    let value = decode_value(&encoded)?;
    let result = CurbyEvidence {
        round,
        value,
        raw_response_hash,
        retrieved_at_ms: now,
        verification: CurbyVerification::RawApiUnverified,
    };
    result.validate()?;
    Ok(result)
}

fn find_round(value: &serde_json::Value) -> Option<String> {
    for key in ["round", "roundNumber", "index"] {
        if let Some(item) = value.get(key) {
            if let Some(text) = item.as_str() {
                return Some(text.to_owned());
            }
            if let Some(number) = item.as_u64() {
                return Some(number.to_string());
            }
        }
    }
    None
}

fn find_random_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => looks_encoded(text).then(|| text.clone()),
        serde_json::Value::Array(values) => values.iter().find_map(find_random_value),
        serde_json::Value::Object(map) => {
            for key in ["randomness", "result", "output", "value", "random", "bytes"] {
                if let Some(found) = map.get(key).and_then(find_random_value) {
                    return Some(found);
                }
            }
            map.values().find_map(find_random_value)
        }
        _ => None,
    }
}

fn looks_encoded(value: &str) -> bool {
    let hex_value = value.strip_prefix("0x").unwrap_or(value);
    (hex_value.len() >= 32
        && hex_value.len().is_multiple_of(2)
        && hex_value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        || value.len() >= 24
}

fn decode_value(value: &str) -> Result<Vec<u8>, String> {
    let hex_value = value.strip_prefix("0x").unwrap_or(value);
    if hex_value.len().is_multiple_of(2) && hex_value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return hex::decode(hex_value).map_err(|error| error.to_string());
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| "unsupported CURBy randomness encoding".into())
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
