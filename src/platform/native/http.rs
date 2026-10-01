//! Bounded HTTPS GET for small text answers (public resolvers).

use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_BODY_BYTES: usize = 16 * 1024;

pub async fn fetch_text(url: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .https_only(true)
        .build()
        .map_err(|error| format!("HTTP client: {error}"))?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let body = response.bytes().await.map_err(|error| error.to_string())?;
    if body.len() > MAX_BODY_BYTES {
        return Err("response too large".into());
    }
    String::from_utf8(body.to_vec()).map_err(|_| "response is not UTF-8".into())
}
