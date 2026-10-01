//! Public Kaspa node discovery through the community wRPC resolvers.
//!
//! This module is transport-free: it builds resolver query URLs and validates
//! their responses. Fetching lives in `platform/`. Only TLS (`wss://`)
//! endpoints are ever accepted from a resolver.

use crate::primitives::NetworkId;

use super::error::NetworkError;

/// Community resolvers; each answers with one healthy public node.
pub const PUBLIC_RESOLVERS: [&str; 16] = [
    "https://eric.kaspa.stream",
    "https://maxim.kaspa.stream",
    "https://sean.kaspa.stream",
    "https://troy.kaspa.stream",
    "https://john.kaspa.red",
    "https://mike.kaspa.red",
    "https://paul.kaspa.red",
    "https://alex.kaspa.red",
    "https://jake.kaspa.green",
    "https://mark.kaspa.green",
    "https://adam.kaspa.green",
    "https://liam.kaspa.green",
    "https://noah.kaspa.blue",
    "https://ryan.kaspa.blue",
    "https://jack.kaspa.blue",
    "https://luke.kaspa.blue",
];

/// Resolver query for a TLS Borsh wRPC node on `network`.
#[must_use]
pub fn query_url(resolver: &str, network: NetworkId) -> String {
    format!(
        "{resolver}/v2/kaspa/{}/tls/wrpc/borsh",
        network.canonical_name()
    )
}

/// Extract the node endpoint from a resolver response (`{"url": "wss://…"}`).
pub fn parse_endpoint(body: &str) -> Result<String, NetworkError> {
    let value: serde_json::Value = serde_json::from_str(body.trim())
        .map_err(|error| NetworkError::InvalidEncoding(format!("resolver response: {error}")))?;
    let endpoint = value
        .get("url")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .ok_or_else(|| NetworkError::InvalidEncoding("resolver response has no url".into()))?;
    let host = endpoint.strip_prefix("wss://").unwrap_or_default();
    if host.is_empty() || host.contains(char::is_whitespace) {
        return Err(NetworkError::InvalidEncoding(format!(
            "resolver returned a non-TLS or malformed endpoint: {endpoint}"
        )));
    }
    Ok(endpoint.to_owned())
}

/// Unique endpoints in first-answer order.
#[must_use]
pub fn unique_endpoints<I: IntoIterator<Item = String>>(endpoints: I) -> Vec<String> {
    let mut unique = Vec::new();
    for endpoint in endpoints {
        if !unique.contains(&endpoint) {
            unique.push(endpoint);
        }
    }
    unique
}
