pub(crate) mod error_payload;
pub mod operation;
pub(crate) mod request;
pub(crate) mod response;

/// Parse a raw wRPC response envelope without exposing transport-internal wire types.
///
/// This is intentionally small and allocation-free so callers and fuzz harnesses can
/// validate untrusted response framing before higher-level decoding.
pub fn validate_response(data: &[u8]) -> Result<(), crate::network::error::NetworkError> {
    response::decode(data).map(|_| ())
}
