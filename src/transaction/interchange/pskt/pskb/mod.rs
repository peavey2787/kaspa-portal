mod encoder;
mod json;
mod model;

#[cfg(feature = "std")]
pub use encoder::encode_pskt_document;
pub use encoder::{encode_covenant, encode_covenant_with_payload, encode_plan};
pub use model::PskbOutput;

/// The canonical JSON of a plain output paying `amount` to `script`.
#[must_use]
pub fn plain_output_value(amount: u64, script: &[u8]) -> serde_json::Value {
    json::output_value(&PskbOutput::plain(amount, script.to_vec()), false)
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
