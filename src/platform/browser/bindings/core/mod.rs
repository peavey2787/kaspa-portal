mod chain;
mod contract;
mod network;
mod privacy;
mod transaction;
mod wallet;

pub use chain::WasmChain;
pub use contract::WasmContract;
pub use network::WasmNetwork;
pub use privacy::WasmPrivacy;
pub use transaction::{WasmPskb, WasmTransaction};
pub use wallet::WasmWallet;

pub(super) fn js_error(error: crate::error::Error) -> wasm_bindgen::JsValue {
    wasm_bindgen::JsValue::from_str(&error.to_string())
}

pub(super) fn decode<T: serde::de::DeserializeOwned>(
    value: &str,
) -> Result<T, wasm_bindgen::JsValue> {
    serde_json::from_str(value)
        .map_err(|error| wasm_bindgen::JsValue::from_str(&format!("invalid JSON: {error}")))
}

pub(super) fn encode<T: serde::Serialize>(value: &T) -> Result<String, wasm_bindgen::JsValue> {
    serde_json::to_string(value)
        .map_err(|error| wasm_bindgen::JsValue::from_str(&format!("JSON encode failed: {error}")))
}

pub(super) fn decimal(value: &str, name: &str) -> Result<u64, wasm_bindgen::JsValue> {
    crate::primitives::serialization::decimal_u64::parse_canonical_decimal(value)
        .map_err(|error| wasm_bindgen::JsValue::from_str(&format!("invalid {name}: {error}")))
}
