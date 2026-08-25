use serde::Serialize;
use serde_json::Value;

/// Transaction view returned by `ChainApi::transaction`.
///
/// The local indexer is the lookup source. `raw` preserves the complete indexed
/// representation while the commonly needed transaction fields are surfaced
/// directly, including the payload.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainTransaction {
    pub txid: String,
    pub version: Option<u16>,
    pub inputs: Value,
    pub outputs: Value,
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    pub locktime: Option<u64>,
    pub subnetwork_id: Option<String>,
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    pub gas: Option<u64>,
    pub payload: Vec<u8>,
    pub raw: Value,
}

impl ChainTransaction {
    pub(crate) fn from_indexed_parts(txid: String, payload: Vec<u8>, raw: Value) -> Self {
        let version = field(&raw, &["version", "txVersion"])
            .and_then(value_u64)
            .and_then(|value| u16::try_from(value).ok());
        let inputs = field(&raw, &["inputs"])
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let outputs = field(&raw, &["outputs"])
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let locktime =
            field(&raw, &["lockTime", "locktime", "fallbackLockTime"]).and_then(value_u64);
        let subnetwork_id = field(&raw, &["subnetworkId", "subnetwork_id"])
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let gas = field(&raw, &["gas"]).and_then(value_u64);
        Self {
            txid,
            version,
            inputs,
            outputs,
            locktime,
            subnetwork_id,
            gas,
            payload,
            raw,
        }
    }
}

fn field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Value> {
    let object = value.as_object()?;
    names.iter().find_map(|name| object.get(*name))
}

fn value_u64(value: &Value) -> Option<u64> {
    match value {
        Value::String(text) => text.parse().ok(),
        Value::Number(number) => number.as_u64(),
        _ => None,
    }
}
