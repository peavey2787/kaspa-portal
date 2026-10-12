#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use serde_json::{Map, Value};

pub(crate) fn parse_exact_u64(value: &Value, field: &str) -> Result<u64, String> {
    match value {
        Value::String(text) => parse_decimal_u64(text, field),
        _ => Err(format!("{field} must be a canonical decimal string")),
    }
}

/// Require every exact-integer PSKT field to be a canonical decimal string:
/// the output amounts always, the optional global and input fields when present.
pub(crate) fn validate_pskt_exact_fields(pskt: &Value) -> Result<(), String> {
    let document = pskt
        .as_object()
        .ok_or_else(|| "PSKT must be an object".to_string())?;
    if let Some(global) = document.get("global").and_then(Value::as_object) {
        validate_optional_fields(global, &["fallbackLockTime", "gas"])?;
    }
    for (index, input) in array(document, "inputs").iter().enumerate() {
        let object = input
            .as_object()
            .ok_or_else(|| format!("input[{index}] must be an object"))?;
        validate_optional_fields(object, &["sequence", "minTime"])?;
        if let Some(utxo) = object.get("utxoEntry").and_then(Value::as_object) {
            validate_optional_fields(utxo, &["amount", "blockDaaScore"])?;
        }
    }
    for (index, output) in array(document, "outputs").iter().enumerate() {
        let amount = output
            .as_object()
            .ok_or_else(|| format!("output[{index}] must be an object"))?
            .get("amount")
            .ok_or_else(|| "missing amount".to_string())?;
        parse_exact_u64(amount, "amount")?;
    }
    Ok(())
}

fn array<'a>(document: &'a Map<String, Value>, field: &str) -> &'a [Value] {
    document
        .get(field)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn validate_optional_fields(object: &Map<String, Value>, fields: &[&str]) -> Result<(), String> {
    for field in fields {
        match object.get(*field) {
            None | Some(Value::Null) => {}
            Some(value) => {
                parse_exact_u64(value, field)?;
            }
        }
    }
    Ok(())
}

fn parse_decimal_u64(text: &str, field: &str) -> Result<u64, String> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.as_bytes()[0] == b'0')
    {
        return Err(format!(
            "{field} must be a canonical unsigned decimal string"
        ));
    }
    text.parse::<u64>()
        .map_err(|error| format!("invalid {field}: {error}"))
}
