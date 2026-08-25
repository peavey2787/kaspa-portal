//! Lossless JSON representation for optional consensus `u64` values.

use serde::{Deserialize, Deserializer, Serializer};

use super::decimal_u64::parse_canonical_decimal;

pub fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(value) => serializer.serialize_some(&value.to_string()),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    value
        .map(|text| parse_canonical_decimal(&text).map_err(serde::de::Error::custom))
        .transpose()
}
