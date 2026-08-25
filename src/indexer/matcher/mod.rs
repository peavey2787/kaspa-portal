use serde::{Deserialize, Serialize};

use crate::indexer::event::IndexedTransaction;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum MatchRule {
    Address(String),
    PayloadPrefix(Vec<u8>),
    PayloadContains(Vec<u8>),
    PayloadExact(Vec<u8>),
    PayloadSuffix(Vec<u8>),
}

impl MatchRule {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Address(address) if address.trim().is_empty() => {
                Err("address matcher cannot be empty".into())
            }
            Self::Address(_) => Ok(()),
            Self::PayloadPrefix(value)
            | Self::PayloadContains(value)
            | Self::PayloadExact(value)
            | Self::PayloadSuffix(value) => validate_payload_matcher(value),
        }
    }

    pub fn matches(&self, transaction: &IndexedTransaction) -> bool {
        match self {
            Self::Address(address) => transaction.addresses.iter().any(|item| item == address),
            Self::PayloadPrefix(value) => transaction.payload.starts_with(value),
            Self::PayloadContains(value) => contains(&transaction.payload, value),
            Self::PayloadExact(value) => transaction.payload == *value,
            Self::PayloadSuffix(value) => transaction.payload.ends_with(value),
        }
    }
}

fn validate_payload_matcher(value: &[u8]) -> Result<(), String> {
    if value.is_empty() {
        return Err("payload matcher cannot be empty".into());
    }
    if value.len() > 4096 {
        return Err("payload matcher exceeds 4096 bytes".into());
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Matcher {
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub id: u64,
    pub rule: MatchRule,
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
