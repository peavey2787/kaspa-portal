use serde::{Deserialize, Serialize};

/// Controls which classes of data the lightweight indexer retains.
///
/// Matching is always evaluated when matchers are configured so callers can
/// consume match events even when those records are not persisted.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum IndexingMode {
    #[default]
    All,
    Transactions,
    Matches,
    Blocks,
    Custom {
        transactions: bool,
        matches: bool,
        blocks: bool,
    },
}

impl IndexingMode {
    pub const fn retains_transactions(self) -> bool {
        match self {
            Self::All | Self::Transactions => true,
            Self::Matches | Self::Blocks => false,
            Self::Custom { transactions, .. } => transactions,
        }
    }

    pub const fn retains_matches(self) -> bool {
        match self {
            Self::All | Self::Matches => true,
            Self::Transactions | Self::Blocks => false,
            Self::Custom { matches, .. } => matches,
        }
    }

    pub const fn retains_blocks(self) -> bool {
        match self {
            Self::All | Self::Blocks => true,
            Self::Transactions | Self::Matches => false,
            Self::Custom { blocks, .. } => blocks,
        }
    }

    /// A match-only index still retains the matching transaction itself so
    /// match queries never point at missing transaction data.
    pub const fn retains_transaction(self, is_match: bool) -> bool {
        self.retains_transactions() || (self.retains_matches() && is_match)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexerConfig {
    #[serde(default)]
    pub mode: IndexingMode,
    pub max_transactions: usize,
    pub max_blocks: usize,
    pub max_matches: usize,
    pub dedupe_window: usize,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub scanner_stale_after_ms: u64,
    #[serde(with = "crate::primitives::serialization::decimal_u64")]
    pub transaction_ttl_ms: u64,
    pub max_payload_bytes: usize,
    pub max_addresses_per_transaction: usize,
    pub max_query_page: usize,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        Self {
            mode: IndexingMode::All,
            max_transactions: 50_000,
            max_blocks: 5_000,
            max_matches: 20_000,
            dedupe_window: 4_096,
            scanner_stale_after_ms: 60_000,
            transaction_ttl_ms: 24 * 60 * 60 * 1000,
            max_payload_bytes: 16_384,
            max_addresses_per_transaction: 256,
            max_query_page: 500,
        }
    }
}

impl IndexerConfig {
    pub fn validate(&self) -> Result<(), String> {
        validate_limits(self)?;
        if self.dedupe_window == 0 || self.dedupe_window > 1_000_000 {
            return Err("dedupe_window must be 1..=1000000".into());
        }
        if self.scanner_stale_after_ms == 0 || self.scanner_stale_after_ms > 86_400_000 {
            return Err("scanner_stale_after_ms must be 1..=86400000".into());
        }
        if !(1..=4096).contains(&self.max_query_page) {
            return Err("max_query_page must be 1..=4096".into());
        }
        if self.max_payload_bytes > 1_048_576 {
            return Err("max_payload_bytes exceeds 1 MiB".into());
        }
        if self.max_addresses_per_transaction > 4096 {
            return Err("max_addresses_per_transaction exceeds hard safety bound".into());
        }
        Ok(())
    }
}

fn validate_limits(config: &IndexerConfig) -> Result<(), String> {
    if config.max_transactions == 0 || config.max_blocks == 0 || config.max_matches == 0 {
        return Err("index limits must be > 0".into());
    }
    if config.max_transactions > 1_000_000 {
        return Err("max_transactions exceeds hard safety bound".into());
    }
    if config.max_blocks > 100_000 {
        return Err("max_blocks exceeds hard safety bound".into());
    }
    if config.max_matches > 1_000_000 {
        return Err("max_matches exceeds hard safety bound".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "unit-tests/config.rs"]
mod unit_tests;
