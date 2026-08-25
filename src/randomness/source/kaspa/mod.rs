use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

/// Public Kaspa-chain evidence admitted to the randomness beacon.
///
/// `finalized` is explicit so an application cannot accidentally feed an
/// unconfirmed candidate block into the beacon while calling it final.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KaspaEntropyEvidence {
    pub block_hash: [u8; 32],
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    pub daa_score: Option<u64>,
    pub finalized: bool,
}

impl KaspaEntropyEvidence {
    pub fn finalized(block_hash: [u8; 32], daa_score: Option<u64>) -> Self {
        Self {
            block_hash,
            daa_score,
            finalized: true,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.block_hash.iter().all(|byte| *byte == 0) {
            return Err("zero Kaspa block hash rejected".into());
        }
        if !self.finalized {
            return Err("Kaspa randomness evidence must be finalized".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct KaspaBlockBuffer {
    inner: Arc<Mutex<VecDeque<KaspaEntropyEvidence>>>,
    capacity: usize,
}

impl Default for KaspaBlockBuffer {
    fn default() -> Self {
        const DEFAULT_CAPACITY: usize = 64;
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(DEFAULT_CAPACITY))),
            capacity: DEFAULT_CAPACITY,
        }
    }
}

impl KaspaBlockBuffer {
    pub fn new(capacity: usize) -> Result<Self, String> {
        if !(1..=256).contains(&capacity) {
            return Err("Kaspa block buffer capacity must be 1..=256".into());
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        })
    }

    pub fn push(&self, value: KaspaEntropyEvidence) -> Result<(), String> {
        value.validate()?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "Kaspa block buffer lock poisoned")?;
        if guard
            .back()
            .map(|existing| existing.block_hash == value.block_hash)
            .unwrap_or(false)
        {
            return Ok(());
        }
        if let (Some(previous), Some(current)) = (
            guard.back().and_then(|item| item.daa_score),
            value.daa_score,
        ) {
            if current < previous {
                return Err("Kaspa evidence DAA score moved backwards".into());
            }
        }
        guard.push_back(value);
        while guard.len() > self.capacity {
            guard.pop_front();
        }
        Ok(())
    }

    pub fn recent(&self, count: usize) -> Result<Vec<KaspaEntropyEvidence>, String> {
        if count == 0 || count > self.capacity {
            return Err("requested Kaspa evidence count outside buffer bounds".into());
        }
        let guard = self
            .inner
            .lock()
            .map_err(|_| "Kaspa block buffer lock poisoned")?;
        if guard.len() < count {
            return Err(format!(
                "need {count} Kaspa blocks but only {} observed",
                guard.len()
            ));
        }
        Ok(guard.iter().skip(guard.len() - count).cloned().collect())
    }
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
