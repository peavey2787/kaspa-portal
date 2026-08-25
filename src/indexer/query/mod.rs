use serde::{Deserialize, Serialize};

use crate::indexer::event::{IndexedBlock, IndexedMatch, IndexedTransaction};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PageRequest {
    pub offset: usize,
    pub limit: usize,
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 100,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub offset: usize,
    pub limit: usize,
    pub total: usize,
    pub has_more: bool,
}

pub fn page<T: Clone>(
    items: &[T],
    request: PageRequest,
    max_page: usize,
) -> Result<Page<T>, String> {
    if request.limit == 0 {
        return Err("page limit must be > 0".into());
    }
    if request.limit > max_page {
        return Err(format!("page limit exceeds configured maximum {max_page}"));
    }

    let start = request.offset.min(items.len());
    let end = start.saturating_add(request.limit).min(items.len());
    Ok(Page {
        items: items[start..end].to_vec(),
        offset: start,
        limit: request.limit,
        total: items.len(),
        has_more: end < items.len(),
    })
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransactionQuery {
    pub address: Option<String>,
    #[serde(with = "crate::primitives::serialization::decimal_opt_u64")]
    pub after_daa_score: Option<u64>,
    pub page: PageRequest,
}

pub fn filter_transactions(
    mut values: Vec<IndexedTransaction>,
    query: &TransactionQuery,
) -> Vec<IndexedTransaction> {
    values.retain(|value| {
        address_matches(value, query.address.as_deref())
            && daa_score_matches(value, query.after_daa_score)
    });
    values.sort_by_key(|value| (value.daa_score.unwrap_or(0), value.observed_at_ms));
    values
}

fn address_matches(transaction: &IndexedTransaction, address: Option<&str>) -> bool {
    address
        .map(|expected| transaction.addresses.iter().any(|item| item == expected))
        .unwrap_or(true)
}

fn daa_score_matches(transaction: &IndexedTransaction, after: Option<u64>) -> bool {
    after
        .map(|minimum| {
            transaction
                .daa_score
                .map(|score| score > minimum)
                .unwrap_or(false)
        })
        .unwrap_or(true)
}

pub type TransactionPage = Page<IndexedTransaction>;
pub type BlockPage = Page<IndexedBlock>;
pub type MatchPage = Page<IndexedMatch>;

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
