use std::collections::{HashSet, VecDeque};

/// Bounded recent-key set used to suppress duplicate stream deliveries without
/// coupling deduplication to whichever records the current retention mode stores.
#[derive(Clone)]
pub struct RecentKeys {
    capacity: usize,
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl RecentKeys {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            set: HashSet::with_capacity(capacity.min(65_536)),
            order: VecDeque::with_capacity(capacity.min(65_536)),
        }
    }

    /// Returns true only for a key that was not already in the recent window.
    pub fn observe(&mut self, key: &str) -> bool {
        if self.set.contains(key) {
            return false;
        }
        let owned = key.to_owned();
        self.set.insert(owned.clone());
        self.order.push_back(owned);
        self.trim();
        true
    }

    pub fn clear(&mut self) {
        self.set.clear();
        self.order.clear();
    }

    fn trim(&mut self) {
        while self.order.len() > self.capacity {
            if let Some(key) = self.order.pop_front() {
                self.set.remove(&key);
            }
        }
    }
}

#[cfg(test)]
#[path = "unit-tests/dedupe.rs"]
mod unit_tests;
