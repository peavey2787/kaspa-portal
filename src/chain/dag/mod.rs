use serde::{Deserialize, Serialize};

use crate::primitives::DaaScore;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DagRange {
    pub from: DaaScore,
    pub to: DaaScore,
    pub limit: usize,
}

impl DagRange {
    pub fn new(from: DaaScore, to: DaaScore, limit: usize) -> Result<Self, String> {
        if from.get() > to.get() {
            return Err("DAG range start exceeds end".into());
        }
        if limit == 0 {
            return Err("DAG range limit must be > 0".into());
        }
        if limit > 100_000 {
            return Err("DAG range limit exceeds 100000".into());
        }
        Ok(Self { from, to, limit })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DagCheckpoint {
    pub daa_score: DaaScore,
    pub block_hash: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DagWalker {
    checkpoints: Vec<DagCheckpoint>,
    cursor: usize,
}

impl DagWalker {
    pub fn from_checkpoints(checkpoints: Vec<DagCheckpoint>) -> Self {
        Self {
            checkpoints,
            cursor: 0,
        }
    }

    pub fn remaining(&self) -> usize {
        self.checkpoints.len().saturating_sub(self.cursor)
    }
}

impl Iterator for DagWalker {
    type Item = DagCheckpoint;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.checkpoints.get(self.cursor).cloned();
        if item.is_some() {
            self.cursor += 1;
        }
        item
    }
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
