//! Lossless JSON adapters for exact consensus integers at browser boundaries.

pub mod decimal_opt_u64;
pub mod decimal_u64;

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
