// Kaspa Portal — organized PSKT subsystem
// License: GPL-3.0

//! Script push helpers shared by PSKT witness materialization.

mod common;

pub(crate) use common::push_data_item;
pub use common::push_redeem_script;

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
