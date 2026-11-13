//! Final transaction submission to a Kaspa node.
pub mod encoder;
mod submit;
pub use submit::{submit, submit_replacement};

#[cfg(test)]
#[path = "unit_tests/mod.rs"]
mod unit_tests;
