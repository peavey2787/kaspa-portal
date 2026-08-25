//! Final transaction submission to a Kaspa node.
pub(crate) mod encoder;
mod submit;
pub use submit::submit;

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
