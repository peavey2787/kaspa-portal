mod locktime;
mod number;
pub use crate::primitives::opcode;
pub mod p2sh;
mod push;
mod standard;
pub mod walk;

pub use locktime::{extract_cltv_locktime, extract_csv_sequence};
pub use number::push_int;
pub(crate) use number::read_canonical_u64;
pub use push::{push_data, push_pubkey};
pub use standard::{p2pk_xonly, p2sh_hash};

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
