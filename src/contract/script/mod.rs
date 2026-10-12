#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
mod locktime;
mod number;
pub use crate::primitives::opcode;
pub mod p2sh;
mod push;
mod standard;
pub mod walk;

pub use locktime::{extract_cltv_locktime, extract_csv_sequence};
pub(crate) use number::element_integer;
pub use number::push_int;
pub use push::{push_data, push_pubkey};
pub use standard::{p2pk_xonly, p2sh_hash};

/// Every element of a well-formed script, for template recognizers that
/// read their variable fields and then rebuild the script to compare.
pub(crate) fn complete_elements(
    script: &[u8],
) -> Option<Vec<crate::primitives::script::Element<'_>>> {
    let mut walker = crate::primitives::script::elements(script);
    let collected = walker.by_ref().collect::<Vec<_>>();
    walker.is_complete().then_some(collected)
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
