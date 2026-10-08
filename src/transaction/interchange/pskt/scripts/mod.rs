// Kaspa Portal — organized PSKT subsystem
// License: GPL-3.0

//! Signature-script construction for PSKT finalization. Finalization (and so
//! every builder but the shared push helpers) is host-side: the `no_std`
//! signing core produces signatures, not final transactions.

mod common;
#[cfg(feature = "std")]
mod contracts;
#[cfg(feature = "std")]
mod multisig;
#[cfg(feature = "std")]
mod p2pk;
#[cfg(feature = "std")]
mod router;

pub(crate) use common::push_data_item;
#[cfg(feature = "std")]
pub(crate) use common::push_data_sigscript;
pub use common::push_redeem_script;
#[cfg(feature = "std")]
pub(crate) use common::{first_schnorr_signature, push_int_sigscript};
#[cfg(feature = "std")]
pub(crate) use contracts::*;
#[cfg(feature = "std")]
pub(crate) use multisig::*;
#[cfg(feature = "std")]
pub(crate) use p2pk::*;
#[cfg(feature = "std")]
pub(crate) use router::{build_signature_script, ScriptBuildOptions};

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
