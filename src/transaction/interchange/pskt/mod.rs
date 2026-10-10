// Kaspa Portal — PSKT / PSKB protocol subsystem
// License: GPL-3.0

//! Organized PSKT/PSKB support. Wire handling, review, and the verify-once
//! [`pipeline`] (KSPT relay, signature merge and finalization) are separate
//! modules behind a single capability-oriented PSKT surface.

pub mod schema;
pub mod shared;
pub mod standard;

mod error;
pub(crate) mod exact_json;
mod model;
pub mod pipeline;
pub mod pskb;
mod review;
pub(crate) mod scripts;
pub(crate) mod wire;

pub use model::{InputSummary, OutputSummary, PartialSigInfo, PsktFormat, PsktSummary};
pub use review::parse_summary;
pub use scripts::push_redeem_script;
pub use wire::{detect_format_hex, set_payload, set_tx_lane};

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
