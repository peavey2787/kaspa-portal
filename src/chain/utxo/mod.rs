//! UTXO chain semantics.

pub use crate::primitives::utxo::UtxoEntry;

/// Chain-facing semantic name for a spendable Kaspa output.
pub type Utxo = UtxoEntry;
