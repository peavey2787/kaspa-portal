//! Consensus-wide size ceilings shared by every domain.

/// Largest serialized transaction a Toccata block can hold: the 1,000,000
/// gram per-block transient mass limit at 4 grams per serialized byte
/// (rusty-kaspa `new_transient_mass_limit` / `TRANSIENT_BYTE_TO_MASS_FACTOR`).
pub const MAX_SERIALIZED_TRANSACTION_BYTES: usize = 250_000;
