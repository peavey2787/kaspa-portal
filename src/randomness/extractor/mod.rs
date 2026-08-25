mod canonical;
mod folding;
mod positions;
pub use canonical::{canonical_evidence, CanonicalEvidence};
pub use folding::{extract_and_fold, ExtractorConfig};
pub use positions::derive_positions;
