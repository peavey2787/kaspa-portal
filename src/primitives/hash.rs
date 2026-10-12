//! BLAKE2b-256, the hash behind Kaspa addresses, scripts, signature hashes
//! and covenant identities. Every BLAKE2b use in Portal goes through here.

/// A 32-byte digest.
pub type Hash32 = [u8; 32];

/// Incremental BLAKE2b-256, optionally keyed for domain separation (Kaspa's
/// hashers key with their domain, e.g. `b"TransactionSigningHash"`).
#[derive(Clone)]
pub struct Blake2b256(blake2b_simd::State);

impl Blake2b256 {
    /// Unkeyed hasher.
    #[must_use]
    pub fn new() -> Self {
        Self(blake2b_simd::Params::new().hash_length(32).to_state())
    }

    /// Hasher keyed with `domain` (at most 64 bytes).
    #[must_use]
    pub fn keyed(domain: &[u8]) -> Self {
        Self(
            blake2b_simd::Params::new()
                .hash_length(32)
                .key(domain)
                .to_state(),
        )
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    #[must_use]
    pub fn finalize(&self) -> Hash32 {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(self.0.finalize().as_bytes());
        digest
    }
}

impl Default for Blake2b256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Unkeyed BLAKE2b-256 of `data`.
#[must_use]
pub fn blake2b_256(data: &[u8]) -> Hash32 {
    Blake2b256::new().update(data).finalize()
}

#[cfg(test)]
#[path = "unit-tests/hash.rs"]
mod unit_tests;
