//! RFC 9381 ECVRF-EDWARDS25519-SHA512-ELL2.
//!
//! This subsystem is deliberately independent from Kaspa wallet keys and from
//! the public beacon/extractor. Never reuse a Kaspa spending key as a VRF key.

use serde::{Deserialize, Serialize};
use vrf_rfc9381::ec::edwards25519::{
    elligator2::{EdVrfEdwards25519Ell2PublicKey, EdVrfEdwards25519Ell2SecretKey},
    EdVrfProof,
};
use vrf_rfc9381::{Ciphersuite, Proof as _, Prover, Verifier};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

pub const VRF_SUITE: &str = "ECVRF-EDWARDS25519-SHA512-ELL2";
pub const VRF_PROOF_LEN: usize = 80;
pub const VRF_OUTPUT_LEN: usize = 64;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VrfSecretKey([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VrfPublicKey(pub [u8; 32]);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VrfProof(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VrfOutput(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VrfResult {
    pub output: VrfOutput,
    pub proof: VrfProof,
}

impl VrfSecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// RFC 9381's Edwards25519 suites derive the public key from the same
    /// 32-byte RFC 8032 seed representation used here.
    pub fn public_key(&self) -> VrfPublicKey {
        let signing = ed25519_dalek::SigningKey::from_bytes(&self.0);
        VrfPublicKey(signing.verifying_key().to_bytes())
    }

    #[cfg(feature = "secret-export")]
    pub fn expose_secret(&self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct VrfApi;

impl VrfApi {
    pub(crate) fn new() -> Self {
        Self
    }

    pub fn generate_keypair(&self) -> Result<(VrfSecretKey, VrfPublicKey)> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|error| Error::Vrf(format!("OS CSPRNG failed: {error}")))?;
        let secret = VrfSecretKey::from_bytes(seed);
        let public = secret.public_key();
        Ok((secret, public))
    }

    pub fn prove(&self, secret: &VrfSecretKey, input: &[u8]) -> Result<VrfResult> {
        prove(secret, input).map_err(Error::Vrf)
    }

    pub fn verify(
        &self,
        public: &VrfPublicKey,
        input: &[u8],
        proof: &VrfProof,
    ) -> Result<VrfOutput> {
        verify(public, input, proof).map_err(Error::Vrf)
    }
}

fn prove(secret: &VrfSecretKey, input: &[u8]) -> core::result::Result<VrfResult, String> {
    let prover = EdVrfEdwards25519Ell2SecretKey::from_slice(&secret.0)
        .map_err(|error| format!("invalid VRF secret key: {error}"))?;
    let proof = prover
        .prove(input)
        .map_err(|error| format!("VRF prove failed: {error}"))?;
    let output = proof
        .proof_to_hash(Ciphersuite::ECVRF_EDWARDS25519_SHA512_ELL2)
        .map_err(|error| format!("VRF proof-to-hash failed: {error}"))?;
    Ok(VrfResult {
        output: VrfOutput(output.to_vec()),
        proof: VrfProof(proof.encode_to_pi()),
    })
}

fn verify(
    public: &VrfPublicKey,
    input: &[u8],
    proof: &VrfProof,
) -> core::result::Result<VrfOutput, String> {
    if proof.0.len() != VRF_PROOF_LEN {
        return Err(format!("VRF proof must be {VRF_PROOF_LEN} bytes"));
    }
    let verifier = EdVrfEdwards25519Ell2PublicKey::from_slice(&public.0)
        .map_err(|error| format!("invalid VRF public key: {error}"))?;
    let decoded =
        EdVrfProof::decode_pi(&proof.0).map_err(|error| format!("invalid VRF proof: {error}"))?;
    let output = verifier
        .verify(input, decoded)
        .map_err(|error| format!("VRF verification failed: {error}"))?;
    Ok(VrfOutput(output.to_vec()))
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
