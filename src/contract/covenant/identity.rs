//! KIP-20 covenant identity and genesis proofs.
//!
//! A covenant ID is fixed when the covenant is created: consensus hashes the
//! outpoint the authorizing input spends together with every output that input
//! authorizes (rusty-kaspa `consensus/core/src/hashing/covenant_id.rs`). The ID
//! then stays the same through every continuation while the P2SH script may
//! change. Because the hash commits to the initial scripts, values and the
//! unique genesis outpoint, anyone holding those preimages can prove what a
//! covenant ID was created as without trusting an indexer:
//!
//! 1. [`verify_genesis`] recomputes the ID from the genesis outpoint and the
//!    authorized outputs and compares it with the claimed ID;
//! 2. [`verify_redeem_script`] proves an authorized output locks the published
//!    redeem script (its P2SH script commits to the script's BLAKE2b hash);
//! 3. `ConsensusTransaction::covenant_genesis` extracts and verifies the
//!    genesis group from the genesis transaction itself.
//!
//! A live covenant UTXO whose node-reported `covenantId` equals the verified ID
//! belongs to that lineage; consensus enforces every continuation.

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::{contract::script::p2sh_hash, primitives::address::script_hash};

/// Domain key of the consensus `CovenantID` BLAKE2b hasher.
const COVENANT_ID_DOMAIN: &[u8] = b"CovenantID";

/// The outpoint a covenant's authorizing input spends at genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisOutpoint {
    pub transaction_id: [u8; 32],
    pub index: u32,
}

/// One output a genesis input authorizes, as committed by the covenant ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizedOutput<'a> {
    /// Position of the output in the genesis transaction.
    pub index: u32,
    pub value: u64,
    pub spk_version: u16,
    pub spk_script: &'a [u8],
}

/// A verified covenant genesis: the claimed ID matches its preimage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CovenantGenesis<'a> {
    pub covenant_id: [u8; 32],
    pub outpoint: GenesisOutpoint,
    /// Input of the genesis transaction that authorized the outputs.
    pub authorizing_input: u16,
    pub outputs: Vec<AuthorizedOutput<'a>>,
}

/// Why a covenant genesis proof was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CovenantProofError {
    #[error("covenant genesis authorizes no outputs")]
    NoAuthorizedOutputs,
    #[error("authorized output indices must be strictly ascending")]
    OutputsNotOrdered,
    #[error("recomputed covenant ID does not match the claimed ID")]
    IdMismatch,
    #[error("outputs bound to the covenant name more than one authorizing input")]
    MixedAuthorizingInputs,
    #[error("authorizing input {0} is not in the transaction")]
    NoSuchInput(u16),
    #[error("output does not lock a version-0 P2SH script")]
    NotPayToScriptHash,
    #[error("output does not lock the given redeem script")]
    RedeemScriptMismatch,
}

/// The KIP-20 covenant ID of `outputs` authorized by the input spending
/// `genesis`; byte-for-byte the consensus computation.
#[must_use]
pub fn covenant_id(genesis: GenesisOutpoint, outputs: &[AuthorizedOutput<'_>]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .key(COVENANT_ID_DOMAIN)
        .to_state();
    state
        .update(&genesis.transaction_id)
        .update(&genesis.index.to_le_bytes())
        .update(&(outputs.len() as u64).to_le_bytes());
    for output in outputs {
        state
            .update(&output.index.to_le_bytes())
            .update(&output.value.to_le_bytes())
            .update(&output.spk_version.to_le_bytes())
            .update(&(output.spk_script.len() as u64).to_le_bytes())
            .update(output.spk_script);
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(state.finalize().as_bytes());
    id
}

/// Proves `claimed` is the covenant created by the input spending `genesis`
/// with exactly `outputs`. Consensus only admits genesis groups whose output
/// indices are non-empty and strictly ascending, so other shapes are refused.
///
/// ```
/// use kaspa_portal::contract::covenant::identity::{
///     covenant_id, verify_genesis, verify_redeem_script, AuthorizedOutput, GenesisOutpoint,
/// };
///
/// let redeem = [0x51];
/// let mut p2sh = vec![0xaa, 0x20];
/// p2sh.extend_from_slice(&kaspa_portal::primitives::address::script_hash(&redeem));
/// p2sh.push(0x87);
/// let genesis = GenesisOutpoint { transaction_id: [0x88; 32], index: 3 };
/// let outputs = [AuthorizedOutput { index: 0, value: 1_000, spk_version: 0, spk_script: &p2sh }];
/// let claimed = covenant_id(genesis, &outputs); // as published, e.g. by a node
///
/// assert!(verify_genesis(&claimed, genesis, &outputs).is_ok());
/// assert!(verify_redeem_script(&outputs[0], &redeem).is_ok());
/// let elsewhere = GenesisOutpoint { index: 4, ..genesis };
/// assert!(verify_genesis(&claimed, elsewhere, &outputs).is_err());
/// ```
pub fn verify_genesis(
    claimed: &[u8; 32],
    genesis: GenesisOutpoint,
    outputs: &[AuthorizedOutput<'_>],
) -> Result<(), CovenantProofError> {
    if outputs.is_empty() {
        return Err(CovenantProofError::NoAuthorizedOutputs);
    }
    if !outputs.windows(2).all(|pair| pair[0].index < pair[1].index) {
        return Err(CovenantProofError::OutputsNotOrdered);
    }
    if covenant_id(genesis, outputs) != *claimed {
        return Err(CovenantProofError::IdMismatch);
    }
    Ok(())
}

/// Proves `output` locks `redeem_script`: a version-0 P2SH script committing
/// to the redeem script's hash.
pub fn verify_redeem_script(
    output: &AuthorizedOutput<'_>,
    redeem_script: &[u8],
) -> Result<(), CovenantProofError> {
    let committed = match (output.spk_version, p2sh_hash(output.spk_script)) {
        (0, Some(hash)) => hash,
        _ => return Err(CovenantProofError::NotPayToScriptHash),
    };
    if committed != script_hash(redeem_script) {
        return Err(CovenantProofError::RedeemScriptMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[path = "unit-tests/identity.rs"]
mod unit_tests;
