//! The specialized covenant templates this pipeline can witness, recognized
//! by the contract builders that define them.

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::contract::{
    commit_reveal::commit_reveal_script_fields,
    covenant::{oracle_v1_attestation_binding, private_swap_script_fields},
    merkle::merkle_whitelist_script_fields,
};

/// Merkle proof levels a `covenantExecution` mask can select (bit 0 is the
/// claim branch, one bit per level after it).
const MAX_MERKLE_DEPTH: u8 = 15;

pub(crate) struct OracleTemplate {
    pub(crate) commitment: [u8; 32],
    pub(crate) oracle_key: [u8; 32],
}

pub(crate) struct CommitTemplate {
    pub(crate) commitment: [u8; 32],
}

pub(crate) struct MerkleTemplate {
    pub(crate) root: [u8; 32],
    pub(crate) depth: u8,
}

pub(crate) fn recognize_private_swap(script: &[u8]) -> Result<(), String> {
    private_swap_script_fields(script)
        .map(|_| ())
        .ok_or_else(|| "not a canonical Private Swap script".to_string())
}

pub(crate) fn recognize_oracle_v1(script: &[u8]) -> Result<OracleTemplate, String> {
    let (_, commitment, oracle_key) = oracle_v1_attestation_binding(script)
        .ok_or_else(|| "not a canonical Oracle-v1 script".to_string())?;
    Ok(OracleTemplate {
        commitment,
        oracle_key,
    })
}

pub(crate) fn recognize_commit_reveal(script: &[u8]) -> Result<CommitTemplate, String> {
    let fields = commit_reveal_script_fields(script)
        .ok_or_else(|| "not a canonical commit-reveal script".to_string())?;
    Ok(CommitTemplate {
        commitment: fields.committed_hash,
    })
}

pub(crate) fn recognize_merkle(script: &[u8]) -> Result<MerkleTemplate, String> {
    let fields = merkle_whitelist_script_fields(script)
        .ok_or_else(|| "not a canonical Merkle-whitelist script".to_string())?;
    if fields.depth > MAX_MERKLE_DEPTH {
        return Err("merkle depth exceeds selector capacity".to_string());
    }
    Ok(MerkleTemplate {
        root: fields.merkle_root,
        depth: fields.depth,
    })
}
