//! Password-to-key derivation for Kaspa Portal encrypted storage using Argon2id v=19.
//!
//! BIP39 is deliberately outside this abstraction: BIP39 seed derivation remains
//! PBKDF2-HMAC-SHA512/2048 because that algorithm is part of the BIP39 standard.

use alloc::vec::Vec;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const KDF_ID_ARGON2ID: u8 = 2;
pub const ARGON2_VERSION_13: u8 = 0x13;
pub const PROFILE_VERSION_1: u8 = 1;
pub const SALT_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const MAX_PASSWORD_SIZE: usize = 128;
pub const METADATA_SIZE: usize = 12;

/// Argon2 workspace block type for callers that need deterministic allocation.
/// Most applications should use the heap-backed convenience APIs; constrained
/// runtimes may provide an exact caller-owned workspace.
pub type PasswordKdfBlock = Block;
pub const WORKSPACE_BLOCK_BYTES: usize = core::mem::size_of::<PasswordKdfBlock>();
pub const WORKSPACE_BLOCK_ALIGN: usize = core::mem::align_of::<PasswordKdfBlock>();

// Fixed v1 policy. Runtime allocation failure never downgrades these parameters.
pub const V1_MEMORY_KIB: u32 = 2_048;
pub const V1_TIME_COST: u32 = 3;
pub const V1_PARALLELISM: u32 = 1;

const EFFECTIVE_SALT_DOMAIN: &[u8] = b"KaspaPortal/Argon2id/effective-salt/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordKdfPurpose {
    PortableBackup,
    PersistentWallet,
    EncryptedTransport,
}

impl PasswordKdfPurpose {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::PortableBackup => b"KaspaPortal/password-kdf/portable-backup/v1",
            Self::PersistentWallet => b"KaspaPortal/password-kdf/persistent-wallet/v1",
            Self::EncryptedTransport => b"KaspaPortal/password-kdf/encrypted-transport/v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordKdfParams {
    pub profile_version: u8,
    pub argon_version: u8,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl PasswordKdfParams {
    pub const fn current() -> Self {
        Self {
            profile_version: PROFILE_VERSION_1,
            argon_version: ARGON2_VERSION_13,
            m_cost_kib: V1_MEMORY_KIB,
            t_cost: V1_TIME_COST,
            p_cost: V1_PARALLELISM,
        }
    }

    pub const fn is_current(self) -> bool {
        // Every comparison is side-effect free. Bitwise boolean composition keeps
        // the exact-profile check branch-light while still evaluating every field.
        (self.profile_version == PROFILE_VERSION_1)
            & (self.argon_version == ARGON2_VERSION_13)
            & (self.m_cost_kib == V1_MEMORY_KIB)
            & (self.t_cost == V1_TIME_COST)
            & (self.p_cost == V1_PARALLELISM)
    }

    pub const fn meets_v1_minimum(self) -> bool {
        (self.argon_version == ARGON2_VERSION_13)
            & (self.m_cost_kib >= V1_MEMORY_KIB)
            & (self.t_cost >= V1_TIME_COST)
            & (self.p_cost >= V1_PARALLELISM)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PasswordKdfError {
    InvalidPasswordLength,
    UnsupportedParameters,
    AllocationFailed,
    DerivationFailed,
}

/// Canonical authenticated metadata for Kaspa Portal password-protected formats.
pub fn encode_metadata(
    parameters: PasswordKdfParams,
) -> Result<[u8; METADATA_SIZE], PasswordKdfError> {
    if !parameters.is_current() {
        return Err(PasswordKdfError::UnsupportedParameters);
    }
    let mut out = [0u8; METADATA_SIZE];
    out[0] = KDF_ID_ARGON2ID;
    out[1] = parameters.profile_version;
    out[2] = parameters.argon_version;
    out[3] = parameters.p_cost as u8;
    out[4..8].copy_from_slice(&parameters.m_cost_kib.to_le_bytes());
    out[8..12].copy_from_slice(&parameters.t_cost.to_le_bytes());
    Ok(out)
}

/// Parse authenticated KDF metadata. Unknown IDs, versions, or downgraded
/// parameters fail closed; readers accept only the authenticated current KDF profile.
pub fn parse_metadata(input: &[u8]) -> Result<PasswordKdfParams, PasswordKdfError> {
    if input.len() != METADATA_SIZE || input[0] != KDF_ID_ARGON2ID {
        return Err(PasswordKdfError::UnsupportedParameters);
    }
    let parameters = PasswordKdfParams {
        profile_version: input[1],
        argon_version: input[2],
        p_cost: u32::from(input[3]),
        m_cost_kib: u32::from_le_bytes([input[4], input[5], input[6], input[7]]),
        t_cost: u32::from_le_bytes([input[8], input[9], input[10], input[11]]),
    };
    if !parameters.is_current() {
        return Err(PasswordKdfError::UnsupportedParameters);
    }
    Ok(parameters)
}

/// Derive exactly 32 bytes with the current fixed Argon2id profile.
pub fn derive_key_32(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
) -> Result<[u8; KEY_SIZE], PasswordKdfError> {
    derive_key_32_with_params(purpose, password, salt, PasswordKdfParams::current())
}

/// Derive exactly 32 bytes using explicit authenticated parameters.
///
/// Current-format readers accept only the current v1 profile. This prevents an
/// attacker from lowering authenticated parameters and avoids accepting an
/// unrecognized future parameter profile as if it were current.
pub fn derive_key_32_with_params(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    parameters: PasswordKdfParams,
) -> Result<[u8; KEY_SIZE], PasswordKdfError> {
    validate_current_inputs(password, parameters)?;
    derive_heap_backed(purpose, password, salt, parameters)
}

/// Number of 1 KiB Argon2 blocks required by the supplied parameters.
///
/// Return the adjusted Argon2 block count required by the implementation.
pub fn workspace_block_count(parameters: PasswordKdfParams) -> Result<usize, PasswordKdfError> {
    Ok(build_params(parameters)?.block_count())
}

/// Current-format derivation using an exact caller-owned workspace.
pub fn derive_key_32_with_workspace(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    parameters: PasswordKdfParams,
    workspace: &mut [PasswordKdfBlock],
) -> Result<[u8; KEY_SIZE], PasswordKdfError> {
    validate_current_inputs(password, parameters)?;
    derive_core(purpose, password, salt, parameters, workspace)
}

fn validate_current_inputs(
    password: &[u8],
    parameters: PasswordKdfParams,
) -> Result<(), PasswordKdfError> {
    let valid_password = (!password.is_empty()) & (password.len() <= MAX_PASSWORD_SIZE);
    if !valid_password {
        return Err(PasswordKdfError::InvalidPasswordLength);
    }
    if !parameters.is_current() {
        return Err(PasswordKdfError::UnsupportedParameters);
    }
    Ok(())
}

#[cfg(test)]
fn validate_benchmark_inputs(
    password: &[u8],
    parameters: PasswordKdfParams,
) -> Result<(), PasswordKdfError> {
    validate_benchmark_password(password)?;
    validate_benchmark_identity(parameters)?;
    validate_benchmark_memory(parameters)?;
    validate_benchmark_parallel_cost(parameters)
}

#[cfg(test)]
fn validate_benchmark_password(password: &[u8]) -> Result<(), PasswordKdfError> {
    let valid = (!password.is_empty()) & (password.len() <= MAX_PASSWORD_SIZE);
    if !valid {
        return Err(PasswordKdfError::UnsupportedParameters);
    }
    Ok(())
}

#[cfg(test)]
fn validate_benchmark_identity(parameters: PasswordKdfParams) -> Result<(), PasswordKdfError> {
    let supported = (parameters.profile_version == PROFILE_VERSION_1)
        & (parameters.argon_version == ARGON2_VERSION_13);
    if !supported {
        return Err(PasswordKdfError::UnsupportedParameters);
    }
    Ok(())
}

#[cfg(test)]
fn validate_benchmark_memory(parameters: PasswordKdfParams) -> Result<(), PasswordKdfError> {
    if parameters.m_cost_kib < 1_024 {
        return Err(PasswordKdfError::UnsupportedParameters);
    }
    Ok(())
}

#[cfg(test)]
fn validate_benchmark_parallel_cost(parameters: PasswordKdfParams) -> Result<(), PasswordKdfError> {
    let valid = (parameters.t_cost > 0) & (parameters.p_cost > 0);
    if !valid {
        return Err(PasswordKdfError::UnsupportedParameters);
    }
    Ok(())
}

fn build_params(parameters: PasswordKdfParams) -> Result<Params, PasswordKdfError> {
    Params::new(
        parameters.m_cost_kib,
        parameters.t_cost,
        parameters.p_cost,
        Some(KEY_SIZE),
    )
    .map_err(|_| PasswordKdfError::UnsupportedParameters)
}

fn derive_effective_salt(purpose: PasswordKdfPurpose, salt: &[u8; SALT_SIZE]) -> [u8; 32] {
    let domain = purpose.domain();
    let mut hasher = Sha256::new();
    hasher.update(EFFECTIVE_SALT_DOMAIN);
    hasher.update([domain.len() as u8]);
    hasher.update(domain);
    hasher.update(salt);
    hasher.finalize().into()
}

#[cfg(test)]
pub fn derive_benchmark_key_32(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    parameters: PasswordKdfParams,
) -> Result<[u8; KEY_SIZE], PasswordKdfError> {
    validate_benchmark_inputs(password, parameters)?;
    derive_heap_backed(purpose, password, salt, parameters)
}

#[cfg(test)]
pub fn derive_benchmark_key_32_with_workspace(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    parameters: PasswordKdfParams,
    workspace: &mut [PasswordKdfBlock],
) -> Result<[u8; KEY_SIZE], PasswordKdfError> {
    validate_benchmark_inputs(password, parameters)?;
    derive_core(purpose, password, salt, parameters, workspace)
}

fn derive_heap_backed(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    parameters: PasswordKdfParams,
) -> Result<[u8; KEY_SIZE], PasswordKdfError> {
    let block_count = workspace_block_count(parameters)?;
    let mut workspace = Vec::<PasswordKdfBlock>::new();
    workspace
        .try_reserve_exact(block_count)
        .map_err(|_| PasswordKdfError::AllocationFailed)?;
    workspace.resize(block_count, PasswordKdfBlock::default());
    let result = derive_core(purpose, password, salt, parameters, &mut workspace);
    zeroize_workspace(&mut workspace);
    result
}

pub fn zeroize_workspace(workspace: &mut [PasswordKdfBlock]) {
    for block in workspace {
        block.as_mut().zeroize();
    }
}

fn derive_core(
    purpose: PasswordKdfPurpose,
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    parameters: PasswordKdfParams,
    workspace: &mut [PasswordKdfBlock],
) -> Result<[u8; KEY_SIZE], PasswordKdfError> {
    let params = build_params(parameters)?;
    if workspace.len() != params.block_count() {
        zeroize_workspace(workspace);
        return Err(PasswordKdfError::AllocationFailed);
    }
    let mut password_copy = [0u8; MAX_PASSWORD_SIZE];
    password_copy[..password.len()].copy_from_slice(password);
    let mut effective_salt = derive_effective_salt(purpose, salt);
    let mut output = [0u8; KEY_SIZE];
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let result = argon.hash_password_into_with_memory(
        &password_copy[..password.len()],
        &effective_salt,
        &mut output,
        &mut *workspace,
    );
    password_copy.zeroize();
    effective_salt.zeroize();
    zeroize_workspace(workspace);
    if result.is_err() {
        output.zeroize();
        Err(PasswordKdfError::DerivationFailed)
    } else {
        Ok(output)
    }
}

#[cfg(test)]
#[path = "unit-tests/password.rs"]
mod unit_tests;
