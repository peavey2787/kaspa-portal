use crate::primitives::bytes::zeroize_bytes;

use crate::{
    transaction::{
        model::{SigHashType, Transaction},
        sighash,
    },
    wallet::derivation::bip32,
};

use super::super::{error::PsktError, validation::validate_base_transaction};
use super::{
    sign_input_with_optional_entropy, signature_state::set_single_signature,
    stealth::stealth_spend_key,
};

fn sign_standard_input(
    tx: &mut Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    target_public_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<bool, PsktError> {
    let key =
        derive_standard_input_key(tx, input_index, account_key, target_public_key, checkpoint)?;
    let Some(key) = key else {
        return Ok(false);
    };
    let mut private_key = *key.private_key_bytes();
    let compressed_public_key = key
        .public_key_compressed()
        .map_err(|_| PsktError::DerivationFailed)?;
    let signature_result = match signing_entropy {
        Some(entropy) => {
            sighash::sign_input_with_entropy(tx, input_index, &private_key, sighash_type, entropy)
        }
        None => sighash::sign_input(tx, input_index, &private_key, sighash_type),
    };
    zeroize_bytes(&mut private_key);
    let signature = signature_result.map_err(|_| PsktError::SigningFailed)?;
    set_single_signature(
        &mut tx.inputs[input_index],
        signature.bytes,
        sighash_type.to_byte(),
        0,
        compressed_public_key,
    );
    Ok(true)
}

fn derive_standard_input_key(
    tx: &Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    target_public_key: &[u8; 32],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<Option<bip32::ExtendedPrivKey>, PsktError> {
    let input = &tx.inputs[input_index];
    if let Some(hint) = input.derivation_hint {
        return derive_hinted_input_key(
            account_key,
            hint.branch,
            hint.index,
            target_public_key,
            checkpoint,
        );
    }
    let Some((address_index, is_change)) = bip32::find_address_index_for_pubkey_with_checkpoint(
        account_key,
        target_public_key,
        checkpoint,
    ) else {
        return Ok(None);
    };
    derive_child_key(account_key, u32::from(address_index), u8::from(is_change)).map(Some)
}

fn derive_hinted_input_key(
    account_key: &bip32::ExtendedPrivKey,
    branch: u8,
    index: u32,
    target_public_key: &[u8; 32],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<Option<bip32::ExtendedPrivKey>, PsktError> {
    if branch > 1 || index >= crate::wallet::derivation::bip32::HARDENED_BIT {
        return Ok(None);
    }
    checkpoint();
    let key = derive_child_key(account_key, index, branch)?;
    checkpoint();
    let derived_public_key = key
        .public_key_x_only()
        .map_err(|_| PsktError::DerivationFailed)?;
    if &derived_public_key != target_public_key {
        return Ok(None);
    }
    Ok(Some(key))
}

fn derive_child_key(
    account_key: &bip32::ExtendedPrivKey,
    index: u32,
    branch: u8,
) -> Result<bip32::ExtendedPrivKey, PsktError> {
    if branch == 1 {
        bip32::derive_change_key(account_key, index)
    } else {
        bip32::derive_address_key(account_key, index)
    }
    .map_err(|_| PsktError::DerivationFailed)
}

fn sign_stealth_input(
    tx: &mut Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    target_public_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<bool, PsktError> {
    let Some(tweak) = tx.stealth_tweak else {
        return Ok(false);
    };
    let Some(mut key) =
        stealth_spend_key(account_key.private_key_bytes(), &tweak, target_public_key)?
    else {
        return Ok(false);
    };
    let signature = sign_input_with_optional_entropy(
        tx,
        input_index,
        &key.private_key,
        sighash_type,
        signing_entropy,
    );
    zeroize_bytes(&mut key.private_key);
    set_single_signature(
        &mut tx.inputs[input_index],
        signature?,
        sighash_type.to_byte(),
        0,
        key.compressed_public_key,
    );
    Ok(true)
}

/// Sign one receive/change/stealth P2PK input for an account key.
pub fn sign_account_input_with_entropy(
    tx: &mut Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
) -> Result<bool, PsktError> {
    let mut no_checkpoint = || {};
    sign_account_input_with_entropy_checkpointed(
        tx,
        input_index,
        account_key,
        sighash_type,
        signing_entropy,
        &mut no_checkpoint,
    )
}

/// Watchdog-friendly account-input signer. The checkpoint is called throughout
/// address-key matching rather than only around the entire search.
pub fn sign_account_input_with_entropy_checkpointed(
    tx: &mut Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<bool, PsktError> {
    let target = super::p2pk::checked_target(tx, input_index)?;
    sign_account_target(
        tx,
        input_index,
        account_key,
        sighash_type,
        signing_entropy,
        target,
        checkpoint,
    )
}

fn sign_account_target(
    tx: &mut Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
    target: Option<[u8; 32]>,
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Result<bool, PsktError> {
    let Some(target) = target else {
        return Ok(false);
    };
    sign_standard_input(
        tx,
        input_index,
        account_key,
        &target,
        sighash_type,
        Some(signing_entropy),
        checkpoint,
    )
    .and_then(|signed| {
        continue_account_signing(
            tx,
            input_index,
            account_key,
            &target,
            sighash_type,
            signing_entropy,
            signed,
        )
    })
}

fn continue_account_signing(
    tx: &mut Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    target: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
    signed: bool,
) -> Result<bool, PsktError> {
    if signed {
        return Ok(true);
    }
    sign_stealth_input(
        tx,
        input_index,
        account_key,
        target,
        sighash_type,
        Some(signing_entropy),
    )
}

/// Sign P2PK inputs whose derived address keys belong to one account key.
fn sign_transaction_multi_addr_account_impl(
    tx: &mut Transaction,
    account_key: &bip32::ExtendedPrivKey,
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<usize, PsktError> {
    validate_base_transaction(tx)?;
    let mut signed_count = 0usize;
    for input_index in 0..tx.num_inputs {
        if sign_account_input(tx, input_index, account_key, sighash_type, signing_entropy)? {
            signed_count += 1;
        }
    }
    signed_count_result(signed_count)
}

fn sign_account_input(
    tx: &mut Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<bool, PsktError> {
    let Some(target) = p2pk_target(tx, input_index) else {
        return Ok(false);
    };
    let mut no_checkpoint = || {};
    if sign_standard_input(
        tx,
        input_index,
        account_key,
        &target,
        sighash_type,
        signing_entropy,
        &mut no_checkpoint,
    )? {
        return Ok(true);
    }
    sign_stealth_input(
        tx,
        input_index,
        account_key,
        &target,
        sighash_type,
        signing_entropy,
    )
}

fn p2pk_target(tx: &Transaction, input_index: usize) -> Option<[u8; 32]> {
    crate::primitives::address::p2pk_xonly(
        tx.inputs[input_index]
            .utxo_entry
            .script_public_key
            .script_bytes(),
    )
}

fn signed_count_result(signed_count: usize) -> Result<usize, PsktError> {
    if signed_count == 0 {
        Err(PsktError::NoInputs)
    } else {
        Ok(signed_count)
    }
}

fn sign_transaction_multi_addr_impl(
    tx: &mut Transaction,
    seed: &[u8; 64],
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<usize, PsktError> {
    let account_key = bip32::derive_account_key(seed).map_err(|_| PsktError::DerivationFailed)?;
    sign_transaction_multi_addr_account_impl(tx, &account_key, sighash_type, signing_entropy)
}

/// Sign with deterministic BIP-340 auxiliary input for host compatibility.
pub fn sign_transaction_multi_addr(
    tx: &mut Transaction,
    seed: &[u8; 64],
    sighash_type: SigHashType,
) -> Result<usize, PsktError> {
    sign_transaction_multi_addr_impl(tx, seed, sighash_type, None)
}

/// Sign with health-checked device entropy mixed into every BIP-340 nonce.
pub fn sign_transaction_multi_addr_with_entropy(
    tx: &mut Transaction,
    seed: &[u8; 64],
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    sign_transaction_multi_addr_impl(tx, seed, sighash_type, Some(signing_entropy))
}

/// Sign receive/change inputs directly from an imported account XPrv.
pub fn sign_transaction_account_multi_addr_with_entropy(
    tx: &mut Transaction,
    account_key: &bip32::ExtendedPrivKey,
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    sign_transaction_multi_addr_account_impl(tx, account_key, sighash_type, Some(signing_entropy))
}

#[cfg(test)]
#[path = "multi_address/unit_tests/mod.rs"]
mod unit_tests;
