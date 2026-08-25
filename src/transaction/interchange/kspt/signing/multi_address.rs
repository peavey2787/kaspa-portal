use crate::primitives::bytes::zeroize_bytes;

use crate::{
    transaction::{
        model::{SigHashType, Transaction},
        sighash,
    },
    wallet::derivation::bip32,
};

use super::super::{error::PsktError, validation::validate_base_transaction};
use super::signature_state::set_single_signature;

fn sign_standard_input(
    tx: &mut Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    target_public_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<bool, PsktError> {
    let Some((address_index, is_change)) =
        bip32::find_address_index_for_pubkey(account_key, target_public_key)
    else {
        return Ok(false);
    };
    let key = if is_change {
        bip32::derive_change_key(account_key, u32::from(address_index))
    } else {
        bip32::derive_address_key(account_key, u32::from(address_index))
    }
    .map_err(|_| PsktError::DerivationFailed)?;
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

fn sign_stealth_input(
    tx: &mut Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    target_public_key: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<bool, PsktError> {
    use k256::elliptic_curve::{ops::Add, sec1::ToEncodedPoint, ScalarPrimitive};
    use k256::{ProjectivePoint, Scalar};

    let account_primitive =
        ScalarPrimitive::<k256::Secp256k1>::from_slice(account_key.private_key_bytes())
            .map_err(|_| PsktError::DerivationFailed)?;
    let account_scalar = {
        let scalar = Scalar::from(account_primitive);
        let point = (ProjectivePoint::GENERATOR * scalar).to_affine();
        let encoded = point.to_encoded_point(true);
        if encoded.as_bytes()[0] == 0x03 {
            -scalar
        } else {
            scalar
        }
    };
    let tweak = ScalarPrimitive::<k256::Secp256k1>::from_slice(&tx.stealth_tweak)
        .map_err(|_| PsktError::DerivationFailed)?;
    let combined_scalar = account_scalar.add(&Scalar::from(tweak));
    let combined_point = (ProjectivePoint::GENERATOR * combined_scalar).to_affine();
    let combined_public_key = combined_point.to_encoded_point(true);
    if &combined_public_key.as_bytes()[1..33] != target_public_key {
        return Ok(false);
    }

    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&combined_scalar.to_bytes());
    let signature_result = match signing_entropy {
        Some(entropy) => {
            sighash::sign_input_with_entropy(tx, input_index, &private_key, sighash_type, entropy)
        }
        None => sighash::sign_input(tx, input_index, &private_key, sighash_type),
    };
    zeroize_bytes(&mut private_key);
    let signature = signature_result.map_err(|_| PsktError::SigningFailed)?;
    let mut compressed_public_key = [0u8; 33];
    compressed_public_key.copy_from_slice(combined_public_key.as_bytes());
    set_single_signature(
        &mut tx.inputs[input_index],
        signature.bytes,
        sighash_type.to_byte(),
        0,
        compressed_public_key,
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
    super::p2pk::checked_target(tx, input_index).and_then(|target| {
        sign_account_target(
            tx,
            input_index,
            account_key,
            sighash_type,
            signing_entropy,
            target,
        )
    })
}

fn sign_account_target(
    tx: &mut Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
    target: Option<[u8; 32]>,
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
    sign_stealth_if_present(
        tx,
        input_index,
        account_key,
        target,
        sighash_type,
        signing_entropy,
    )
}

fn sign_stealth_if_present(
    tx: &mut Transaction,
    input_index: usize,
    account_key: &bip32::ExtendedPrivKey,
    target: &[u8; 32],
    sighash_type: SigHashType,
    signing_entropy: &[u8; 32],
) -> Result<bool, PsktError> {
    if tx.has_stealth_tweak {
        sign_stealth_input(
            tx,
            input_index,
            account_key,
            target,
            sighash_type,
            Some(signing_entropy),
        )
    } else {
        Ok(false)
    }
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
    if sign_standard_input(
        tx,
        input_index,
        account_key,
        &target,
        sighash_type,
        signing_entropy,
    )? {
        return Ok(true);
    }
    if tx.has_stealth_tweak {
        return sign_stealth_input(
            tx,
            input_index,
            account_key,
            &target,
            sighash_type,
            signing_entropy,
        );
    }
    Ok(false)
}

fn p2pk_target(tx: &Transaction, input_index: usize) -> Option<[u8; 32]> {
    let script = &tx.inputs[input_index].utxo_entry.script_public_key;
    if script.script_len != 34 || script.script[0] != 0x20 || script.script[33] != 0xac {
        return None;
    }
    let mut target = [0u8; 32];
    target.copy_from_slice(&script.script[1..33]);
    Some(target)
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

/// Sign using standard deterministic BIP-340 nonce derivation.
pub fn sign_transaction_multi_addr(
    tx: &mut Transaction,
    seed: &[u8; 64],
    sighash_type: SigHashType,
) -> Result<usize, PsktError> {
    sign_transaction_multi_addr_impl(tx, seed, sighash_type, None)
}

/// Sign with caller-supplied CSPRNG entropy mixed into every BIP-340 nonce.
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
