use crate::{
    primitives::bytes::zeroize_bytes, transaction::signing::anti_klepto::protocol::SESSION_ID_LEN,
};

use crate::{
    crypto::{anti_klepto as crypto, schnorr::SchnorrSignature},
    transaction::{
        interchange::kspt::PsktError,
        model::{SigHashType, Transaction},
        sighash,
    },
    wallet::derivation::bip32,
};

use super::super::context::{SigningContext, SigningKeyMaterial};

pub fn initial_signature_counts(tx: &Transaction) -> alloc::vec::Vec<u8> {
    tx.inputs().iter().map(|input| input.sig_count).collect()
}

pub fn finalize_raw_key_signatures(
    tx: &mut Transaction,
    private_key: &[u8; 32],
    initial_counts: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
) -> Result<usize, PsktError> {
    let public_key = bip32::compressed_pubkey_from_raw_key(private_key)
        .map_err(|_| PsktError::DerivationFailed)?;
    finalize_matching(
        tx,
        initial_counts,
        session_id,
        host_secret,
        |_, sig_pubkey| {
            if sig_pubkey == &public_key {
                Some(SigningKeyMaterial {
                    private_key: *private_key,
                    compressed_public_key: public_key,
                })
            } else {
                None
            }
        },
    )
}

pub fn finalize_account_signatures(
    tx: &mut Transaction,
    account_key: &bip32::ExtendedPrivKey,
    initial_counts: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
) -> Result<usize, PsktError> {
    let raw = account_key.to_raw();
    finalize_account_set_signatures(tx, &[(raw, true)], initial_counts, session_id, host_secret)
}

pub fn finalize_account_set_signatures(
    tx: &mut Transaction,
    accounts: &[([u8; 65], bool)],
    initial_counts: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
) -> Result<usize, PsktError> {
    let mut context = SigningContext::from_account_raw(accounts);
    finalize_matching(
        tx,
        initial_counts,
        session_id,
        host_secret,
        |tx, sig_pubkey| {
            let mut target = [0u8; 32];
            target.copy_from_slice(&sig_pubkey[1..33]);
            if let Some(material) = context.matching_material(&target) {
                return Some(material);
            }
            if tx.has_stealth_tweak {
                for seed_index in 0..context.seed_count() {
                    if let Some(material) = stealth_material(&context, seed_index, tx, &target) {
                        return Some(material);
                    }
                }
            }
            None
        },
    )
}

fn finalize_matching<F>(
    tx: &mut Transaction,
    initial_counts: &[u8],
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
    mut resolve: F,
) -> Result<usize, PsktError>
where
    F: FnMut(&Transaction, &[u8; 33]) -> Option<SigningKeyMaterial>,
{
    if initial_counts.len() < tx.num_inputs {
        return Err(PsktError::InvalidSignatureState);
    }
    let mut changed = 0usize;
    for (input_index, initial_count) in initial_counts
        .iter()
        .copied()
        .enumerate()
        .take(tx.num_inputs)
    {
        changed += finalize_input_signatures(
            tx,
            input_index,
            initial_count,
            session_id,
            host_secret,
            &mut resolve,
        )?;
    }
    if changed == 0 {
        Err(PsktError::NoInputs)
    } else {
        Ok(changed)
    }
}

fn finalize_input_signatures<F>(
    tx: &mut Transaction,
    input_index: usize,
    initial_count: u8,
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
    resolve: &mut F,
) -> Result<usize, PsktError>
where
    F: FnMut(&Transaction, &[u8; 33]) -> Option<SigningKeyMaterial>,
{
    let start = usize::from(initial_count);
    let end = usize::from(tx.inputs[input_index].sig_count);
    validate_signature_range(tx, input_index, start, end)?;
    for slot in start..end {
        finalize_signature_slot(tx, input_index, slot, session_id, host_secret, resolve)?;
    }
    Ok(end - start)
}

fn validate_signature_range(
    tx: &Transaction,
    input_index: usize,
    start: usize,
    end: usize,
) -> Result<(), PsktError> {
    tx.inputs[input_index]
        .sigs
        .get(start..end)
        .map(|_| ())
        .ok_or(PsktError::InvalidSignatureState)
}

fn finalize_signature_slot<F>(
    tx: &mut Transaction,
    input_index: usize,
    slot: usize,
    session_id: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; 32],
    resolve: &mut F,
) -> Result<(), PsktError>
where
    F: FnMut(&Transaction, &[u8; 33]) -> Option<SigningKeyMaterial>,
{
    let sig = tx.inputs[input_index].sigs[slot].clone();
    if !sig.present || sig.pubkey_compressed[0] == 0 {
        return Err(PsktError::InvalidSignatureState);
    }
    let Some(mut material) = resolve(tx, &sig.pubkey_compressed) else {
        return Err(PsktError::DerivationFailed);
    };
    if material.compressed_public_key != sig.pubkey_compressed {
        zeroize_bytes(&mut material.private_key);
        return Err(PsktError::DerivationFailed);
    }
    let result = finalize_with_material(
        tx,
        FinalizeSignatureMaterial {
            input_index,
            slot,
            sighash_byte: sig.sighash_type,
            provisional_bytes: sig.signature,
            session_id,
            host_secret,
            private_key: &material.private_key,
        },
    );
    zeroize_bytes(&mut material.private_key);
    result
}

struct FinalizeSignatureMaterial<'a> {
    input_index: usize,
    slot: usize,
    sighash_byte: u8,
    provisional_bytes: [u8; 64],
    session_id: &'a [u8; SESSION_ID_LEN],
    host_secret: &'a [u8; 32],
    private_key: &'a [u8; 32],
}

fn finalize_with_material(
    tx: &mut Transaction,
    material: FinalizeSignatureMaterial<'_>,
) -> Result<(), PsktError> {
    let sighash_type =
        SigHashType::from_byte(material.sighash_byte).ok_or(PsktError::InvalidSigHashType)?;
    let message = sighash::calculate_sighash(tx, material.input_index, sighash_type);
    let provisional = SchnorrSignature {
        bytes: material.provisional_bytes,
    };
    let final_signature = crypto::tweak_provisional_signature(
        material.private_key,
        &message,
        &provisional,
        material.session_id,
        material.host_secret,
        u32::try_from(material.input_index).map_err(|_| PsktError::TooManyInputs)?,
        material.slot as u8,
    )
    .map_err(|_| PsktError::SigningFailed)?;
    tx.inputs[material.input_index].sigs[material.slot].signature = final_signature.bytes;
    Ok(())
}

fn stealth_material(
    context: &SigningContext,
    seed_index: usize,
    tx: &Transaction,
    target_xonly: &[u8; 32],
) -> Option<SigningKeyMaterial> {
    use k256::elliptic_curve::{ops::Add, sec1::ToEncodedPoint, ScalarPrimitive};
    use k256::{ProjectivePoint, Scalar};

    let account = context.account_material(seed_index)?;
    let account_primitive =
        ScalarPrimitive::<k256::Secp256k1>::from_slice(&account.private_key).ok()?;
    let account_scalar = {
        let scalar = Scalar::from(account_primitive);
        let encoded = (ProjectivePoint::GENERATOR * scalar)
            .to_affine()
            .to_encoded_point(true);
        if encoded.as_bytes()[0] == 0x03 {
            -scalar
        } else {
            scalar
        }
    };
    let tweak = ScalarPrimitive::<k256::Secp256k1>::from_slice(&tx.stealth_tweak).ok()?;
    let combined = account_scalar.add(&Scalar::from(tweak));
    let point = (ProjectivePoint::GENERATOR * combined)
        .to_affine()
        .to_encoded_point(true);
    if &point.as_bytes()[1..33] != target_xonly {
        return None;
    }
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(&combined.to_bytes());
    let mut compressed_public_key = [0u8; 33];
    compressed_public_key.copy_from_slice(point.as_bytes());
    Some(SigningKeyMaterial {
        private_key,
        compressed_public_key,
    })
}
