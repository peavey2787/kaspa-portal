use crate::primitives::bytes::zeroize_bytes;

use crate::transaction::{
    model::{MultisigInfo, ScriptType, SigHashType, Transaction},
    sighash,
};

use super::super::{
    error::PsktError, script::analyze_input_script, validation::validate_base_transaction,
};
use super::{
    context::SigningContext,
    covenant::sign_covenant_input,
    signature_state::{append_signature, has_pubkey_position},
};

fn sign_p2pk_input(
    tx: &mut Transaction,
    input_index: usize,
    context: &SigningContext,
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<usize, PsktError> {
    if tx.inputs[input_index].sig_count != 0 {
        return Ok(0);
    }
    let script = &tx.inputs[input_index].utxo_entry.script_public_key.script;
    let mut target = [0u8; 32];
    target.copy_from_slice(&script[1..33]);

    for seed_index in 0..context.seed_count() {
        let Some(mut material) = context.direct_address_material(seed_index, &target) else {
            continue;
        };
        let signature_result = match signing_entropy {
            Some(entropy) => sighash::sign_input_with_entropy(
                tx,
                input_index,
                &material.private_key,
                sighash_type,
                entropy,
            ),
            None => sighash::sign_input(tx, input_index, &material.private_key, sighash_type),
        };
        zeroize_bytes(&mut material.private_key);
        let signature = signature_result.map_err(|_| PsktError::SigningFailed)?;
        super::signature_state::set_single_signature(
            &mut tx.inputs[input_index],
            signature.bytes,
            sighash_type.to_byte(),
            0,
            material.compressed_public_key,
        );
        return Ok(1);
    }
    Ok(0)
}

fn account_positions(context: &SigningContext, multisig: &MultisigInfo) -> [Option<u8>; 8] {
    let mut positions = [None, None, None, None, None, None, None, None];
    for (seed_index, position) in positions.iter_mut().enumerate().take(context.seed_count()) {
        let Some(account_xonly) = context.account_xonly(seed_index) else {
            continue;
        };
        for pubkey_position in 0..multisig.n as usize {
            if account_xonly == multisig.pubkeys[pubkey_position] {
                *position = Some(pubkey_position as u8);
                break;
            }
        }
    }
    positions
}

fn sign_multisig_input(
    tx: &mut Transaction,
    input_index: usize,
    multisig: &MultisigInfo,
    context: &mut SigningContext,
    sighash_type: SigHashType,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<usize, PsktError> {
    let hint = tx.inputs[input_index].ms45_hint;
    if hint.present {
        return super::ms45::sign_input(
            tx,
            input_index,
            multisig,
            context,
            sighash_type,
            signing_entropy,
            &hint,
        );
    }
    let positions = account_positions(context, multisig);
    let mut added = 0usize;
    for pubkey_position in 0..multisig.n as usize {
        added += sign_multisig_position(
            tx,
            multisig,
            context,
            MultisigPositionRequest {
                input_index,
                sighash_type,
                signing_entropy,
                positions: &positions,
                pubkey_position,
            },
        )?;
    }
    Ok(added)
}

struct MultisigPositionRequest<'a> {
    input_index: usize,
    sighash_type: SigHashType,
    signing_entropy: Option<&'a [u8; 32]>,
    positions: &'a [Option<u8>; 8],
    pubkey_position: usize,
}

fn sign_multisig_position(
    tx: &mut Transaction,
    multisig: &MultisigInfo,
    context: &mut SigningContext,
    request: MultisigPositionRequest<'_>,
) -> Result<usize, PsktError> {
    let position = request.pubkey_position as u8;
    if has_pubkey_position(&tx.inputs[request.input_index], position) {
        return Ok(0);
    }
    let target = &multisig.pubkeys[request.pubkey_position];
    for seed_index in 0..context.seed_count() {
        let Some(mut material) =
            multisig_material(context, request.positions, seed_index, position, target)
        else {
            continue;
        };
        let signature = super::sign_input_with_optional_entropy(
            tx,
            request.input_index,
            &material.private_key,
            request.sighash_type,
            request.signing_entropy,
        )?;
        zeroize_bytes(&mut material.private_key);
        let added = append_signature(
            &mut tx.inputs[request.input_index],
            signature,
            request.sighash_type.to_byte(),
            position,
            material.compressed_public_key,
        );
        return Ok(usize::from(added));
    }
    Ok(0)
}

fn multisig_material(
    context: &mut SigningContext,
    positions: &[Option<u8>; 8],
    seed_index: usize,
    position: u8,
    target: &[u8; 32],
) -> Option<super::context::SigningKeyMaterial> {
    if positions[seed_index] == Some(position) {
        context.account_material(seed_index)
    } else if positions[seed_index].is_none() {
        context.cached_address_material(seed_index, target)
    } else {
        None
    }
}

/// Sign one supported input with mnemonic/account material. This is used by
/// firmware to provide truthful per-input progress for large transactions.
pub fn sign_multisig_account_sets_input_with_entropy(
    tx: &mut Transaction,
    input_index: usize,
    accounts: &[([u8; 65], bool)],
    ms45_accounts: &[([u8; 65], bool)],
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    validate_base_transaction(tx)?;
    super::p2pk::ensure_input_index(tx, input_index)?;
    let mut context = SigningContext::from_account_sets(accounts, ms45_accounts);
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    sign_classified_account_input(
        tx,
        &mut context,
        ClassifiedAccountRequest {
            input_index,
            sighash_type,
            active_account_idx,
            signing_entropy,
            script_type,
            multisig: multisig.as_ref(),
        },
    )
}

pub fn sign_multisig_accounts_input_with_entropy(
    tx: &mut Transaction,
    input_index: usize,
    accounts: &[([u8; 65], bool)],
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    validate_base_transaction(tx)
        .and_then(|()| super::p2pk::ensure_input_index(tx, input_index))
        .and_then(|()| {
            sign_account_context_input(
                tx,
                input_index,
                accounts,
                sighash_type,
                active_account_idx,
                signing_entropy,
            )
        })
}

fn sign_account_context_input(
    tx: &mut Transaction,
    input_index: usize,
    accounts: &[([u8; 65], bool)],
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    let mut context = SigningContext::from_account_raw(accounts);
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    sign_classified_account_input(
        tx,
        &mut context,
        ClassifiedAccountRequest {
            input_index,
            sighash_type,
            active_account_idx,
            signing_entropy,
            script_type,
            multisig: multisig.as_ref(),
        },
    )
}

struct ClassifiedAccountRequest<'a> {
    input_index: usize,
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &'a [u8; 32],
    script_type: ScriptType,
    multisig: Option<&'a MultisigInfo>,
}

fn sign_classified_account_input(
    tx: &mut Transaction,
    context: &mut SigningContext,
    request: ClassifiedAccountRequest<'_>,
) -> Result<usize, PsktError> {
    if request.script_type == ScriptType::P2PK {
        return sign_p2pk_input(
            tx,
            request.input_index,
            context,
            request.sighash_type,
            Some(request.signing_entropy),
        );
    }
    sign_non_p2pk_account_input(tx, context, request)
}

fn sign_non_p2pk_account_input(
    tx: &mut Transaction,
    context: &mut SigningContext,
    request: ClassifiedAccountRequest<'_>,
) -> Result<usize, PsktError> {
    if let Some(info) = request.multisig {
        return sign_multisig_input(
            tx,
            request.input_index,
            info,
            context,
            request.sighash_type,
            Some(request.signing_entropy),
        );
    }
    sign_covenant_account_input(
        tx,
        request.input_index,
        context,
        request.sighash_type,
        request.active_account_idx,
        request.signing_entropy,
        request.script_type,
    )
}

fn sign_covenant_account_input(
    tx: &mut Transaction,
    input_index: usize,
    context: &mut SigningContext,
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &[u8; 32],
    script_type: ScriptType,
) -> Result<usize, PsktError> {
    if script_type != ScriptType::P2SH {
        return Ok(0);
    }
    sign_covenant_input(
        tx,
        input_index,
        context,
        sighash_type,
        active_account_idx,
        Some(signing_entropy),
    )
}

/// Sign every supported input with the loaded seed set.
fn sign_transaction_with_context(
    tx: &mut Transaction,
    mut context: SigningContext,
    sighash_type: SigHashType,
    active_seed_idx: Option<usize>,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<usize, PsktError> {
    validate_base_transaction(tx)?;
    let mut total_added = 0usize;
    for input_index in 0..tx.num_inputs {
        total_added += sign_supported_input(
            tx,
            input_index,
            &mut context,
            sighash_type,
            active_seed_idx,
            signing_entropy,
        )?;
    }
    if total_added == 0 {
        Err(PsktError::NoInputs)
    } else {
        Ok(total_added)
    }
}

fn sign_supported_input(
    tx: &mut Transaction,
    input_index: usize,
    context: &mut SigningContext,
    sighash_type: SigHashType,
    active_seed_idx: Option<usize>,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<usize, PsktError> {
    let (script_type, multisig) = analyze_input_script(tx, input_index);
    match (script_type, multisig.as_ref()) {
        (ScriptType::P2PK, _) => {
            sign_p2pk_input(tx, input_index, context, sighash_type, signing_entropy)
        }
        (ScriptType::Multisig | ScriptType::P2SH, Some(info)) => sign_multisig_input(
            tx,
            input_index,
            info,
            context,
            sighash_type,
            signing_entropy,
        ),
        (ScriptType::P2SH, None) => sign_covenant_input(
            tx,
            input_index,
            context,
            sighash_type,
            active_seed_idx,
            signing_entropy,
        ),
        _ => Ok(0),
    }
}

fn sign_transaction_multisig_impl(
    tx: &mut Transaction,
    seeds: &[([u8; 64], bool)],
    sighash_type: SigHashType,
    active_seed_idx: Option<usize>,
    signing_entropy: Option<&[u8; 32]>,
) -> Result<usize, PsktError> {
    sign_transaction_with_context(
        tx,
        SigningContext::from_seeds(seeds),
        sighash_type,
        active_seed_idx,
        signing_entropy,
    )
}

pub fn sign_transaction_multisig(
    tx: &mut Transaction,
    seeds: &[([u8; 64], bool)],
    sighash_type: SigHashType,
    active_seed_idx: Option<usize>,
) -> Result<usize, PsktError> {
    sign_transaction_multisig_impl(tx, seeds, sighash_type, active_seed_idx, None)
}

/// Sign every supported input with auxiliary randomness derived from a
/// health-checked device entropy sample.
pub fn sign_transaction_multisig_with_entropy(
    tx: &mut Transaction,
    seeds: &[([u8; 64], bool)],
    sighash_type: SigHashType,
    active_seed_idx: Option<usize>,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    sign_transaction_multisig_impl(
        tx,
        seeds,
        sighash_type,
        active_seed_idx,
        Some(signing_entropy),
    )
}

/// Sign every supported input using mnemonic-derived and imported account XPrvs.
pub fn sign_transaction_multisig_accounts_with_entropy(
    tx: &mut Transaction,
    accounts: &[([u8; 65], bool)],
    sighash_type: SigHashType,
    active_account_idx: Option<usize>,
    signing_entropy: &[u8; 32],
) -> Result<usize, PsktError> {
    sign_transaction_with_context(
        tx,
        SigningContext::from_account_raw(accounts),
        sighash_type,
        active_account_idx,
        Some(signing_entropy),
    )
}
