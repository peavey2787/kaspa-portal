use crate::{
    network::client::NetworkClient,
    transaction::builder::{
        model::{PlannedOutput, UnsignedTransactionPlan},
        planning::{amounts, plan_multisig},
        selection::{select_explicit, sort_largest_first},
    },
    transaction::interchange::pskt::pskb,
    wallet::multisig::{
        build_redeem_script, resolve_address_path, MultisigDescriptor, ResolvedMultisigPath,
    },
};

mod branch;
mod consolidation;

use branch::next_change_index;

/// Scan the receive/change branches of a 45' multisig descriptor and return
/// a canonical JSON summary of labelled UTXOs and the next free indices.
pub async fn scan_branch(
    descriptor_text: &str,
    cosigner: u32,
    depth: u32,
    client: &NetworkClient,
    prefix: &str,
) -> Result<String, String> {
    branch::scan_branch_json(descriptor_text, cosigner, depth, client, prefix).await
}

/// Parameters for consolidating explicitly selected UTXOs from multiple
/// addresses of one 45' multisig descriptor.
pub struct MultisigConsolidationRequest<'a> {
    pub descriptor_text: &'a str,
    pub sources_json: &'a str,
    pub destination_address: &'a str,
    pub amount: u64,
    pub fee: u64,
    pub cosigner: u32,
    pub change_index_hint: u32,
}

/// Build a PSKB that consolidates explicitly selected UTXOs from multiple
/// addresses of one 45' multisig descriptor.
pub async fn create_consolidation(
    client: &NetworkClient,
    request: &MultisigConsolidationRequest<'_>,
) -> Result<String, String> {
    consolidation::create_multi_address(request, client).await
}

#[derive(Clone, Copy)]
pub enum MultisigSelection<'a> {
    Automatic,
    Explicit(&'a [usize]),
}

pub struct MultisigTransactionRequest<'a> {
    pub descriptor_text: &'a str,
    pub source_address: &'a str,
    pub destination_address: &'a str,
    pub amount: u64,
    pub fee: u64,
    pub change_address: &'a str,
    pub requested_index: u32,
    pub change_index_hint: u32,
    pub selection: MultisigSelection<'a>,
}

pub(crate) struct PreparedMultisig {
    pub(crate) redeem_script: Vec<u8>,
    pub(crate) sig_op_count: u8,
    pub(crate) minimum_signatures: u8,
    pub(crate) destination_script: Vec<u8>,
    pub(crate) change_script: Vec<u8>,
    pub(crate) source_derivations: serde_json::Value,
    pub(crate) change_derivations: serde_json::Value,
    #[cfg(test)]
    pub(crate) source_path: ResolvedMultisigPath,
}

pub async fn create(
    client: &NetworkClient,
    request: MultisigTransactionRequest<'_>,
) -> Result<String, String> {
    let descriptor = MultisigDescriptor::parse(request.descriptor_text)?;
    let source_path =
        resolve_address_path(&descriptor, request.source_address, request.requested_index)?;
    let change_index =
        transaction_change_index(client, &descriptor, &source_path, &request).await?;
    let prepared = prepare_request_at_change(&request, change_index)?;
    let utxos =
        crate::network::queries::utxos::fetch_for_address(client, request.source_address).await?;
    encode_from_utxos(&request, &prepared, utxos)
}

async fn transaction_change_index(
    client: &NetworkClient,
    descriptor: &MultisigDescriptor,
    source_path: &ResolvedMultisigPath,
    request: &MultisigTransactionRequest<'_>,
) -> Result<u32, String> {
    if request.change_index_hint != u32::MAX {
        return Ok(request.change_index_hint);
    }
    if !descriptor.is_hd45() {
        return Ok(source_path.index);
    }
    next_change_index(
        descriptor,
        source_path.cosigner,
        MULTISIG_BRANCH_SCAN_DEPTH,
        client,
        request.source_address,
    )
    .await
}

#[cfg(test)]
pub(super) fn prepare_request(
    request: &MultisigTransactionRequest<'_>,
) -> Result<PreparedMultisig, String> {
    let fallback = if request.change_index_hint == u32::MAX {
        request.requested_index
    } else {
        request.change_index_hint
    };
    prepare_request_at_change(request, fallback)
}

fn prepare_request_at_change(
    request: &MultisigTransactionRequest<'_>,
    change_index: u32,
) -> Result<PreparedMultisig, String> {
    validate_amounts(request)?;
    let descriptor = MultisigDescriptor::parse(request.descriptor_text)?;
    let source_path =
        resolve_address_path(&descriptor, request.source_address, request.requested_index)?;
    let (redeem_script, sig_op_count, source_derivations) =
        prepare_source_material(&descriptor, &source_path, request.source_address)?;
    let (change_script, change_derivations) =
        prepare_change_material(&descriptor, &source_path, request, change_index)?;
    Ok(PreparedMultisig {
        redeem_script,
        sig_op_count,
        minimum_signatures: descriptor.threshold(),
        destination_script: crate::primitives::address::address_to_script_pubkey(
            request.destination_address,
        )?,
        change_script,
        source_derivations,
        change_derivations,
        #[cfg(test)]
        source_path,
    })
}

fn prepare_source_material(
    descriptor: &MultisigDescriptor,
    source_path: &ResolvedMultisigPath,
    source_address: &str,
) -> Result<(Vec<u8>, u8, serde_json::Value), String> {
    let public_keys =
        descriptor.public_keys_at(source_path.index, source_path.cosigner, source_path.chain)?;
    let redeem_script = build_redeem_script(descriptor.threshold(), &public_keys)?;
    verify_source_address(source_address, &redeem_script)?;
    let derivations =
        descriptor.bip32_derivations(source_path.index, source_path.cosigner, source_path.chain)?;
    Ok((redeem_script, public_keys.len() as u8, derivations))
}

fn prepare_change_material(
    descriptor: &MultisigDescriptor,
    source_path: &ResolvedMultisigPath,
    request: &MultisigTransactionRequest<'_>,
    change_index: u32,
) -> Result<(Vec<u8>, serde_json::Value), String> {
    if descriptor.is_hd45() {
        return prepare_hd45_change(
            descriptor,
            source_path,
            request.source_address,
            change_index,
        );
    }
    prepare_static_change(request)
}

fn prepare_static_change(
    request: &MultisigTransactionRequest<'_>,
) -> Result<(Vec<u8>, serde_json::Value), String> {
    if request.change_address != request.source_address {
        return Err("Static multisig change address must match the source address".into());
    }
    Ok((
        crate::primitives::address::address_to_script_pubkey(request.source_address)?,
        serde_json::json!({}),
    ))
}

fn prepare_hd45_change(
    descriptor: &MultisigDescriptor,
    source_path: &ResolvedMultisigPath,
    source_address: &str,
    change_index: u32,
) -> Result<(Vec<u8>, serde_json::Value), String> {
    let change_keys = descriptor.public_keys_at(change_index, source_path.cosigner, 1)?;
    let change_redeem = build_redeem_script(descriptor.threshold(), &change_keys)?;
    let change_address = crate::contract::script::p2sh::script_to_address(
        &change_redeem,
        address_prefix(source_address),
    )?;
    Ok((
        crate::primitives::address::address_to_script_pubkey(&change_address)?,
        descriptor.bip32_derivations(change_index, source_path.cosigner, 1)?,
    ))
}

pub(super) fn validate_amounts(request: &MultisigTransactionRequest<'_>) -> Result<(), String> {
    if request.amount == 0 || amounts::is_dust(request.amount) {
        return Err(format!(
            "Invalid multisig recipient amount: {} sompi",
            request.amount
        ));
    }
    Ok(())
}

pub(super) fn verify_source_address(
    source_address: &str,
    redeem_script: &[u8],
) -> Result<(), String> {
    let derived = crate::contract::script::p2sh::script_to_address(
        redeem_script,
        address_prefix(source_address),
    )?;
    if derived == source_address {
        return Ok(());
    }
    Err("Multisig descriptor does not control the source address".into())
}

pub(crate) fn encode_from_utxos(
    request: &MultisigTransactionRequest<'_>,
    prepared: &PreparedMultisig,
    utxos: Vec<crate::chain::utxo::UtxoEntry>,
) -> Result<String, String> {
    let selected = select_multisig_utxos(request, prepared, utxos)?;
    let fee = multisig_standard_fee(prepared, selected.len(), request.fee)?;
    let selected_total = crate::transaction::builder::selection::checked_total(&selected)?;
    if selected_total < amounts::checked_required(request.amount, fee)? {
        return Err(format!(
            "Selected multisig UTXOs do not cover the Toccata standard fee ({fee} sompi); select additional UTXOs",
        ));
    }
    let destination = PlannedOutput::new(request.amount, prepared.destination_script.clone());
    let (mut plan, _) = plan_multisig(
        selected,
        destination,
        fee,
        prepared.change_script.clone(),
        &prepared.redeem_script,
        prepared.sig_op_count,
    )?;
    attach_derivation_maps(&mut plan, prepared);
    pskb::encode_plan(&plan)
}

fn multisig_standard_fee(
    prepared: &PreparedMultisig,
    input_count: usize,
    requested_fee: u64,
) -> Result<u64, String> {
    multisig_standard_fee_for_shape(
        MultisigSigningShape {
            minimum_signatures: prepared.minimum_signatures,
            redeem_script_len: prepared.redeem_script.len(),
            sig_op_count: prepared.sig_op_count,
        },
        input_count,
        &[
            prepared.destination_script.len(),
            prepared.change_script.len(),
        ],
        requested_fee,
    )
}

/// Signing shape every input of one multisig spend shares.
#[derive(Clone, Copy)]
pub(super) struct MultisigSigningShape {
    pub(super) minimum_signatures: u8,
    pub(super) redeem_script_len: usize,
    pub(super) sig_op_count: u8,
}

/// Node-standard fee for the final signed multisig transaction: the threshold
/// signatures plus redeem script in every input, priced at the minimum
/// standard fee rate, and never below the caller's requested fee.
pub(super) fn multisig_standard_fee_for_shape(
    shape: MultisigSigningShape,
    input_count: usize,
    output_script_lengths: &[usize],
    requested_fee: u64,
) -> Result<u64, String> {
    let input_shape = crate::transaction::mass::SignedInputShape {
        signature_script_len: multisig_signature_script_len(
            shape.minimum_signatures,
            shape.redeem_script_len,
        )?,
        sig_op_count: shape.sig_op_count,
    };
    let (standard_fee, _, _) = crate::transaction::mass::estimate_non_contextual_fee_for_shape(
        input_shape,
        input_count,
        output_script_lengths,
        0,
        crate::transaction::mass::MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM,
    )?;
    Ok(requested_fee.max(standard_fee))
}

/// `threshold` 65-byte signature pushes, then the redeem-script push.
fn multisig_signature_script_len(threshold: u8, redeem_len: usize) -> Result<u64, String> {
    let redeem_len =
        u64::try_from(redeem_len).map_err(|_| "redeem script length exceeds u64".to_string())?;
    let push_prefix = match redeem_len {
        0..=75 => 1,
        76..=255 => 2,
        _ => 3,
    };
    u64::from(threshold)
        .checked_mul(66)
        .and_then(|value| value.checked_add(push_prefix))
        .and_then(|value| value.checked_add(redeem_len))
        .ok_or_else(|| "Multisig signature script exceeds supported range".to_string())
}

fn select_multisig_utxos(
    request: &MultisigTransactionRequest<'_>,
    prepared: &PreparedMultisig,
    mut utxos: Vec<crate::chain::utxo::UtxoEntry>,
) -> Result<Vec<crate::chain::utxo::UtxoEntry>, String> {
    if utxos.is_empty() {
        return Err("No UTXOs found for multisig address".into());
    }
    match request.selection {
        MultisigSelection::Automatic => {
            // Each added input raises the standard fee, so re-price after
            // every selection step.
            sort_largest_first(&mut utxos);
            let mut selected = Vec::new();
            let mut total = 0u64;
            for utxo in utxos {
                total = total
                    .checked_add(utxo.amount)
                    .ok_or_else(|| "UTXO total exceeds supported monetary range".to_string())?;
                selected.push(utxo);
                let fee = multisig_standard_fee(prepared, selected.len(), request.fee)?;
                if total >= amounts::checked_required(request.amount, fee)? {
                    return Ok(selected);
                }
            }
            Err("Insufficient multisig funds after applying the Toccata standard fee".into())
        }
        MultisigSelection::Explicit(indices) => select_explicit(utxos, indices),
    }
}

fn attach_derivation_maps(plan: &mut UnsignedTransactionPlan, prepared: &PreparedMultisig) {
    for input in &mut plan.inputs {
        input.bip32_derivations = Some(prepared.source_derivations.clone());
    }
    if let Some(change) = multisig_change_output(&mut plan.outputs) {
        change.bip32_derivations = Some(prepared.change_derivations.clone());
    }
}

fn multisig_change_output(outputs: &mut [PlannedOutput]) -> Option<&mut PlannedOutput> {
    if outputs.len() <= 1 {
        return None;
    }
    outputs.last_mut()
}

pub const MULTISIG_BRANCH_SCAN_DEPTH: u32 = 40;

fn address_prefix(address: &str) -> &str {
    match address.split_once(':') {
        Some((value, _)) => value,
        None => "kaspa",
    }
}

#[cfg(test)]
#[path = "multisig/unit-tests/mod.rs"]
mod unit_tests;
