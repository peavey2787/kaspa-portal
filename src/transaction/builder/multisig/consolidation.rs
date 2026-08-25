//! Multi-address 45' multisig consolidation planning.

use crate::{
    network::client::NetworkClient,
    transaction::builder::{
        model::{PlannedInput, PlannedOutput, UnsignedTransactionPlan},
        planning::amounts,
    },
    transaction::interchange::pskt::pskb,
    wallet::multisig::{build_redeem_script, resolve_address_path, MultisigDescriptor},
};

use super::{
    address_prefix, branch::next_change_index, MultisigConsolidationRequest,
    MULTISIG_BRANCH_SCAN_DEPTH,
};

#[derive(Clone, serde::Deserialize)]
pub struct MultisigConsolidationSource {
    pub address: String,
    pub tx_id: String,
    pub index: u32,
}

pub(crate) async fn create_multi_address(
    request: &MultisigConsolidationRequest<'_>,
    client: &NetworkClient,
) -> Result<String, String> {
    let prepared = prepare_consolidation(
        request.descriptor_text,
        request.sources_json,
        request.cosigner,
    )?;
    let available =
        crate::network::queries::utxos::fetch_for_addresses(client, &prepared.unique_addresses)
            .await?;
    finish_consolidation(prepared, &available, request, client).await
}

pub(super) struct PreparedConsolidation {
    descriptor: MultisigDescriptor,
    sources: Vec<MultisigConsolidationSource>,
    resolved: ResolvedConsolidationSources,
    unique_addresses: Vec<String>,
}

pub(super) fn prepare_consolidation(
    descriptor_text: &str,
    sources_json: &str,
    cosigner: u32,
) -> Result<PreparedConsolidation, String> {
    let descriptor = MultisigDescriptor::parse(descriptor_text)?;
    require_hd45_consolidation(&descriptor)?;
    let sources = parse_consolidation_sources(sources_json)?;
    let resolved = resolve_consolidation_sources(&descriptor, &sources, cosigner)?;
    let unique_addresses = unique_source_addresses(&sources);
    Ok(PreparedConsolidation {
        descriptor,
        sources,
        resolved,
        unique_addresses,
    })
}

pub(super) async fn finish_consolidation(
    prepared: PreparedConsolidation,
    available: &[crate::chain::utxo::UtxoEntry],
    request: &MultisigConsolidationRequest<'_>,
    client: &NetworkClient,
) -> Result<String, String> {
    let (inputs, total) =
        build_consolidation_inputs(&prepared.sources, available, &prepared.resolved)?;
    let required = required_total(request.amount, request.fee)?;
    require_selected_total(total, required)?;
    let outputs = consolidation_outputs(
        &prepared.descriptor,
        &prepared.sources[0].address,
        request,
        total - required,
        client,
    )
    .await?;
    pskb::encode_plan(&UnsignedTransactionPlan {
        tx_version: 0,
        inputs,
        outputs,
        payload: Vec::new(),
    })
}

async fn consolidation_outputs(
    descriptor: &MultisigDescriptor,
    source_address: &str,
    request: &MultisigConsolidationRequest<'_>,
    change: u64,
    client: &NetworkClient,
) -> Result<Vec<PlannedOutput>, String> {
    let destination_script =
        crate::primitives::address::address_to_script_pubkey(request.destination_address)?;
    let mut outputs = vec![PlannedOutput::new(request.amount, destination_script)];
    append_consolidation_change(
        ChangeOutputRequest {
            descriptor,
            source_address,
            prefix: address_prefix(source_address),
            cosigner: request.cosigner,
            change_index_hint: request.change_index_hint,
            client,
            change,
        },
        &mut outputs,
    )
    .await?;
    Ok(outputs)
}

pub(super) type ResolvedConsolidationSources =
    std::collections::HashMap<String, (Vec<u8>, serde_json::Value, u8)>;

fn require_hd45_consolidation(descriptor: &MultisigDescriptor) -> Result<(), String> {
    if descriptor.is_hd45() {
        return Ok(());
    }
    Err("Multi-address consolidation requires a multi_hd45 descriptor".into())
}

pub(super) fn parse_consolidation_sources(
    sources_json: &str,
) -> Result<Vec<MultisigConsolidationSource>, String> {
    let sources: Vec<MultisigConsolidationSource> =
        serde_json::from_str(sources_json).map_err(|error| format!("sources_json: {error}"))?;
    require_source_count(sources.len())?;
    Ok(sources)
}

pub(super) fn require_source_count(count: usize) -> Result<(), String> {
    if (1..=3).contains(&count) {
        return Ok(());
    }
    Err("Select between 1 and 3 multisig UTXOs".into())
}

pub(super) fn resolve_consolidation_sources(
    descriptor: &MultisigDescriptor,
    sources: &[MultisigConsolidationSource],
    cosigner: u32,
) -> Result<ResolvedConsolidationSources, String> {
    let mut resolved = ResolvedConsolidationSources::new();
    for source in sources {
        resolve_consolidation_source_once(descriptor, source, cosigner, &mut resolved)?;
    }
    Ok(resolved)
}

fn resolve_consolidation_source_once(
    descriptor: &MultisigDescriptor,
    source: &MultisigConsolidationSource,
    cosigner: u32,
    resolved: &mut ResolvedConsolidationSources,
) -> Result<(), String> {
    if resolved.contains_key(&source.address) {
        return Ok(());
    }
    let material = resolve_consolidation_source(descriptor, source, cosigner)?;
    resolved.insert(source.address.clone(), material);
    Ok(())
}

fn resolve_consolidation_source(
    descriptor: &MultisigDescriptor,
    source: &MultisigConsolidationSource,
    cosigner: u32,
) -> Result<(Vec<u8>, serde_json::Value, u8), String> {
    let path = resolve_address_path(descriptor, &source.address, MULTISIG_BRANCH_SCAN_DEPTH)?;
    if path.cosigner != cosigner {
        return Err("Selected source belongs to a different cosigner branch".into());
    }
    let keys = descriptor.public_keys_at(path.index, path.cosigner, path.chain)?;
    let redeem = build_redeem_script(descriptor.threshold(), &keys)?;
    let derivations = descriptor.bip32_derivations(path.index, path.cosigner, path.chain)?;
    Ok((redeem, derivations, keys.len() as u8))
}

pub(super) fn unique_source_addresses(sources: &[MultisigConsolidationSource]) -> Vec<String> {
    let mut addresses = sources
        .iter()
        .map(|source| source.address.clone())
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    addresses
}

pub(super) fn build_consolidation_inputs(
    sources: &[MultisigConsolidationSource],
    available: &[crate::chain::utxo::UtxoEntry],
    resolved: &ResolvedConsolidationSources,
) -> Result<(Vec<PlannedInput>, u64), String> {
    let mut inputs = Vec::with_capacity(sources.len());
    let mut total = 0u64;
    for source in sources {
        let (input, amount) = build_consolidation_input(source, available, resolved)?;
        total = total
            .checked_add(amount)
            .ok_or("selected multisig total overflow".to_string())?;
        inputs.push(input);
    }
    Ok((inputs, total))
}

fn build_consolidation_input(
    source: &MultisigConsolidationSource,
    available: &[crate::chain::utxo::UtxoEntry],
    resolved: &ResolvedConsolidationSources,
) -> Result<(PlannedInput, u64), String> {
    let utxo = find_selected_utxo(source, available)?;
    let amount = utxo.amount;
    let (redeem, derivations, sigops) = resolved
        .get(&source.address)
        .ok_or("unresolved multisig source".to_string())?;
    Ok((
        PlannedInput::p2sh_multisig(utxo, redeem, *sigops)
            .with_bip32_derivations(derivations.clone()),
        amount,
    ))
}

fn find_selected_utxo(
    source: &MultisigConsolidationSource,
    available: &[crate::chain::utxo::UtxoEntry],
) -> Result<crate::chain::utxo::UtxoEntry, String> {
    for utxo in available {
        if utxo.tx_id == source.tx_id && utxo.index == source.index {
            return Ok(utxo.clone());
        }
    }
    Err(format!("UTXO {}:{} not found", source.tx_id, source.index))
}

pub(super) fn required_total(amount: u64, fee: u64) -> Result<u64, String> {
    amount
        .checked_add(fee)
        .ok_or("multisig required amount overflow".to_string())
}

pub(super) fn require_selected_total(total: u64, required: u64) -> Result<(), String> {
    if total >= required {
        return Ok(());
    }
    Err(format!("Selected {total} sompi but need {required}"))
}

pub(super) struct ChangeOutputRequest<'a> {
    pub descriptor: &'a MultisigDescriptor,
    pub source_address: &'a str,
    pub prefix: &'a str,
    pub cosigner: u32,
    pub change_index_hint: u32,
    pub client: &'a NetworkClient,
    pub change: u64,
}

pub(super) async fn append_consolidation_change(
    request: ChangeOutputRequest<'_>,
    outputs: &mut Vec<PlannedOutput>,
) -> Result<(), String> {
    if !should_append_change(request.change) {
        return Ok(());
    }
    outputs.push(consolidation_change_output(&request).await?);
    Ok(())
}

fn should_append_change(change: u64) -> bool {
    change != 0 && !amounts::is_dust(change)
}

async fn consolidation_change_output(
    request: &ChangeOutputRequest<'_>,
) -> Result<PlannedOutput, String> {
    let change_index = resolve_change_index(
        request.descriptor,
        request.source_address,
        request.cosigner,
        request.change_index_hint,
        request.client,
    )
    .await?;
    let keys = request
        .descriptor
        .public_keys_at(change_index, request.cosigner, 1)?;
    let redeem = build_redeem_script(request.descriptor.threshold(), &keys)?;
    let address = crate::contract::script::p2sh::script_to_address(&redeem, request.prefix)?;
    let script = crate::primitives::address::address_to_script_pubkey(&address)?;
    let derivations = request
        .descriptor
        .bip32_derivations(change_index, request.cosigner, 1)?;
    Ok(PlannedOutput::new(request.change, script).with_bip32_derivations(derivations))
}

pub(super) async fn resolve_change_index(
    descriptor: &MultisigDescriptor,
    source_address: &str,
    cosigner: u32,
    change_index_hint: u32,
    client: &NetworkClient,
) -> Result<u32, String> {
    if change_index_hint != u32::MAX {
        return Ok(change_index_hint);
    }
    next_change_index(
        descriptor,
        cosigner,
        MULTISIG_BRANCH_SCAN_DEPTH,
        client,
        source_address,
    )
    .await
}
