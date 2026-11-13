//! Mass-priced planning: every standard send and consolidation pays the
//! feerate on its complete mass, including the KIP-9 storage mass of small
//! outputs, so a payment of a few KAS is not priced like a 2,300-gram
//! transfer.

use crate::{
    chain::utxo::UtxoEntry,
    transaction::builder::{
        model::UnsignedTransactionPlan,
        planning::{amounts, plan_consolidation, plan_payment},
        selection::{checked_total, select_for_consolidation, sort_largest_first},
    },
    wallet::account::WalletData,
};

use super::{encode_plan, required_mass_fee, storage_mass_fee, PreparedSend};

/// The most UTXOs one consolidation spends.
const CONSOLIDATION_INPUTS: usize = 5;

/// What a send carries besides its recipient: an optional payload and the
/// feerate (sompi per gram) its mass is priced at.
#[derive(Clone, Copy, Debug)]
pub(in crate::transaction::builder) struct SendPricing<'a> {
    pub(in crate::transaction::builder) payload: &'a [u8],
    pub(in crate::transaction::builder) fee_rate: u64,
}

/// Spend the cheapest largest-first prefix of `utxos` within `max_inputs`.
pub(in crate::transaction::builder) fn create_send_from_utxos(
    wallet: &WalletData,
    prepared: &PreparedSend,
    pricing: SendPricing<'_>,
    mut utxos: Vec<UtxoEntry>,
    max_inputs: usize,
) -> Result<String, String> {
    if max_inputs == 0 {
        return Err("UTXO selection limit must be at least 1".into());
    }
    // KIP-9 storage mass grows as the change output shrinks, so the smallest
    // covering selection can leave a tiny change that costs more in fee (or,
    // once it is storage-dust, is burned as fee) than one more input would.
    // Evaluate each largest-first prefix within the input limit and keep the
    // cheapest complete plan.
    sort_largest_first(&mut utxos);
    utxos.truncate(max_inputs);
    let minimum_required =
        amounts::checked_required(prepared.output.amount, prepared.minimum_fee())?;
    let mut best: Option<(u64, UnsignedTransactionPlan)> = None;
    let mut total = 0u64;
    for count in 1..=utxos.len() {
        total = total
            .checked_add(utxos[count - 1].amount)
            .ok_or_else(|| "UTXO total exceeds supported monetary range".to_string())?;
        if total < minimum_required {
            continue;
        }
        let Some(candidate) = price_send(wallet, prepared, pricing, utxos[..count].to_vec()) else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(best_fee, _)| candidate.0 < *best_fee)
        {
            best = Some(candidate);
        }
    }
    match best {
        Some((_, plan)) => encode_plan(&plan),
        None => Err(format!(
            "Insufficient funds within the current {max_inputs}-UTXO selection limit: have {total} sompi, need at least {minimum_required} sompi plus mass fees. Raise the Advanced UTXO limit or choose UTXOs manually."
        )),
    }
}

/// Spend exactly `selected`, paying the feerate on that plan's mass.
pub(in crate::transaction::builder) fn create_send_selected_from_utxos(
    wallet: &WalletData,
    prepared: &PreparedSend,
    pricing: SendPricing<'_>,
    selected: Vec<UtxoEntry>,
) -> Result<String, String> {
    if selected.is_empty() {
        return Err("No UTXOs provided".into());
    }
    let available = checked_total(&selected)?;
    let (_, plan) = price_send(wallet, prepared, pricing, selected).ok_or_else(|| {
        format!(
            "Selected UTXOs hold {available} sompi, which cannot pay {} sompi plus its mass fee",
            prepared.output.amount
        )
    })?;
    encode_plan(&plan)
}

/// Merge the largest UTXOs into one receive output, paying the feerate on
/// the consolidation's mass and never less than `requested_fee`.
pub(in crate::transaction::builder) fn create_consolidation_from_utxos(
    wallet: &WalletData,
    requested_fee: u64,
    utxos: Vec<UtxoEntry>,
    fee_rate: u64,
) -> Result<String, String> {
    let selected = select_for_consolidation(utxos, CONSOLIDATION_INPUTS)?;
    let (_, plan) = converge(requested_fee, fee_rate, requested_fee, |fee| {
        plan_consolidation(wallet, selected.clone(), fee)
    })?;
    encode_plan(&plan)
}

/// The complete plan and the fee it pays for spending exactly `selected`, or
/// `None` when `selected` cannot pay the amount plus its mass-derived fee.
fn price_send(
    wallet: &WalletData,
    prepared: &PreparedSend,
    pricing: SendPricing<'_>,
    selected: Vec<UtxoEntry>,
) -> Option<(u64, UnsignedTransactionPlan)> {
    let selected_total = checked_total(&selected).ok()?;
    let mut output_script_lengths = vec![prepared.output.script_public_key.len()];
    output_script_lengths.extend(change_script_length(wallet).ok()?);
    let estimate = storage_mass_fee(
        &selected,
        selected_total,
        prepared.output.amount,
        prepared.fee,
        pricing.payload.len(),
        &output_script_lengths,
        pricing.fee_rate,
    )
    .ok()?;
    converge(estimate, pricing.fee_rate, prepared.minimum_fee(), |fee| {
        let mut plan = plan_payment(wallet, selected.clone(), vec![prepared.output.clone()], fee)?;
        plan.payload = pricing.payload.to_vec();
        Ok(plan)
    })
    .ok()
}

/// The script length of the wallet's next change output, when it has one.
fn change_script_length(wallet: &WalletData) -> Result<Option<usize>, String> {
    wallet
        .change_addresses
        .get(wallet.next_change_index)
        .map(|address| {
            crate::primitives::address::address_to_script_pubkey(address).map(|script| script.len())
        })
        .transpose()
}

/// Re-plan at the fee each plan's exact mass demands until a plan pays for
/// itself; returns that plan and the fee it actually pays.
fn converge(
    mut fee: u64,
    fee_rate: u64,
    minimum_fee: u64,
    mut plan_at: impl FnMut(u64) -> Result<UnsignedTransactionPlan, String>,
) -> Result<(u64, UnsignedTransactionPlan), String> {
    const MAX_FEE_PASSES: usize = 8;
    for _ in 0..MAX_FEE_PASSES {
        let plan = plan_at(fee)?;
        let paid = paid_fee(&plan)?;
        let required = plan_mass_fee(&plan, fee_rate, minimum_fee)?;
        if required <= paid {
            return Ok((paid, plan));
        }
        fee = required;
    }
    Err("mass-priced fee did not converge".into())
}

/// What `plan` leaves to the miner: its inputs less its outputs.
fn paid_fee(plan: &UnsignedTransactionPlan) -> Result<u64, String> {
    let inputs = amounts::checked_sum(plan.inputs.iter().map(|input| input.utxo.amount))?;
    let outputs = amounts::checked_sum(plan.outputs.iter().map(|output| output.amount))?;
    inputs
        .checked_sub(outputs)
        .ok_or_else(|| "plan outputs exceed its inputs".to_string())
}

/// The fee the feerate demands for exactly `plan`: its compute and KIP-9
/// storage mass, never below `minimum_fee`.
fn plan_mass_fee(
    plan: &UnsignedTransactionPlan,
    fee_rate: u64,
    minimum_fee: u64,
) -> Result<u64, String> {
    let inputs = plan
        .inputs
        .iter()
        .map(|input| (input.utxo.amount, 1u64))
        .collect::<Vec<_>>();
    let outputs = plan
        .outputs
        .iter()
        .map(|output| (output.amount, 1u64))
        .collect::<Vec<_>>();
    let script_lengths = plan
        .outputs
        .iter()
        .map(|output| output.script_public_key.len())
        .collect::<Vec<_>>();
    required_mass_fee(
        &inputs,
        plan.inputs.len(),
        &outputs,
        &script_lengths,
        plan.payload.len(),
        fee_rate,
        minimum_fee,
    )
}
