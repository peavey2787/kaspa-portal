//! Payload send planning: choose the input set whose complete plan is
//! cheapest, accounting for KIP-9 storage mass of the change output.

use crate::{
    chain::utxo::UtxoEntry,
    transaction::builder::{
        model::UnsignedTransactionPlan, planning::amounts, planning::plan_payment,
    },
    wallet::account::WalletData,
};

use super::{encode_plan, storage_mass_fee_with_payload, PreparedSend, MINIMUM_PLANNER_FEE};

pub(in crate::transaction::builder) fn create_send_with_payload_from_utxos(
    wallet: &WalletData,
    prepared: &PreparedSend,
    amount: u64,
    requested_fee: u64,
    payload: &[u8],
    mut utxos: Vec<UtxoEntry>,
    fee_rate: u64,
) -> Result<String, String> {
    const MAX_INPUTS: usize = 8;
    // KIP-9 storage mass grows as the change output shrinks, so the smallest
    // covering selection can leave a tiny change that costs more in fee (or,
    // once it is storage-dust, is burned as fee) than one more input would.
    // Evaluate each largest-first prefix within the input limit and keep the
    // cheapest complete plan.
    crate::transaction::builder::selection::sort_largest_first(&mut utxos);
    let minimum_required =
        amounts::checked_required(amount, MINIMUM_PLANNER_FEE.max(requested_fee))?;
    let mut best: Option<(u64, UnsignedTransactionPlan)> = None;
    let mut total = 0u64;
    for count in 1..=utxos.len().min(MAX_INPUTS) {
        total = total
            .checked_add(utxos[count - 1].amount)
            .ok_or_else(|| "UTXO total exceeds supported monetary range".to_string())?;
        if total < minimum_required {
            continue;
        }
        let Some((fee, plan)) = plan_payload_send(
            wallet,
            prepared,
            amount,
            requested_fee,
            payload,
            utxos[..count].to_vec(),
            fee_rate,
        ) else {
            continue;
        };
        if best.as_ref().is_none_or(|(best_fee, _)| fee < *best_fee) {
            best = Some((fee, plan));
        }
    }
    match best {
        Some((_, plan)) => encode_plan(&plan),
        None => {
            let available = utxos.iter().take(MAX_INPUTS).try_fold(0u64, |sum, utxo| {
                sum.checked_add(utxo.amount)
                    .ok_or_else(|| "UTXO total exceeds supported monetary range".to_string())
            })?;
            Err(format!(
                "Insufficient funds within the current {MAX_INPUTS}-UTXO selection limit: have {available} sompi, need at least {minimum_required} sompi plus mass fees. Raise the Advanced UTXO limit or choose UTXOs manually."
            ))
        }
    }
}

/// The complete plan and its fee for spending exactly `selected`, or `None`
/// when `selected` cannot pay the amount plus its mass-derived fee.
fn plan_payload_send(
    wallet: &WalletData,
    prepared: &PreparedSend,
    amount: u64,
    requested_fee: u64,
    payload: &[u8],
    selected: Vec<UtxoEntry>,
    fee_rate: u64,
) -> Option<(u64, UnsignedTransactionPlan)> {
    const MAX_FEE_PASSES: usize = 8;
    let selected_total = crate::transaction::builder::selection::checked_total(&selected).ok()?;
    let potential_change_script_length = wallet
        .change_addresses
        .get(wallet.next_change_index)
        .map(|address| crate::primitives::address::address_to_script_pubkey(address))
        .transpose()
        .ok()?
        .map(|script| script.len());
    let mut output_script_lengths = vec![prepared.output.script_public_key.len()];
    if let Some(change_script_length) = potential_change_script_length {
        output_script_lengths.push(change_script_length);
    }
    let mut fee = storage_mass_fee_with_payload(
        &selected,
        selected_total,
        amount,
        requested_fee,
        payload.len(),
        &output_script_lengths,
        fee_rate,
    )
    .ok()?;
    for _ in 0..MAX_FEE_PASSES {
        if amounts::checked_required(amount, fee).ok()? > selected_total {
            return None;
        }
        let mut plan =
            plan_payment(wallet, selected.clone(), vec![prepared.output.clone()], fee).ok()?;
        plan.payload = payload.to_vec();
        let exact_script_lengths = plan
            .outputs
            .iter()
            .map(|output| output.script_public_key.len())
            .collect::<Vec<_>>();
        let (non_contextual_fee, _, _) = crate::transaction::mass::estimate_non_contextual_fee(
            plan.inputs.len(),
            &exact_script_lengths,
            plan.payload.len(),
            fee_rate,
        )
        .ok()?;
        if non_contextual_fee <= fee {
            let paid = selected_total
                .checked_sub(plan.outputs.iter().map(|output| output.amount).sum::<u64>())?;
            return Some((paid, plan));
        }
        fee = non_contextual_fee
            .max(requested_fee)
            .max(MINIMUM_PLANNER_FEE);
    }
    None
}
