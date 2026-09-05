use crate::{
    chain::utxo::UtxoEntry,
    network::client::NetworkClient,
    transaction::builder::{
        model::{PlannedOutput, UnsignedTransactionPlan},
        planning::{amounts, plan_consolidation, plan_payment},
        selection::{select_automatic_with_limit, select_explicit, select_for_consolidation},
    },
    transaction::interchange::pskt::pskb,
    wallet::account::WalletData,
};

const DEFAULT_PLANNER_FEE_RATE: u64 = 110;
const MINIMUM_PLANNER_FEE: u64 = 300_000;

pub async fn create_send(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    fee: u64,
    client: &NetworkClient,
) -> Result<String, String> {
    let prepared = prepare_send(destination, amount, fee)?;
    let addresses = wallet
        .receive_addresses
        .iter()
        .chain(wallet.change_addresses.iter())
        .cloned()
        .collect::<Vec<_>>();
    let utxos = crate::network::queries::utxos::fetch_for_addresses(client, &addresses).await?;
    create_send_from_utxos(wallet, &prepared, utxos)
}

pub async fn create_send_with_payload(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    requested_fee: u64,
    payload: &[u8],
    client: &NetworkClient,
) -> Result<String, String> {
    if payload.len() > crate::transaction::model::MAX_PAYLOAD_SIZE {
        return Err(format!(
            "transaction payload exceeds KSPT v1 limit of {} bytes",
            crate::transaction::model::MAX_PAYLOAD_SIZE
        ));
    }
    let prepared = prepare_send(destination, amount, requested_fee)?;
    let addresses = wallet
        .receive_addresses
        .iter()
        .chain(wallet.change_addresses.iter())
        .cloned()
        .collect::<Vec<_>>();
    let utxos = crate::network::queries::utxos::fetch_for_addresses(client, &addresses).await?;
    let fee_rate = crate::network::queries::fees::get(client)
        .await
        .ok()
        .and_then(|estimate| finite_fee_rate(estimate.normal_sompi_per_gram))
        .unwrap_or(DEFAULT_PLANNER_FEE_RATE);
    create_send_with_payload_from_utxos(
        wallet,
        &prepared,
        amount,
        requested_fee,
        payload,
        utxos,
        fee_rate,
    )
}

fn create_send_with_payload_from_utxos(
    wallet: &WalletData,
    prepared: &PreparedSend,
    amount: u64,
    requested_fee: u64,
    payload: &[u8],
    utxos: Vec<UtxoEntry>,
    fee_rate: u64,
) -> Result<String, String> {
    const MAX_FEE_SELECTION_PASSES: usize = 12;
    let mut fee = MINIMUM_PLANNER_FEE.max(requested_fee);
    let potential_change_script_length = wallet
        .change_addresses
        .get(wallet.next_change_index)
        .map(|address| crate::primitives::address::address_to_script_pubkey(address))
        .transpose()?
        .map(|script| script.len());

    for _ in 0..MAX_FEE_SELECTION_PASSES {
        let required = amounts::checked_required(amount, fee)?;
        let selected = select_automatic_with_limit(utxos.clone(), required, 8)?;
        let selected_total = crate::transaction::builder::selection::checked_total(&selected)?;

        let mut output_script_lengths = vec![prepared.output.script_public_key.len()];
        if let Some(change_script_length) = potential_change_script_length {
            output_script_lengths.push(change_script_length);
        }

        let required_fee = storage_mass_fee_with_payload(
            &selected,
            selected_total,
            amount,
            requested_fee,
            payload.len(),
            &output_script_lengths,
            fee_rate,
        )?;
        if required_fee > fee {
            fee = required_fee;
            continue;
        }

        let mut plan = plan_payment(wallet, selected, vec![prepared.output.clone()], fee)?;
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
        )?;
        if non_contextual_fee > fee {
            fee = non_contextual_fee
                .max(requested_fee)
                .max(MINIMUM_PLANNER_FEE);
            continue;
        }
        return encode_plan(&plan);
    }

    Err("payload-aware fee/UTXO selection did not converge".into())
}

pub async fn create_send_limited(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    fee: u64,
    max_inputs: usize,
    client: &NetworkClient,
) -> Result<String, String> {
    let prepared = prepare_send(destination, amount, fee)?;
    let addresses = wallet
        .receive_addresses
        .iter()
        .chain(wallet.change_addresses.iter())
        .cloned()
        .collect::<Vec<_>>();
    crate::network::queries::utxos::fetch_for_addresses(client, &addresses)
        .await
        .and_then(|utxos| create_limited_send_from_utxos(wallet, &prepared, utxos, max_inputs))
}

pub(super) fn create_limited_send_from_utxos(
    wallet: &WalletData,
    prepared: &PreparedSend,
    utxos: Vec<UtxoEntry>,
    max_inputs: usize,
) -> Result<String, String> {
    select_automatic_with_limit(utxos, prepared.required, max_inputs).and_then(|selected| {
        encode_payment(wallet, selected, prepared.output.clone(), prepared.fee)
    })
}

pub async fn create_send_selected(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    fee: u64,
    indices: &[usize],
    client: &NetworkClient,
) -> Result<String, String> {
    let prepared = prepare_send(destination, amount, fee)?;
    let addresses = wallet
        .receive_addresses
        .iter()
        .chain(wallet.change_addresses.iter())
        .cloned()
        .collect::<Vec<_>>();
    let utxos = crate::network::queries::utxos::fetch_for_addresses(client, &addresses).await?;
    create_send_selected_from_utxos(wallet, &prepared, indices, utxos)
}

pub async fn create_consolidation(
    wallet: &WalletData,
    fee: u64,
    client: &NetworkClient,
) -> Result<String, String> {
    let addresses = wallet
        .receive_addresses
        .iter()
        .chain(wallet.change_addresses.iter())
        .cloned()
        .collect::<Vec<_>>();
    let utxos = crate::network::queries::utxos::fetch_for_addresses(client, &addresses).await?;
    create_consolidation_from_utxos(wallet, fee, utxos)
}

pub fn create_pskb_with_utxos(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    requested_fee: u64,
    selected: Vec<UtxoEntry>,
) -> Result<String, String> {
    let prepared = prepare_send(destination, amount, requested_fee)?;
    if selected.is_empty() {
        return Err("No UTXOs provided".into());
    }
    let selected_total = crate::transaction::builder::selection::checked_total(&selected)?;
    let fee = storage_mass_fee(&selected, selected_total, amount, requested_fee)?;
    encode_payment(wallet, selected, prepared.output, fee)
}

#[derive(Clone, Debug)]
pub(super) struct PreparedSend {
    output: PlannedOutput,
    required: u64,
    fee: u64,
}

pub(super) fn prepare_send(
    destination: &str,
    amount: u64,
    fee: u64,
) -> Result<PreparedSend, String> {
    validate_recipient_amount(amount)?;
    let required = amounts::checked_required(amount, fee)?;
    let output = PlannedOutput::new(
        amount,
        crate::primitives::address::address_to_script_pubkey(destination)?,
    );
    Ok(PreparedSend {
        output,
        required,
        fee,
    })
}

pub(super) fn create_send_from_utxos(
    wallet: &WalletData,
    prepared: &PreparedSend,
    utxos: Vec<UtxoEntry>,
) -> Result<String, String> {
    let selected = select_automatic_with_limit(utxos, prepared.required, 8)?;
    encode_payment(wallet, selected, prepared.output.clone(), prepared.fee)
}

pub(super) fn create_send_selected_from_utxos(
    wallet: &WalletData,
    prepared: &PreparedSend,
    indices: &[usize],
    utxos: Vec<UtxoEntry>,
) -> Result<String, String> {
    let selected = select_explicit(utxos, indices)?;
    encode_payment(wallet, selected, prepared.output.clone(), prepared.fee)
}

pub(super) fn create_consolidation_from_utxos(
    wallet: &WalletData,
    fee: u64,
    utxos: Vec<UtxoEntry>,
) -> Result<String, String> {
    let selected = select_for_consolidation(utxos, 5)?;
    encode_plan(&plan_consolidation(wallet, selected, fee)?)
}

fn encode_payment(
    wallet: &WalletData,
    selected: Vec<UtxoEntry>,
    output: PlannedOutput,
    fee: u64,
) -> Result<String, String> {
    encode_plan(&plan_payment(wallet, selected, vec![output], fee)?)
}

fn encode_plan(plan: &UnsignedTransactionPlan) -> Result<String, String> {
    pskb::encode_plan(plan)
}

pub(super) fn validate_recipient_amount(amount: u64) -> Result<(), String> {
    if amount == 0 {
        return Err("amount must be > 0".into());
    }
    if amounts::is_dust(amount) {
        return Err(format!("amount too small ({} sompi)", amount));
    }
    Ok(())
}

pub(super) fn storage_mass_fee(
    selected: &[UtxoEntry],
    selected_total: u64,
    amount: u64,
    requested_fee: u64,
) -> Result<u64, String> {
    let outputs = [34usize, 34usize];
    storage_mass_fee_with_payload(
        selected,
        selected_total,
        amount,
        requested_fee,
        0,
        &outputs,
        DEFAULT_PLANNER_FEE_RATE,
    )
}

pub(super) fn storage_mass_fee_with_payload(
    selected: &[UtxoEntry],
    selected_total: u64,
    amount: u64,
    requested_fee: u64,
    payload_len: usize,
    output_script_lengths: &[usize],
    fee_rate: u64,
) -> Result<u64, String> {
    const MAX_FEE_PASSES: usize = 16;

    let inputs = selected
        .iter()
        .map(|utxo| (utxo.amount, 1u64))
        .collect::<Vec<_>>();
    let minimum_fee = MINIMUM_PLANNER_FEE.max(requested_fee);
    // Preserve the planner's fail-closed monetary-range contract before any
    // selected-value short-circuit. An amount at (or too near) u64::MAX cannot
    // be paired with even the minimum fee without overflowing the supported
    // monetary range.
    let _ = amounts::checked_required(amount, minimum_fee)?;
    let available_fee = selected_total
        .checked_sub(amount)
        .ok_or_else(|| "Selected value is below payment amount".to_string())?;
    let mut fee = minimum_fee;

    for _ in 0..MAX_FEE_PASSES {
        if fee > available_fee {
            return Ok(fee);
        }

        let change = available_fee - fee;
        if amounts::is_dust(change) {
            let required_no_change = required_mass_fee(
                &inputs,
                selected.len(),
                &[(amount, 1u64)],
                output_script_lengths
                    .first()
                    .copied()
                    .ok_or_else(|| "missing output script length for fee estimate".to_string())?,
                payload_len,
                fee_rate,
                minimum_fee,
            )?;

            // Omitting dust change means the complete input-minus-payment remainder
            // becomes the transaction fee. Return that actual fee when it satisfies
            // mass policy; otherwise return the larger requirement so the caller can
            // select additional inputs.
            return Ok(if available_fee >= required_no_change {
                available_fee
            } else {
                required_no_change
            });
        }

        let script_lengths = output_script_lengths
            .get(..2)
            .ok_or_else(|| "missing output script length for fee estimate".to_string())?;
        let required_fee = required_mass_fee_for_scripts(
            &inputs,
            selected.len(),
            &[(amount, 1u64), (change, 1u64)],
            script_lengths,
            payload_len,
            fee_rate,
            minimum_fee,
        )?;
        if required_fee <= fee {
            return Ok(fee);
        }
        fee = required_fee;
    }

    Err("payload-aware storage-mass fee calculation did not converge".into())
}

fn required_mass_fee(
    inputs: &[(u64, u64)],
    input_count: usize,
    outputs: &[(u64, u64)],
    output_script_length: usize,
    payload_len: usize,
    fee_rate: u64,
    minimum_fee: u64,
) -> Result<u64, String> {
    required_mass_fee_for_scripts(
        inputs,
        input_count,
        outputs,
        &[output_script_length],
        payload_len,
        fee_rate,
        minimum_fee,
    )
}

fn required_mass_fee_for_scripts(
    inputs: &[(u64, u64)],
    input_count: usize,
    outputs: &[(u64, u64)],
    output_script_lengths: &[usize],
    payload_len: usize,
    fee_rate: u64,
    minimum_fee: u64,
) -> Result<u64, String> {
    if output_script_lengths.len() != outputs.len() {
        return Err("missing output script length for fee estimate".into());
    }
    let effective_fee_rate =
        fee_rate.max(crate::transaction::mass::MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM);
    let (non_contextual_fee, _, _) = crate::transaction::mass::estimate_non_contextual_fee(
        input_count,
        output_script_lengths,
        payload_len,
        effective_fee_rate,
    )?;
    let storage_mass = amounts::storage_mass_estimate(inputs, outputs)?;
    let storage_fee = storage_mass
        .checked_mul(effective_fee_rate)
        .ok_or_else(|| "Estimated storage fee exceeds supported range".to_string())?;
    Ok(non_contextual_fee.max(storage_fee).max(minimum_fee))
}

fn finite_fee_rate(value: f64) -> Option<u64> {
    if !value.is_finite() || value <= 0.0 || value > u64::MAX as f64 {
        return None;
    }
    Some(value.ceil() as u64)
}
