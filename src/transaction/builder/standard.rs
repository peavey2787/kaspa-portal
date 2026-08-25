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
    const DEFAULT_PLANNER_FEE_RATE: u64 = 110;
    const MINIMUM_FEE: u64 = 300_000;

    let inputs = selected
        .iter()
        .map(|utxo| (utxo.amount, 1u64))
        .collect::<Vec<_>>();
    let mut fee = MINIMUM_FEE.max(requested_fee);
    for _ in 0..3 {
        let required = amounts::checked_required(amount, fee)?;
        let change = selected_total.saturating_sub(required);
        let outputs = if !amounts::is_dust(change) {
            vec![(amount, 1u64), (change, 1u64)]
        } else {
            vec![(amount, 1u64)]
        };
        let output_script_lengths = vec![34usize; outputs.len()];
        let (non_contextual_fee, _, _) = crate::transaction::mass::estimate_non_contextual_fee(
            selected.len(),
            &output_script_lengths,
            0,
            DEFAULT_PLANNER_FEE_RATE,
        )?;
        let storage_mass = amounts::storage_mass_estimate(&inputs, &outputs)?;
        let storage_fee = storage_mass
            .checked_mul(DEFAULT_PLANNER_FEE_RATE)
            .ok_or_else(|| "Estimated storage fee exceeds supported range".to_string())?;
        fee = non_contextual_fee
            .max(storage_fee)
            .max(MINIMUM_FEE)
            .max(requested_fee);
    }
    Ok(fee)
}
