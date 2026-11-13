use crate::{
    chain::utxo::UtxoEntry,
    network::client::NetworkClient,
    primitives::numeric::ceil_to_u64,
    transaction::builder::{
        model::{PlannedOutput, UnsignedTransactionPlan},
        planning::amounts,
        selection::select_explicit,
    },
    transaction::interchange::pskt::pskb,
    wallet::account::WalletData,
};

/// The feerate (sompi per gram) a send is priced at when the node gives no
/// estimate, and the rate an offline PSKB is priced at.
const DEFAULT_PLANNER_FEE_RATE: u64 = 110;
const MINIMUM_PLANNER_FEE: u64 = 300_000;
/// The most UTXOs an automatic send spends.
const AUTOMATIC_SEND_INPUTS: usize = 8;

#[path = "standard/priced.rs"]
mod priced;
pub(super) use priced::{
    create_consolidation_from_utxos, create_send_from_utxos, create_send_selected_from_utxos,
    SendPricing,
};

pub async fn create_send(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    fee: u64,
    client: &NetworkClient,
) -> Result<String, String> {
    create_send_limited(
        wallet,
        destination,
        amount,
        fee,
        AUTOMATIC_SEND_INPUTS,
        client,
    )
    .await
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
            "transaction payload exceeds the {}-byte consensus limit",
            crate::transaction::model::MAX_PAYLOAD_SIZE
        ));
    }
    let prepared = prepare_send(wallet, destination, amount, requested_fee)?;
    let utxos = wallet_utxos(wallet, client).await?;
    let pricing = SendPricing {
        payload,
        fee_rate: planner_fee_rate(client).await,
    };
    create_send_from_utxos(wallet, &prepared, pricing, utxos, AUTOMATIC_SEND_INPUTS)
}

pub async fn create_send_limited(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    fee: u64,
    max_inputs: usize,
    client: &NetworkClient,
) -> Result<String, String> {
    let prepared = prepare_send(wallet, destination, amount, fee)?;
    let utxos = wallet_utxos(wallet, client).await?;
    let pricing = SendPricing {
        payload: &[],
        fee_rate: planner_fee_rate(client).await,
    };
    create_send_from_utxos(wallet, &prepared, pricing, utxos, max_inputs)
}

pub async fn create_send_selected(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    fee: u64,
    indices: &[usize],
    client: &NetworkClient,
) -> Result<String, String> {
    let prepared = prepare_send(wallet, destination, amount, fee)?;
    let selected = select_explicit(wallet_utxos(wallet, client).await?, indices)?;
    let pricing = SendPricing {
        payload: &[],
        fee_rate: planner_fee_rate(client).await,
    };
    create_send_selected_from_utxos(wallet, &prepared, pricing, selected)
}

pub async fn create_consolidation(
    wallet: &WalletData,
    fee: u64,
    client: &NetworkClient,
) -> Result<String, String> {
    let utxos = wallet_utxos(wallet, client).await?;
    create_consolidation_from_utxos(wallet, fee, utxos, planner_fee_rate(client).await)
}

/// Build a send from caller-chosen UTXOs without a node, priced at the
/// default planner feerate.
pub fn create_pskb_with_utxos(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    requested_fee: u64,
    selected: Vec<UtxoEntry>,
) -> Result<String, String> {
    let prepared = prepare_send(wallet, destination, amount, requested_fee)?;
    let pricing = SendPricing {
        payload: &[],
        fee_rate: DEFAULT_PLANNER_FEE_RATE,
    };
    create_send_selected_from_utxos(wallet, &prepared, pricing, selected)
}

/// Every UTXO on the wallet's receive and change addresses.
async fn wallet_utxos(
    wallet: &WalletData,
    client: &NetworkClient,
) -> Result<Vec<UtxoEntry>, String> {
    let addresses = wallet
        .receive_addresses
        .iter()
        .chain(wallet.change_addresses.iter())
        .cloned()
        .collect::<Vec<_>>();
    crate::network::queries::utxos::fetch_for_addresses(client, &addresses).await
}

/// The node's normal-priority feerate, or the default when it gives none.
async fn planner_fee_rate(client: &NetworkClient) -> u64 {
    crate::network::queries::fees::get(client)
        .await
        .ok()
        .and_then(|estimate| ceil_to_u64(estimate.normal_sompi_per_gram))
        .unwrap_or(DEFAULT_PLANNER_FEE_RATE)
}

#[derive(Clone, Debug)]
pub(super) struct PreparedSend {
    output: PlannedOutput,
    fee: u64,
}

impl PreparedSend {
    /// The least fee this send pays, whatever its mass.
    fn minimum_fee(&self) -> u64 {
        MINIMUM_PLANNER_FEE.max(self.fee)
    }
}

/// Validate a single-recipient send; the destination must be on the
/// wallet's own network.
pub(super) fn prepare_send(
    wallet: &WalletData,
    destination: &str,
    amount: u64,
    fee: u64,
) -> Result<PreparedSend, String> {
    validate_recipient_amount(amount)?;
    amounts::checked_required(amount, fee)?;
    let output = PlannedOutput::new(
        amount,
        crate::primitives::address::address_to_script_pubkey_on(
            destination,
            wallet.address_prefix()?,
        )?,
    );
    Ok(PreparedSend { output, fee })
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

/// Estimate the fee a single-recipient send of `amount` from `selected`
/// needs at `fee_rate`, accounting for the storage mass of its change (or
/// the whole remainder, once that change is storage-dust).
pub(super) fn storage_mass_fee(
    selected: &[UtxoEntry],
    selected_total: u64,
    amount: u64,
    requested_fee: u64,
    payload_len: usize,
    output_script_lengths: &[usize],
    fee_rate: u64,
) -> Result<u64, String> {
    // Each pass lowers the change (raising its storage mass) until the fee
    // stops rising or the change turns into storage-dust; near that boundary
    // the steps shrink, so allow a generous (cheap, arithmetic-only) bound.
    const MAX_FEE_PASSES: usize = 256;

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
                    .get(..1)
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
        let required_fee = required_mass_fee(
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

pub(super) fn required_mass_fee(
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
