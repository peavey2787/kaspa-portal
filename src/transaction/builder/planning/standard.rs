use crate::{
    chain::utxo::UtxoEntry,
    transaction::builder::{
        model::{PlannedOutput, UnsignedTransactionPlan},
        selection::checked_total,
    },
    wallet::account::derivation::WalletData,
};

use super::{amounts::checked_sum, calculate_change};

pub fn plan_payment(
    wallet: &WalletData,
    selected: Vec<UtxoEntry>,
    mut recipients: Vec<PlannedOutput>,
    fee: u64,
) -> Result<UnsignedTransactionPlan, String> {
    let selected_total = checked_total(&selected)?;
    let spend_total = checked_sum(recipients.iter().map(|output| output.amount))?;
    let change = calculate_change(selected_total, spend_total, fee)?;

    if change > 0 {
        let address = wallet
            .change_addresses
            .get(wallet.next_change_index)
            .ok_or_else(|| "No more change addresses. Re-import kpub.".to_string())?;
        let script = crate::primitives::address::address_to_script_pubkey(address)?;
        let index = u32::try_from(wallet.next_change_index)
            .map_err(|_| "Change derivation index exceeds u32".to_string())?;
        recipients.push(PlannedOutput::new(change, script).with_derivation(1, index));
    }

    Ok(UnsignedTransactionPlan::standard(selected, recipients))
}

pub fn plan_consolidation(
    wallet: &WalletData,
    selected: Vec<UtxoEntry>,
    fee: u64,
) -> Result<UnsignedTransactionPlan, String> {
    let total = checked_total(&selected)?;
    let amount = total
        .checked_sub(fee)
        .ok_or_else(|| "Balance too low to cover fee".to_string())?;
    if amount == 0 {
        return Err("Balance too low to cover fee".into());
    }
    let address = wallet
        .receive_addresses
        .first()
        .ok_or_else(|| "Wallet has no receive address".to_string())?;
    let script = crate::primitives::address::address_to_script_pubkey(address)?;
    Ok(UnsignedTransactionPlan::standard(
        selected,
        vec![PlannedOutput::new(amount, script).with_derivation(0, 0)],
    ))
}
