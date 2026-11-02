//! Spends from KIP-22 addresses. A redeem script with no selectors is the
//! degenerate covenant path, so signing and finalization share that pipeline:
//! the final script is `<signature> <redeem script>`.

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    primitives::{address::p2sh_script, utxo::UtxoEntry},
    wallet::derivation::kip22,
};

use super::planning::calculate_change;
use super::pskb::{
    encode_wire, CovenantExecution, CovenantInputPolicy, PskbGlobalPlan, PskbInputPlan,
    PskbOutputPlan, PskbPlan,
};

const MAX_PAYMENT_INPUTS: usize = 8;

/// A coin at a KIP-22 address and the public key its redeem script reveals.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Kip22Coin {
    pub utxo: UtxoEntry,
    pub xonly: [u8; 32],
}

/// Encode an unsigned PSKB spending `coins` to `outputs`. A coin whose script
/// does not commit to its stated key is rejected before anything is signed.
pub fn encode_spend(coins: &[Kip22Coin], outputs: Vec<PskbOutputPlan>) -> Result<String, String> {
    if coins.is_empty() {
        return Err("KIP-22 spend has no inputs".to_string());
    }
    let inputs = coins
        .iter()
        .map(input_plan)
        .collect::<Result<Vec<_>, _>>()?;
    encode_wire(&PskbPlan {
        global: PskbGlobalPlan::standard(),
        inputs,
        outputs,
    })
}

/// Pay `amount` to `destination_script`, spending the largest coins first (at
/// most `MAX_PAYMENT_INPUTS`). Change always returns to a KIP-22 address, so a
/// payment cannot move the remainder to a key-revealing P2PK output.
pub fn encode_payment(
    coins: &[Kip22Coin],
    destination_script: &[u8],
    amount: u64,
    fee: u64,
    change_xonly: &[u8; 32],
) -> Result<String, String> {
    let selected = select_coins(
        coins,
        amount.checked_add(fee).ok_or("Amount plus fee overflows")?,
    )?;
    let total = selected.iter().try_fold(0u64, |sum, coin| {
        sum.checked_add(coin.utxo.amount)
            .ok_or("UTXO total overflows")
    })?;
    let mut outputs = vec![PskbOutputPlan::plain(amount, destination_script)];
    let change = calculate_change(total, amount, fee)?;
    if change > 0 {
        let script = p2sh_script(&kip22::redeem_script_hash(change_xonly));
        outputs.push(PskbOutputPlan::plain(change, &script));
    }
    encode_spend(&selected, outputs)
}

fn select_coins(coins: &[Kip22Coin], required: u64) -> Result<Vec<Kip22Coin>, String> {
    let mut sorted = coins.to_vec();
    sorted.sort_by_key(|coin| core::cmp::Reverse(coin.utxo.amount));
    let mut total = 0u64;
    let mut selected = Vec::new();
    for coin in sorted.into_iter().take(MAX_PAYMENT_INPUTS) {
        total = total
            .checked_add(coin.utxo.amount)
            .ok_or("UTXO total overflows")?;
        selected.push(coin);
        if total >= required {
            return Ok(selected);
        }
    }
    Err(format!(
        "Insufficient KIP-22 funds: have {total} sompi, need {required} sompi"
    ))
}

fn input_plan(coin: &Kip22Coin) -> Result<PskbInputPlan, String> {
    let source_script = p2sh_script(&kip22::redeem_script_hash(&coin.xonly));
    if coin.utxo.script_public_key != source_script {
        return Err(format!(
            "UTXO {}:{} does not pay the KIP-22 script for its key",
            coin.utxo.tx_id, coin.utxo.index
        ));
    }
    Ok(PskbInputPlan::covenant(
        coin.utxo.clone(),
        &source_script,
        &kip22::redeem_script(&coin.xonly),
        CovenantInputPolicy {
            sequence: u64::MAX,
            sig_op_count: 1,
            minimum_signatures: 1,
            proprietaries: Value::Array(Vec::new()),
            min_time: Some(0),
            execution: Some(CovenantExecution {
                supplied_mask: 0,
                supplied_true_mask: 0,
            }),
        },
    ))
}

#[cfg(test)]
#[path = "unit_tests/kip22.rs"]
mod unit_tests;
