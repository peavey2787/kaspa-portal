use serde_json::{json, Value};

use crate::{
    transaction::builder::model::PlannedInput, transaction::interchange::pskt::pskb::PskbOutput,
};

pub fn input_value(input: &PlannedInput) -> Value {
    let script_public_key = format!("0000{}", hex::encode(&input.utxo.script_public_key));
    let redeem_script = input
        .redeem_script
        .as_ref()
        .map(|script| Value::String(hex::encode(script)))
        .unwrap_or(Value::Null);
    json!({
        "utxoEntry": {
            "amount": input.utxo.amount.to_string(),
            "scriptPublicKey": script_public_key,
            "blockDaaScore": input.utxo.block_daa_score.to_string(),
            "isCoinbase": false
        },
        "previousOutpoint": {
            "transactionId": input.utxo.tx_id,
            "index": input.utxo.index
        },
        "sequence": input.sequence.to_string(),
        "minTime": Value::Null,
        "partialSigs": {},
        "sighashType": 1u8,
        "redeemScript": redeem_script,
        "sigOpCount": input.sig_op_count,
        "bip32Derivations": input.bip32_derivations.clone().unwrap_or_else(|| json!({})),
        "finalScriptSig": Value::Null,
        "proprietaries": {}
    })
}

pub fn output_value(output: &PskbOutput, include_covenant_binding: bool) -> Value {
    let script_public_key = format!("0000{}", hex::encode(&output.script));
    let covenant_binding = match output.covenant {
        Some((authorizing_input, covenant_id)) => json!({
            "authorizingInput": authorizing_input,
            "covenantId": hex::encode(covenant_id)
        }),
        None => Value::Null,
    };
    let proprietaries = match output.derivation_hint {
        Some((branch, index)) => json!({
            "kaspaPortalDerivation": { "branch": branch, "index": index.to_string() }
        }),
        None => json!({}),
    };

    if include_covenant_binding {
        json!({
            "amount": output.amount.to_string(),
            "scriptPublicKey": script_public_key,
            "covenantBinding": covenant_binding,
            "redeemScript": Value::Null,
            "bip32Derivations": output.bip32_derivations.clone().unwrap_or_else(|| json!({})),
            "proprietaries": proprietaries
        })
    } else {
        json!({
            "amount": output.amount.to_string(),
            "scriptPublicKey": script_public_key,
            "redeemScript": Value::Null,
            "bip32Derivations": output.bip32_derivations.clone().unwrap_or_else(|| json!({})),
            "proprietaries": proprietaries
        })
    }
}
