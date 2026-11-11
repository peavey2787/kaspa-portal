use crate::transaction::model::Transaction;

pub(super) fn same_transaction_body(left: &Transaction, right: &Transaction) -> bool {
    same_transaction_header(left, right)
        && same_transaction_inputs(left, right)
        && same_transaction_outputs(left, right)
}

fn same_transaction_header(left: &Transaction, right: &Transaction) -> bool {
    (
        left.version,
        left.num_inputs,
        left.num_outputs,
        left.network,
        left.locktime,
        left.subnetwork_id,
        left.gas,
        left.payload.len(),
        left.stealth_tweak,
    ) == (
        right.version,
        right.num_inputs,
        right.num_outputs,
        right.network,
        right.locktime,
        right.subnetwork_id,
        right.gas,
        right.payload.len(),
        right.stealth_tweak,
    ) && left.payload == right.payload
}

fn same_transaction_inputs(left: &Transaction, right: &Transaction) -> bool {
    for index in 0..left.num_inputs {
        if !same_input_body(left, right, index) || !same_existing_signatures(left, right, index) {
            return false;
        }
    }
    true
}

fn same_input_body(left: &Transaction, right: &Transaction, index: usize) -> bool {
    let a = &left.inputs[index];
    let b = &right.inputs[index];
    (
        a.previous_outpoint.transaction_id,
        a.previous_outpoint.index,
        a.sequence,
        a.sig_op_count,
        a.utxo_entry.amount,
        a.utxo_entry.script_public_key.version,
        a.utxo_entry.script_public_key.script_len,
        a.ms45_hint,
    ) == (
        b.previous_outpoint.transaction_id,
        b.previous_outpoint.index,
        b.sequence,
        b.sig_op_count,
        b.utxo_entry.amount,
        b.utxo_entry.script_public_key.version,
        b.utxo_entry.script_public_key.script_len,
        b.ms45_hint,
    ) && a.utxo_entry.script_public_key.script[..a.utxo_entry.script_public_key.script_len]
        == b.utxo_entry.script_public_key.script[..b.utxo_entry.script_public_key.script_len]
        && left.redeem_bytes(index) == right.redeem_bytes(index)
        && b.sigs.len() >= a.sigs.len()
}

fn same_existing_signatures(left: &Transaction, right: &Transaction, input_index: usize) -> bool {
    let existing = &left.inputs[input_index].sigs;
    right.inputs[input_index]
        .sigs
        .get(..existing.len())
        .is_some_and(|carried| {
            existing
                .iter()
                .zip(carried)
                .all(|(left, right)| same_signature_slot(left, right))
        })
}

fn same_signature_slot(
    left: &crate::transaction::model::InputSig,
    right: &crate::transaction::model::InputSig,
) -> bool {
    (left.signature, left.sighash_type, left.pubkey_pos)
        == (right.signature, right.sighash_type, right.pubkey_pos)
}

fn same_transaction_outputs(left: &Transaction, right: &Transaction) -> bool {
    for index in 0..left.num_outputs {
        if !same_output_body(&left.outputs[index], &right.outputs[index]) {
            return false;
        }
    }
    true
}

fn same_output_body(
    left: &crate::transaction::model::TransactionOutput,
    right: &crate::transaction::model::TransactionOutput,
) -> bool {
    (
        left.value,
        left.script_public_key.version,
        left.script_public_key.script_len,
        left.covenant,
        left.derivation_hint,
        left.ms45_hint,
    ) == (
        right.value,
        right.script_public_key.version,
        right.script_public_key.script_len,
        right.covenant,
        right.derivation_hint,
        right.ms45_hint,
    ) && left.script_public_key.script[..left.script_public_key.script_len]
        == right.script_public_key.script[..right.script_public_key.script_len]
}

#[cfg(test)]
#[path = "unit_tests/transaction_body.rs"]
mod unit_tests;
