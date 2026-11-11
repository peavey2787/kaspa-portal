use super::same_transaction_body;
use crate::transaction::model::{Ms45Derivation, Transaction};

fn transaction_with_hints() -> Transaction {
    let mut transaction = Transaction::try_new().expect("transaction storage");
    transaction.ensure_input_slots(1).expect("input slot");
    transaction.num_inputs = 1;
    transaction.num_outputs = 1;
    let hint = Ms45Derivation {
        cosigner: 1,
        chain: 0,
        index: 7,
    };
    transaction.inputs[0].ms45_hint = Some(hint);
    transaction.outputs[0].ms45_hint = Some(hint);
    transaction
}

#[test]
fn a_signer_cannot_rewrite_an_input_derivation_hint() {
    let original = transaction_with_hints();
    assert!(same_transaction_body(&original, &transaction_with_hints()));
    let rewrites: [fn(&mut Option<Ms45Derivation>); 4] = [
        |hint| *hint = None,
        |hint| hint.as_mut().expect("hint").cosigner = 0,
        |hint| hint.as_mut().expect("hint").chain = 1,
        |hint| hint.as_mut().expect("hint").index = 8,
    ];
    for rewrite in rewrites {
        let mut signed = transaction_with_hints();
        rewrite(&mut signed.inputs[0].ms45_hint);
        assert!(!same_transaction_body(&original, &signed));
    }
}

#[test]
fn a_signer_cannot_rewrite_a_change_derivation_hint() {
    let original = transaction_with_hints();
    let mut signed = transaction_with_hints();
    signed.outputs[0].ms45_hint.as_mut().expect("hint").index = 8;
    assert!(!same_transaction_body(&original, &signed));
}
