use super::*;
use crate::transaction::model::TransactionLimits;

#[test]
fn transaction_shape_accepts_exact_input_limit_and_rejects_beyond_it() {
    let limits = TransactionLimits {
        max_inputs: 32,
        max_payload_bytes: 768,
    };
    let mut tx = Transaction::try_new_with(limits).expect("transaction");
    tx.ensure_input_slots(limits.max_inputs + 1)
        .expect_err("slots beyond the device limit are refused");
    tx.ensure_input_slots(limits.max_inputs).expect("max slots");
    tx.num_inputs = limits.max_inputs;
    tx.num_outputs = 1;
    assert_eq!(validate_transaction_shape(&tx), Ok(()));

    tx.num_inputs = limits.max_inputs + 1;
    assert_eq!(
        validate_transaction_shape(&tx),
        Err(PsktError::TooManyInputs)
    );
}

#[test]
fn transaction_shape_rejects_payload_beyond_device_limit() {
    let limits = TransactionLimits {
        max_inputs: 1,
        max_payload_bytes: 4,
    };
    let mut tx = Transaction::try_new_with(limits).expect("transaction");
    tx.ensure_input_slots(1).expect("slot");
    tx.num_inputs = 1;
    tx.num_outputs = 1;
    tx.set_payload(&[1, 2, 3, 4]).expect("payload at limit");
    assert_eq!(validate_transaction_shape(&tx), Ok(()));
    tx.payload.push(5);
    assert_eq!(
        validate_transaction_shape(&tx),
        Err(PsktError::PayloadTooLong)
    );
}
