use super::*;

#[test]
fn serialization_shape_accepts_exact_input_limit_and_rejects_beyond_it() {
    let mut tx = Transaction::try_new().expect("transaction");
    let max_inputs = tx.limits.max_inputs;
    tx.ensure_input_slots(max_inputs).expect("max slots");
    tx.num_inputs = max_inputs;
    tx.num_outputs = 1;
    let parsed = PsktParsed::empty();
    assert_eq!(validate_serialization_shape(&tx, &parsed, b""), Ok(()));

    tx.num_inputs = max_inputs + 1;
    assert_eq!(
        validate_serialization_shape(&tx, &parsed, b""),
        Err(PskError::TooManyInputs)
    );
}

#[test]
fn serialization_shape_enforces_the_transaction_runtime_input_limit() {
    let limits = crate::transaction::model::TransactionLimits {
        max_inputs: 2,
        ..crate::transaction::model::TransactionLimits::default()
    };
    let mut tx = Transaction::try_new_with(limits).expect("transaction");
    tx.ensure_input_slots(2).expect("limit slots");
    tx.num_inputs = 2;
    tx.num_outputs = 1;
    let parsed = PsktParsed::empty();
    assert_eq!(validate_serialization_shape(&tx, &parsed, b""), Ok(()));

    tx.num_inputs = 3;
    assert_eq!(
        validate_serialization_shape(&tx, &parsed, b""),
        Err(PskError::TooManyInputs)
    );
}

#[test]
fn retry_only_retries_output_buffer_exhaustion() {
    let tx = Transaction::try_new().expect("transaction");
    let parsed = PsktParsed::empty();
    assert_eq!(
        retry_pskt_vec(
            &tx,
            &parsed,
            b"",
            TxInputFormat::PsktSingle,
            1,
            PskError::InvalidScriptLen,
        ),
        Err(PskError::InvalidScriptLen),
    );
}
