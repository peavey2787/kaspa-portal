//! Compile-time proof that no authorized value can be rewritten through a public field.

macro_rules! private_fields {
    ($owner:ident: $($name:ident => $field:ident),+ $(,)?) => {
        $(
            #[doc = concat!(
                "```compile_fail
",
                "use kaspa_portal::transaction::interchange::pskt::pipeline::", stringify!($owner), ";
",
                "fn read(value: &", stringify!($owner), ") { let _ = &value.", stringify!($field), "; }
",
                "```",
            )]
            pub struct $name;
        )+
    };
}

/// ```
/// use kaspa_portal::transaction::interchange::pskt::pipeline::VerifiedTransaction;
/// fn read(value: &VerifiedTransaction) { let _ = (value.inputs(), value.outputs()); }
/// ```
pub struct TheTokenIsReadThroughAccessors;

private_fields!(VerifiedTransaction:
    TransactionVersion => version,
    TransactionLocktime => locktime,
    TransactionSubnetwork => subnetwork_id,
    TransactionGas => gas,
    TransactionPayload => payload,
    TransactionInputs => inputs,
    TransactionOutputs => outputs,
);
private_fields!(VerifiedInput:
    InputPreviousTransaction => previous_tx_id,
    InputPreviousIndex => previous_index,
    InputAmount => amount,
    InputSequence => sequence,
    InputSigOpCount => sig_op_count,
    InputScriptVersion => script_version,
    InputScript => script_public_key,
    InputCovenantFlag => has_covenant_id,
    InputWitness => witness,
);
private_fields!(VerifiedOutput:
    OutputAmount => amount,
    OutputScriptVersion => script_version,
    OutputScript => script_public_key,
    OutputCovenant => covenant,
);
