//! Finalization and analysis through the public transaction facade.

use serde_json::json;

use super::TransactionApi;
use crate::{
    error::Error,
    transaction::interchange::{
        kspt::wire::Limits,
        pskt::pipeline::{
            test_support::{pskb, sign_first_input, unsigned_document},
            verify_for_broadcast,
        },
    },
};

fn signed_wire() -> String {
    let mut document = unsigned_document(None, 0x11);
    document["inputs"][0]["utxoEntry"]["amount"] = json!("1000000000");
    document["outputs"][0]["amount"] = json!("999000000");
    pskb(&sign_first_input(document, &[0x11]))
}

#[test]
fn finalize_and_analysis_are_the_verified_pipeline_results() {
    let api = TransactionApi::new(None);
    let wire = signed_wire();
    let verified = verify_for_broadcast(&wire, Limits::grammar()).expect("verified");

    let finalized = api.finalize(&wire).expect("finalize");
    let expected = verified.to_consensus().expect("consensus");
    assert_eq!(
        finalized.inputs[0].sig_script,
        expected.inputs[0].sig_script
    );
    assert_eq!(finalized.storage_mass, expected.storage_mass);

    let analysis = api.analyze_with_fee_rate(&wire, 150).expect("analysis");
    assert_eq!(analysis.fee_sompi, 1_000_000);
    assert_eq!(analysis.recommended_fee_rate_sompi_per_gram, 150);
}

#[test]
fn unverifiable_wires_are_transaction_errors() {
    let api = TransactionApi::new(None);
    let unsigned = pskb(&unsigned_document(None, 0x11));
    assert!(matches!(
        api.finalize(&unsigned),
        Err(Error::Transaction(_))
    ));
    assert!(matches!(
        api.analyze_with_fee_rate(&unsigned, 100),
        Err(Error::Transaction(_))
    ));
}
