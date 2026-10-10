//! Mass and fee analysis of a verified transaction.

use serde_json::json;

use super::{
    analyze_verified, mass_validity, MAX_COMPUTE_MASS, MAX_STORAGE_MASS, MAX_TRANSIENT_MASS,
};
use crate::transaction::interchange::{
    kspt::wire::Limits,
    pskt::pipeline::{
        test_support::{pskb, sign_first_input, unsigned_document},
        verify_for_broadcast, VerifiedTransaction,
    },
};

/// Spend 10 KAS, paying `fee` sompi, so storage mass stays well within limits.
fn verified(fee: u64) -> VerifiedTransaction {
    const SPENT: u64 = 1_000_000_000;
    let mut document = unsigned_document(None, 0x11);
    document["inputs"][0]["utxoEntry"]["amount"] = json!(SPENT.to_string());
    document["outputs"][0]["amount"] = json!(SPENT.wrapping_sub(fee).to_string());
    verify_for_broadcast(
        &pskb(&sign_first_input(document, &[0x11])),
        Limits::grammar(),
    )
    .expect("verified")
}

#[test]
fn analysis_of_a_p2pk_spend_is_byte_and_gram_exact() {
    let transaction = verified(10_000);
    let analysis = analyze_verified(&transaction, 0).expect("analysis");
    // 94 header bytes + 118 for the input (66-byte witness) + 19 for the output.
    assert_eq!(analysis.estimated_serialized_bytes, 231);
    // Bytes, plus 10 grams per output script byte (2 + 1), plus one sig op.
    assert_eq!(analysis.compute_mass, 231 + 30 + 1_000);
    assert_eq!(analysis.transient_mass, 231 * 4);
    assert_eq!(analysis.normalized_transient_mass, 462);
    assert_eq!(
        analysis.storage_mass,
        transaction.to_consensus().unwrap().storage_mass
    );
    assert_eq!(analysis.maximum_mass, MAX_COMPUTE_MASS);
    assert_eq!(analysis.fee_sompi, 10_000);
    assert_eq!(analysis.fee_mass, 1_261);
    assert_eq!(analysis.fee_rate_sompi_per_gram, 10_000 / 1_261);
    assert_eq!(analysis.minimum_fee_sompi, 126_100);
    assert_eq!(analysis.recommended_fee_rate_sompi_per_gram, 100);
    assert_eq!(analysis.recommended_fee_sompi, 126_100);
    assert!(analysis.compute_mass_valid);
    assert!(analysis.transient_mass_valid);
    assert!(analysis.storage_mass_valid);
    assert!(analysis.mass_valid);
    assert!(!analysis.fee_sufficient);
}

#[test]
fn analysis_raises_the_rate_floor_and_judges_the_fee_against_it() {
    let paid = verified(126_100);
    let at_floor = analyze_verified(&paid, 99).expect("analysis");
    assert_eq!(at_floor.recommended_fee_rate_sompi_per_gram, 100);
    assert_eq!(at_floor.fee_rate_sompi_per_gram, 100);
    assert!(at_floor.fee_sufficient);

    let raised = analyze_verified(&paid, 101).expect("analysis");
    assert_eq!(raised.recommended_fee_rate_sompi_per_gram, 101);
    assert_eq!(raised.recommended_fee_sompi, 1_261 * 101);
    assert!(!raised.fee_sufficient);
}

#[test]
fn analysis_refuses_a_transaction_that_creates_more_than_it_spends() {
    assert_eq!(
        analyze_verified(&verified(u64::MAX), 0).map(|analysis| analysis.fee_sompi),
        Err("transaction outputs exceed inputs".to_string())
    );
}

#[test]
fn each_mass_dimension_alone_makes_the_transaction_invalid() {
    // A dust-sized output drives storage mass far above its limit.
    let mut dust = unsigned_document(None, 0x11);
    dust["outputs"][0]["amount"] = json!("1000");
    let dust = verify_for_broadcast(&pskb(&sign_first_input(dust, &[0x11])), Limits::grammar())
        .expect("verified");
    let analysis = analyze_verified(&dust, 0).expect("analysis");
    assert!(analysis.compute_mass_valid && analysis.transient_mass_valid);
    assert!(!analysis.storage_mass_valid);
    assert!(!analysis.mass_valid);
}

#[test]
fn mass_validity_holds_only_at_or_below_every_limit() {
    let (compute, transient, storage) = (MAX_COMPUTE_MASS, MAX_TRANSIENT_MASS, MAX_STORAGE_MASS);
    assert_eq!(
        mass_validity(compute, transient, storage),
        [true, true, true, true]
    );
    assert_eq!(
        mass_validity(compute + 1, transient, storage),
        [false, true, true, false]
    );
    assert_eq!(
        mass_validity(compute, transient + 1, storage),
        [true, false, true, false]
    );
    assert_eq!(
        mass_validity(compute, transient, storage + 1),
        [true, true, false, false]
    );
}
