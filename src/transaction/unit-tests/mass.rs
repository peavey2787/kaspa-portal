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

#[test]
fn serialized_size_estimate_matches_rusty_kaspa_field_by_field() {
    use crate::transaction::consensus::{
        ConsensusInput, ConsensusOutput, ConsensusTransaction, InputEncoding,
    };

    let transaction = |tx_version: u16, covenant: Option<(u16, [u8; 32])>| ConsensusTransaction {
        tx_version,
        input_encoding: InputEncoding::Compact,
        inputs: vec![ConsensusInput {
            prev_tx_id: [1; 32],
            prev_index: 0,
            sig_script: vec![0; 66],
            sequence: 0,
            sig_op_count: 1,
        }],
        outputs: vec![ConsensusOutput {
            value: 1,
            spk_version: 0,
            spk_script: vec![0; 34],
            covenant,
        }],
        locktime: 0,
        subnetwork_id: [0; 20],
        gas: 0,
        payload: vec![0; 5],
        storage_mass: 0,
    };
    // version 2, input count 8, outpoint 36, script 8 + 66, sequence 8,
    // output count 8, value 8, spk version 2, script 8 + 34, locktime 8,
    // subnetwork 20, gas 8, payload hash 32, payload 8 + 5.
    const V0: u64 = 2 + 8 + (36 + 8 + 66 + 8) + 8 + (8 + 2 + 8 + 34) + 8 + 20 + 8 + 32 + 8 + 5;
    assert_eq!(
        super::estimated_serialized_size(&transaction(0, None)),
        Ok(V0)
    );
    // Version 1 inputs carry a u16 compute budget.
    assert_eq!(
        super::estimated_serialized_size(&transaction(1, None)),
        Ok(V0 + 2)
    );
    // A covenant binding adds its authorizing input and id.
    assert_eq!(
        super::estimated_serialized_size(&transaction(1, Some((0, [7; 32])))),
        Ok(V0 + 2 + 34)
    );
}

#[test]
fn thread_withdraw_fee_prices_kip9_storage_mass_and_floors() {
    use super::ThreadWithdrawFee;
    let fee = |thread_amount, withdraw, fee_rate_sompi_per_gram| {
        ThreadWithdrawFee {
            thread_amount,
            withdraw,
            minimum_fee: 300_000,
            fee_rate_sompi_per_gram,
        }
        .calculate()
    };
    // Outputs 10,000 + 4,445 grams less the arithmetic input mass of 4,000.
    assert_eq!(fee(1_000_000_000, 100_000_000, 100), Ok(1_044_500));
    assert_eq!(fee(1_000_000_000, 100_000_000, 1), Ok(300_000));
    // Storage mass of 600 grams stays under the compute-mass estimate.
    assert_eq!(fee(10_000_000_000, 5_000_000_000, 1_000), Ok(2_500_000));
    // A 0.01 KAS payout carries 1,000,000 grams of storage mass.
    assert!(fee(1_000_000_000, 1_000_000, 1).is_err());
    // Nothing remains to return, or nothing is withdrawn: only the floor.
    assert_eq!(fee(1_000_000, 700_000, 100), Ok(300_000));
    assert_eq!(fee(1_000_000, 900_000, 100), Ok(300_000));
    assert_eq!(fee(1_000_000_000, 0, 100), Ok(300_000));
    assert_eq!(fee(1_000, 2_000, 100), Ok(300_000));
}

#[test]
fn thread_maximum_withdraw_is_the_largest_amount_that_still_prices() {
    use super::ThreadWithdrawFee;
    let thread = |thread_amount| ThreadWithdrawFee {
        thread_amount,
        withdraw: 0,
        minimum_fee: 300_000,
        fee_rate_sompi_per_gram: 1,
    };
    let minimum_return = 10_000_000;
    let best = thread(1_000_000_000).maximum_withdraw(u64::MAX, minimum_return);
    let fee = ThreadWithdrawFee {
        withdraw: best,
        ..thread(1_000_000_000)
    }
    .calculate()
    .unwrap();
    assert!(1_000_000_000 - best - fee >= minimum_return);
    let over = ThreadWithdrawFee {
        withdraw: best + 1,
        ..thread(1_000_000_000)
    }
    .calculate();
    assert!(over.map_or(true, |fee| 1_000_000_000 - best - 1 - fee < minimum_return));
    assert_eq!(
        thread(1_000_000_000).maximum_withdraw(5_000, minimum_return),
        0
    );
    assert_eq!(
        thread(1_000_000_000).maximum_withdraw(200_000_000, minimum_return),
        200_000_000
    );
    assert_eq!(
        thread(5_000_000).maximum_withdraw(u64::MAX, minimum_return),
        0
    );
}
