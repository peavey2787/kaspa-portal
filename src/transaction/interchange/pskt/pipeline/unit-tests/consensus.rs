//! Consensus materialization and fee of the verified transaction.

use serde_json::{json, Value};

use super::super::test_support::{pskb, sign_first_input, unsigned_document};
use super::{finalize_json, SIGNER_TEST_LIMITS};
use crate::transaction::consensus::{ConsensusTransaction, InputEncoding};

fn verified(document: &Value) -> super::VerifiedTransaction {
    super::super::verify_for_broadcast(&pskb(document), SIGNER_TEST_LIMITS).expect("verified")
}

fn signed_p2pk() -> Value {
    let mut document = unsigned_document(None, 0x11);
    document["global"]["txVersion"] = json!(1);
    document["global"]["fallbackLockTime"] = json!("42");
    document["global"]["subnetworkId"] = json!("ab".repeat(20));
    document["global"]["gas"] = json!("7");
    document["global"]["txPayload"] = json!("cafe");
    document["inputs"][0]["sequence"] = json!("9");
    document["inputs"][0]["sigOpCount"] = json!(2);
    document["outputs"][0]["covenantBinding"] = json!({
        "authorizingInput": 0,
        "covenantId": "cd".repeat(32)
    });
    sign_first_input(document, &[0x11])
}

#[test]
fn consensus_transaction_is_exactly_the_authorized_transaction() {
    let document = signed_p2pk();
    let transaction = verified(&document).to_consensus().expect("consensus");
    let finalized: Value =
        serde_json::from_str(&finalize_json(&pskb(&document)).expect("final JSON")).unwrap();

    assert_eq!(transaction.tx_version, 1);
    assert_eq!(transaction.input_encoding, InputEncoding::Budgeted);
    assert_eq!(transaction.locktime, 42);
    assert_eq!(transaction.subnetwork_id, [0xab; 20]);
    assert_eq!(transaction.gas, 7);
    assert_eq!(transaction.payload, [0xca, 0xfe]);

    let [input] = transaction.inputs.as_slice() else {
        panic!("one input");
    };
    assert_eq!(input.prev_tx_id, [0x22; 32]);
    assert_eq!(input.prev_index, 7);
    assert_eq!(input.sequence, 9);
    assert_eq!(input.sig_op_count, 2);
    assert_eq!(
        hex::encode(&input.sig_script),
        finalized["inputs"][0]["signatureScript"]
    );

    let [output] = transaction.outputs.as_slice() else {
        panic!("one output");
    };
    assert_eq!(output.value, 90_000);
    assert_eq!(output.spk_version, 0);
    assert_eq!(output.spk_script, [0x51]);
    assert_eq!(output.covenant, Some((0, [0xcd; 32])));
    assert_eq!(
        transaction.storage_mass,
        ConsensusTransaction::storage_mass_for(&[(100_000, 34, false)], &transaction.outputs)
            .unwrap()
    );
}

#[test]
fn storage_mass_charges_a_spent_covenant_identity() {
    let plain = verified(&signed_p2pk()).to_consensus().unwrap();
    let mut document = signed_p2pk();
    document["inputs"][0]["utxoEntry"]["covenantId"] = json!("ef".repeat(32));
    let covenant = verified(&sign_first_input(clear_signatures(document), &[0x11]))
        .to_consensus()
        .unwrap();
    assert_eq!(
        covenant.storage_mass,
        ConsensusTransaction::storage_mass_for(&[(100_000, 34, true)], &covenant.outputs).unwrap()
    );
    // KIP-9: C/90_000 - C/100_000 for the plain spend; a spent covenant
    // identity makes the input two storage units, so the relaxed mass is 0.
    assert_eq!(plain.storage_mass, 1_111_111);
    assert_eq!(covenant.storage_mass, 0);
}

#[test]
fn fee_is_spent_minus_created_and_refuses_overspending() {
    assert_eq!(verified(&signed_p2pk()).fee(), Ok(10_000));

    let mut exact = unsigned_document(None, 0x11);
    exact["outputs"][0]["amount"] = json!("100000");
    assert_eq!(verified(&sign_first_input(exact, &[0x11])).fee(), Ok(0));

    let mut overspend = unsigned_document(None, 0x11);
    overspend["outputs"][0]["amount"] = json!("100001");
    let overspend = sign_first_input(overspend, &[0x11]);
    assert_eq!(
        verified(&overspend).fee(),
        Err("transaction outputs exceed inputs".to_string())
    );
}

fn clear_signatures(mut document: Value) -> Value {
    document["inputs"][0]["partialSigs"] = json!({});
    document
}

#[test]
fn sign_pskt_hands_the_relayed_transaction_to_the_signer_and_merges_its_result() {
    use crate::{primitives::address::KaspaNetwork, transaction::model::Transaction};

    let unsigned = pskb(&unsigned_document(None, 0x11));
    let mut seen = None;
    let merged = super::super::sign_pskt(
        &unsigned,
        KaspaNetwork::Testnet,
        SIGNER_TEST_LIMITS,
        |transaction: &mut Transaction| {
            seen = Some((transaction.num_inputs, transaction.num_outputs));
            Ok(())
        },
    );
    assert_eq!(seen, Some((1, 1)));
    assert_eq!(
        merged,
        super::super::merge_signed_kspt(
            &unsigned,
            &super::super::encode_pskt(&unsigned, KaspaNetwork::Testnet, SIGNER_TEST_LIMITS)
                .unwrap(),
            KaspaNetwork::Testnet,
            SIGNER_TEST_LIMITS,
        )
    );

    let refused = super::super::sign_pskt(
        &unsigned,
        KaspaNetwork::Testnet,
        SIGNER_TEST_LIMITS,
        |_: &mut Transaction| Err("signer declined".to_string()),
    );
    assert_eq!(refused, Err("signer declined".to_string()));
}

/// A compact KSPT flagged fully signed whose signature is a placeholder.
const PLACEHOLDER_SIGNED_KSPT: &str = "4b53505401010000010000000100000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111010000006400000000000000000000000000000001000022204444444444444444444444444444444444444444444444444444444444444444ac0100012222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222200005a00000000000000000022205555555555555555555555555555555555555555555555555555555555555555ac4e01";

#[test]
fn placeholder_signatures_and_unsupported_versions_never_reach_consensus_bytes() {
    let bytes = hex::decode(PLACEHOLDER_SIGNED_KSPT).expect("fixture hex");
    assert!(super::verify_complete_kspt(&bytes).is_err());

    let mut future = bytes;
    future[6..8].copy_from_slice(&2u16.to_le_bytes());
    let error =
        super::verify_complete_kspt(&future).expect_err("future transaction version refused");
    assert!(
        error.to_ascii_lowercase().contains("version"),
        "unexpected error: {error}"
    );

    let mut placeholder = unsigned_document(None, 0x11);
    placeholder["inputs"][0]["partialSigs"] = json!({
        format!("02{}", "11".repeat(32)): {"schnorr": "22".repeat(64)}
    });
    assert!(super::super::verify_for_broadcast(&pskb(&placeholder), SIGNER_TEST_LIMITS).is_err());
}
