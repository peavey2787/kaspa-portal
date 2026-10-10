//! Generic covenant finalization along any fully selected execution path.

use k256::schnorr::SigningKey;
use serde_json::{json, Value};

use super::super::test_support::{pskb, sighash_all_for_pskt, xonly};
use super::{finalize_json, Network};

const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;

fn key(script: &mut Vec<u8>, marker: u8, check: u8) {
    script.push(0x20);
    script.extend_from_slice(&xonly(marker));
    script.push(check);
}

/// `IF <a> CHECKSIG ELSE IF <b> CHECKSIG ELSE 1 ENDIF ENDIF`
fn nested_escrow() -> Vec<u8> {
    let mut script = vec![OP_IF];
    key(&mut script, 0x41, OP_CHECKSIG);
    script.extend_from_slice(&[OP_ELSE, OP_IF]);
    key(&mut script, 0x42, OP_CHECKSIG);
    script.extend_from_slice(&[OP_ELSE, 0x51, OP_ENDIF, OP_ENDIF]);
    script
}

fn document(redeem: &[u8], mask: u16, truth: u16) -> Value {
    let hash = blake2b_simd::Params::new().hash_length(32).hash(redeem);
    json!({
        "global": {
            "version": 0, "txVersion": 0, "inputCount": 1, "outputCount": 1,
            "fallbackLockTime": "0", "subnetworkId": "00".repeat(20), "gas": "0", "txPayload": ""
        },
        "inputs": [{
            "previousOutpoint": {"transactionId": "22".repeat(32), "index": 7},
            "utxoEntry": {
                "amount": "100000",
                "scriptPublicKey": format!("0000aa20{}87", hex::encode(hash.as_bytes()))
            },
            "sequence": "0", "sigOpCount": 1, "sighashType": 1,
            "redeemScript": hex::encode(redeem),
            "covenantExecution": {
                "suppliedMask": mask.to_string(),
                "suppliedTrueMask": truth.to_string()
            },
            "partialSigs": {}, "proprietaries": {}
        }],
        "outputs": [{"amount": "90000", "scriptPublicKey": "000051", "covenantBinding": null}]
    })
}

/// Sign with `marker` and return the document plus the 65-byte signature push.
fn signed(mut document: Value, marker: u8) -> (Value, Vec<u8>) {
    let digest = sighash_all_for_pskt(&pskb(&document), Network::Mainnet, 0).expect("sighash");
    let signing = SigningKey::from_bytes(&[marker; 32]).expect("test signing key");
    let signature = signing.sign_raw(&digest, &[0u8; 32]).expect("signature");
    document["inputs"][0]["partialSigs"] = json!({
        format!("02{}", hex::encode(signing.verifying_key().to_bytes())): {
            "schnorr": hex::encode(signature.to_bytes())
        }
    });
    let mut push = vec![65];
    push.extend_from_slice(&signature.to_bytes());
    push.push(0x01);
    (document, push)
}

fn signature_script(document: &Value) -> Result<Vec<u8>, String> {
    let finalized: Value =
        serde_json::from_str(&finalize_json(&pskb(document))?).expect("finalized JSON");
    Ok(hex::decode(
        finalized["inputs"][0]["signatureScript"]
            .as_str()
            .expect("signature script"),
    )
    .expect("signature script hex"))
}

fn with_redeem(mut witness: Vec<u8>, redeem: &[u8]) -> Vec<u8> {
    let mut push = Vec::new();
    crate::contract::script::push_data(&mut push, redeem);
    witness.extend_from_slice(&push);
    witness
}

#[test]
fn nested_branch_signers_finalize_with_selectors_in_consumption_order() {
    let redeem = nested_escrow();
    let (owner, owner_sig) = signed(document(&redeem, 0b11, 0b01), 0x41);
    let mut expected = owner_sig;
    expected.push(0x51);
    assert_eq!(signature_script(&owner), Ok(with_redeem(expected, &redeem)));

    // Outer ELSE then inner IF: the inner selector is consumed second, so it
    // sits below the outer one on the stack.
    let (beneficiary, beneficiary_sig) = signed(document(&redeem, 0b11, 0b10), 0x42);
    let mut expected = beneficiary_sig;
    expected.extend_from_slice(&[0x51, 0x00]);
    assert_eq!(
        signature_script(&beneficiary),
        Ok(with_redeem(expected, &redeem))
    );
}

#[test]
fn a_keyless_branch_finalizes_from_its_selectors_alone() {
    let redeem = nested_escrow();
    let refund = document(&redeem, 0b11, 0b00);
    assert_eq!(
        signature_script(&refund),
        Ok(with_redeem(vec![0x00, 0x00], &redeem))
    );

    // A signature that the keyless path does not consume is refused.
    let (signed_refund, _) = signed(refund, 0x42);
    assert!(signature_script(&signed_refund).is_err());
}

#[test]
fn a_selector_free_key_path_finalizes_with_only_its_signature() {
    let mut redeem = Vec::new();
    key(&mut redeem, 0x43, OP_CHECKSIGVERIFY);
    redeem.push(0x51);
    let (treasury, signature) = signed(document(&redeem, 0, 0), 0x43);
    assert_eq!(
        signature_script(&treasury),
        Ok(with_redeem(signature, &redeem))
    );
}

#[test]
fn a_selector_after_the_signature_check_is_pushed_beneath_the_signature() {
    // IF <owner> CHECKSIGVERIFY IF 1 ELSE 1 ENDIF ELSE <beneficiary> CHECKSIG ENDIF
    let mut redeem = vec![OP_IF];
    key(&mut redeem, 0x44, OP_CHECKSIGVERIFY);
    redeem.extend_from_slice(&[OP_IF, 0x51, OP_ELSE, 0x51, OP_ENDIF, OP_ELSE]);
    key(&mut redeem, 0x45, OP_CHECKSIG);
    redeem.push(OP_ENDIF);
    let (owner, signature) = signed(document(&redeem, 0b11, 0b01), 0x44);
    let mut expected = vec![0x00];
    expected.extend_from_slice(&signature);
    expected.push(0x51);
    assert_eq!(signature_script(&owner), Ok(with_redeem(expected, &redeem)));
}

#[test]
fn signatures_outside_the_selected_path_or_incomplete_selectors_never_finalize() {
    let redeem = nested_escrow();
    // The owner signs but covenantExecution selects the beneficiary branch.
    let (wrong_branch, _) = signed(document(&redeem, 0b11, 0b10), 0x41);
    assert!(signature_script(&wrong_branch).is_err());
    // An assignment missing the inner selector is not a complete plan.
    let (incomplete, _) = signed(document(&redeem, 0b01, 0b01), 0x41);
    assert!(signature_script(&incomplete).is_err());
    // A path reaching a multisig check has no generic plan.
    let multisig_path = [OP_IF, 0xae, OP_ELSE, 0x51, OP_ENDIF];
    assert!(signature_script(&document(&multisig_path, 1, 1)).is_err());
}

fn p2sh(redeem: &[u8]) -> Vec<u8> {
    let hash = blake2b_simd::Params::new().hash_length(32).hash(redeem);
    let mut script = vec![0xaa, 0x20];
    script.extend_from_slice(hash.as_bytes());
    script.push(0x87);
    script
}

/// Decode a builder-encoded PSKB into its single PSKT document.
fn planned_document(wire: &str) -> Value {
    let (format, root) = super::super::test_support::decode(wire).expect("decode PSKB");
    super::super::test_support::document(&root, format)
        .expect("document")
        .clone()
}

#[test]
fn builder_planned_global_allowance_paths_finalize_through_the_verified_pipeline() {
    use crate::{
        chain::utxo::UtxoEntry,
        contract::covenant::build_global_allowance_script,
        transaction::builder::pskb::{
            encode_wire, plan_global_thread_withdrawal, GlobalThreadPolicy,
            GlobalThreadWithdrawalRequest,
        },
    };

    let (owner, beneficiary) = (0x61, 0x62);
    let redeem =
        build_global_allowance_script(&xonly(owner), &xonly(beneficiary), 5_000_000, 0, 0, &[7; 8]);
    let covenant_spk = p2sh(&redeem);
    let thread = UtxoEntry {
        tx_id: "22".repeat(32),
        index: 7,
        amount: 100_000_000,
        script_public_key: covenant_spk.clone(),
        block_daa_score: 1,
        covenant_id: None,
    };
    let policy = GlobalThreadPolicy::allowance(0);

    let withdrawal = plan_global_thread_withdrawal(GlobalThreadWithdrawalRequest {
        thread_utxos: core::slice::from_ref(&thread),
        covenant_script_public_key: &covenant_spk,
        destination_script_public_key: &[0x51],
        redeem_script: &redeem,
        covenant_id: &[0x24; 32],
        withdrawal: 2_000_000,
        fee: 1_000_000,
        csv_sequence: 0,
        policy: &policy,
    })
    .expect("withdrawal plan");
    let document = planned_document(&encode_wire(&withdrawal.plan).expect("wire"));
    let (beneficiary_document, signature) = signed(document, beneficiary);
    // Beneficiary: signature, then the outer ELSE selector; the inner
    // continuation branch is computed by the script and needs no selector.
    let mut expected = signature;
    expected.push(0x00);
    assert_eq!(
        signature_script(&beneficiary_document),
        Ok(with_redeem(expected, &redeem))
    );

    // The owner's free reclaim path is the outer IF.
    let mut owner_document = planned_document(&encode_wire(&withdrawal.plan).expect("wire"));
    owner_document["inputs"][0]["covenantExecution"] =
        json!({"suppliedMask": "3", "suppliedTrueMask": "1"});
    let (signed_owner, owner_signature) = signed(owner_document, owner);
    let mut expected = owner_signature;
    expected.push(0x51);
    assert_eq!(
        signature_script(&signed_owner),
        Ok(with_redeem(expected, &redeem))
    );
}

#[test]
fn a_path_needing_two_signatures_is_incomplete_with_one() {
    use crate::primitives::address::KaspaNetwork;

    // <a> CHECKSIGVERIFY <b> CHECKSIG: both keys sit on the only path.
    let mut redeem = Vec::new();
    key(&mut redeem, 0x46, OP_CHECKSIGVERIFY);
    key(&mut redeem, 0x47, OP_CHECKSIG);
    let unsigned = document(&redeem, 0, 0);
    let (one, _) = signed(unsigned.clone(), 0x46);
    let complete = |document: &Value| {
        super::super::is_complete(
            &pskb(document),
            KaspaNetwork::Mainnet,
            super::SIGNER_TEST_LIMITS,
        )
    };
    assert_eq!(complete(&one), Ok(false));
    assert!(signature_script(&one).is_err());

    let both = crate::transaction::interchange::pskt::pipeline::test_support::sign_first_input(
        unsigned,
        &[0x46, 0x47],
    );
    assert_eq!(complete(&both), Ok(true));
}
