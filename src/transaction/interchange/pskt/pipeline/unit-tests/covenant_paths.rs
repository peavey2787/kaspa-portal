//! Generic covenant finalization along any fully selected execution path.

use k256::schnorr::SigningKey;
use serde_json::{json, Value};

use super::super::test_support::{encode, sighash_all_for_pskt, Format};
use super::{finalize_json, Network};

const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;

fn xonly(marker: u8) -> [u8; 32] {
    let signing = SigningKey::from_bytes(&[marker; 32]).expect("test signing key");
    signing.verifying_key().to_bytes().into()
}

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

fn pskb(document: &Value) -> String {
    encode(Format::Pskb, &json!([document])).expect("encode PSKB")
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
