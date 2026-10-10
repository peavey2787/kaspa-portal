mod consensus;
mod covenant_paths;
mod coverage_ratchet;
mod finalization;

use serde_json::json;

use super::test_support::SIGNER_TEST_LIMITS;
use super::{attach_input_derivation, attach_output_derivation, VerifiedTransaction};
use crate::{
    primitives::address::KaspaNetwork as Network, transaction::interchange::kspt::wire::Derivation,
};

// The vectors below were written against the KasKold signer's capacity.

fn encode_pskt(pskt_hex: &str, network: Network) -> Result<Vec<u8>, String> {
    super::encode_pskt(pskt_hex, network, SIGNER_TEST_LIMITS)
}

fn merge_signed_kspt(original: &str, signed: &[u8], network: Network) -> Result<String, String> {
    super::merge_signed_kspt(original, signed, network, SIGNER_TEST_LIMITS)
}

fn finalize_json(pskt_hex: &str) -> Result<String, String> {
    super::finalize_json(pskt_hex, SIGNER_TEST_LIMITS)
}

fn pskt_verified_signature_counts(pskt_hex: &str, network: Network) -> Result<Vec<u8>, String> {
    super::verified_signature_counts(pskt_hex, network, SIGNER_TEST_LIMITS)
}

fn verify_complete_kspt(data: &[u8]) -> Result<VerifiedTransaction, String> {
    super::verify_complete_kspt(data, SIGNER_TEST_LIMITS)
}

const fn derivation(branch: u8, index: u32) -> Derivation {
    Derivation { branch, index }
}

#[test]
fn derivation_helpers_own_kaskold_proprietary_encoding() {
    let original = test_pskb([0x11; 32], 500);
    let attached = attach_input_derivation(&original, 0, derivation(0, 500)).expect("attach hint");
    let (format, root) = super::test_support::decode(&attached).expect("decode");
    let doc = super::test_support::document(&root, format).expect("document");
    assert_eq!(
        doc["inputs"][0]["proprietaries"]["kassignerDerivation"]["branch"],
        0
    );
    assert_eq!(
        doc["inputs"][0]["proprietaries"]["kassignerDerivation"]["index"],
        "500"
    );

    let attached_output =
        attach_output_derivation(&attached, 0, derivation(1, 700)).expect("attach output hint");
    let (format, root) = super::test_support::decode(&attached_output).expect("decode output hint");
    let doc = super::test_support::document(&root, format).expect("output document");
    assert_eq!(
        doc["outputs"][0]["proprietaries"]["kassignerDerivation"]["branch"],
        1
    );
    assert_eq!(
        doc["outputs"][0]["proprietaries"]["kassignerDerivation"]["index"],
        "700"
    );

    assert!(attach_input_derivation(&original, 0, derivation(0, 0x8000_0000)).is_err());
    assert!(attach_input_derivation(&original, 0, derivation(2, 500)).is_err());
    assert!(attach_output_derivation(&original, 0, derivation(1, 0x8000_0000)).is_err());
}

fn test_pskb(input_key: [u8; 32], _index: u32) -> String {
    let input_script = format!("000020{}ac", hex::encode(input_key));
    let output_script = input_script.clone();
    let document = json!({
        "global": {
            "version": 0,
            "txVersion": 0,
            "inputCount": 1,
            "outputCount": 1,
            "fallbackLockTime": "0",
            "subnetworkId": "0000000000000000000000000000000000000000",
            "gas": "0",
            "txPayload": ""
        },
        "inputs": [{
            "previousOutpoint": { "transactionId": hex::encode([0x77u8; 32]), "index": 0 },
            "utxoEntry": { "amount": "100000", "scriptPublicKey": input_script },
            "sequence": "0",
            "sigOpCount": 1,
            "sighashType": 1,
            "partialSigs": {},
            "proprietaries": {}
        }],
        "outputs": [{ "amount": "90000", "scriptPublicKey": output_script, "proprietaries": {} }]
    });
    super::test_support::encode(super::test_support::Format::Pskb, &json!([document]))
        .expect("encode PSKB")
}
