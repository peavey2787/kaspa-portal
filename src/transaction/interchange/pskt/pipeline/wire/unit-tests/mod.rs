use super::*;
use serde_json::{json, Value};

#[test]
fn derivation_hint_covers_absent_shape_branch_and_index_boundaries() {
    assert_eq!(parse_derivation(&json!({})), Ok(None));
    assert!(parse_derivation(&json!([])).is_err());
    assert!(parse_derivation(&json!({"kassignerDerivation": null})).is_err());
    assert!(parse_derivation(&json!({"kassignerDerivation": []})).is_err());

    assert!(parse_derivation(&json!({"kassignerDerivation": {"index": 0}})).is_err());
    assert!(parse_derivation(&json!({"kassignerDerivation": {"branch": 0}})).is_err());
    assert!(parse_derivation(&json!({"kassignerDerivation": {"branch": 2, "index": 0}})).is_err());
    assert!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 256, "index": 0}})).is_err()
    );
    assert!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": "01", "index": 0}})).is_err()
    );

    let soft_limit = crate::wallet::derivation::bip32::HARDENED_BIT;
    assert!(parse_derivation(&json!({
        "kassignerDerivation": {"branch": 1, "index": soft_limit}
    }))
    .is_err());
    assert!(parse_derivation(&json!({
        "kassignerDerivation": {"branch": 1, "index": u64::from(u32::MAX) + 1}
    }))
    .is_err());

    assert_eq!(
        parse_derivation(&json!({
            "kassignerDerivation": {"branch": 0, "index": 0}
        })),
        Ok(Some((0, 0)))
    );
    assert_eq!(
        parse_derivation(&json!({
            "kassignerDerivation": {"branch": "1", "index": (soft_limit - 1).to_string()}
        })),
        Ok(Some((1, soft_limit - 1)))
    );
}

fn standard_pskb(inputs: u8) -> String {
    use crate::{
        chain::utxo::UtxoEntry,
        transaction::builder::model::{PlannedOutput, UnsignedTransactionPlan},
    };
    let utxos = (0..inputs)
        .map(|index| UtxoEntry {
            tx_id: format!("{:02x}", index + 1).repeat(32),
            index: u32::from(index),
            amount: 50_000_000,
            script_public_key: vec![0x20; 34],
            block_daa_score: 1,
            covenant_id: None,
        })
        .collect();
    crate::transaction::interchange::pskt::pskb::encode_plan(&UnsignedTransactionPlan::standard(
        utxos,
        vec![PlannedOutput::new(40_000_000, vec![0x21; 34])],
    ))
    .expect("PSKB")
}

#[test]
fn sole_signature_fills_the_only_unsigned_input_once() {
    let mut public_key = [0x22; 33];
    public_key[0] = 0x02;
    let signed =
        attach_sole_signature(&standard_pskb(1), &public_key, &[0x33; 64]).expect("sole signature");
    let (format, root) = decode(&signed).expect("decode");
    let input = &document(&root, format).expect("document")["inputs"][0];
    assert_eq!(
        input["partialSigs"][hex::encode(public_key)]["schnorr"],
        hex::encode([0x33; 64])
    );

    assert_eq!(
        attach_sole_signature(&signed, &public_key, &[0x44; 64]),
        Err("input already carries a signature".to_string())
    );
    for inputs in [0, 2] {
        assert_eq!(
            attach_sole_signature(&standard_pskb(inputs), &public_key, &[0x33; 64]),
            Err(format!(
                "a sole signature needs exactly one input, got {inputs}"
            ))
        );
    }
    assert!(attach_sole_signature("00", &public_key, &[0x33; 64]).is_err());
    let without_signatures = raw_pskb(&json!([{"global": {}, "inputs": [{}], "outputs": []}]));
    assert_eq!(
        attach_sole_signature(&without_signatures, &public_key, &[0x33; 64]),
        Err("inputs[0].partialSigs must be an object".to_string())
    );
}

/// The relay's strict reading: envelope, canonical JSON, document schema and
/// the typed relay model.
fn strict_decode(wire_hex: &str) -> Result<(), String> {
    super::super::encode_pskt(
        wire_hex,
        crate::primitives::address::KaspaNetwork::Testnet,
        crate::transaction::interchange::kspt::wire::Limits::grammar(),
    )
    .map(|_| ())
}

fn canonical_pskb_wire(document: Value) -> String {
    raw_pskb(&crate::transaction::interchange::pskt::unit_tests::canonical_test_pskt(document))
}

fn raw_pskb(root: &Value) -> String {
    let mut wire = b"PSKB".to_vec();
    wire.extend_from_slice(hex::encode(serde_json::to_vec(root).unwrap()).as_bytes());
    hex::encode(wire)
}

fn assert_strict_rejects(mut root: Value, mutate: impl FnOnce(&mut Value)) {
    mutate(&mut root);
    assert!(strict_decode(&raw_pskb(&root)).is_err());
}

#[test]
fn exact_four_byte_magic_is_not_misclassified_as_a_short_outer_envelope() {
    assert!(strict_decode("50534b54").is_err());
}

#[test]
fn pskt_shape_and_output_optional_boundaries_are_exercised_through_strict_strict_decode() {
    let base = || {
        json!([{
            "global": {},
            "inputs": [{
                "utxoEntry": {"amount": 2, "scriptPublicKey": "0000"},
                "previousOutpoint": {
                    "transactionId": "00".repeat(32),
                    "index": 0
                },
                "sighashType": 1,
                "proprietaries": {}
            }],
            "outputs": [{
                "amount": 1,
                "scriptPublicKey": "0000",
                "proprietaries": {}
            }]
        }])
    };

    let valid = canonical_pskb_wire(base());
    strict_decode(&valid).expect("valid output optionals");

    let mut with_null_redeem = base();
    with_null_redeem[0]["outputs"][0]["redeemScript"] = serde_json::Value::Null;
    strict_decode(&canonical_pskb_wire(with_null_redeem)).expect("null redeem script");

    for (field, value) in [
        ("redeemScript", json!(1)),
        ("bip32Derivations", json!([])),
        ("proprietaries", json!([])),
    ] {
        let mut invalid =
            crate::transaction::interchange::pskt::unit_tests::canonical_test_pskt(base());
        invalid[0]["outputs"][0][field] = value;
        let json = serde_json::to_vec(&invalid).unwrap();
        let mut wire = b"PSKB".to_vec();
        wire.extend_from_slice(hex::encode(json).as_bytes());
        assert!(strict_decode(&hex::encode(wire)).is_err());
    }

    let mut bad_script = base();
    bad_script[0]["outputs"][0]["scriptPublicKey"] = json!("zz");
    assert!(strict_decode(&canonical_pskb_wire(bad_script)).is_err());
}

#[test]
fn strict_decode_covers_global_input_output_and_nested_schema_rejection_matrix() {
    let base = crate::transaction::interchange::pskt::unit_tests::canonical_test_pskt(json!([{
        "global": {
            "fallbackLockTime": "0",
            "subnetworkId": "00".repeat(20),
            "gas": "0",
            "txPayload": ""
        },
        "inputs": [{
            "utxoEntry": {"amount": "2", "scriptPublicKey": "0000"},
            "previousOutpoint": {"transactionId": "00".repeat(32), "index": 0},
            "sequence": "0",
            "sigOpCount": 1,
            "minimumSignatures": 1,
            "sighashType": 1,
            "redeemScript": null,
            "partialSigs": {},
            "bip32Derivations": {},
            "proprietaries": {},
            "covenantExecution": null
        }],
        "outputs": [{
            "amount": "1",
            "scriptPublicKey": "0000",
            "redeemScript": null,
            "bip32Derivations": {},
            "proprietaries": {},
            "covenantBinding": null
        }]
    }]));
    assert!(
        strict_decode(&raw_pskb(&base)).is_ok(),
        "canonical strict-decode fixture"
    );

    for key in ["global", "inputs", "outputs"] {
        assert_strict_rejects(base.clone(), |root| {
            root[0].as_object_mut().unwrap().remove(key);
        });
    }

    for (field, value) in [
        ("version", Value::Null),
        ("version", json!(1)),
        ("txVersion", json!(65_535)),
        ("inputCount", json!(2)),
        ("outputCount", json!(2)),
        ("fallbackLockTime", json!(true)),
        ("gas", json!([])),
        ("inputsModifiable", json!(1)),
        ("outputsModifiable", json!("false")),
        ("xpubs", json!([])),
        ("proprietaries", Value::Null),
        ("id", json!(1)),
        ("txPayload", json!("0")),
        ("subnetworkId", json!("00")),
        ("covenantBranch", json!("unsupported")),
    ] {
        assert_strict_rejects(base.clone(), |root| {
            root[0]["global"][field] = value;
        });
    }

    for (field, value) in [
        ("utxoEntry", json!([])),
        ("previousOutpoint", json!([])),
        ("sighashType", Value::Null),
        ("sighashType", json!(2)),
        ("sigOpCount", Value::Null),
        ("sigOpCount", json!(6)),
        ("minimumSignatures", Value::Null),
        ("minimumSignatures", json!(0)),
        ("minimumSignatures", json!(6)),
        ("redeemScript", json!(1)),
        ("partialSigs", Value::Null),
        ("partialSigs", json!([])),
        ("bip32Derivations", Value::Null),
        ("bip32Derivations", json!([])),
        ("proprietaries", Value::Null),
        ("proprietaries", json!([])),
        ("covenantExecution", json!(1)),
    ] {
        assert_strict_rejects(base.clone(), |root| {
            root[0]["inputs"][0][field] = value;
        });
    }

    for (field, value) in [
        ("amount", Value::Null),
        ("scriptPublicKey", Value::Null),
        ("scriptPublicKey", json!("0")),
        ("redeemScript", json!(1)),
        ("bip32Derivations", json!([])),
        ("proprietaries", json!([])),
        ("covenantBinding", json!(1)),
    ] {
        assert_strict_rejects(base.clone(), |root| {
            root[0]["outputs"][0][field] = value;
        });
    }

    for value in [
        json!({}),
        json!({"suppliedMask": 1}),
        json!({"suppliedMask": 1, "suppliedTrueMask": 2}),
        json!({"suppliedMask": 65_536, "suppliedTrueMask": 0}),
        json!({"suppliedMask": 1, "suppliedTrueMask": 0, "extra": 0}),
    ] {
        assert_strict_rejects(base.clone(), |root| {
            root[0]["inputs"][0]["covenantExecution"] = value;
        });
    }

    for value in [
        json!({}),
        json!({"authorizingInput": 0}),
        json!({"authorizingInput": 1, "covenantId": "00".repeat(32)}),
        json!({"authorizingInput": 0, "covenantId": "00"}),
        json!({"authorizingInput": 0, "covenantId": "00".repeat(32), "extra": 0}),
    ] {
        assert_strict_rejects(base.clone(), |root| {
            root[0]["outputs"][0]["covenantBinding"] = value;
        });
    }

    assert_strict_rejects(base.clone(), |root| {
        root[0]["inputs"][0]["utxoEntry"]["amount"] = Value::Null;
    });
    assert_strict_rejects(base.clone(), |root| {
        root[0]["inputs"][0]["utxoEntry"]["scriptPublicKey"] = json!("0");
    });
    assert_strict_rejects(base.clone(), |root| {
        root[0]["inputs"][0]["utxoEntry"]["covenantId"] = json!("00");
    });
    assert_strict_rejects(base.clone(), |root| {
        root[0]["inputs"][0]["previousOutpoint"]["transactionId"] = json!("00");
    });
    assert_strict_rejects(base, |root| {
        root[0]["inputs"][0]["previousOutpoint"]["index"] = json!(u64::from(u32::MAX) + 1);
    });
}
