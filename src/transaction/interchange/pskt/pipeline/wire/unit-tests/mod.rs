use super::*;
use serde_json::{json, Value};

#[test]
fn derivation_hint_covers_absent_shape_branch_and_index_boundaries() {
    assert_eq!(parse_derivation(&json!({})), Ok(None));
    crate::test_support::assert_err_text(
        &parse_derivation(&json!([])),
        "proprietaries must be an object",
    );
    crate::test_support::assert_err_text(
        &parse_derivation(&json!({"kassignerDerivation": null})),
        "kassignerDerivation must be an object",
    );
    crate::test_support::assert_err_text(
        &parse_derivation(&json!({"kassignerDerivation": []})),
        "kassignerDerivation must be an object",
    );

    crate::test_support::assert_err_text(
        &parse_derivation(&json!({"kassignerDerivation": {"index": 0}})),
        "kassignerDerivation.branch is missing",
    );
    crate::test_support::assert_err_text(
        &parse_derivation(&json!({"kassignerDerivation": {"branch": 0}})),
        "kassignerDerivation.index is missing",
    );
    crate::test_support::assert_err_text(
        &parse_derivation(&json!({"kassignerDerivation": {"branch": 2, "index": 0}})),
        "kassignerDerivation.branch must be 0 or 1",
    );
    crate::test_support::assert_err_text(
        &parse_derivation(&json!({"kassignerDerivation": {"branch": 256, "index": 0}})),
        "kassignerDerivation.branch must be 0 or 1",
    );
    crate::test_support::assert_err_text(
        &parse_derivation(&json!({"kassignerDerivation": {"branch": "01", "index": 0}})),
        "kassignerDerivation.branch must be a canonical unsigned decimal string",
    );

    let soft_limit = crate::wallet::derivation::bip32::HARDENED_BIT;
    crate::test_support::assert_err_text(
        &parse_derivation(&json!({
            "kassignerDerivation": {"branch": 1, "index": soft_limit}
        })),
        "kassignerDerivation.index must be a non-hardened u32",
    );
    crate::test_support::assert_err_text(
        &parse_derivation(&json!({
            "kassignerDerivation": {"branch": 1, "index": u64::from(u32::MAX) + 1}
        })),
        "kassignerDerivation.index must be a non-hardened u32",
    );

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
    crate::test_support::assert_err_text(
        &attach_sole_signature("00", &public_key, &[0x33; 64]),
        "payload too short",
    );
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

fn assert_strict_rejects(mut root: Value, expected: &str, mutate: impl FnOnce(&mut Value)) {
    mutate(&mut root);
    assert_eq!(strict_decode(&raw_pskb(&root)), Err(expected.to_string()));
}

#[test]
fn exact_four_byte_magic_is_not_misclassified_as_a_short_outer_envelope() {
    crate::test_support::assert_err_text(
        &strict_decode("50534b54"),
        "invalid canonical JSON structure",
    );
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

    for ((field, value), expected) in [
        (
            ("redeemScript", json!(1)),
            "output[0].redeemScript must be a lowercase hexadecimal string",
        ),
        (
            ("bip32Derivations", json!([])),
            "output[0].bip32Derivations has the wrong JSON type",
        ),
        (
            ("proprietaries", json!([])),
            "output[0].proprietaries has the wrong JSON type",
        ),
    ] {
        let mut invalid =
            crate::transaction::interchange::pskt::unit_tests::canonical_test_pskt(base());
        invalid[0]["outputs"][0][field] = value;
        let json = serde_json::to_vec(&invalid).unwrap();
        let mut wire = b"PSKB".to_vec();
        wire.extend_from_slice(hex::encode(json).as_bytes());
        crate::test_support::assert_err_text(&strict_decode(&hex::encode(wire)), expected);
    }

    let mut bad_script = base();
    bad_script[0]["outputs"][0]["scriptPublicKey"] = json!("zz");
    crate::test_support::assert_err_text(
        &strict_decode(&canonical_pskb_wire(bad_script)),
        "output[0].scriptPublicKey must contain a four-hex-digit script version",
    );
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

    for (key, expected) in [
        ("global", "missing PSKT.global"),
        ("inputs", "missing PSKT.inputs"),
        ("outputs", "missing PSKT.outputs"),
    ] {
        assert_strict_rejects(base.clone(), expected, |root| {
            root[0].as_object_mut().unwrap().remove(key);
        });
    }

    for (field, value, expected) in [
        ("version", Value::Null, "global.version must not be null"),
        ("version", json!(1), "unsupported PSKT version: 1"),
        (
            "txVersion",
            json!(65_535),
            "unsupported transaction version: 65535",
        ),
        (
            "inputCount",
            json!(2),
            "declared PSKT input/output counts do not match arrays",
        ),
        (
            "outputCount",
            json!(2),
            "declared PSKT input/output counts do not match arrays",
        ),
        (
            "fallbackLockTime",
            json!(true),
            "global.fallbackLockTime must be a decimal string or exact legacy integer",
        ),
        (
            "gas",
            json!([]),
            "global.gas must be a decimal string or exact legacy integer",
        ),
        (
            "inputsModifiable",
            json!(1),
            "global.inputsModifiable has the wrong JSON type",
        ),
        (
            "outputsModifiable",
            json!("false"),
            "global.outputsModifiable has the wrong JSON type",
        ),
        ("xpubs", json!([]), "global.xpubs has the wrong JSON type"),
        (
            "proprietaries",
            Value::Null,
            "global.proprietaries must not be null",
        ),
        ("id", json!(1), "global.id has the wrong JSON type"),
        (
            "txPayload",
            json!("0"),
            "global.txPayload must be even-length lowercase hexadecimal",
        ),
        ("subnetworkId", json!("00"), "subnetworkId must be 20 bytes"),
        (
            "covenantBranch",
            json!("unsupported"),
            "unsupported global.covenantBranch: unsupported",
        ),
    ] {
        assert_strict_rejects(base.clone(), expected, |root| {
            root[0]["global"][field] = value;
        });
    }

    for (field, value, expected) in [
        (
            "utxoEntry",
            json!([]),
            "input[0].utxoEntry has the wrong JSON type",
        ),
        (
            "previousOutpoint",
            json!([]),
            "input[0].previousOutpoint has the wrong JSON type",
        ),
        (
            "sighashType",
            Value::Null,
            "input[0].sighashType must not be null",
        ),
        (
            "sighashType",
            json!(2),
            "input[0].sighashType is unsupported: 2",
        ),
        (
            "sigOpCount",
            Value::Null,
            "input[0].sigOpCount must not be null",
        ),
        (
            "sigOpCount",
            json!(6),
            "input[0]: sigOpCount exceeds signer capabilities",
        ),
        (
            "minimumSignatures",
            Value::Null,
            "input[0].minimumSignatures must not be null",
        ),
        (
            "minimumSignatures",
            json!(0),
            "input[0].minimumSignatures must be within 1..=5",
        ),
        (
            "minimumSignatures",
            json!(6),
            "input[0].minimumSignatures must be within 1..=5",
        ),
        (
            "redeemScript",
            json!(1),
            "input[0].redeemScript must be a lowercase hexadecimal string",
        ),
        (
            "partialSigs",
            Value::Null,
            "input[0].partialSigs must not be null",
        ),
        (
            "partialSigs",
            json!([]),
            "input[0].partialSigs has the wrong JSON type",
        ),
        (
            "bip32Derivations",
            Value::Null,
            "input[0].bip32Derivations must not be null",
        ),
        (
            "bip32Derivations",
            json!([]),
            "input[0].bip32Derivations has the wrong JSON type",
        ),
        (
            "proprietaries",
            Value::Null,
            "input[0].proprietaries must not be null",
        ),
        (
            "proprietaries",
            json!([]),
            "input[0].proprietaries has the wrong JSON type",
        ),
        (
            "covenantExecution",
            json!(1),
            "input[0].covenantExecution has the wrong JSON type",
        ),
    ] {
        assert_strict_rejects(base.clone(), expected, |root| {
            root[0]["inputs"][0][field] = value;
        });
    }

    for (field, value, expected) in [
        ("amount", Value::Null, "output[0].amount must not be null"),
        (
            "scriptPublicKey",
            Value::Null,
            "output[0].scriptPublicKey must not be null",
        ),
        (
            "scriptPublicKey",
            json!("0"),
            "output[0].scriptPublicKey must contain a four-hex-digit script version",
        ),
        (
            "redeemScript",
            json!(1),
            "output[0].redeemScript must be a lowercase hexadecimal string",
        ),
        (
            "bip32Derivations",
            json!([]),
            "output[0].bip32Derivations has the wrong JSON type",
        ),
        (
            "proprietaries",
            json!([]),
            "output[0].proprietaries has the wrong JSON type",
        ),
        (
            "covenantBinding",
            json!(1),
            "output[0].covenantBinding has the wrong JSON type",
        ),
    ] {
        assert_strict_rejects(base.clone(), expected, |root| {
            root[0]["outputs"][0][field] = value;
        });
    }

    for (value, expected) in [
        (json!({}), "missing input[0].covenantExecution.suppliedMask"),
        (
            json!({"suppliedMask": 1}),
            "missing input[0].covenantExecution.suppliedTrueMask",
        ),
        (
            json!({"suppliedMask": 1, "suppliedTrueMask": 2}),
            "input[0]: covenantExecution true-mask contains unsupplied decisions",
        ),
        (
            json!({"suppliedMask": 65_536, "suppliedTrueMask": 0}),
            "input[0]: covenantExecution.suppliedMask exceeds u16",
        ),
        (
            json!({"suppliedMask": 1, "suppliedTrueMask": 0, "extra": 0}),
            "input[0]: covenantExecution must contain only suppliedMask and suppliedTrueMask",
        ),
    ] {
        assert_strict_rejects(base.clone(), expected, |root| {
            root[0]["inputs"][0]["covenantExecution"] = value;
        });
    }

    for (value, expected) in [
        (
            json!({}),
            "missing output[0].covenantBinding.authorizingInput",
        ),
        (
            json!({"authorizingInput": 0}),
            "missing output[0].covenantBinding.covenantId",
        ),
        (
            json!({"authorizingInput": 1, "covenantId": "00".repeat(32)}),
            "output[0] covenant authorizing input is out of range",
        ),
        (
            json!({"authorizingInput": 0, "covenantId": "00"}),
            "output[0] covenant id must be 32 bytes",
        ),
        (
            json!({"authorizingInput": 0, "covenantId": "00".repeat(32), "extra": 0}),
            "output[0] covenantBinding must contain only authorizingInput and covenantId",
        ),
    ] {
        assert_strict_rejects(base.clone(), expected, |root| {
            root[0]["outputs"][0]["covenantBinding"] = value;
        });
    }

    assert_strict_rejects(
        base.clone(),
        "input[0].utxoEntry.amount must not be null",
        |root| {
            root[0]["inputs"][0]["utxoEntry"]["amount"] = Value::Null;
        },
    );
    assert_strict_rejects(
        base.clone(),
        "input[0].utxoEntry.scriptPublicKey must contain a four-hex-digit script version",
        |root| {
            root[0]["inputs"][0]["utxoEntry"]["scriptPublicKey"] = json!("0");
        },
    );
    assert_strict_rejects(
        base.clone(),
        "input[0]: utxoEntry.covenantId must be 32 bytes",
        |root| {
            root[0]["inputs"][0]["utxoEntry"]["covenantId"] = json!("00");
        },
    );
    assert_strict_rejects(base.clone(), "input[0]: tx_id not 32 bytes", |root| {
        root[0]["inputs"][0]["previousOutpoint"]["transactionId"] = json!("00");
    });
    assert_strict_rejects(base, "input[0]: index exceeds u32", |root| {
        root[0]["inputs"][0]["previousOutpoint"]["index"] = json!(u64::from(u32::MAX) + 1);
    });
}
