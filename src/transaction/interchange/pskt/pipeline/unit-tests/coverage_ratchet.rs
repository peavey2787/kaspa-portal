use k256::schnorr::SigningKey;
use serde_json::{json, Value};

use super::super::test_support::{
    decode, document, encode, find_pubkey_position, parse_derivation, parse_ms45,
    parse_multisig_redeem, sighash_all_for_pskt, Format, InputFields,
};
use super::{encode_pskt, merge_signed_kspt, Network};

#[test]
fn host_pskt_parser_rejects_duplicate_keys_escapes_unicode_and_excess_nesting() {
    fn wire(json: &[u8]) -> String {
        let mut bytes = Vec::from(*b"PSKT");
        bytes.extend_from_slice(hex::encode(json).as_bytes());
        hex::encode(bytes)
    }

    for json in [
        br#"{"a":1,"a":2}"#.as_slice(),
        br#"{"a":"\u0061"}"#.as_slice(),
        r#"{"a":"é"}"#.as_bytes(),
    ] {
        assert!(decode(&wire(json)).is_err());
    }

    let mut nested = Vec::new();
    nested.extend(core::iter::repeat_n(b'[', 33));
    nested.push(b'0');
    nested.extend(core::iter::repeat_n(b']', 33));
    assert!(decode(&wire(&nested)).is_err());
}

#[test]
fn host_pskt_outer_wire_decode_covers_resource_hex_magic_and_both_formats() {
    assert!(decode("").unwrap_err().contains("payload too short"));
    assert!(decode("0").unwrap_err().contains("even-length ASCII hex"));
    assert!(decode("GG").unwrap_err().contains("outer PSKT/PSKB hex"));
    assert!(decode(&hex::encode(b"NOPE"))
        .unwrap_err()
        .contains("Not a PSKT/PSKB"));

    let mut pskt = Vec::from(*b"PSKT");
    pskt.extend_from_slice(hex::encode(br#"{}"#).as_bytes());
    let (format, root) = decode(&hex::encode(pskt)).expect("PSKT decode");
    assert_eq!(format, Format::Pskt);
    assert!(root.is_object());

    let mut pskb = Vec::from(*b"PSKB");
    pskb.extend_from_slice(hex::encode(br#"[]"#).as_bytes());
    let (format, root) = decode(&hex::encode(pskb)).expect("PSKB decode");
    assert_eq!(format, Format::Pskb);
    assert!(root.is_array());

    let oversized = "00".repeat(super::super::test_support::MAX_PSKT_WIRE_HEX_CHARS / 2 + 1);
    assert!(decode(&oversized).unwrap_err().contains("resource ceiling"));
}

#[test]
fn relay_field_parsers_cover_multisig_positions_ms45_and_derivation_boundaries() {
    let redeem = multisig(&[0x11, 0x22, 0x33], 2);
    assert_eq!(parse_multisig_redeem(&redeem), Some((2, 3)));
    assert_eq!(
        parse_multisig_redeem(&multisig(&(1u8..=6).collect::<Vec<_>>(), 6)),
        None,
        "consumer multisig policy is capped at five keys",
    );
    for invalid in [
        vec![],
        vec![0x10, 0x51, 0xae],
        vec![0x50, 0x51, 0xae],
        vec![0x51, 0x20, 0x11, 0x51, 0xae],
        vec![0x52, 0x20, 0x11, 0x51, 0xae],
        {
            let mut value = multisig(&[0x11], 1);
            value[1] = 0x21;
            value
        },
        {
            let mut value = multisig(&[0x11], 1);
            *value.last_mut().unwrap() = 0xad;
            value
        },
    ] {
        assert_eq!(parse_multisig_redeem(&invalid), None);
    }
    assert_eq!(
        find_pubkey_position(&redeem, &format!("02{}", "22".repeat(32))),
        Some(1)
    );
    assert_eq!(find_pubkey_position(&redeem, "00"), None);
    assert_eq!(
        find_pubkey_position(&redeem, &format!("02{}", "zz".repeat(32))),
        None
    );
    assert_eq!(
        find_pubkey_position(&redeem, &format!("02{}", "44".repeat(32))),
        None
    );
    let mut bad_push = redeem.clone();
    bad_push[1] = 0x21;
    assert_eq!(
        find_pubkey_position(&bad_push, &format!("02{}", "11".repeat(32))),
        None
    );

    assert_eq!(
        parse_ms45(&json!({"key": {"derivationPath": "m/45'/111111'/0'/2/1/9"}})),
        Ok(Some((2, 1, 9)))
    );
    assert!(parse_ms45(&json!({"key": {"derivationPath": "m/45'/111111'/0'/2/2/9"}})).is_err());
    assert!(parse_ms45(&json!({"key": {"derivationPath": "m/45'/111111'/0'/2'/1/9"}})).is_err());

    assert_eq!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 0, "index": "7"}})),
        Ok(Some((0, 7)))
    );
    assert_eq!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 1, "index": 8}})),
        Ok(Some((1, 8)))
    );
    assert!(parse_derivation(&json!({"kassignerDerivation": {"branch": 2, "index": 8}})).is_err());
    assert!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 256, "index": 8}})).is_err()
    );
    assert!(parse_derivation(
        &json!({"kassignerDerivation": {"branch": 0, "index": 0x8000_0000u64}})
    )
    .is_err());
    assert!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 0, "index": u64::MAX}}))
            .is_err()
    );
    assert!(parse_derivation(
        &json!({"kassignerDerivation": {"branch": 0, "index": "not-a-number"}})
    )
    .is_err());
    assert!(
        parse_derivation(&json!({"kassignerDerivation": {"branch": 0, "index": true}})).is_err()
    );
    assert!(parse_derivation(&json!({"kassignerDerivation": {"index": "7"}})).is_err());
    assert_eq!(parse_derivation(&json!({})), Ok(None));
}

#[test]
fn canonical_relay_and_merge_cover_multisig_metadata_and_signature_ordering() {
    let redeem = cryptographic_multisig(&[0x11, 0x22, 0x33], 2);
    let mut original_doc = base_document(json!({}), Some(&redeem));
    original_doc["inputs"][0]["proprietaries"] = json!({
        "kassignerDerivation": {"branch": 0, "index": "17"},
        "stealthTweak": "55".repeat(32)
    });
    original_doc["inputs"][0]["bip32Derivations"] = json!({
        "a": {"derivationPath": "m/45'/111111'/0'/2/0/17"}
    });
    original_doc["outputs"][0]["proprietaries"] = json!({
        "kassignerDerivation": {"branch": 1, "index": 18}
    });
    original_doc["outputs"][0]["bip32Derivations"] = json!({
        "b": {"derivationPath": "m/45'/111111'/0'/2/1/18"}
    });
    original_doc["outputs"][0]["covenantBinding"] = json!({
        "authorizingInput": 0,
        "covenantId": "66".repeat(32)
    });
    let original = encode_pskb(original_doc.clone());

    let signed_doc = sign_document(original_doc, &[0x33, 0x11]);
    let signed_source = encode_pskb(signed_doc);
    let signed_kspt = encode_pskt(&signed_source, Network::Mainnet).expect("signed KSPT");
    let merged =
        merge_signed_kspt(&original, &signed_kspt, Network::Mainnet).expect("merge multisig");
    assert!(merge_signed_kspt(&original, b"BAD", Network::Mainnet).is_err());
    let (format, root) = super::super::test_support::decode(&merged).expect("decode merged");
    let doc = document(&root, format).expect("merged document");
    assert_eq!(
        doc["inputs"][0]["partialSigs"].as_object().unwrap().len(),
        2
    );

    let mut p2pk_doc = base_document(json!({}), None);
    p2pk_doc["inputs"][0]["utxoEntry"]["scriptPublicKey"] =
        json!(format!("000020{}ac", hex::encode(xonly(0x11))));
    let p2pk_signed = encode_pskb(sign_document(p2pk_doc, &[0x11]));
    assert!(!encode_pskt(&p2pk_signed, Network::Mainnet)
        .expect("P2PK signatures")
        .is_empty());

    let mut covenant_redeem = vec![0x20];
    covenant_redeem.extend_from_slice(&xonly(0x11));
    covenant_redeem.push(0xac);
    let covenant_signed = encode_pskb(sign_document(
        base_document(json!({}), Some(&covenant_redeem)),
        &[0x11],
    ));
    assert!(!encode_pskt(&covenant_signed, Network::Mainnet)
        .expect("specialized redeem relay")
        .is_empty());
}

#[test]
fn canonical_merge_covers_generic_covenant_signature_binding() {
    let owner = 0x41;
    let beneficiary = 0x42;
    let mut redeem = vec![0x63, 0x20];
    redeem.extend_from_slice(&xonly(owner));
    redeem.extend_from_slice(&[0xac, 0x67, 0x20]);
    redeem.extend_from_slice(&xonly(beneficiary));
    redeem.extend_from_slice(&[0xac, 0x68]);

    let hash = blake2b_simd::Params::new().hash_length(32).hash(&redeem);
    let p2sh = format!("0000aa20{}87", hex::encode(hash.as_bytes()));

    let mut original_doc = base_document(json!({}), Some(&redeem));
    original_doc["inputs"][0]["utxoEntry"]["scriptPublicKey"] = json!(p2sh);
    original_doc["inputs"][0]["covenantExecution"] =
        json!({"suppliedMask": "1", "suppliedTrueMask": "1"});
    let original = encode_pskb(original_doc.clone());

    let signed_source = encode_pskb(sign_document(original_doc, &[owner]));
    let signed_kspt = encode_pskt(&signed_source, Network::Mainnet).expect("signed covenant KSPT");
    let merged = merge_signed_kspt(&original, &signed_kspt, Network::Mainnet)
        .expect("merge generic covenant signature");
    let (format, root) = decode(&merged).expect("decode merged covenant PSKT");
    let doc = document(&root, format).expect("merged covenant document");
    let partials = doc["inputs"][0]["partialSigs"]
        .as_object()
        .expect("merged covenant partial signatures");
    assert_eq!(partials.len(), 1);
    assert!(partials.contains_key(&format!("02{}", hex::encode(xonly(owner)))));
}

#[test]
fn relay_input_parser_covers_covenant_id_execution_and_optional_boundaries() {
    let base_input = || base_document(json!({}), None)["inputs"][0].clone();

    let parsed = InputFields::parse(&base_input()).expect("base input");
    assert!(!parsed.has_covenant_id);

    let mut null_id = base_input();
    null_id["utxoEntry"]["covenantId"] = Value::Null;
    assert!(
        !InputFields::parse(&null_id)
            .expect("null covenant id")
            .has_covenant_id
    );

    let mut valid_id = base_input();
    valid_id["utxoEntry"]["covenantId"] = json!("ab".repeat(32));
    assert!(
        InputFields::parse(&valid_id)
            .expect("canonical covenant id")
            .has_covenant_id
    );

    for bad_id in [json!(true), json!("a"), json!("ab"), json!("AB".repeat(32))] {
        let mut input = base_input();
        input["utxoEntry"]["covenantId"] = bad_id;
        assert!(InputFields::parse(&input).is_err());
    }

    let mut defaults = base_input();
    defaults.as_object_mut().unwrap().remove("sequence");
    defaults.as_object_mut().unwrap().remove("sigOpCount");
    let parsed = InputFields::parse(&defaults).expect("schema defaults");
    assert_eq!(parsed.sequence, 0);
    assert_eq!(parsed.sig_op_count, 1);

    let mut null_execution = base_input();
    null_execution["covenantExecution"] = Value::Null;
    assert_eq!(
        InputFields::parse(&null_execution)
            .expect("null execution")
            .covenant_execution,
        None
    );

    let mut execution = base_input();
    execution["covenantExecution"] = json!({"suppliedMask": "3", "suppliedTrueMask": "1"});
    assert_eq!(
        InputFields::parse(&execution)
            .expect("canonical execution")
            .covenant_execution,
        Some((3, 1))
    );

    for bad_execution in [
        json!(1),
        json!({}),
        json!({"suppliedMask": 1}),
        json!({"suppliedMask": 1, "suppliedTrueMask": 2}),
        json!({"suppliedMask": 65_536, "suppliedTrueMask": 0}),
        json!({"suppliedMask": 1, "suppliedTrueMask": 0, "extra": 0}),
    ] {
        let mut input = base_input();
        input["covenantExecution"] = bad_execution;
        assert!(InputFields::parse(&input).is_err());
    }

    let mut null_redeem = base_input();
    null_redeem["redeemScript"] = Value::Null;
    assert!(InputFields::parse(&null_redeem)
        .expect("null redeem")
        .redeem_script
        .is_none());

    for (field, value) in [
        ("redeemScript", json!(1)),
        ("partialSigs", json!([])),
        ("sighashType", json!(2)),
        ("sigOpCount", json!(6)),
    ] {
        let mut input = base_input();
        input[field] = value;
        assert!(InputFields::parse(&input).is_err(), "{field}");
    }
}

#[test]
fn relay_persistent_vault_detection_covers_absent_false_true_and_invalid_metadata() {
    let plain = encode_pskb(base_document(json!({}), None));
    assert!(!encode_pskt(&plain, Network::Mainnet)
        .expect("plain relay")
        .is_empty());

    let mut disabled = base_document(json!({}), None);
    disabled["inputs"][0]["proprietaries"] = json!({"persistentVault": false});
    assert!(!encode_pskt(&encode_pskb(disabled), Network::Mainnet)
        .expect("disabled persistent vault")
        .is_empty());

    let mut enabled = base_document(json!({}), None);
    enabled["inputs"][0]["proprietaries"] = json!({"persistentVault": true});
    assert!(!encode_pskt(&encode_pskb(enabled), Network::Mainnet)
        .expect("derived persistent vault covenant")
        .is_empty());

    let mut invalid = base_document(json!({}), None);
    invalid["inputs"][0]["proprietaries"] = json!({"persistentVault": "true"});
    assert!(encode_pskt(&encode_pskb(invalid), Network::Mainnet)
        .unwrap_err()
        .contains("persistentVault must be boolean"));
}

fn xonly(marker: u8) -> [u8; 32] {
    let signing = SigningKey::from_bytes(&[marker; 32]).expect("test signing key");
    signing.verifying_key().to_bytes().into()
}

fn cryptographic_multisig(keys: &[u8], threshold: u8) -> Vec<u8> {
    let mut script = vec![0x50 + threshold];
    for key in keys {
        script.push(0x20);
        script.extend_from_slice(&xonly(*key));
    }
    script.push(0x50 + u8::try_from(keys.len()).expect("test multisig key count"));
    script.push(0xae);
    script
}

fn sign_document(mut document: Value, signers: &[u8]) -> Value {
    let wire = encode_pskb(document.clone());
    let digest = sighash_all_for_pskt(&wire, Network::Mainnet, 0).expect("test sighash");
    let partials = document["inputs"][0]["partialSigs"]
        .as_object_mut()
        .expect("partialSigs object");
    for marker in signers {
        let signing = SigningKey::from_bytes(&[*marker; 32]).expect("test signing key");
        let signature = signing
            .sign_raw(&digest, &[0u8; 32])
            .expect("test signature");
        partials.insert(
            format!("02{}", hex::encode(signing.verifying_key().to_bytes())),
            json!({"schnorr": hex::encode(signature.to_bytes())}),
        );
    }
    document
}

fn multisig(keys: &[u8], threshold: u8) -> Vec<u8> {
    let mut script = vec![0x50 + threshold];
    for key in keys {
        script.push(0x20);
        script.extend_from_slice(&[*key; 32]);
    }
    script.push(0x50 + u8::try_from(keys.len()).unwrap());
    script.push(0xae);
    script
}

fn base_document(partials: Value, redeem: Option<&[u8]>) -> Value {
    let input_script = if redeem.is_some() {
        format!("0000aa20{}87", "44".repeat(32))
    } else {
        format!("000020{}ac", "11".repeat(32))
    };
    json!({
        "global": {
            "version": 0,
            "txVersion": 0,
            "inputCount": 1,
            "outputCount": 1,
            "fallbackLockTime": "0",
            "subnetworkId": "00".repeat(20),
            "gas": "0",
            "txPayload": ""
        },
        "inputs": [{
            "previousOutpoint": {"transactionId": "22".repeat(32), "index": 0},
            "utxoEntry": {"amount": "100000", "scriptPublicKey": input_script},
            "sequence": "0",
            "sigOpCount": 1,
            "sighashType": 1,
            "redeemScript": redeem.map(hex::encode),
            "partialSigs": partials,
            "proprietaries": {},
            "bip32Derivations": {}
        }],
        "outputs": [{
            "amount": "90000",
            "scriptPublicKey": format!("000020{}ac", "33".repeat(32)),
            "proprietaries": {},
            "bip32Derivations": {},
            "covenantBinding": null
        }]
    })
}

fn encode_pskb(document: Value) -> String {
    encode(Format::Pskb, &json!([document])).expect("encode PSKB")
}
