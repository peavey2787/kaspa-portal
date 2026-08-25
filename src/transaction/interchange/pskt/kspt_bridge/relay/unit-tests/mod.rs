use super::*;
use serde_json::json;

fn global() -> Map<String, Value> {
    json!({
        "txVersion": 1,
        "fallbackLockTime": "7",
        "subnetworkId": "00".repeat(20),
        "gas": "9",
        "txPayload": "aabb"
    })
    .as_object()
    .expect("global object")
    .clone()
}

#[test]
fn global_encoding_helpers_cover_defaults_payload_and_header_limits() {
    let fields = parse_global_encoding_fields(&global()).expect("global fields");
    assert_eq!(fields.tx_version, 1);
    assert_eq!(fields.locktime, 7);
    assert_eq!(fields.subnetwork_id, [0u8; 20]);
    assert_eq!(fields.gas, 9);
    assert_eq!(fields.payload, vec![0xaa, 0xbb]);

    let mut values = Map::new();
    assert_eq!(optional_exact_u64(&values, "x"), Ok(0));
    values.insert("x".into(), Value::Null);
    assert_eq!(optional_exact_u64(&values, "x"), Ok(0));
    values.insert("x".into(), json!("12"));
    assert_eq!(optional_exact_u64(&values, "x"), Ok(12));
    values.insert("txPayload".into(), json!("0102"));
    assert_eq!(decode_payload(&values), vec![1, 2]);
    values.insert("txPayload".into(), json!("zz"));
    assert!(decode_payload(&values).is_empty());
    values.insert("txPayload".into(), json!(9));
    assert!(decode_payload(&values).is_empty());

    let header = encode_transaction_header(&fields, 3, 2).expect("transaction header");
    assert_eq!(&header[..6], b"KSPT\x01\x00");
    assert_eq!(u32::from_le_bytes(header[8..12].try_into().unwrap()), 3);
    assert_eq!(header[12], 2);
    assert_eq!(&header[49..51], &2u16.to_le_bytes());
    assert_eq!(&header[51..], &[0xaa, 0xbb]);
    assert_eq!(
        encode_transaction_header(&fields, 0, 256).unwrap_err(),
        "too many outputs"
    );

    let huge = GlobalEncodingFields {
        tx_version: 0,
        locktime: 0,
        subnetwork_id: [0; 20],
        gas: 0,
        payload: vec![0u8; usize::from(u16::MAX) + 1],
    };
    assert_eq!(
        encode_transaction_header(&huge, 0, 0).unwrap_err(),
        "transaction payload is too large"
    );

    let mut missing = global();
    missing.remove("txVersion");
    let missing_error = match parse_global_encoding_fields(&missing) {
        Ok(_) => panic!("missing txVersion must be rejected"),
        Err(error) => error,
    };
    assert_eq!(missing_error, "missing txVersion");

    let mut unsupported = global();
    unsupported.insert("txVersion".into(), json!(2));
    assert_eq!(
        parse_global_encoding_fields(&unsupported).unwrap_err(),
        "unsupported txVersion: 2",
    );

    let mut overflow = global();
    overflow.insert("txVersion".into(), json!(u64::from(u16::MAX) + 1));
    let overflow_error = match parse_global_encoding_fields(&overflow) {
        Ok(_) => panic!("overflowing txVersion must be rejected"),
        Err(error) => error,
    };
    assert_eq!(overflow_error, "txVersion exceeds u16");
}

#[test]
fn network_and_trailer_helpers_cover_valid_invalid_and_ignored_metadata() {
    assert_eq!(parse_network_code("mainnet"), Ok(1));
    assert_eq!(parse_network_code("testnet-10"), Ok(2));
    assert_eq!(parse_network_code("testnet-12"), Ok(2));
    assert_eq!(parse_network_code("testnet-14"), Ok(2));
    assert_eq!(parse_network_code("devnet"), Ok(3));
    assert_eq!(parse_network_code("simnet"), Ok(4));
    assert_eq!(
        parse_network_code("other").unwrap_err(),
        "unsupported network: other"
    );
    assert_eq!(
        parse_network_code("testnet-custom").unwrap_err(),
        "unsupported network: testnet-custom"
    );

    let mut network = Vec::new();
    append_network(&mut network, 4);
    assert_eq!(network, vec![b'N', 4]);

    let outputs = vec![
        json!({"proprietaries": {"kaspaPortalDerivation": {"branch": 1, "index": "37"}}}),
        json!({"proprietaries": {"kaspaPortalDerivation": {"branch": 2, "index": 4}}}),
        json!({"proprietaries": {"kaspaPortalDerivation": {"branch": 0, "index": "bad"}}}),
        json!({}),
    ];
    let mut hints = Vec::new();
    append_derivation_hints(&mut hints, &outputs);
    assert_eq!(hints, vec![b'D', 0, 1, 37, 0, 0, 0]);

    let mut too_far = vec![Value::Null; 257];
    too_far[256] = json!({"proprietaries": {"kaspaPortalDerivation": {"branch": 0, "index": 1}}});
    let mut ignored = Vec::new();
    append_derivation_hints(&mut ignored, &too_far);
    assert!(ignored.is_empty());

    let mut stealth = Vec::new();
    append_stealth_tweak(
        &mut stealth,
        &[json!({"proprietaries": {"stealthTweak": "ab".repeat(32)}})],
    );
    assert_eq!(stealth[0], b'S');
    assert_eq!(&stealth[1..], &[0xab; 32]);
    let mut malformed = Vec::new();
    append_stealth_tweak(
        &mut malformed,
        &[
            json!({"proprietaries": {"stealthTweak": "ab".repeat(31)}}),
            json!({"proprietaries": {"stealthTweak": "zz"}}),
        ],
    );
    assert!(malformed.is_empty());
}

fn valid_input() -> Value {
    json!({
        "previousOutpoint": {"transactionId": "11".repeat(32), "index": 2},
        "proprietaries": {"persistentVault": true}
    })
}

fn valid_output() -> Value {
    json!({"amount": "9", "scriptPublicKey": format!("000020{}ac", "22".repeat(32))})
}

#[test]
fn covenant_binding_trailers_cover_derived_success_and_explicit_failures() {
    let mut buffer = Vec::new();
    append_derived_covenant_binding(&mut buffer, &[valid_input()], &[valid_output()]);
    assert_eq!(buffer.len(), 36);
    assert_eq!(buffer[0], b'C');
    assert_eq!(buffer[1], 0);
    assert_eq!(&buffer[2..4], &[0, 0]);

    let mut absent = Vec::new();
    append_derived_covenant_binding(&mut absent, &[json!({})], &[valid_output()]);
    assert!(absent.is_empty());
    append_derived_covenant_binding(
        &mut absent,
        &[valid_input()],
        &[
            json!({"amount": "9", "scriptPublicKey": "bad", "covenantBinding": {"authorizingInput": 0, "covenantId": "11".repeat(32)}}),
        ],
    );
    assert!(
        absent.is_empty(),
        "explicit binding suppresses derived binding"
    );

    let mut explicit = Vec::new();
    append_explicit_covenant_bindings(
        &mut explicit,
        &[json!({
            "covenantBinding": {"authorizingInput": 7, "covenantId": "ab".repeat(32)}
        })],
    )
    .expect("explicit binding");
    assert_eq!(explicit.len(), 36);
    assert_eq!(&explicit[..4], &[b'C', 0, 7, 0]);
    assert_eq!(&explicit[4..], &[0xab; 32]);

    for (binding, expected) in [
        (
            json!({"covenantId": "ab".repeat(32)}),
            "missing authorizingInput",
        ),
        (
            json!({"authorizingInput": u64::from(u16::MAX) + 1, "covenantId": "ab".repeat(32)}),
            "exceeds u16",
        ),
        (json!({"authorizingInput": 0}), "missing covenantId"),
        (
            json!({"authorizingInput": 0, "covenantId": "zz"}),
            "not hex",
        ),
        (
            json!({"authorizingInput": 0, "covenantId": "ab".repeat(31)}),
            "must be 32 bytes",
        ),
    ] {
        let error = append_explicit_covenant_bindings(
            &mut Vec::new(),
            &[json!({"covenantBinding": binding})],
        )
        .unwrap_err();
        assert!(error.contains(expected), "{error}");
    }

    let mut many = vec![Value::Null; 257];
    many[256] = json!({"covenantBinding": {"authorizingInput": 0, "covenantId": "ab".repeat(32)}});
    assert_eq!(
        append_explicit_covenant_bindings(&mut Vec::new(), &many).unwrap_err(),
        "too many outputs"
    );
}

#[test]
fn section_and_first_output_helpers_cover_missing_and_malformed_shapes() {
    let document = json!({"global": {}, "inputs": [], "outputs": []});
    let map = document.as_object().unwrap();
    assert!(global_field(map).is_ok());
    assert!(array_field(map, "inputs").unwrap().is_empty());
    assert_eq!(array_field(map, "missing").unwrap_err(), "missing missing");
    assert_eq!(validate_counts(&[], &[]), Ok(()));
    assert_eq!(validate_counts(&[], &vec![Value::Null; 255]), Ok(()));
    assert_eq!(
        validate_counts(&[], &vec![Value::Null; 256]).unwrap_err(),
        "too many outputs"
    );

    assert_eq!(first_output(&[valid_output()]).unwrap().0, 9);
    assert!(first_output(&[]).is_none());
    assert!(first_output(&[Value::Null]).is_none());
    assert!(first_output(&[json!({})]).is_none());
    assert!(first_output(&[json!({"amount": "9", "scriptPublicKey": "bad"})]).is_none());
}
