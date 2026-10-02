use super::*;
use crate::self_test::address::run_address_tests;

// Tests — verified against official rusty-kaspa test vectors
// ═══════════════════════════════════════════════════════════════════

#[test]
fn address_vectors_pass() {
    let (passed, total) = run_address_tests();
    assert_eq!(passed, total);
}

#[test]
fn address_validation_accepts_canonical_output_and_rejects_malformed_text() {
    let mut encoded = [0u8; MAX_ADDR_LEN];
    let length = encode_p2pk(&[0x42; 32], &mut encoded);
    let valid = &encoded[..length];
    assert!(validate_kaspa_address(valid));

    assert!(!validate_kaspa_address(b""));
    assert!(!validate_kaspa_address(b"kaspa:"));
    for network in [
        KaspaNetwork::Mainnet,
        KaspaNetwork::Testnet,
        KaspaNetwork::Devnet,
        KaspaNetwork::Simnet,
    ] {
        let mut network_address = [0u8; MAX_ADDR_LEN];
        let length = encode_address_for_network(
            &[0x42; 32],
            AddressType::P2pk,
            network,
            &mut network_address,
        );
        assert!(validate_kaspa_address(&network_address[..length]));
        assert!(core::str::from_utf8(&network_address[..length])
            .unwrap()
            .starts_with(network.hrp().unwrap()));
    }
    assert!(!validate_kaspa_address(b"other:qwerty"));

    let mut invalid_character = valid.to_vec();
    invalid_character[10] = b'i';
    assert!(!validate_kaspa_address(&invalid_character));

    let mut invalid_checksum = valid.to_vec();
    let last = invalid_checksum.len() - 1;
    invalid_checksum[last] = if invalid_checksum[last] == b'q' {
        b'p'
    } else {
        b'q'
    };
    assert!(!validate_kaspa_address(&invalid_checksum));

    let mut too_long = valid.to_vec();
    too_long.extend_from_slice(b"qqqqqqqqq");
    assert!(!validate_kaspa_address(&too_long));
}

#[test]
fn network_metadata_maps_names_wire_labels_hrps_and_unknowns() {
    let cases = [
        ("mainnet", KaspaNetwork::Mainnet, 1u8, "MAINNET", "kaspa"),
        (
            "testnet",
            KaspaNetwork::Testnet,
            2u8,
            "TESTNET",
            "kaspatest",
        ),
        (
            "kaspatest",
            KaspaNetwork::Testnet,
            2u8,
            "TESTNET",
            "kaspatest",
        ),
        ("devnet", KaspaNetwork::Devnet, 3u8, "DEVNET", "kaspadev"),
        ("kaspadev", KaspaNetwork::Devnet, 3u8, "DEVNET", "kaspadev"),
        ("simnet", KaspaNetwork::Simnet, 4u8, "SIMNET", "kaspasim"),
        ("kaspasim", KaspaNetwork::Simnet, 4u8, "SIMNET", "kaspasim"),
    ];

    for (name, network, wire, label, hrp) in cases {
        assert_eq!(KaspaNetwork::from_name(name), Some(network));
        assert_eq!(KaspaNetwork::from_wire(wire), Some(network));
        assert_eq!(network.label(), label);
        assert_eq!(network.hrp(), Some(hrp));
        let mut rendered = [0u8; MAX_ADDR_LEN];
        let rendered =
            encode_address_str_for_network(&[0x24; 32], AddressType::P2pk, network, &mut rendered);
        assert!(rendered.starts_with(hrp));
        assert_eq!(rendered.as_bytes()[hrp.len()], b':');
    }

    for testnet_name in ["testnet-10", "testnet-11", "testnet-custom"] {
        assert_eq!(
            KaspaNetwork::from_name(testnet_name),
            Some(KaspaNetwork::Testnet)
        );
    }
    assert_eq!(KaspaNetwork::from_name("MAINNET"), None);
    assert_eq!(KaspaNetwork::from_name("unknown"), None);
    assert_eq!(KaspaNetwork::from_wire(0), None);
    assert_eq!(KaspaNetwork::from_wire(5), None);
    assert_eq!(KaspaNetwork::from_wire(u8::MAX), None);
    assert_eq!(KaspaNetwork::Unknown.hrp(), None);
    assert_eq!(KaspaNetwork::Unknown.label(), "NETWORK UNKNOWN");

    let mut address = [0u8; MAX_ADDR_LEN];
    assert_eq!(
        encode_address_for_network(
            &[0x42; 32],
            AddressType::P2pk,
            KaspaNetwork::Unknown,
            &mut address
        ),
        0,
    );
}

#[test]
fn mainnet_string_helper_matches_network_bound_encoder() {
    let key = [0x35u8; 32];
    let mut default_buf = [0u8; MAX_ADDR_LEN];
    let mut bound_buf = [0u8; MAX_ADDR_LEN];
    let default = encode_address_str(&key, AddressType::P2pk, &mut default_buf);
    let bound = encode_address_str_for_network(
        &key,
        AddressType::P2pk,
        KaspaNetwork::Mainnet,
        &mut bound_buf,
    );
    assert_eq!(default, bound);
    assert!(default.starts_with("kaspa:"));
}

#[test]
fn script_builder_rejects_unknown_address_versions() {
    let encoded = encode_address_text(&[0x55; 32], 0x7f, "kaspa");
    assert!(address_to_script_pubkey(&encoded)
        .unwrap_err()
        .contains("Unknown version"));
}
