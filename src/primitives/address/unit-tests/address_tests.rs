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

#[test]
fn decode_address_accepts_only_p2pk_and_p2sh_versions() {
    for version in 0u8..=255 {
        let address = encode_address_bytes(&[0x42; 32], version, "kaspa");
        let decoded = decode_address(&address);
        if matches!(version, 0x00 | 0x08) {
            assert_eq!(decoded, Ok((version, [0x42; 32])));
        } else {
            assert!(decoded.is_err(), "version {version:#x} must be rejected");
        }
    }
}

#[test]
fn only_defined_versions_with_their_exact_lengths_are_addresses() {
    for (version, length) in [(0x00, 32), (0x01, 33), (0x08, 32)] {
        let valid = encode_address_bytes(&vec![0x42; length], version, "kaspa");
        assert!(validate_kaspa_address(valid.as_bytes()), "{version:#x}");
        for wrong in [length - 1, length + 1] {
            let address = encode_address_bytes(&vec![0x42; wrong], version, "kaspa");
            assert!(!validate_kaspa_address(address.as_bytes()));
        }
    }
    for version in [0x02, 0x07, 0x09, 0xff] {
        let address = encode_address_bytes(&[0x42; 32], version, "kaspa");
        assert!(!validate_kaspa_address(address.as_bytes()), "{version:#x}");
    }
    let ecdsa = encode_address_bytes(&[0x42; 33], 0x01, "kaspa");
    assert!(address_to_script_pubkey(&ecdsa)
        .unwrap_err()
        .contains("Unsupported script version"));
}

#[test]
fn the_longest_address_fits_the_output_buffer() {
    let mut out = [0u8; MAX_ADDR_LEN];
    let length = encode_address_for_network(
        &[0x42; 33],
        AddressType::P2pkEcdsa,
        KaspaNetwork::Testnet,
        &mut out,
    );
    assert_eq!(length, 73);
    assert_eq!(
        encode_address_for_network(
            &[0x42; 32],
            AddressType::P2pkEcdsa,
            KaspaNetwork::Testnet,
            &mut out
        ),
        0
    );
}

#[test]
fn convert_bits_pads_only_a_partial_final_group() {
    // 40 bits regroup exactly into 8 five-bit groups: no padding group.
    assert_eq!(convert_bits(&[0xff; 5], 8, 5, true).unwrap(), vec![31; 8]);
    // 8 bits leave 3 bits, padded with two zero bits: 0b111_00.
    assert_eq!(convert_bits(&[0xff], 8, 5, true).unwrap(), vec![31, 28]);
    // 16 bits leave 1 bit, padded with four zero bits: 0b1_0000.
    assert_eq!(
        convert_bits(&[0xff, 0xff], 8, 5, true).unwrap(),
        vec![31, 31, 31, 16]
    );
}

#[test]
fn convert_bits_rejects_out_of_range_values_and_bad_padding() {
    assert_eq!(convert_bits(&[31, 28], 5, 8, false).unwrap(), vec![0xff]);
    assert!(convert_bits(&[32], 5, 8, false).is_err());
    // Non-zero padding bits.
    assert!(convert_bits(&[31, 29], 5, 8, false).is_err());
    // A whole spare input group (5 leftover bits) is not padding.
    assert!(convert_bits(&[31, 28, 0], 5, 8, false).is_err());
    // 4 leftover zero bits are valid padding.
    assert_eq!(
        convert_bits(&[31, 31, 31, 16], 5, 8, false).unwrap(),
        vec![0xff, 0xff]
    );
    assert!(convert_bits(&[31, 31, 31, 24], 5, 8, false).is_err());
}

#[test]
fn polymod_matches_reference_values() {
    assert_eq!(polymod([].into_iter()), 1);
    assert_eq!(polymod([0u8].into_iter()), 32);
    assert_eq!(polymod([31u8].into_iter()), 63);
}
