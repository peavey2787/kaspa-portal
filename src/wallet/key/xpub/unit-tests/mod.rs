use super::*;
use crate::self_test::xpub::run_xpub_tests;
#[cfg(test)]
use crate::wallet::derivation::bip32::Bip32Error;
use crate::wallet::key::account::{ACCOUNT_KEY_CHILD_INDEX, ACCOUNT_KEY_VERSION};

// ─── Self-Tests ───────────────────────────────────────────────────────

#[test]
fn xpub_vectors_pass() {
    let (passed, total) = run_xpub_tests();
    assert_eq!(passed, total);
}

#[test]
fn canonical_kpub_wrappers_and_binary_qr_import_are_covered() {
    let seed = [0x42u8; 64];
    let account = crate::wallet::derivation::bip32::derive_account_key(&seed).expect("account");
    let mut text = [0u8; KPUB_MAX_LEN];
    let text_len =
        serialize_account_kpub(&account, [1, 2, 3, 4], &mut text).expect("canonical account kpub");

    let mut decoded = [0u8; XPUB_PAYLOAD_LEN];
    assert_eq!(
        decode_kpub_text(&text[..text_len], &mut decoded),
        Ok(XPUB_PAYLOAD_LEN)
    );
    let mut decoded_alias = [0u8; XPUB_PAYLOAD_LEN];
    assert_eq!(
        kpub_text_to_raw(&text[..text_len], &mut decoded_alias),
        Ok(XPUB_PAYLOAD_LEN)
    );
    assert_eq!(decoded_alias, decoded);

    let mut framed = [0u8; XPUB_PAYLOAD_LEN + 1];
    let framed_len = crate::primitives::qr_payload::wrap_v1_raw(&decoded, &mut framed)
        .expect("binary QR envelope");
    let imported = import_kpub_qr(&framed[..framed_len]).expect("QR account key");
    assert_eq!(imported.chain_code, *account.chain_code_bytes());
    assert_eq!(imported.pubkey, account.public_key_compressed().unwrap());

    assert!(decode_kpub_text(b"not-a-kpub", &mut decoded).is_err());
    assert!(kpub_text_to_raw(b"not-a-kpub", &mut decoded).is_err());
    assert!(import_kpub_qr(&[]).is_err());
    assert!(import_kpub_qr(&[crate::primitives::qr_payload::PAYLOAD_V1_RAW]).is_err());
}

#[test]
fn account_xprv_public_wrappers_and_invalid_import_are_covered() {
    let seed = [0x24u8; 64];
    let account = crate::wallet::derivation::bip32::derive_account_key(&seed).expect("account key");
    let mut text = [0u8; XPRV_MAX_LEN];
    let length =
        serialize_account_key_xprv(&account, [9, 8, 7, 6], &mut text).expect("account xprv");

    let imported = import_xprv(&text[..length]).expect("imported xprv");
    assert_eq!(imported.private_key_bytes(), account.private_key_bytes());
    assert_eq!(imported.chain_code_bytes(), account.chain_code_bytes());
    assert_eq!(imported.depth, account.depth);

    assert!(import_xprv(b"not-an-xprv").is_err());
    let mut shallow =
        crate::wallet::derivation::bip32::ExtendedPrivKey::from_parts([1u8; 32], [2u8; 32], 2);
    assert!(serialize_account_key_xprv(&shallow, [0; 4], &mut text).is_err());
    shallow.depth = 3;
    assert!(serialize_account_key_xprv(&shallow, [0; 4], &mut text).is_ok());
}

#[test]
fn base58check_roundtrips_boundary_payloads_and_rejects_corruption() {
    for payload in [
        &[0u8][..],
        &[0, 0, 1][..],
        b"kaspa-portal Base58Check",
        &[0x55u8; XPUB_PAYLOAD_LEN][..],
    ] {
        let mut encoded = [0u8; 192];
        let encoded_len = base58check_encode(payload, &mut encoded);
        assert!(encoded_len > 0);

        let mut decoded = [0u8; 128];
        let decoded_len = base58check_decode(&encoded[..encoded_len], &mut decoded);
        assert_eq!(decoded_len, payload.len());
        assert_eq!(&decoded[..decoded_len], payload);
    }

    let mut decoded = [0x55u8; 128];
    assert_eq!(base58check_decode(b"", &mut decoded), 0);
    assert_eq!(base58check_decode(b"1", &mut decoded), 0);
    assert_eq!(base58check_decode(b"0OIl", &mut decoded), 0);

    let mut encoded = [0u8; 192];
    let encoded_len = base58check_encode(b"checksum", &mut encoded);
    encoded[encoded_len - 1] = if encoded[encoded_len - 1] == b'1' {
        b'2'
    } else {
        b'1'
    };
    assert_eq!(base58check_decode(&encoded[..encoded_len], &mut decoded), 0);
}

#[test]
fn base58_encoding_respects_output_capacity_and_leading_zeroes() {
    let mut empty = [];
    assert_eq!(base58_encode(b"nonempty", &mut empty), 0);

    let mut one = [0u8; 1];
    assert_eq!(base58_encode(&[0, 0, 1], &mut one), 1);
    assert_eq!(one, [b'1']);

    let mut exact = [0u8; 3];
    assert_eq!(base58_encode(&[0, 0, 1], &mut exact), 3);
    assert_eq!(&exact, b"112");
}

#[test]
fn account_xprv_import_rejects_each_metadata_boundary_with_valid_checksum() {
    let seed = [0x36u8; 64];
    let mut text = [0u8; XPRV_MAX_LEN];
    let length = derive_and_serialize_xprv(&seed, &mut text).expect("account xprv");
    let mut decoded = [0u8; 128];
    let decoded_len = base58check_decode(&text[..length], &mut decoded);
    assert_eq!(decoded_len, XPUB_PAYLOAD_LEN);

    for (offset, replacement) in [
        (0usize, decoded[0] ^ 1),
        (4, 2),
        (9, decoded[9] ^ 1),
        (45, 1),
    ] {
        let mut payload = [0u8; XPUB_PAYLOAD_LEN];
        payload.copy_from_slice(&decoded[..XPUB_PAYLOAD_LEN]);
        payload[offset] = replacement;
        let mut invalid = [0u8; XPRV_MAX_LEN];
        let invalid_len = base58check_encode(&payload, &mut invalid);
        assert!(invalid_len > 0, "offset {offset}");
        assert!(
            import_xprv_with_metadata(&invalid[..invalid_len]).is_err(),
            "offset {offset}"
        );
    }
}

#[test]
fn kpub_and_xpub_import_boundaries_are_explicit() {
    let seed = [0x51u8; 64];
    let account = crate::wallet::derivation::bip32::derive_account_key(&seed).expect("account");
    let parent = crate::wallet::derivation::bip32::derive_path(&seed, &[0x8000_002c, 0x8001_b207])
        .expect("parent")
        .public_key_compressed()
        .expect("parent pubkey");
    let mut text = [0u8; KPUB_MAX_LEN];
    assert!(serialize_kpub(
        &account,
        &parent,
        ACCOUNT_KEY_CHILD_INDEX.wrapping_add(1),
        &mut text,
    )
    .is_err());

    let length = serialize_kpub(&account, &parent, ACCOUNT_KEY_CHILD_INDEX, &mut text)
        .expect("canonical kpub");
    let mut decoded = [0u8; XPUB_PAYLOAD_LEN];
    assert_eq!(
        decode_kpub_or_xpub(&text[..length], &mut decoded),
        Ok(XPUB_PAYLOAD_LEN)
    );
    assert!(decode_kpub_or_xpub(b"not-a-kpub", &mut decoded).is_err());
    assert!(import_kpub_raw(&[0u8; XPUB_PAYLOAD_LEN]).is_err());
}

#[test]
fn base58_extreme_lengths_and_each_checksum_byte_are_rejected() {
    let mut encoded = [0u8; 512];
    let mut decoded = [0u8; 128];

    // A full 128-byte non-zero integer cannot be represented in the fixed
    // 128-character encoder scratch space and must fail closed.
    assert_eq!(base58_encode(&[0xff; 128], &mut encoded), 0);
    // Excessively long Base58 input must not overrun the fixed decode integer.
    assert_eq!(base58check_decode(&[b'z'; 300], &mut decoded), 0);

    let payload = b"checksum-stage";
    let checksum = sha256d(payload);
    for checksum_index in 0..4 {
        let mut raw = [0u8; 32];
        raw[..payload.len()].copy_from_slice(payload);
        raw[payload.len()..payload.len() + 4].copy_from_slice(&checksum[..4]);
        raw[payload.len() + checksum_index] ^= 1;
        let encoded_len = base58_encode(&raw[..payload.len() + 4], &mut encoded);
        assert!(encoded_len > 0);
        assert_eq!(base58check_decode(&encoded[..encoded_len], &mut decoded), 0);
    }
}

#[test]
fn multisig_account_parts_export_canonical_kpub() {
    let seed = [0x63u8; 64];
    let parts = derive_multisig_account_parts(&seed, 0).expect("45' account parts");
    assert_eq!(parts.depth, 3);
    assert_eq!(u32::from_be_bytes(parts.child_num), 0x8000_0000);
    assert!(matches!(parts.pubkey[0], 0x02 | 0x03));
    assert!(matches!(
        derive_multisig_account_parts(&seed, 0x8000_0000),
        Err(Bip32Error::InvalidKey)
    ));

    let mut encoded = [0u8; KPUB_MAX_LEN];
    let length =
        derive_and_serialize_multisig_kpub(&seed, &mut encoded).expect("45' canonical kpub");
    assert_eq!(length, KPUB_MAX_LEN);
    assert!(encoded.starts_with(KPUB_TEXT_PREFIX));
    let decoded = parse_kpub_parts(&encoded[..length]).expect("round-trip 45' parts");
    assert_eq!(decoded, parts);
}

#[test]
fn multisig_account_parts_nonzero_child_number_is_hardened() {
    let parts = derive_multisig_account_parts(&[0x6eu8; 64], 9).expect("45' account 9 parts");
    assert_eq!(parts.child_num, 0x8000_0009u32.to_be_bytes());
}

#[test]
fn payload_parser_requires_version_and_compressed_prefix_independently() {
    let mut payload = [0u8; XPUB_PAYLOAD_LEN];
    payload[..4].copy_from_slice(&ACCOUNT_KEY_VERSION);
    payload[45] = 0x02;
    assert!(kpub::parts_from_payload(&payload).is_some());

    let mut bad_version = payload;
    bad_version[0] ^= 0x01;
    assert!(kpub::parts_from_payload(&bad_version).is_none());

    let mut bad_prefix = payload;
    bad_prefix[45] = 0x04;
    assert!(kpub::parts_from_payload(&bad_prefix).is_none());

    payload[45] = 0x03;
    assert!(kpub::parts_from_payload(&payload).is_some());
}
