use super::*;

#[test]
fn account_level_xpub_normalizes_to_canonical_payload_version() {
    const XPUB: &[u8] = b"xpub6BtkpE81MZgN8a3jn6A8ZnivpLvZfei6iJm43BeRrqscqPZNJoTzS5LAHvkDPmn2NCiqhs342s78kGiwibgGnpjabYPkCHqLtzd82ATmiF6";
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(
        decode_bip32_xpub(XPUB, &mut payload),
        Ok(ACCOUNT_KEY_PAYLOAD_LEN)
    );
    assert_eq!(payload[..4], ACCOUNT_KEY_VERSION);
    assert_eq!(payload[4], ACCOUNT_KEY_DEPTH);
}

#[test]
fn arbitrary_base58check_payload_is_not_an_xpub() {
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert!(decode_bip32_xpub(b"not-an-xpub", &mut payload).is_err());
}

/// Account key exported by the original hardware-signer release (seed bytes
/// `3i + 17`); `ORIGINAL_PAYLOAD` is its canonical payload.
const ORIGINAL_KPUB: &[u8] = b"kpub2JigDdskmLLjkiA8PVnrGyEaCvwGrzET2X26crHBHDtGZERboYT4SnGXXRc7vyyNgvfuJF2XaFxqQ9uBVpU9FosVzcDhe5nfHyi2CLLzpPm";
const ORIGINAL_PAYLOAD: [u8; ACCOUNT_KEY_PAYLOAD_LEN] = [
    0x03, 0x8f, 0x33, 0x2e, 0x03, 0x8f, 0x43, 0x5e, 0x7f, 0x80, 0x00, 0x00, 0x00, 0x7e, 0x95, 0xe6,
    0x10, 0x9b, 0x69, 0xe2, 0xe5, 0xb5, 0xe5, 0x02, 0x03, 0x16, 0x9f, 0x29, 0x84, 0x29, 0xc7, 0x74,
    0x81, 0xcf, 0xcb, 0x17, 0xb5, 0x53, 0xa4, 0x90, 0xdd, 0xb6, 0x5b, 0x89, 0xe7, 0x03, 0xf6, 0x2a,
    0x46, 0x03, 0xcd, 0x37, 0xd4, 0x06, 0x86, 0xe1, 0xff, 0xb2, 0x54, 0x66, 0xf5, 0x33, 0x0e, 0x4f,
    0xec, 0xc5, 0xea, 0xb5, 0x5f, 0xed, 0x43, 0xda, 0xbc, 0x4c, 0xc7, 0x28, 0x71, 0x8b,
];

#[test]
fn rusty_kaspa_base58_kpub_decodes_to_the_canonical_payload() {
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(
        decode_base58_kpub(ORIGINAL_KPUB, &mut payload),
        Ok(ACCOUNT_KEY_PAYLOAD_LEN)
    );
    assert_eq!(payload, ORIGINAL_PAYLOAD);

    let mut through_any = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    crate::wallet::key::xpub::decode_kpub_or_xpub(ORIGINAL_KPUB, &mut through_any)
        .expect("Base58 kpub through the general account-key import");
    assert_eq!(through_any, ORIGINAL_PAYLOAD);
}

#[test]
fn base58_kpub_and_xpub_versions_are_not_interchangeable() {
    const XPUB: &[u8] = b"xpub6BtkpE81MZgN8a3jn6A8ZnivpLvZfei6iJm43BeRrqscqPZNJoTzS5LAHvkDPmn2NCiqhs342s78kGiwibgGnpjabYPkCHqLtzd82ATmiF6";
    let mut payload = [0x55u8; ACCOUNT_KEY_PAYLOAD_LEN];
    assert_eq!(
        decode_base58_kpub(XPUB, &mut payload),
        Err(Bip32XpubImportError::InvalidPayload)
    );
    assert_eq!(payload, [0u8; ACCOUNT_KEY_PAYLOAD_LEN]);
    assert_eq!(
        decode_bip32_xpub(ORIGINAL_KPUB, &mut payload),
        Err(Bip32XpubImportError::InvalidPayload)
    );
}

#[test]
fn base58_kpub_rejects_corruption_and_overflow() {
    let mut payload = [0u8; ACCOUNT_KEY_PAYLOAD_LEN];
    let mut corrupted = ORIGINAL_KPUB.to_vec();
    let last = corrupted.last_mut().expect("kpub is not empty");
    *last = if *last == b'm' { b'n' } else { b'm' };
    assert_eq!(
        decode_base58_kpub(&corrupted, &mut payload),
        Err(Bip32XpubImportError::InvalidChecksum)
    );
    assert_eq!(
        decode_base58_kpub(b"", &mut payload),
        Err(Bip32XpubImportError::Empty)
    );
    assert_eq!(
        decode_base58_kpub(b"kpub0", &mut payload),
        Err(Bip32XpubImportError::InvalidCharacter)
    );
    assert_eq!(
        decode_base58_kpub(&[b'z'; 300], &mut payload),
        Err(Bip32XpubImportError::Overflow)
    );
}
