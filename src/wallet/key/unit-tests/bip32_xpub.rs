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
