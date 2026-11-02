use crate::network::codec::responses::utxo;

#[test]
fn short_utxo_response_is_an_error_not_an_empty_set() {
    crate::test_support::assert_err(&utxo::decode(&[]), "TruncatedPayload");
    crate::test_support::assert_err(&utxo::decode(&[1, 0, 0]), "TruncatedPayload");
}

#[test]
fn malformed_utxo_wrapper_is_rejected() {
    crate::test_support::assert_err(&utxo::decode(&[1, 1, 0, 0, 0, 0]), "TruncatedPayload");
}

#[test]
fn utxo_response_vector_is_stable() {
    let bytes = hex::decode(concat!(
        "0177000000010071000000010000006900000001002500000001",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "030000003a000000020400000000000000000001000000510500000000000000",
        "00013333333333333333333333333333333333333333333333333333333333333333"
    ))
    .expect("fixture hex should decode");
    let entries = utxo::decode(&bytes).expect("UTXO response should decode");

    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.tx_id, "22".repeat(32));
    assert_eq!(entry.index, 3);
    assert_eq!(entry.amount, 4);
    assert_eq!(entry.script_public_key, [0x51]);
    assert_eq!(entry.block_daa_score, 5);
    let expected_covenant_id = "33".repeat(32);
    assert_eq!(
        entry.covenant_id.as_deref(),
        Some(expected_covenant_id.as_str())
    );
}

fn bytes_field(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn wrap_entries(entries_blob: &[u8]) -> Vec<u8> {
    let mut outer = 1u16.to_le_bytes().to_vec();
    outer.extend_from_slice(&bytes_field(entries_blob));
    let mut response = vec![1];
    response.extend_from_slice(&bytes_field(&outer));
    response
}

fn encoded_entry(
    optional_tag: u8,
    outpoint_len: usize,
    version: u8,
    covenant_tag: Option<u8>,
) -> Vec<u8> {
    let mut entry = vec![0, optional_tag];
    if optional_tag == 1 {
        entry.extend_from_slice(&[0, 0]);
        entry.extend_from_slice(&bytes_field(&[]));
    }
    let mut outpoint = vec![0; outpoint_len];
    if outpoint_len >= 37 {
        outpoint[1..33].fill(0x22);
        outpoint[33..37].copy_from_slice(&3u32.to_le_bytes());
    }
    entry.extend_from_slice(&bytes_field(&outpoint));

    let mut utxo = vec![version];
    utxo.extend_from_slice(&4u64.to_le_bytes());
    utxo.extend_from_slice(&0u16.to_le_bytes());
    utxo.extend_from_slice(&bytes_field(&[0x51]));
    utxo.extend_from_slice(&5u64.to_le_bytes());
    utxo.push(0);
    if let Some(tag) = covenant_tag {
        utxo.push(tag);
        if tag == 1 {
            utxo.extend_from_slice(&[0x33; 32]);
        }
    }
    entry.extend_from_slice(&bytes_field(&utxo));
    entry
}

fn one_entry_response(entry: &[u8]) -> Vec<u8> {
    let mut entries = 1u32.to_le_bytes().to_vec();
    entries.extend_from_slice(&bytes_field(entry));
    wrap_entries(&entries)
}

fn repeated_entry_response(entry: &[u8], count: u32) -> Vec<u8> {
    let mut entries = count.to_le_bytes().to_vec();
    for _ in 0..count {
        entries.extend_from_slice(&bytes_field(entry));
    }
    wrap_entries(&entries)
}

#[test]
fn utxo_response_preserves_every_entry_in_multi_entry_reply() {
    let response = repeated_entry_response(&encoded_entry(0, 37, 1, None), 5);
    let entries = utxo::decode(&response).expect("multi-entry UTXO response should decode");
    assert_eq!(entries.len(), 5);
}

#[test]
fn utxo_response_covers_empty_count_limit_optional_and_outpoint_boundaries() {
    assert!(utxo::decode(&wrap_entries(&0u32.to_le_bytes()))
        .unwrap()
        .is_empty());
    crate::test_support::assert_err(&utxo::decode(&wrap_entries(&[])), "TruncatedPayload");

    let too_many = (1_000_001u32).to_le_bytes();
    crate::test_support::assert_err(&utxo::decode(&wrap_entries(&too_many)), "InvalidLength");

    let no_optional = one_entry_response(&encoded_entry(0, 37, 1, None));
    let entries = utxo::decode(&no_optional).expect("entry without optional envelope");
    assert_eq!(entries.len(), 1);
    assert!(entries[0].covenant_id.is_none());

    let short_outpoint = one_entry_response(&encoded_entry(0, 36, 1, None));
    crate::test_support::assert_err(
        &utxo::decode(&short_outpoint),
        r#"InvalidEncoding("entry 0: outpoint 36 bytes")"#,
    );
    let long_outpoint = one_entry_response(&encoded_entry(0, 38, 1, None));
    crate::test_support::assert_err(
        &utxo::decode(&long_outpoint),
        r#"InvalidEncoding("entry 0: outpoint 38 bytes")"#,
    );
}

#[test]
fn utxo_with_a_script_version_the_builder_cannot_sign_is_refused() {
    // marker/tag (2) + outpoint field (4 + 37) + utxo length (4)
    // + entry version (1) + amount (8)
    const SCRIPT_VERSION_OFFSET: usize = 56;
    let mut entry = encoded_entry(0, 37, 1, None);
    assert_eq!(
        entry[SCRIPT_VERSION_OFFSET..SCRIPT_VERSION_OFFSET + 2],
        [0, 0]
    );
    entry[SCRIPT_VERSION_OFFSET] = 1;
    crate::test_support::assert_err(
        &utxo::decode(&one_entry_response(&entry)),
        r#"InvalidEncoding("entry 0: script version 1 is not spendable")"#,
    );
}

#[test]
fn utxo_response_rejects_a_missing_marker_and_trailing_bytes() {
    let mut unmarked = one_entry_response(&encoded_entry(0, 37, 1, None));
    unmarked[0] = 0;
    crate::test_support::assert_err(
        &utxo::decode(&unmarked),
        r#"InvalidEncoding("GetUtxosByAddressesResponse is missing its payload marker")"#,
    );

    let mut padded = one_entry_response(&encoded_entry(0, 37, 1, None));
    padded.push(0);
    crate::test_support::assert_err(
        &utxo::decode(&padded),
        r#"InvalidEncoding("trailing bytes after GetUtxosByAddressesResponse")"#,
    );

    let mut entries = 1u32.to_le_bytes().to_vec();
    entries.extend_from_slice(&bytes_field(&encoded_entry(0, 37, 1, None)));
    entries.push(0);
    crate::test_support::assert_err(
        &utxo::decode(&wrap_entries(&entries)),
        r#"InvalidEncoding("trailing bytes after UTXO entry list")"#,
    );
}

#[test]
fn utxo_response_skips_present_optional_metadata_and_rejects_truncation() {
    let with_metadata = one_entry_response(&encoded_entry(1, 37, 2, Some(1)));
    let entries = utxo::decode(&with_metadata).expect("entry with optional metadata");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].tx_id, "22".repeat(32));
    let expected_covenant_id = "33".repeat(32);
    assert_eq!(
        entries[0].covenant_id.as_deref(),
        Some(expected_covenant_id.as_str())
    );

    let truncated_metadata = one_entry_response(&[0, 1, 0, 0, 4, 0, 0, 0, 0xaa]);
    crate::test_support::assert_err(&utxo::decode(&truncated_metadata), "TruncatedPayload");
}

#[test]
fn utxo_response_covers_both_covenant_version_short_circuit_paths() {
    let version_one = one_entry_response(&encoded_entry(0, 37, 1, None));
    assert!(utxo::decode(&version_one).unwrap()[0].covenant_id.is_none());

    let version_two_without_covenant = one_entry_response(&encoded_entry(0, 37, 2, Some(0)));
    assert!(utxo::decode(&version_two_without_covenant).unwrap()[0]
        .covenant_id
        .is_none());
}

#[test]
fn utxo_entry_count_limit_is_inclusive() {
    use crate::network::error::NetworkError;

    // At the limit the count is accepted and decoding stops at the missing entry.
    let at_limit = utxo::decode(&wrap_entries(&1_000_000u32.to_le_bytes())).unwrap_err();
    assert!(
        !matches!(at_limit, NetworkError::InvalidLength),
        "{at_limit:?}"
    );
    let over = utxo::decode(&wrap_entries(&1_000_001u32.to_le_bytes())).unwrap_err();
    assert!(matches!(over, NetworkError::InvalidLength), "{over:?}");
}
