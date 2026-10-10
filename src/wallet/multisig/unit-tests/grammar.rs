use super::*;

const N: usize = 5;

fn blank(kind: MultisigDescriptorKind) -> ParsedMultisigDescriptor<N> {
    ParsedMultisigDescriptor {
        threshold: 1,
        participant_count: 0,
        kind,
        static_public_keys: [[0; 32]; N],
        public_keys: [[0; 33]; N],
        chain_codes: [[0; 32]; N],
        depths: [0; N],
        parent_fingerprints: [[0; 4]; N],
        child_numbers: [[0; 4]; N],
    }
}

#[test]
fn kind_predicates_distinguish_all_three_descriptor_kinds() {
    let static_descriptor = blank(MultisigDescriptorKind::Static);
    let hd44 = blank(MultisigDescriptorKind::Hd44);
    let hd45 = blank(MultisigDescriptorKind::Hd45);
    assert!(!static_descriptor.is_hd());
    assert!(!static_descriptor.is_hd45());
    assert!(hd44.is_hd());
    assert!(!hd44.is_hd45());
    assert!(hd45.is_hd());
    assert!(hd45.is_hd45());
}

#[test]
fn threshold_grammar_checks_each_boundary_independently() {
    assert_eq!(
        split_threshold(b",aa"),
        Err(MultisigDescriptorError::InvalidThreshold)
    );
    assert_eq!(
        split_threshold(b"1234,aa"),
        Err(MultisigDescriptorError::InvalidThreshold)
    );
    assert_eq!(
        split_threshold(b"x,aa"),
        Err(MultisigDescriptorError::InvalidThreshold)
    );
    let (threshold, tail) = split_threshold(b"123,aa").expect("three-digit threshold");
    assert_eq!(threshold, 123);
    assert_eq!(tail, b"aa");
}

#[test]
fn trimming_and_hex_decoding_make_progress_and_preserve_exact_bytes() {
    assert_eq!(trim_trailing_ascii_whitespace(b"abc \t\r\n"), b"abc");
    let mut decoded = [0u8; 3];
    decode_hex_bytes(b"0fab10", &mut decoded).expect("hex");
    assert_eq!(decoded, [0x0f, 0xab, 0x10]);
}

#[test]
fn hd45_sort_moves_parallel_metadata_and_handles_equal_neighbors() {
    let mut parsed = blank(MultisigDescriptorKind::Hd45);
    parsed.participant_count = 3;
    parsed.public_keys[0][1] = 30;
    parsed.public_keys[1][1] = 20;
    parsed.public_keys[2][1] = 10;
    parsed.chain_codes[0][0] = 3;
    parsed.chain_codes[1][0] = 2;
    parsed.chain_codes[2][0] = 1;
    parsed.depths[0] = 30;
    parsed.depths[1] = 20;
    parsed.depths[2] = 10;
    parsed.parent_fingerprints[0][0] = 3;
    parsed.parent_fingerprints[1][0] = 2;
    parsed.parent_fingerprints[2][0] = 1;
    parsed.child_numbers[0][0] = 3;
    parsed.child_numbers[1][0] = 2;
    parsed.child_numbers[2][0] = 1;
    let mut encoded = [[0u8; HD45_KPUB_LEN]; N];
    encoded[0][0] = 3;
    encoded[1][0] = 2;
    encoded[2][0] = 1;
    sort_hd45_by_encoded(&mut parsed, &mut encoded);
    assert_eq!([encoded[0][0], encoded[1][0], encoded[2][0]], [1, 2, 3]);
    assert_eq!(
        [
            parsed.public_keys[0][1],
            parsed.public_keys[1][1],
            parsed.public_keys[2][1]
        ],
        [10, 20, 30]
    );
    assert_eq!(
        [
            parsed.chain_codes[0][0],
            parsed.chain_codes[1][0],
            parsed.chain_codes[2][0]
        ],
        [1, 2, 3]
    );
    assert_eq!(
        [parsed.depths[0], parsed.depths[1], parsed.depths[2]],
        [10, 20, 30]
    );
    assert_eq!(
        [
            parsed.parent_fingerprints[0][0],
            parsed.parent_fingerprints[1][0],
            parsed.parent_fingerprints[2][0],
        ],
        [1, 2, 3],
    );
    assert_eq!(
        [
            parsed.child_numbers[0][0],
            parsed.child_numbers[1][0],
            parsed.child_numbers[2][0],
        ],
        [1, 2, 3],
    );

    encoded[0] = [7; HD45_KPUB_LEN];
    encoded[1] = [7; HD45_KPUB_LEN];
    parsed.participant_count = 2;
    parsed.public_keys[0][1] = 10;
    parsed.public_keys[1][1] = 20;
    sort_hd45_by_encoded(&mut parsed, &mut encoded);
    assert_eq!(encoded[0], encoded[1]);
    assert_eq!(
        [parsed.public_keys[0][1], parsed.public_keys[1][1]],
        [10, 20],
        "equal encoded participants must keep canonical stable order",
    );
}

#[test]
fn duplicate_hd_requires_both_pubkey_and_chain_code_to_match() {
    let mut parsed = blank(MultisigDescriptorKind::Hd44);
    parsed.participant_count = 2;
    parsed.public_keys[0][0] = 2;
    parsed.public_keys[1][0] = 2;
    parsed.chain_codes[0][0] = 1;
    parsed.chain_codes[1][0] = 2;
    assert_eq!(reject_duplicate_hd(&parsed), Ok(()));

    parsed.public_keys[1][0] = 3;
    parsed.chain_codes[1][0] = 1;
    assert_eq!(reject_duplicate_hd(&parsed), Ok(()));

    parsed.public_keys[1] = parsed.public_keys[0];
    parsed.chain_codes[1] = parsed.chain_codes[0];
    assert_eq!(
        reject_duplicate_hd(&parsed),
        Err(MultisigDescriptorError::DuplicateParticipant)
    );
}

fn hd44_participant(prefix: u8, fill: u8) -> String {
    let mut raw = [fill; 65];
    raw[0] = prefix;
    hex::encode(raw)
}

#[test]
fn canonical_multisig_parser_covers_static_and_hd44_without_heap_owned_grammar() {
    let static_a = "11".repeat(32);
    let static_b = "22".repeat(32);
    let parsed =
        parse_multisig_descriptor::<N>(format!("multi(1,{static_a},{static_b})").as_bytes())
            .expect("static descriptor");
    assert_eq!(parsed.kind, MultisigDescriptorKind::Static);
    assert_eq!(parsed.participant_count, 2);

    let first = hd44_participant(0x02, 0x31);
    let second = hd44_participant(0x03, 0x52);
    let parsed = parse_multisig_descriptor::<N>(
        format!("# exported descriptor\n  multi_hd(2,{first},{second})\r\n").as_bytes(),
    )
    .expect("HD44 descriptor");
    assert_eq!(parsed.kind, MultisigDescriptorKind::Hd44);
    assert_eq!(parsed.threshold, 2);
    assert_eq!(parsed.public_keys[0][0], 0x02);
    assert_eq!(parsed.public_keys[1][0], 0x03);
}

#[test]
fn canonical_multisig_parser_enforces_bounds_thresholds_and_duplicates() {
    let first = hd44_participant(0x02, 0x31);
    let second = hd44_participant(0x03, 0x52);
    assert_eq!(
        parse_multisig_descriptor::<N>(format!("multi_hd(0,{first},{second})").as_bytes()),
        Err(MultisigDescriptorError::InvalidThreshold),
    );
    assert_eq!(
        parse_multisig_descriptor::<N>(format!("multi_hd(1,{first},{first})").as_bytes()),
        Err(MultisigDescriptorError::DuplicateParticipant),
    );

    let entries = (0..=N)
        .map(|index| {
            hd44_participant(
                if index.is_multiple_of(2) { 0x02 } else { 0x03 },
                index as u8 + 1,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        parse_multisig_descriptor::<N>(format!("multi_hd(1,{entries})").as_bytes()),
        Err(MultisigDescriptorError::TooManyParticipants),
    );
}

#[test]
fn canonical_hd45_order_is_identical_for_unsorted_and_sorted_kpub_text() {
    const FIRST: &str = "kpub1:038f332e03405ab68380000000f0453f0894cc8c84ebf6e6208e0c7916e9ddbd14919f9bbb92b0690b4e353392020327c7136972883eab5a7722ec3d4302f888804ecce61658ae962a2c56bb7571";
    const SECOND: &str = "kpub1:038f332e03a7457270800000002908be01d75735944f29befbdbcd173ab00df2d44c6d5ab51a839413fda90cbf035b986b584de244f5d6a1939192f676a9f2992a63b0f43cdc452dcb40d9dd7081";
    let unsorted = format!("multi_hd45(1,{SECOND},{FIRST})");
    let sorted = format!("multi_hd45(1,{FIRST},{SECOND})");
    let left = parse_multisig_descriptor::<N>(unsorted.as_bytes()).expect("unsorted HD45");
    let right = parse_multisig_descriptor::<N>(sorted.as_bytes()).expect("sorted HD45");
    assert_eq!(left.kind, MultisigDescriptorKind::Hd45);
    assert_eq!(left, right);
}

#[test]
fn multisig_descriptor_error_messages_cover_every_stable_variant_without_branching() {
    let errors = [
        MultisigDescriptorError::UnsupportedFormat,
        MultisigDescriptorError::InvalidThreshold,
        MultisigDescriptorError::TooFewParticipants,
        MultisigDescriptorError::TooManyParticipants,
        MultisigDescriptorError::InvalidParticipantLength,
        MultisigDescriptorError::InvalidHex,
        MultisigDescriptorError::InvalidCompressedPublicKey,
        MultisigDescriptorError::InvalidKpub,
        MultisigDescriptorError::InvalidKpubDepth,
        MultisigDescriptorError::DuplicateParticipant,
    ];
    for error in errors {
        assert!(!error.message().is_empty());
    }
    assert_eq!(errors.len(), 10);
}

#[test]
fn canonical_multisig_parser_covers_static_format_length_hex_and_threshold_failures() {
    let key = "11".repeat(32);
    assert_eq!(
        parse_multisig_descriptor::<N>(b"not-a-descriptor"),
        Err(MultisigDescriptorError::UnsupportedFormat),
    );
    assert_eq!(
        parse_multisig_descriptor::<N>(format!("multi(1,{})", "11".repeat(31)).as_bytes()),
        Err(MultisigDescriptorError::InvalidParticipantLength),
    );
    let invalid_hex_key = format!("{}2z", "22".repeat(31));
    assert_eq!(
        parse_multisig_descriptor::<N>(format!("multi(1,{key},{invalid_hex_key})").as_bytes()),
        Err(MultisigDescriptorError::InvalidHex),
    );
    assert_eq!(
        parse_multisig_descriptor::<N>(format!("multi(3,{key},{})", "22".repeat(32)).as_bytes()),
        Err(MultisigDescriptorError::InvalidThreshold),
    );
}
