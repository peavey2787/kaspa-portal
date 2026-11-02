use super::{encode, encoded_len, parse, MAX_SCRIPT_KEYS};
use alloc::vec;

const A: [u8; 32] = [0x11; 32];
const B: [u8; 32] = [0x22; 32];

#[test]
fn encodes_the_canonical_layout_and_parses_it_back() {
    let mut out = [0u8; 69];
    assert_eq!(encode(1, &[A, B], &mut out), Some(69));
    let mut expected = vec![0x51, 0x20];
    expected.extend_from_slice(&A);
    expected.push(0x20);
    expected.extend_from_slice(&B);
    expected.extend_from_slice(&[0x52, 0xae]);
    assert_eq!(out.as_slice(), expected.as_slice());
    assert_eq!(encoded_len(2), 69);

    let parsed = parse(&out).expect("canonical script");
    assert_eq!((parsed.threshold(), parsed.key_count()), (1, 2));
    assert_eq!(parsed.key(0), Some(A));
    assert_eq!(parsed.key(1), Some(B));
    assert_eq!(parsed.key(2), None);
    assert_eq!(parsed.position_of(&B), Some(1));
    assert_eq!(parsed.position_of(&[0x33; 32]), None);
    assert_eq!(parsed.keys().collect::<alloc::vec::Vec<_>>(), [A, B]);
}

#[test]
fn encoding_rejects_bad_thresholds_counts_and_short_buffers() {
    let mut out = [0u8; 1024];
    assert_eq!(encode(0, &[A], &mut out), None);
    assert_eq!(encode(2, &[A], &mut out), None);
    assert_eq!(encode(1, &[], &mut out), None);
    assert_eq!(encode(1, &[A], &mut out[..35]), None);
    assert_eq!(encode(1, &[A], &mut out[..36]), Some(36));
    let keys = [A; MAX_SCRIPT_KEYS + 1];
    assert_eq!(
        encode(16, &keys[..MAX_SCRIPT_KEYS], &mut out),
        Some(encoded_len(16))
    );
    assert_eq!(out[encoded_len(16) - 2], 0x60);
    assert_eq!(encode(1, &keys, &mut out), None);
}

#[test]
fn parsing_accepts_only_the_exact_canonical_shape() {
    let mut valid = [0u8; 69];
    encode(2, &[A, B], &mut valid).expect("encode");
    assert!(parse(&valid).is_some());
    for (index, value) in [
        (0, 0x00),
        (0, 0x61),
        (0, 0x53),
        (67, 0x00),
        (67, 0x61),
        (68, 0xac),
        (1, 0x21),
        (34, 0x21),
    ] {
        let mut bad = valid;
        bad[index] = value;
        assert_eq!(parse(&bad), None, "byte {index} = {value:#x}");
    }
    assert_eq!(parse(&valid[..68]), None);
    assert_eq!(parse(&[]), None);
    assert_eq!(parse(&[0x51]), None);
    assert_eq!(parse(&[0x51, 0xae]), None);
    let mut extra = valid.to_vec();
    extra.insert(67, 0x00);
    assert_eq!(parse(&extra), None);
}
