use super::{unwrap_v1_raw, wrap_v1_raw, MAX_RAW_LEN, PAYLOAD_V1_RAW};
use alloc::vec;

#[test]
fn unwrap_requires_the_v1_header_and_a_body() {
    assert_eq!(unwrap_v1_raw(&[PAYLOAD_V1_RAW, 7, 8]), Some(&[7, 8][..]));
    assert_eq!(unwrap_v1_raw(&[PAYLOAD_V1_RAW]), None);
    assert_eq!(unwrap_v1_raw(&[]), None);
    assert_eq!(unwrap_v1_raw(&[0x02, 7]), None);
}

#[test]
fn wrap_accepts_one_to_max_bytes_into_a_large_enough_buffer() {
    let mut out = vec![0u8; MAX_RAW_LEN + 2];
    assert_eq!(wrap_v1_raw(&[], &mut out), None);
    assert_eq!(wrap_v1_raw(&[9], &mut out), Some(2));
    assert_eq!(&out[..2], &[PAYLOAD_V1_RAW, 9]);
    let max = vec![0x5a; MAX_RAW_LEN];
    assert_eq!(wrap_v1_raw(&max, &mut out), Some(MAX_RAW_LEN + 1));
    assert_eq!(wrap_v1_raw(&vec![0x5a; MAX_RAW_LEN + 1], &mut out), None);

    let mut exact = [0u8; 3];
    assert_eq!(wrap_v1_raw(&[1, 2], &mut exact), Some(3));
    assert_eq!(exact, [PAYLOAD_V1_RAW, 1, 2]);
    let mut short = [0u8; 2];
    assert_eq!(wrap_v1_raw(&[1, 2], &mut short), None);
    assert_eq!(short, [0, 0]);
}
