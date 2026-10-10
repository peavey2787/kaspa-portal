use super::{push_data_item, push_redeem_script};

#[test]
fn data_pushes_are_byte_exact_at_every_prefix_boundary() {
    for (length, prefix) in [
        (0usize, vec![0x00]),
        (1, vec![0x01]),
        (75, vec![0x4b]),
        (76, vec![0x4c, 0x4c]),
        (255, vec![0x4c, 0xff]),
        (256, vec![0x4d, 0x00, 0x01]),
        (65_535, vec![0x4d, 0xff, 0xff]),
    ] {
        let payload = vec![0xa5; length];
        let mut script = Vec::new();
        push_data_item(&mut script, &payload).expect("push");
        assert_eq!(
            &script[..prefix.len()],
            prefix.as_slice(),
            "length {length}"
        );
        assert_eq!(
            &script[prefix.len()..],
            payload.as_slice(),
            "length {length}"
        );
    }
}

#[test]
fn oversized_pushes_and_redeem_scripts_are_refused() {
    assert_eq!(
        push_data_item(&mut Vec::new(), &vec![0; 65_536]),
        Err("data item too large".to_string())
    );
    assert_eq!(
        push_redeem_script(&mut Vec::new(), &vec![0; 65_536]),
        Err("redeem script too large".to_string())
    );
    let mut redeem = Vec::new();
    push_redeem_script(&mut redeem, &[0x51]).expect("small redeem");
    assert_eq!(redeem, [0x01, 0x51]);
}
