use super::{elements, read_element, Element};

#[test]
fn every_push_width_and_plain_opcode_reads_exactly() {
    let element = |opcode, data: &'static [u8]| Element { opcode, data };
    assert_eq!(read_element(&[0x00], 0), Some((element(0x00, &[]), 1)));
    assert_eq!(
        read_element(&[0x02, 7, 8, 9], 0),
        Some((element(0x02, &[7, 8]), 3))
    );
    assert_eq!(
        read_element(&[0x4c, 2, 7, 8], 0),
        Some((element(0x4c, &[7, 8]), 4))
    );
    assert_eq!(
        read_element(&[0x4d, 2, 0, 7, 8], 0),
        Some((element(0x4d, &[7, 8]), 5))
    );
    assert_eq!(
        read_element(&[0x4e, 2, 0, 0, 0, 7, 8], 0),
        Some((element(0x4e, &[7, 8]), 7))
    );
    assert_eq!(
        read_element(&[0x51, 0xac], 1),
        Some((element(0xac, &[]), 2))
    );
    assert_eq!(read_element(&[0x4c, 0], 0), Some((element(0x4c, &[]), 2)));
}

#[test]
fn truncated_pushes_and_out_of_range_offsets_are_refused() {
    for script in [
        &[][..],
        &[0x02, 7],
        &[0x4c],
        &[0x4c, 1],
        &[0x4d, 1],
        &[0x4d, 1, 0],
        &[0x4e, 1, 0, 0],
        &[0x4e, 1, 0, 0, 0],
    ] {
        assert_eq!(read_element(script, 0), None, "{script:02x?}");
    }
    assert_eq!(read_element(&[0x51], 1), None);
}

#[test]
fn push_classification_covers_op_0_through_pushdata4() {
    let push = |opcode| Element { opcode, data: &[] }.is_push();
    assert!(push(0x00) && push(0x4b) && push(0x4e));
    assert!(!push(0x4f) && !push(0x51) && !push(0xac));
}

#[test]
fn elements_walk_a_script_and_report_malformed_tails() {
    let script = [0x51, 0x02, 7, 8, 0xac];
    let mut walker = elements(&script);
    assert!(!walker.is_complete());
    let opcodes = walker
        .by_ref()
        .map(|element| element.opcode)
        .collect::<alloc::vec::Vec<_>>();
    assert_eq!(opcodes, [0x51, 0x02, 0xac]);
    assert!(walker.is_complete());

    let mut truncated = elements(&[0x51, 0x02, 7]);
    assert_eq!(truncated.next().map(|element| element.opcode), Some(0x51));
    assert_eq!(truncated.next(), None);
    assert!(!truncated.is_complete());
    assert_eq!(truncated.next(), None);
    assert!(elements(&[]).is_complete());
}
