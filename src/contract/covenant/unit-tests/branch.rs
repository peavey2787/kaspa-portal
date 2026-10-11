use alloc::vec::Vec;

use crate::contract::covenant::branch::{resolve_covenant_branches, BranchResolveError};

#[test]
fn binds_keys_to_nested_branch_paths() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let mut script = Vec::from([0x63, 0x20]);
    script.extend_from_slice(&a);
    script.extend_from_slice(&[0xad, 0x67, 0x63, 0x20]);
    script.extend_from_slice(&b);
    script.extend_from_slice(&[0xac, 0x68, 0x68]);
    let resolved = resolve_covenant_branches(&script).expect("nested covenant");
    assert_eq!(resolved.len(), 2);
    assert_eq!(resolved.selector_mask(), 0b11);
    assert_eq!(resolved.key_at(0).expect("first key").if_mask & 1, 1);
    assert_eq!(resolved.key_at(1).expect("second key").if_mask & 1, 0);
    assert_eq!(resolved.key_at(1).expect("second key").if_mask & 2, 2);
}

#[test]
fn records_actual_op_notif_witness_truth_values() {
    let first_key = [3u8; 32];
    let second_key = [4u8; 32];
    let mut script = Vec::from([0x64, 0x20]);
    script.extend_from_slice(&first_key);
    script.extend_from_slice(&[0xac, 0x67, 0x20]);
    script.extend_from_slice(&second_key);
    script.extend_from_slice(&[0xac, 0x68]);
    let resolved = resolve_covenant_branches(&script).expect("OP_NOTIF covenant");
    let first = resolved.key_at(0).expect("first key");
    let second = resolved.key_at(1).expect("second key");
    assert!(first.matches_selectors(1, 0));
    assert!(!first.matches_selectors(1, 1));
    assert!(second.matches_selectors(1, 1));
    assert!(!second.matches_selectors(1, 0));
}

#[test]
fn duplicate_key_binding_on_the_same_branch_is_rejected() {
    let key = [9u8; 32];
    let mut script = Vec::from([0x20]);
    script.extend_from_slice(&key);
    script.push(0xac);
    script.push(0x20);
    script.extend_from_slice(&key);
    script.push(0xad);
    assert_eq!(
        resolve_covenant_branches(&script),
        Err(BranchResolveError::AmbiguousKey)
    );
}

#[test]
fn reused_key_requires_branch_disambiguation_and_malformed_flow_is_rejected() {
    let key = [7u8; 32];
    let mut script = Vec::from([0x63, 0x20]);
    script.extend_from_slice(&key);
    script.extend_from_slice(&[0xac, 0x67, 0x20]);
    script.extend_from_slice(&key);
    script.extend_from_slice(&[0xac, 0x68]);
    let resolved = resolve_covenant_branches(&script).expect("reused key covenant");
    assert_eq!(resolved.len(), 2);
    assert_eq!(
        resolved.unique_position_for_key(&key),
        Err(BranchResolveError::AmbiguousKey)
    );
    assert_eq!(resolved.position_for_key_with_selectors(&key, 1, 1), Ok(0));
    assert_eq!(resolved.position_for_key_with_selectors(&key, 1, 0), Ok(1));
    assert_eq!(
        resolve_covenant_branches(&[0x67]),
        Err(BranchResolveError::MalformedScript)
    );
    assert_eq!(
        resolve_covenant_branches(&[0x63]),
        Err(BranchResolveError::MalformedScript)
    );
}

fn key_check(script: &mut Vec<u8>, marker: u8, check: u8) {
    script.push(0x20);
    script.extend_from_slice(&[marker; 32]);
    script.push(check);
}

#[test]
fn each_key_records_exactly_its_enclosing_selectors() {
    // IF { k1 IF { k2 } ELSE { k3 } k4 } NOTIF { k5 } ENDIF k6
    let mut script = Vec::from([0x63]);
    key_check(&mut script, 1, 0xad);
    script.push(0x63);
    key_check(&mut script, 2, 0xac);
    script.push(0x67);
    key_check(&mut script, 3, 0xac);
    script.push(0x68);
    key_check(&mut script, 4, 0xad);
    script.extend_from_slice(&[0x68, 0x64]);
    key_check(&mut script, 5, 0xac);
    script.push(0x68);
    key_check(&mut script, 6, 0xac);
    let resolved = resolve_covenant_branches(&script).expect("nested covenant");
    assert!(!resolved.is_empty());
    assert_eq!(resolved.selector_mask(), 0b111);
    let masks: Vec<(u8, u16, u16)> = (0..resolved.len() as u8)
        .map(|position| {
            let key = resolved.key_at(position).unwrap();
            (key.key[0], key.decision_mask, key.if_mask)
        })
        .collect();
    assert_eq!(
        masks,
        [
            (1, 0b001, 0b001),
            (2, 0b011, 0b011),
            (3, 0b011, 0b001),
            (4, 0b001, 0b001),
            (5, 0b100, 0b000),
            (6, 0b000, 0b000),
        ]
    );
    assert_eq!(
        resolved.key_at(6),
        Err(BranchResolveError::PositionOutOfRange)
    );
}

#[test]
fn an_empty_script_resolves_to_no_keys_and_bare_pushes_are_not_keys() {
    let empty = resolve_covenant_branches(&[]).unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.key_at(0), Err(BranchResolveError::PositionOutOfRange));
    // A PUSH32 not consumed by CHECKSIG(VERIFY) is data, not a key.
    let mut data = Vec::from([0x20]);
    data.extend_from_slice(&[8; 32]);
    data.push(0x87);
    assert!(resolve_covenant_branches(&data).unwrap().is_empty());
}

#[test]
fn sixteen_branches_resolve_and_a_seventeenth_is_rejected() {
    let branches = |count: usize| [0x63, 0x68].repeat(count);
    assert_eq!(
        resolve_covenant_branches(&branches(16))
            .unwrap()
            .selector_mask(),
        u16::MAX
    );
    assert_eq!(
        resolve_covenant_branches(&branches(17)),
        Err(BranchResolveError::BranchDepthExceeded)
    );
}

#[test]
fn malformed_control_flow_and_truncated_pushes_are_rejected() {
    let mut short_key = Vec::from([0x20]);
    short_key.extend_from_slice(&[1; 31]);
    for script in [
        &[0x68][..],
        &[0x63, 0x67, 0x67, 0x68],
        &[0x63, 0x68, 0x68],
        &short_key,
        &[0x02, 0x01],
        &[0x4c],
        &[0x4c, 0x02, 0x01],
        &[0x4d, 0x01],
        &[0x4d, 0x02, 0x00, 0x01],
        &[0x4e, 0x01, 0x00, 0x00],
        &[0x4e, 0x02, 0x00, 0x00, 0x00, 0x01],
    ] {
        assert_eq!(
            resolve_covenant_branches(script),
            Err(BranchResolveError::MalformedScript),
            "{script:02x?}"
        );
    }
}

#[test]
fn pushdata_payloads_are_skipped_whatever_bytes_they_hold() {
    // Each payload holds IF/ELSE/ENDIF bytes that must not be parsed.
    for push in [
        &[0x03, 0x63, 0x67, 0x68][..],
        &[0x4c, 0x03, 0x63, 0x67, 0x68],
        &[0x4d, 0x03, 0x00, 0x63, 0x67, 0x68],
        &[0x4e, 0x03, 0x00, 0x00, 0x00, 0x63, 0x67, 0x68],
    ] {
        let mut script = push.to_vec();
        key_check(&mut script, 9, 0xac);
        let resolved = resolve_covenant_branches(&script).expect("pushdata skipped");
        assert_eq!(resolved.len(), 1, "{push:02x?}");
        assert_eq!(resolved.selector_mask(), 0);
    }
}
