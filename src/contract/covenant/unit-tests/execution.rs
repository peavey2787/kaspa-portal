use alloc::vec::Vec;

use crate::contract::covenant::{
    branch::resolve_covenant_branches,
    execution::{trace_witness, ExecutionError, WitnessItem},
};

use WitnessItem::{Selector, Signature};

const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;

fn key(script: &mut Vec<u8>, byte: u8, check: u8) {
    script.push(0x20);
    script.extend_from_slice(&[byte; 32]);
    script.push(check);
}

/// `IF <a> CHECKSIG ELSE IF <b> CHECKSIG ELSE <keyless> ENDIF ENDIF`
fn nested_escrow() -> Vec<u8> {
    let mut script = Vec::from([OP_IF]);
    key(&mut script, 0xa1, OP_CHECKSIG);
    script.extend_from_slice(&[OP_ELSE, OP_IF]);
    key(&mut script, 0xb2, OP_CHECKSIG);
    script.extend_from_slice(&[OP_ELSE, 0x51, OP_ENDIF, OP_ENDIF]);
    script
}

/// `IF <owner> CHECKSIGVERIFY IF 1 ELSE 1 ENDIF ELSE <beneficiary> CHECKSIG ENDIF`
fn owner_then_inner_selector() -> Vec<u8> {
    let mut script = Vec::from([OP_IF]);
    key(&mut script, 0xc3, OP_CHECKSIGVERIFY);
    script.extend_from_slice(&[OP_IF, 0x51, OP_ELSE, 0x51, OP_ENDIF, OP_ELSE]);
    key(&mut script, 0xd4, OP_CHECKSIG);
    script.push(OP_ENDIF);
    script
}

#[test]
fn nested_paths_consume_outer_selector_first_then_inner_then_signature() {
    let script = nested_escrow();
    assert_eq!(
        trace_witness(&script, 0b11, 0b01),
        Ok(Vec::from([Selector(true), Signature { position: 0 }]))
    );
    assert_eq!(
        trace_witness(&script, 0b11, 0b10),
        Ok(Vec::from([
            Selector(false),
            Selector(true),
            Signature { position: 1 }
        ]))
    );
    // The keyless refund branch consumes only its two selectors.
    assert_eq!(
        trace_witness(&script, 0b11, 0b00),
        Ok(Vec::from([Selector(false), Selector(false)]))
    );
}

#[test]
fn a_selector_after_a_signature_check_is_consumed_after_that_signature() {
    let script = owner_then_inner_selector();
    assert_eq!(
        trace_witness(&script, 0b11, 0b11),
        Ok(Vec::from([
            Selector(true),
            Signature { position: 0 },
            Selector(true)
        ]))
    );
    assert_eq!(
        trace_witness(&script, 0b11, 0b01),
        Ok(Vec::from([
            Selector(true),
            Signature { position: 0 },
            Selector(false)
        ]))
    );
    assert_eq!(
        trace_witness(&script, 0b11, 0b00),
        Ok(Vec::from([Selector(false), Signature { position: 1 }]))
    );
}

#[test]
fn trace_positions_name_the_resolver_key_reached_by_the_selectors() {
    for script in [nested_escrow(), owner_then_inner_selector()] {
        let branches = resolve_covenant_branches(&script).expect("resolvable covenant");
        let mask = branches.selector_mask();
        for truth in 0..=mask {
            let Ok(items) = trace_witness(&script, mask, truth) else {
                continue;
            };
            for item in items {
                if let Signature { position } = item {
                    let binding = branches.key_at(position).expect("resolver key");
                    assert!(binding.matches_selectors(mask, truth));
                }
            }
        }
    }
}

#[test]
fn op_notif_executes_its_body_on_a_false_selector() {
    let mut script = Vec::from([OP_NOTIF]);
    key(&mut script, 0x11, OP_CHECKSIG);
    script.push(OP_ELSE);
    key(&mut script, 0x22, OP_CHECKSIG);
    script.push(OP_ENDIF);
    assert_eq!(
        trace_witness(&script, 1, 0),
        Ok(Vec::from([Selector(false), Signature { position: 0 }]))
    );
    assert_eq!(
        trace_witness(&script, 1, 1),
        Ok(Vec::from([Selector(true), Signature { position: 1 }]))
    );
}

#[test]
fn selector_free_scripts_consume_only_their_signatures() {
    let mut treasury = Vec::new();
    key(&mut treasury, 0x33, OP_CHECKSIGVERIFY);
    treasury.extend_from_slice(&[0xb3, 0x51, 0x9c]);
    assert_eq!(
        trace_witness(&treasury, 0, 0),
        Ok(Vec::from([Signature { position: 0 }]))
    );
    assert_eq!(
        trace_witness(&[0x00, 0xb3, 0x51, 0x9c], 0, 0),
        Ok(Vec::new())
    );
}

#[test]
fn a_32_byte_data_push_not_checked_as_a_signature_is_not_a_key() {
    let mut script = Vec::from([0x20]);
    script.extend_from_slice(&[0x44; 32]);
    script.push(0x87);
    key(&mut script, 0x55, OP_CHECKSIG);
    assert_eq!(
        trace_witness(&script, 0, 0),
        Ok(Vec::from([Signature { position: 0 }]))
    );
}

#[test]
fn every_selector_bit_must_be_assigned_and_nothing_else() {
    let script = nested_escrow();
    assert_eq!(
        trace_witness(&script, 0b01, 0b01),
        Err(ExecutionError::IncompleteSelectors)
    );
    assert_eq!(
        trace_witness(&script, 0b10, 0b00),
        Err(ExecutionError::IncompleteSelectors)
    );
    assert_eq!(
        trace_witness(&script, 0b111, 0b001),
        Err(ExecutionError::IncompleteSelectors)
    );
    assert_eq!(
        trace_witness(&script, 0b11, 0b111),
        Err(ExecutionError::IncompleteSelectors)
    );
}

#[test]
fn signature_checks_a_selector_witness_cannot_satisfy_are_refused_on_the_taken_path() {
    for unsupported in [0xab, 0xae, 0xaf, 0xd7] {
        let script = [OP_IF, unsupported, OP_ELSE, 0x51, OP_ENDIF];
        assert_eq!(
            trace_witness(&script, 1, 1),
            Err(ExecutionError::UnsupportedSignatureCheck),
            "{unsupported:#x}"
        );
        assert_eq!(
            trace_witness(&script, 1, 0),
            Ok(Vec::from([Selector(false)]))
        );
    }
    for bare in [OP_CHECKSIG, OP_CHECKSIGVERIFY] {
        let script = [0x76, bare];
        assert_eq!(
            trace_witness(&script, 0, 0),
            Err(ExecutionError::UnsupportedSignatureCheck)
        );
    }
    // A canonical check consumes the key-push marker; a second check does not.
    let mut doubled = Vec::new();
    key(&mut doubled, 0x66, OP_CHECKSIG);
    doubled.push(OP_CHECKSIG);
    assert_eq!(
        trace_witness(&doubled, 0, 0),
        Err(ExecutionError::UnsupportedSignatureCheck)
    );
}

#[test]
fn malformed_control_flow_and_pushes_are_rejected() {
    for script in [
        &[OP_ELSE][..],
        &[OP_ENDIF],
        &[OP_IF],
        &[OP_IF, OP_ELSE, OP_ELSE, OP_ENDIF],
        &[0x20, 0x01],
        &[0x4c],
        &[0x4c, 0x02, 0x00],
    ] {
        let mask = u16::from(script.first() == Some(&OP_IF));
        assert_eq!(
            trace_witness(script, mask, mask),
            Err(ExecutionError::MalformedScript),
            "{script:02x?}"
        );
    }
}

#[test]
fn branch_depth_and_key_count_are_bounded() {
    let mut deep = Vec::from([OP_IF; 17]);
    deep.extend_from_slice(&[OP_ENDIF; 17]);
    assert_eq!(
        trace_witness(&deep, u16::MAX, u16::MAX),
        Err(ExecutionError::BranchDepthExceeded)
    );

    let mut wide = Vec::new();
    for _ in 0..17 {
        wide.extend_from_slice(&[OP_IF, OP_ENDIF]);
    }
    assert_eq!(
        trace_witness(&wide, u16::MAX, 0),
        Err(ExecutionError::BranchDepthExceeded)
    );

    let mut keys = Vec::new();
    for byte in 0..17u8 {
        key(&mut keys, byte, OP_CHECKSIGVERIFY);
    }
    assert_eq!(trace_witness(&keys, 0, 0), Err(ExecutionError::TooManyKeys));
}
