use alloc::vec::Vec;

use crate::contract::covenant::{
    branch::resolve_covenant_branches,
    build_global_allowance_script, build_global_spending_limit_script,
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
    script.push(0x75);
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
        assert_eq!(
            trace_witness(&[bare], 0, 0),
            Err(ExecutionError::UnsupportedSignatureCheck)
        );
        // A signature the script pushed itself is not a witness signature.
        let mut scripted = Vec::from([0x51]);
        key(&mut scripted, 0x77, bare);
        assert_eq!(
            trace_witness(&scripted, 0, 0),
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

#[test]
fn a_computed_branch_consumes_no_selector_while_its_bit_stays_assigned() {
    let owner = [0x31; 32];
    let beneficiary = [0x32; 32];
    let allowance = build_global_allowance_script(&owner, &beneficiary, 5_000, 10, 20, &[7; 8]);
    // Outer owner/beneficiary IF is the only witness selector; the inner
    // continuation-or-close IF tests a value the script computed.
    assert_eq!(
        trace_witness(&allowance, 0b11, 0b01),
        Ok(Vec::from([Selector(true), Signature { position: 0 }]))
    );
    assert_eq!(
        trace_witness(&allowance, 0b11, 0b00),
        Ok(Vec::from([Selector(false), Signature { position: 1 }]))
    );
    assert_eq!(
        trace_witness(&allowance, 0b11, 0b10),
        trace_witness(&allowance, 0b11, 0b00)
    );
    assert_eq!(
        trace_witness(&allowance, 0b01, 0b00),
        Err(ExecutionError::IncompleteSelectors)
    );

    let limit = build_global_spending_limit_script(&owner, 5_000, 10, &[9; 8]);
    assert_eq!(
        trace_witness(&limit, 0b1, 0b0),
        Ok(Vec::from([Signature { position: 0 }]))
    );
}

#[test]
fn computed_branch_arms_must_be_pure_and_agree_on_their_stack_effect() {
    // 1 IF 1 ELSE 1 1 ENDIF: the arms leave different depths.
    assert_eq!(
        trace_witness(&[0x51, OP_IF, 0x51, OP_ELSE, 0x51, 0x51, OP_ENDIF], 1, 0),
        Err(ExecutionError::DataDependentBranch)
    );
    // A key check inside a computed arm would need a witness signature.
    let mut keyed = Vec::from([0x51, OP_IF]);
    key(&mut keyed, 0x41, OP_CHECKSIG);
    keyed.extend_from_slice(&[OP_ELSE, 0x51, OP_ENDIF]);
    assert_eq!(
        trace_witness(&keyed, 1, 1),
        Err(ExecutionError::DataDependentBranch)
    );
    // An arm needing two script items when only one remains reaches the witness.
    assert_eq!(
        trace_witness(&[0x51, 0x51, OP_IF, 0x87, OP_ELSE, 0x87, OP_ENDIF], 1, 0),
        Err(ExecutionError::WitnessDataRequired)
    );
    // The same arms with enough script items below them are pure.
    assert_eq!(
        trace_witness(
            &[0x51, 0x51, 0x51, OP_IF, 0x87, OP_ELSE, 0x87, OP_ENDIF, 0x69],
            1,
            0
        ),
        Ok(Vec::new())
    );
    // Nested computed branches compose; unmodelled opcodes inside are refused.
    assert_eq!(
        trace_witness(
            &[
                0x51, 0x51, OP_IF, 0x51, OP_IF, 0x75, OP_ELSE, 0x75, OP_ENDIF, OP_ELSE, 0x75,
                OP_ENDIF
            ],
            0b11,
            0
        ),
        Ok(Vec::new())
    );
    assert_eq!(
        trace_witness(&[0x51, OP_IF, 0x74, OP_ELSE, 0x74, OP_ENDIF], 1, 0),
        Err(ExecutionError::UnsupportedOpcode)
    );
}

#[test]
fn witness_data_beyond_selectors_and_signatures_needs_a_typed_plan() {
    // A hash-lock preimage would come from the witness.
    let mut preimage = Vec::from([0xaa, 0x20]);
    preimage.extend_from_slice(&[0x55; 32]);
    preimage.push(0x88);
    assert_eq!(
        trace_witness(&preimage, 0, 0),
        Err(ExecutionError::WitnessDataRequired)
    );
    // Opcodes whose stack effect depends on data are not modelled.
    for opcode in [0x74, 0x79, 0x7a, 0xd7, 0xa6] {
        assert!(
            trace_witness(&[0x51, 0x51, opcode], 0, 0).is_err(),
            "{opcode:#x}"
        );
    }
    assert_eq!(
        trace_witness(&[0x51, 0x79], 0, 0),
        Err(ExecutionError::UnsupportedOpcode)
    );
}

#[test]
fn modelled_opcodes_have_their_exact_stack_effects() {
    // Each script leaves exactly one item if, and only if, the effect is right:
    // with one item fewer, the final VERIFY reaches the witness.
    for (setup, opcode) in [
        (0usize, 0x61u8),
        (2, 0x69),
        (2, 0x75),
        (2, 0xb0),
        (2, 0xb1),
        (3, 0x6d),
        (2, 0x6e),
        (1, 0x76),
        (1, 0x82),
        (2, 0x77),
        (2, 0x78),
        (2, 0x7d),
        (3, 0x7b),
        (2, 0x7c),
        (3, 0x7f),
        (3, 0xa5),
        (3, 0x88),
        (3, 0x9d),
        (1, 0x8b),
        (1, 0xaa),
        (2, 0x87),
        (2, 0xa2),
        (0, 0xb9),
        (1, 0xcf),
        (2, 0xd3),
    ] {
        let (pops, pushes) = super::stack_effect(opcode).expect("modelled opcode");
        assert!(setup >= pops, "{opcode:#x}");
        let mut script = alloc::vec![0x51; setup];
        script.push(opcode);
        let remaining = setup - pops + pushes;
        script.extend(core::iter::repeat_n(0x69, remaining));
        assert_eq!(trace_witness(&script, 0, 0), Ok(Vec::new()), "{opcode:#x}");
        script.push(0x69);
        assert_eq!(
            trace_witness(&script, 0, 0),
            Err(ExecutionError::WitnessDataRequired),
            "{opcode:#x}"
        );
    }
}

#[test]
fn nested_computed_branches_count_what_they_need_from_below_and_carry_their_effect() {
    // Outer computed IF; its THEN arm holds a computed IF whose arms each drop
    // an item, so the THEN arm needs two items below it: the inner condition
    // and the dropped item. Its ELSE arm needs one.
    let script = |depth: usize| {
        let mut script = alloc::vec![0x51; depth];
        script.extend_from_slice(&[
            OP_IF, OP_IF, 0x75, OP_ELSE, 0x75, OP_ENDIF, 0x51, 0x51, OP_ELSE, 0x75, 0x51, OP_ENDIF,
        ]);
        script
    };
    assert_eq!(
        trace_witness(&script(2), 0b11, 0),
        Err(ExecutionError::WitnessDataRequired)
    );
    assert_eq!(trace_witness(&script(3), 0b11, 0), Ok(Vec::new()));

    // With nothing after the inner branch, its replace-in-place arms still
    // need the item beneath the inner condition.
    let bare = |depth: usize| {
        let mut script = alloc::vec![0x51; depth];
        script.extend_from_slice(&[
            OP_IF, OP_IF, 0x75, 0x51, OP_ELSE, 0x75, 0x51, OP_ENDIF, OP_ELSE, 0x75, OP_ENDIF,
        ]);
        script
    };
    assert_eq!(
        trace_witness(&bare(2), 0b11, 0),
        Err(ExecutionError::WitnessDataRequired)
    );
    assert_eq!(trace_witness(&bare(3), 0b11, 0), Ok(Vec::new()));

    // A computed branch that grows the stack leaves exactly that many items.
    let mut grows = Vec::from([0x51, 0x51, OP_IF, 0x51, OP_ELSE, 0x51, OP_ENDIF, 0x69, 0x69]);
    assert_eq!(trace_witness(&grows, 1, 0), Ok(Vec::new()));
    grows.push(0x69);
    assert_eq!(
        trace_witness(&grows, 1, 0),
        Err(ExecutionError::WitnessDataRequired)
    );
}
