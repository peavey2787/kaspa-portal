use alloc::vec::Vec;

use super::{resolve_execution_branches, MAX_COVENANT_KEYS};
use crate::contract::covenant::branch::resolve_covenant_branches;

/// `IF <k0> CHECKSIG ELSE IF <k1> CHECKSIG ELSE ... <kn> CHECKSIG ENDIF...`
fn branch_chain(keys: usize) -> Vec<u8> {
    let mut script = Vec::new();
    for key in 0..keys {
        if key + 1 < keys {
            script.push(0x63);
        }
        script.push(0x20);
        script.extend_from_slice(&[key as u8 + 1; 32]);
        script.push(0xac);
        if key + 1 < keys {
            script.push(0x67);
        }
    }
    script.extend(core::iter::repeat_n(0x68, keys - 1));
    script
}

#[test]
fn execution_resolution_admits_exactly_the_candidate_key_capacity() {
    for (keys, admitted) in [(MAX_COVENANT_KEYS, true), (MAX_COVENANT_KEYS + 1, false)] {
        let script = branch_chain(keys);
        let mask = resolve_covenant_branches(&script)
            .expect("structurally valid chain")
            .selector_mask();
        assert_eq!(
            resolve_execution_branches(&script, mask, 0).is_ok(),
            admitted,
            "{keys} keys"
        );
    }
}
