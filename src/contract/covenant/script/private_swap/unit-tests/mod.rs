use super::build_private_swap_script;
use crate::contract::script::opcode::{OP_BLAKE2B, OP_CHECKSIGFROMSTACK, OP_SHA256};

#[test]
fn private_swap_script_is_canonical_and_has_no_hashlock_or_checksigfromstack() {
    let destination: Vec<u8> = [0, 0, 0x20].into_iter().chain([3u8; 32]).collect();
    let script =
        build_private_swap_script(&[1; 32], &[2; 32], &destination, 5000, &[4; 16]).unwrap();
    assert!(!script.contains(&OP_SHA256));
    assert!(!script.contains(&OP_BLAKE2B));
    assert!(!script.contains(&OP_CHECKSIGFROMSTACK));
}
