// Kaspa Portal — KIP-20 Tagged/Split Vault builders.
// License: GPL-3.0.

//! KIP-20 tagged- and split-vault script builders and covenant-id computation.
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

use crate::contract::script::{opcode as covenant_ops, push_pubkey};

/// Build a Tagged Vault redeem script.
///
/// The script enforces two things:
///   1. Owner signature (standard CHECKSIG)
///   2. Output[0] must carry the same covenant_id as this input
///
/// This is the simplest possible covenant that exercises the KIP-20
/// covenant ID opcodes. It proves state continuity: any spend must
/// create a continuation UTXO tagged with the same covenant_id.
///
/// Script:
///   <owner_pk> OP_CHECKSIGVERIFY
///   OP_TX_INPUT_IDX           // push current input index
///   OP_INPUT_COVENANT_ID      // push this input's covenant_id (32 bytes)
///   0                         // output index 0
///   OP_OUTPUT_COVENANT_ID     // push output[0]'s covenant_id (32 bytes)
///   OP_EQUALVERIFY
///   OP_1
///
/// sig_op_count: 1 (CHECKSIGVERIFY)
pub fn build_tagged_vault_script(owner_pubkey: &[u8; 32]) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(64);

    // Owner must sign
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Read this input's covenant_id
    s.push(OP_TX_INPUT_INDEX); // push current input idx
    s.push(OP_INPUT_COVENANT_ID); // 0xcf: pop idx, push covenant_id

    // Read output[0]'s covenant_id
    s.push(OP_0); // push 0
    s.push(OP_OUTPUT_COVENANT_ID); // 0xd5: pop idx, push covenant_id

    // They must match
    s.push(OP_EQUALVERIFY);

    // Leave TRUE on stack
    s.push(OP_1);

    s
}

// ================================================================
// Split Vault: one input splits into two tagged outputs (KIP-20)
// ================================================================

/// Build a Split Vault redeem script.
///
/// Enforces:
///   1. Owner signature
///   2. Exactly 2 outputs carry the same covenant_id as this input
///   3. This input authorizes exactly 2 outputs
///
/// This exercises: OP_AUTH_OUTPUT_COUNT (0xcb), OP_COV_OUTPUT_COUNT (0xd2),
/// OP_INPUT_COVENANT_ID (0xcf), OP_TX_INPUT_IDX (0xb9), plus CHECKSIGVERIFY.
///
/// Script:
///   <owner_pk> CHECKSIGVERIFY
///   TX_INPUT_IDX INPUT_COVENANT_ID   // get our covenant_id
///   DUP                              // need it twice
///   COV_OUTPUT_COUNT                 // how many outputs share this id?
///   2 EQUALVERIFY                    // must be exactly 2
///   TX_INPUT_IDX AUTH_OUTPUT_COUNT   // how many outputs does this input auth?
///   2 EQUALVERIFY                    // must be exactly 2
///   DROP                             // clean the dup'd covenant_id
///   1
///
/// sig_op_count: 1 (CHECKSIGVERIFY)
pub fn build_split_vault_script(owner_pubkey: &[u8; 32]) -> Vec<u8> {
    use covenant_ops::*;
    let mut s = Vec::with_capacity(48);

    // Owner must sign
    push_pubkey(&mut s, owner_pubkey);
    s.push(OP_CHECKSIGVERIFY);

    // Read this input's covenant_id
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_INPUT_COVENANT_ID); // stack: [cov_id]

    // DUP for two checks
    s.push(OP_DUP); // stack: [cov_id, cov_id]

    // Check: exactly 2 outputs carry this covenant_id
    s.push(OP_COV_OUTPUT_COUNT); // stack: [cov_id, count]
    s.push(0x52); // OP_2
    s.push(OP_EQUALVERIFY); // stack: [cov_id]

    // Check: this input authorizes exactly 2 outputs
    s.push(OP_TX_INPUT_INDEX);
    s.push(OP_AUTH_OUTPUT_COUNT); // stack: [cov_id, auth_count]
    s.push(0x52); // OP_2
    s.push(OP_EQUALVERIFY); // stack: [cov_id]

    // Clean up
    s.push(OP_DROP); // stack: []
    s.push(OP_1); // stack: [TRUE]

    s
}
