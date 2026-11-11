use crate::transaction::model::{InputSig, TransactionInput};

pub(super) fn has_pubkey_position(input: &TransactionInput, pubkey_position: u8) -> bool {
    input
        .sigs
        .iter()
        .any(|slot| slot.pubkey_pos == pubkey_position)
}

pub(super) fn set_single_signature(
    input: &mut TransactionInput,
    signature: [u8; 64],
    sighash_type: u8,
    pubkey_position: u8,
    compressed_public_key: [u8; 33],
) {
    input.sigs.replace_with(InputSig {
        signature,
        sighash_type,
        pubkey_pos: pubkey_position,
        pubkey_compressed: compressed_public_key,
    });
    input.sighash_type = sighash_type;
}

pub(super) fn append_signature(
    input: &mut TransactionInput,
    signature: [u8; 64],
    sighash_type: u8,
    pubkey_position: u8,
    compressed_public_key: [u8; 33],
) -> bool {
    if has_pubkey_position(input, pubkey_position) {
        return false;
    }
    if !input.sigs.is_empty() && input.sighash_type != sighash_type {
        return false;
    }
    input.sighash_type = sighash_type;
    input.sigs.push(InputSig {
        signature,
        sighash_type,
        pubkey_pos: pubkey_position,
        pubkey_compressed: compressed_public_key,
    })
}
