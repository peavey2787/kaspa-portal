//! Multisig child derivation and redeem-script construction.

use crate::wallet::{
    derivation::bip32::{derive_child_pub, ExtendedPubKey},
    key::xpub::KpubParts,
};

use super::super::constants::MAX_MULTISIG_KEYS;
use super::{validation::valid_config, MultisigConfig, MultisigFamily};

pub(super) fn serialized_parts(parts: &KpubParts) -> [u8; 74] {
    let mut out = [0u8; 74];
    out[0] = parts.depth;
    out[1..5].copy_from_slice(&parts.parent_fp);
    out[5..9].copy_from_slice(&parts.child_num);
    out[9..41].copy_from_slice(&parts.chain_code);
    out[41..74].copy_from_slice(&parts.pubkey);
    out
}

pub(super) fn push_byte(buf: &mut [u8], pos: &mut usize, byte: u8) {
    if *pos < buf.len() {
        buf[*pos] = byte;
    }
    *pos = pos.saturating_add(1);
}

pub(super) fn derive_multisig_children(
    config: &MultisigConfig,
) -> Option<[[u8; 32]; MAX_MULTISIG_KEYS]> {
    let (cosigner, chain) = match config.family {
        MultisigFamily::Hd45 {
            cosigner_index,
            chain,
        } => (u32::from(cosigner_index), u32::from(chain)),
        MultisigFamily::Legacy44 => (0, 0),
    };
    derive_children_at(config, cosigner, chain, config.addr_index)
}

pub(super) fn derive_children_at(
    config: &MultisigConfig,
    cosigner: u32,
    chain: u32,
    index: u32,
) -> Option<[[u8; 32]; MAX_MULTISIG_KEYS]> {
    let mut children = [[0u8; 32]; MAX_MULTISIG_KEYS];
    for (slot, child) in children.iter_mut().enumerate().take(usize::from(config.n)) {
        let parent = ExtendedPubKey {
            pubkey: config.cosigner_pubkeys[slot],
            chain_code: config.cosigner_chain_codes[slot],
            depth: config.cosigner_depth[slot].max(3),
        };
        let family_key = if config.family.is_hd45() {
            derive_child_pub(&parent, cosigner).ok()?
        } else {
            parent
        };
        let chain_key = derive_child_pub(&family_key, chain).ok()?;
        let address = derive_child_pub(&chain_key, index).ok()?;
        *child = address.x_only();
    }
    Some(children)
}

pub(super) fn sort_xonly_children(children: &mut [[u8; 32]; MAX_MULTISIG_KEYS], count: usize) {
    for index in 1..count {
        let mut cursor = index;
        while cursor > 0 && children[cursor - 1] > children[cursor] {
            children.swap(cursor - 1, cursor);
            cursor -= 1;
        }
    }
}

pub(super) fn encode_redeem(
    m: u8,
    n: u8,
    children: &[[u8; 32]; MAX_MULTISIG_KEYS],
    out: &mut [u8],
) -> Option<usize> {
    if !valid_config(m, n) {
        return None;
    }
    crate::primitives::multisig_script::encode(m, children.get(..usize::from(n))?, out)
}

pub(super) fn write_multisig_script(
    config: &mut MultisigConfig,
    children: &[[u8; 32]; MAX_MULTISIG_KEYS],
) -> usize {
    let Some(length) = encode_redeem(config.m, config.n, children, &mut config.script) else {
        return 0;
    };
    config.script_len = length;
    length
}
