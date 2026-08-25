// Kaspa multisig transaction model.
// SPDX-License-Identifier: GPL-3.0-only

use crate::{
    transaction::sighash::blake2b_hash,
    wallet::{
        derivation::bip32::{derive_child_pub, ExtendedPubKey},
        key::xpub::KpubParts,
    },
};

use super::{
    constants::{
        MAX_MULTISIG_KEYS, MAX_MULTISIG_WALLETS, MAX_SCRIPT_SIZE, OP_1, OP_CHECKMULTISIG,
        OP_DATA_32,
    },
    input::Ms45Hint,
};

/// Canonical 45' multisig configuration.
///
/// Addresses derive `/cosigner/chain/index` beneath `m/45'/111111'/0'` and
/// preserve canonical parent ordering across every derived address.
#[derive(Clone)]
pub struct MultisigConfig {
    pub m: u8,
    pub n: u8,
    pub cosigner_pubkeys: [[u8; 33]; MAX_MULTISIG_KEYS],
    pub cosigner_chain_codes: [[u8; 32]; MAX_MULTISIG_KEYS],
    pub addr_index: u32,
    /// This wallet's position in the canonical descriptor.
    pub cosigner_index: u8,
    /// Address chain: 0=external/receive, 1=change.
    pub chain: u8,
    /// Metadata required to re-serialize each participant byte-identically.
    pub cosigner_depth: [u8; MAX_MULTISIG_KEYS],
    pub cosigner_parent_fp: [[u8; 4]; MAX_MULTISIG_KEYS],
    pub cosigner_child_num: [[u8; 4]; MAX_MULTISIG_KEYS],
    pub script: [u8; MAX_SCRIPT_SIZE],
    pub script_len: usize,
    pub active: bool,
}

impl Default for MultisigConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl MultisigConfig {
    pub const fn new() -> Self {
        Self {
            m: 0,
            n: 0,
            cosigner_pubkeys: [[0; 33]; MAX_MULTISIG_KEYS],
            cosigner_chain_codes: [[0; 32]; MAX_MULTISIG_KEYS],
            addr_index: 0,
            cosigner_index: 0,
            chain: 0,
            cosigner_depth: [0; MAX_MULTISIG_KEYS],
            cosigner_parent_fp: [[0; 4]; MAX_MULTISIG_KEYS],
            cosigner_child_num: [[0; 4]; MAX_MULTISIG_KEYS],
            script: [0; MAX_SCRIPT_SIZE],
            script_len: 0,
            active: false,
        }
    }

    /// Store one full cosigner entry so canonical descriptor ordering can be
    /// reproduced without discarding BIP32 metadata.
    pub fn set_cosigner(&mut self, index: usize, parts: &KpubParts) -> bool {
        if index >= MAX_MULTISIG_KEYS {
            return false;
        }
        self.cosigner_pubkeys[index] = parts.pubkey;
        self.cosigner_chain_codes[index] = parts.chain_code;
        self.cosigner_depth[index] = parts.depth;
        self.cosigner_parent_fp[index] = parts.parent_fp;
        self.cosigner_child_num[index] = parts.child_num;
        true
    }

    #[must_use]
    pub fn slot_empty(&self, index: usize) -> bool {
        index < MAX_MULTISIG_KEYS && self.cosigner_pubkeys[index] == [0; 33]
    }

    /// Build the redeem script for the current family/chain/index.
    pub fn build_script(&mut self) -> usize {
        if !valid_multisig_config(self.m, self.n) || self.chain > 1 {
            return 0;
        }
        let Some(children) = derive_multisig_children(self) else {
            return 0;
        };
        write_multisig_script(self, &children)
    }

    /// Check whether this descriptor reproduces a P2SH script hash at an
    /// untrusted derivation hint. Hints are lookup indexes, never authority.
    #[must_use]
    pub fn matches_at(&self, hint: &Ms45Hint, script_hash: &[u8; 32]) -> bool {
        if !valid_hint(self, hint) {
            return false;
        }
        let Some(children) = derive_children_at(self, hint.cosigner, hint.chain, hint.index) else {
            return false;
        };
        let mut redeem = [0u8; MAX_SCRIPT_SIZE];
        let Some(length) = encode_redeem(self.m, self.n, &children, &mut redeem) else {
            return false;
        };
        blake2b_hash(&redeem[..length]) == *script_hash
    }

    /// Sort account parents into canonical serialized-kpub order.
    pub fn sort_cosigners(&mut self) {
        let n = self.n as usize;
        for index in 1..n {
            let mut cursor = index;
            while cursor > 0 && self.serialized_entry(cursor - 1) > self.serialized_entry(cursor) {
                self.cosigner_pubkeys.swap(cursor - 1, cursor);
                self.cosigner_chain_codes.swap(cursor - 1, cursor);
                self.cosigner_depth.swap(cursor - 1, cursor);
                self.cosigner_parent_fp.swap(cursor - 1, cursor);
                self.cosigner_child_num.swap(cursor - 1, cursor);
                cursor -= 1;
            }
        }
    }

    #[must_use]
    pub fn same_wallet_as(&self, other: &Self) -> bool {
        (
            self.m,
            self.n,
            &self.cosigner_pubkeys,
            &self.cosigner_chain_codes,
        ) == (
            other.m,
            other.n,
            &other.cosigner_pubkeys,
            &other.cosigner_chain_codes,
        )
    }

    /// Resolve this wallet's family by matching its account kpub against the
    /// already-canonicalized descriptor.
    pub fn resolve_cosigner_index(&mut self, own: &KpubParts) -> bool {
        let own_entry = serialized_parts(own);
        for index in 0..self.n as usize {
            if self.serialized_entry(index) == own_entry {
                self.cosigner_index = index as u8;
                return true;
            }
        }
        false
    }

    /// Human-readable multisig label including family and chain.
    pub fn label(&self, buf: &mut [u8]) -> usize {
        let mut pos = 0usize;
        push_byte(buf, &mut pos, b'0' + self.m);
        for byte in b"-of-" {
            push_byte(buf, &mut pos, *byte);
        }
        push_byte(buf, &mut pos, b'0' + self.n);
        for byte in b" 45' S" {
            push_byte(buf, &mut pos, *byte);
        }
        push_byte(buf, &mut pos, b'0' + self.cosigner_index);
        for byte in b"/C" {
            push_byte(buf, &mut pos, *byte);
        }
        push_byte(buf, &mut pos, b'0' + self.chain);
        pos.min(buf.len())
    }

    fn serialized_entry(&self, index: usize) -> [u8; 74] {
        let mut out = [0u8; 74];
        out[0] = self.cosigner_depth[index];
        out[1..5].copy_from_slice(&self.cosigner_parent_fp[index]);
        out[5..9].copy_from_slice(&self.cosigner_child_num[index]);
        out[9..41].copy_from_slice(&self.cosigner_chain_codes[index]);
        out[41..74].copy_from_slice(&self.cosigner_pubkeys[index]);
        out
    }
}

fn valid_hint(config: &MultisigConfig, hint: &Ms45Hint) -> bool {
    hint.present
        && hint.chain <= 1
        && hint.cosigner < 0x8000_0000
        && hint.index < 0x8000_0000
        && valid_multisig_config(config.m, config.n)
}

fn serialized_parts(parts: &KpubParts) -> [u8; 74] {
    let mut out = [0u8; 74];
    out[0] = parts.depth;
    out[1..5].copy_from_slice(&parts.parent_fp);
    out[5..9].copy_from_slice(&parts.child_num);
    out[9..41].copy_from_slice(&parts.chain_code);
    out[41..74].copy_from_slice(&parts.pubkey);
    out
}

fn push_byte(buf: &mut [u8], pos: &mut usize, byte: u8) {
    if *pos < buf.len() {
        buf[*pos] = byte;
    }
    *pos = pos.saturating_add(1);
}

fn valid_multisig_config(m: u8, n: u8) -> bool {
    m != 0 && n != 0 && m <= n && n as usize <= MAX_MULTISIG_KEYS
}

fn derive_multisig_children(config: &MultisigConfig) -> Option<[[u8; 32]; MAX_MULTISIG_KEYS]> {
    derive_children_at(
        config,
        u32::from(config.cosigner_index),
        u32::from(config.chain),
        config.addr_index,
    )
}

fn derive_children_at(
    config: &MultisigConfig,
    cosigner: u32,
    chain: u32,
    index: u32,
) -> Option<[[u8; 32]; MAX_MULTISIG_KEYS]> {
    let mut children = [[0u8; 32]; MAX_MULTISIG_KEYS];
    for (slot, child) in children.iter_mut().enumerate().take(config.n as usize) {
        let parent = ExtendedPubKey {
            pubkey: config.cosigner_pubkeys[slot],
            chain_code: config.cosigner_chain_codes[slot],
            depth: config.cosigner_depth[slot].max(3),
        };
        let family = derive_child_pub(&parent, cosigner).ok()?;
        let chain_key = derive_child_pub(&family, chain).ok()?;
        let address = derive_child_pub(&chain_key, index).ok()?;
        *child = address.x_only();
    }
    Some(children)
}

fn encode_redeem(
    m: u8,
    n: u8,
    children: &[[u8; 32]; MAX_MULTISIG_KEYS],
    out: &mut [u8],
) -> Option<usize> {
    if !valid_multisig_config(m, n) {
        return None;
    }
    let needed = 1 + n as usize * 33 + 2;
    if needed > out.len() {
        return None;
    }
    let mut pos = 0usize;
    out[pos] = OP_1 + m - 1;
    pos += 1;
    for child in children.iter().take(n as usize) {
        out[pos] = OP_DATA_32;
        pos += 1;
        out[pos..pos + 32].copy_from_slice(child);
        pos += 32;
    }
    out[pos] = OP_1 + n - 1;
    pos += 1;
    out[pos] = OP_CHECKMULTISIG;
    pos += 1;
    Some(pos)
}

fn write_multisig_script(
    config: &mut MultisigConfig,
    children: &[[u8; 32]; MAX_MULTISIG_KEYS],
) -> usize {
    let Some(length) = encode_redeem(config.m, config.n, children, &mut config.script) else {
        return 0;
    };
    config.script_len = length;
    length
}

/// Storage for multisig wallet configurations.
#[derive(Default)]
pub struct MultisigStore {
    pub configs: [MultisigConfig; MAX_MULTISIG_WALLETS],
}

impl MultisigStore {
    pub const fn new() -> Self {
        Self {
            configs: [MultisigConfig::new(), MultisigConfig::new()],
        }
    }

    #[must_use]
    pub fn find_free(&self) -> Option<usize> {
        self.configs.iter().position(|config| !config.active)
    }
}
