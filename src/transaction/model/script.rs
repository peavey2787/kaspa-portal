// Kaspa protocol implementation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::constants::{MAX_MULTISIG_KEYS, MAX_SCRIPT_SIZE};
use crate::primitives::{
    multisig_script,
    opcode::{OP_BLAKE2B, OP_CHECKSIG, OP_DATA_32, OP_EQUAL},
};

// ─── Script Public Key ────────────────────────────────────────────────

/// ScriptPubKey with version (Kaspa versions its scripts)
#[derive(Debug, Clone)]
/// Script public key with version byte (Kaspa uses version 0).
pub struct ScriptPublicKey {
    pub version: u16,
    pub script: [u8; MAX_SCRIPT_SIZE],
    pub script_len: usize,
}

impl Default for ScriptPublicKey {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptPublicKey {
    pub fn new() -> Self {
        Self {
            version: 0,
            script: [0u8; MAX_SCRIPT_SIZE],
            script_len: 0,
        }
    }

    /// Get the raw script bytes.
    pub fn script_bytes(&self) -> &[u8] {
        &self.script[..self.script_len]
    }
}

// ─── UTXO Entry (previous output being spent) ──────────────────

/// UTXO entry being spent (provided by companion app)
#[derive(Debug, Clone)]
/// Unspent transaction output entry (amount + script + metadata).
pub struct UtxoEntry {
    pub amount: u64, // sompi (1 KAS = 100_000_000 sompi)
    pub script_public_key: ScriptPublicKey,
    /// DAA score from the node. Not part of the sighash, but retained exactly
    /// so JSON round-trips never need a JavaScript `Number`.
    pub block_daa_score: u64,
}

// ─── Multisig Script Info ────────────────────────────────────────────

/// Parsed multisig script: M-of-N with extracted pubkeys
#[derive(Debug, Clone)]
/// Detected M-of-N multisig parameters from a script.
pub struct MultisigInfo {
    pub m: u8, // required signatures
    pub n: u8, // total pubkeys
    pub pubkeys: [[u8; 32]; MAX_MULTISIG_KEYS],
}

impl Default for MultisigInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl MultisigInfo {
    pub fn new() -> Self {
        Self {
            m: 0,
            n: 0,
            pubkeys: [[0u8; 32]; MAX_MULTISIG_KEYS],
        }
    }
}

/// Script type detected from scriptPublicKey
#[derive(Debug, Clone, Copy, PartialEq)]
/// Detected script type (P2PK, P2SH, multisig, or unknown).
pub enum ScriptType {
    /// Standard P2PK Schnorr: OP_DATA_32 <pubkey> OP_CHECKSIG
    P2PK,
    /// P2SH: OP_BLAKE2B OP_DATA_32 <script_hash> OP_EQUAL
    P2SH,
    /// M-of-N multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
    Multisig,
    /// Unknown/unsupported script
    Unknown,
}

/// Parse a scriptPublicKey and detect its type
pub fn detect_script_type(script: &[u8], len: usize) -> ScriptType {
    if is_p2pk_script(script, len) {
        return ScriptType::P2PK;
    }
    if is_p2sh_script(script, len) {
        return ScriptType::P2SH;
    }
    if is_multisig_script(script, len) {
        return ScriptType::Multisig;
    }
    ScriptType::Unknown
}

fn is_p2pk_script(script: &[u8], len: usize) -> bool {
    len == 34 && script.first() == Some(&OP_DATA_32) && script.get(33) == Some(&OP_CHECKSIG)
}

fn is_p2sh_script(script: &[u8], len: usize) -> bool {
    len == 35
        && script.first() == Some(&OP_BLAKE2B)
        && script.get(1) == Some(&OP_DATA_32)
        && script.get(34) == Some(&OP_EQUAL)
}

/// A multisig redeem script within this model's key capacity.
fn signer_multisig(script: &[u8], len: usize) -> Option<multisig_script::MultisigScript<'_>> {
    multisig_script::parse(script.get(..len)?)
        .filter(|parsed| usize::from(parsed.key_count()) <= MAX_MULTISIG_KEYS)
}

fn is_multisig_script(script: &[u8], len: usize) -> bool {
    signer_multisig(script, len).is_some()
}

/// Parse a multisig scriptPublicKey, extracting M, N, and pubkeys.
/// Returns None if not a valid multisig script.
pub fn parse_multisig_script(script: &[u8], len: usize) -> Option<MultisigInfo> {
    let parsed = signer_multisig(script, len)?;
    let mut info = MultisigInfo::new();
    info.m = parsed.threshold();
    info.n = parsed.key_count();
    for (slot, key) in info.pubkeys.iter_mut().zip(parsed.keys()) {
        *slot = key;
    }
    Some(info)
}
