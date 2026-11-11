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

use super::{
    annotations::{CovenantExecution, Derivation, Ms45Derivation},
    constants::{Hash256, MAX_SCRIPT_SIZE},
    script::UtxoEntry,
    signatures::{IncomingPartialSig, InputSig, SignatureSlots},
};

// ─── Outpoint ─────────────────────────────────────────────────────────

/// Reference to a previous output (transaction ID + index)
#[derive(Debug, Clone)]
/// A transaction outpoint: previous tx ID + output index.
pub struct Outpoint {
    pub transaction_id: Hash256,
    pub index: u32,
}

/// Transaction input with support for multiple signatures (multisig)
#[derive(Debug, Clone)]
/// A transaction input: references a UTXO and provides a signature.
pub struct TransactionInput {
    pub previous_outpoint: Outpoint,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub utxo_entry: UtxoEntry,
    /// Signatures — up to MAX_SIGS_PER_INPUT for multisig
    pub sigs: SignatureSlots<InputSig>,
    /// Sighash policy requested by the PSKT input. Signed slots record the
    /// actual sighash byte alongside each signature.
    pub sighash_type: u8,
    /// P2SH redeem script (the actual multisig script inside the P2SH wrapper).
    /// For scripts <= 256 bytes, stored inline here.
    /// For scripts > 256 bytes (covenants), stored in Transaction::redeem_pool.
    pub redeem_script: [u8; MAX_SCRIPT_SIZE],
    pub redeem_script_len: usize,
    /// Byte offset into Transaction::redeem_pool when this input's redeem
    /// script lives there instead of in the inline redeem_script array.
    pub redeem_pool_offset: Option<u16>,
    /// Partial signatures carried in an incoming PSKT, keyed by full pubkey.
    /// Preserved byte-for-byte on re-serialization so counterparty signers
    /// see the same PSKT they sent, plus our additions. Empty for KSPT flow.
    pub incoming_partial_sigs: SignatureSlots<IncomingPartialSig>,
    /// Untrusted standard-account receive/change path hint carried by KSPT v4.
    /// The signer must derive this exact child and verify its x-only public key
    /// matches the input script before using it.
    pub derivation_hint: Option<Derivation>,
    /// 45' address path extracted from `bip32Derivations`, if present.
    pub ms45_hint: Option<Ms45Derivation>,
    /// Explicit witness selector assignment proving the covenant execution branch.
    pub covenant_execution: Option<CovenantExecution>,
}

impl TransactionInput {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            previous_outpoint: Outpoint {
                transaction_id: [0u8; 32],
                index: 0,
            },
            sequence: 0,
            sig_op_count: 1,
            utxo_entry: UtxoEntry {
                amount: 0,
                script_public_key: super::script::ScriptPublicKey::new(),
                block_daa_score: 0,
            },
            sigs: SignatureSlots::new(),
            sighash_type: 0,
            redeem_script: [0u8; MAX_SCRIPT_SIZE],
            redeem_script_len: 0,
            redeem_pool_offset: None,
            incoming_partial_sigs: SignatureSlots::new(),
            derivation_hint: None,
            ms45_hint: None,
            covenant_execution: None,
        }
    }
}
