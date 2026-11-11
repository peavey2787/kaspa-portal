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

//! A digest of everything an owner approves and nothing a signer adds.

use super::Transaction;
use crate::primitives::hash::{Blake2b256, Hash32};
use crate::transaction::model::{
    Covenant, CovenantExecution, Derivation, Ms45Derivation, ScriptPublicKey, TransactionInput,
    TransactionOutput,
};

const REVIEW_DOMAIN: &[u8] = b"KaspaPortalTransactionReview";

impl Transaction {
    /// Commit to every field a review shows or a signature covers: the
    /// network, version, each input with the coin it spends, its redeem script
    /// and its hints, each output with its covenant and hints, locktime,
    /// subnetwork, gas, payload and stealth tweak. Signatures are left out, so
    /// the digest stays fixed while signers add them. A signer that keeps the
    /// digest an owner approved can refuse a transaction that changed since.
    #[must_use]
    pub fn review_digest(&self) -> Hash32 {
        let mut hasher = Blake2b256::keyed(REVIEW_DOMAIN);
        hasher
            .update(&[self.network as u8])
            .update(&self.version.to_le_bytes());
        absorb_len(&mut hasher, self.num_inputs);
        for (index, input) in self.inputs().iter().enumerate() {
            absorb_input(&mut hasher, input, self.redeem_bytes(index));
        }
        absorb_len(&mut hasher, self.num_outputs);
        for output in self.outputs() {
            absorb_output(&mut hasher, output);
        }
        hasher
            .update(&self.locktime.to_le_bytes())
            .update(&self.subnetwork_id)
            .update(&self.gas.to_le_bytes());
        absorb_bytes(&mut hasher, &self.payload);
        self.stealth_tweak.absorb(&mut hasher);
        hasher.finalize()
    }
}

fn absorb_len(hasher: &mut Blake2b256, len: usize) {
    hasher.update(&u64::try_from(len).unwrap_or(u64::MAX).to_le_bytes());
}

fn absorb_bytes(hasher: &mut Blake2b256, bytes: &[u8]) {
    absorb_len(hasher, bytes.len());
    hasher.update(bytes);
}

fn absorb_input(hasher: &mut Blake2b256, input: &TransactionInput, redeem: &[u8]) {
    hasher
        .update(&input.previous_outpoint.transaction_id)
        .update(&input.previous_outpoint.index.to_le_bytes())
        .update(&input.sequence.to_le_bytes())
        .update(&[input.sig_op_count, input.sighash_type])
        .update(&input.utxo_entry.amount.to_le_bytes());
    input.utxo_entry.script_public_key.absorb(hasher);
    absorb_bytes(hasher, redeem);
    input.derivation_hint.absorb(hasher);
    input.ms45_hint.absorb(hasher);
    input.covenant_execution.absorb(hasher);
}

fn absorb_output(hasher: &mut Blake2b256, output: &TransactionOutput) {
    hasher.update(&output.value.to_le_bytes());
    output.script_public_key.absorb(hasher);
    output.covenant.absorb(hasher);
    output.derivation_hint.absorb(hasher);
    output.ms45_hint.absorb(hasher);
}

/// A reviewed fact written unambiguously into the review digest.
trait Absorb {
    fn absorb(&self, hasher: &mut Blake2b256);
}

impl<T: Absorb> Absorb for Option<T> {
    fn absorb(&self, hasher: &mut Blake2b256) {
        match self {
            None => {
                hasher.update(&[0]);
            }
            Some(value) => {
                hasher.update(&[1]);
                value.absorb(hasher);
            }
        }
    }
}

impl Absorb for [u8; 32] {
    fn absorb(&self, hasher: &mut Blake2b256) {
        hasher.update(self);
    }
}

impl Absorb for ScriptPublicKey {
    fn absorb(&self, hasher: &mut Blake2b256) {
        hasher.update(&self.version.to_le_bytes());
        absorb_bytes(hasher, self.script_bytes());
    }
}

impl Absorb for Derivation {
    fn absorb(&self, hasher: &mut Blake2b256) {
        hasher
            .update(&[self.branch])
            .update(&self.index.to_le_bytes());
    }
}

impl Absorb for Ms45Derivation {
    fn absorb(&self, hasher: &mut Blake2b256) {
        hasher
            .update(&self.cosigner.to_le_bytes())
            .update(&self.chain.to_le_bytes())
            .update(&self.index.to_le_bytes());
    }
}

impl Absorb for CovenantExecution {
    fn absorb(&self, hasher: &mut Blake2b256) {
        hasher
            .update(&self.supplied_mask.to_le_bytes())
            .update(&self.supplied_true_mask.to_le_bytes());
    }
}

impl Absorb for Covenant {
    fn absorb(&self, hasher: &mut Blake2b256) {
        hasher
            .update(&self.authorizing_input.to_le_bytes())
            .update(&self.id);
    }
}
