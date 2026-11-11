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
    annotations::{Covenant, Derivation, Ms45Derivation},
    script::ScriptPublicKey,
};

// ─── Transaction Output ───────────────────────────────────────────────

/// Transaction output
#[derive(Debug, Clone)]
/// A transaction output: amount + destination script.
pub struct TransactionOutput {
    pub value: u64, // sompi
    pub script_public_key: ScriptPublicKey,
    /// Covenant binding (KIP-20, tx version >= 1)
    pub covenant: Option<Covenant>,
    /// Optional non-authoritative wallet derivation hint supplied by the watcher.
    /// The signer must independently derive and match the actual output before
    /// classifying it as wallet-owned or change. Branch 0=receive, 1=change.
    pub derivation_hint: Option<Derivation>,
    /// Coordinated-multisig derivation claim from an output
    /// `bip32Derivations` map. It is advisory until a loaded descriptor
    /// reproduces the actual output script hash.
    pub ms45_hint: Option<Ms45Derivation>,
}

impl TransactionOutput {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            value: 0,
            script_public_key: ScriptPublicKey::new(),
            covenant: None,
            derivation_hint: None,
            ms45_hint: None,
        }
    }
}
