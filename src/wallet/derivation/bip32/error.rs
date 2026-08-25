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

// ─── Errores ──────────────────────────────────────────────────────────

/// Errors during HD key derivation (BIP32).
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum Bip32Error {
    /// Derived private key is zero or >= curve order
    #[error("invalid BIP32 private key")]
    InvalidKey,
    /// Invalid chain code
    #[error("invalid BIP32 chain code")]
    InvalidChainCode,
    /// Error parsing key with k256
    #[error("BIP32 elliptic-curve operation failed")]
    CurveError,
    /// Empty derivation path
    #[error("BIP32 derivation path is empty")]
    EmptyPath,
}
