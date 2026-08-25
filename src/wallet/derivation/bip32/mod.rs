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

//! BIP32 hierarchical deterministic key derivation.
//!
//! Key representations, derivation operations, paths, address lookup, and
//! scalar arithmetic live in single-purpose modules.

mod address_lookup;
mod child;
mod constants;
mod error;
mod extended_private;
mod extended_public;
mod paths;
mod scalar;

pub use address_lookup::{
    find_address_index_for_pubkey, AddrPubkeyTable, ADDR_SCAN_DEPTH, SIGN_MATCH_DEPTH,
};
pub use child::{derive_child, derive_child_pub, master_key_from_seed};
pub use constants::{CACHED_ADDR_COUNT, KASPA_MAINNET_PATH, KASPA_TESTNET_PATH};
pub use error::Bip32Error;
pub use extended_private::{compressed_pubkey_from_raw_key, pubkey_from_raw_key, ExtendedPrivKey};
pub use extended_public::ExtendedPubKey;
pub use paths::{
    derive_account_key, derive_address_key, derive_change_key, derive_multisig_account_key,
    derive_multisig_address_key, derive_path, derive_path_for_index, AccountKeyDerivation,
};

#[cfg(test)]
use crate::wallet::derivation::hmac::hmac_sha512;
#[cfg(test)]
use constants::{BITCOIN_SEED, HARDENED_BIT, SECP256K1_ORDER};
#[cfg(test)]
use k256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
#[cfg(test)]
use scalar::{is_less_than_order, is_zero, scalar_add_mod_n};

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
pub mod unit_tests;
