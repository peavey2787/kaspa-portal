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

// Stable Kaspa sighash facade.

mod blake2b;
mod components;
mod digest;
mod signing;

pub use blake2b::{blake2b_hash, KaspaBlake2b};
pub use digest::calculate_sighash;
pub use signing::{sign_input, sign_input_with_entropy};

#[cfg(test)]
use crate::transaction::model::*;

#[cfg(test)]
#[path = "unit-tests/sighash_tests.rs"]
pub mod unit_tests;
