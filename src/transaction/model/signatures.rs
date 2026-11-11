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

use core::ops::{Deref, DerefMut};

use super::constants::MAX_SIGS_PER_INPUT;

const _: () = assert!(MAX_SIGS_PER_INPUT <= u8::MAX as usize);

/// A signature record with an all-zero value for unused storage.
pub trait EmptySlot: Copy {
    const EMPTY: Self;
}

/// The signatures one input carries, in the order they were added, up to
/// [`MAX_SIGS_PER_INPUT`].
///
/// The slice view holds exactly the added signatures, so a record is either
/// carried or unreachable: there is no separate count or presence flag to
/// disagree with it. Unused storage is kept wiped.
#[derive(Clone, Debug)]
pub struct SignatureSlots<T> {
    slots: [T; MAX_SIGS_PER_INPUT],
    len: u8,
}

impl<T: EmptySlot> SignatureSlots<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [T::EMPTY; MAX_SIGS_PER_INPUT],
            len: 0,
        }
    }

    /// Number of signatures carried, which always fits a wire count byte.
    #[must_use]
    pub const fn count(&self) -> u8 {
        self.len
    }

    #[must_use]
    pub fn is_full(&self) -> bool {
        usize::from(self.len) == MAX_SIGS_PER_INPUT
    }

    /// Append a signature, or refuse it when every slot is taken.
    #[must_use]
    pub fn push(&mut self, value: T) -> bool {
        let Some(slot) = self.slots.get_mut(usize::from(self.len)) else {
            return false;
        };
        *slot = value;
        self.len += 1;
        true
    }

    /// Keep the first `len` signatures, dropping and wiping the rest. Keeping
    /// more than are carried changes nothing.
    pub fn truncate(&mut self, len: u8) {
        let kept = self.len.min(len);
        self.slots[usize::from(kept)..].fill(T::EMPTY);
        self.len = kept;
    }

    /// Drop every signature and wipe the storage it used.
    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Carry exactly one signature.
    pub fn replace_with(&mut self, value: T) {
        self.clear();
        self.slots[0] = value;
        self.len = 1;
    }
}

impl<T: EmptySlot> Default for SignatureSlots<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Deref for SignatureSlots<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.slots[..usize::from(self.len)]
    }
}

impl<T> DerefMut for SignatureSlots<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.slots[..usize::from(self.len)]
    }
}

/// A signature attached to a transaction input.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct InputSig {
    pub signature: [u8; 64],
    pub sighash_type: u8,
    /// Position in the multisig public key list (0-based), 0 for P2PK.
    pub pubkey_pos: u8,
    /// 33-byte compressed secp256k1 pubkey that produced this signature.
    /// Populated by the account signers in `interchange/kspt/signing/` and
    /// needed only by the standard PSKT serializer. KSPT emission ignores it
    /// because KSPT identifies signers by `pubkey_pos` alone. All zero when
    /// the signer is not known.
    pub pubkey_compressed: [u8; 33],
}

impl EmptySlot for InputSig {
    const EMPTY: Self = Self {
        signature: [0u8; 64],
        sighash_type: 0,
        pubkey_pos: 0,
        pubkey_compressed: [0u8; 33],
    };
}

/// A partial signature received in an incoming PSKT, keyed by full pubkey.
///
/// Unlike `InputSig` (which is positional in the multisig redeem script),
/// `IncomingPartialSig` carries the full 33-byte compressed pubkey so the
/// signer can identify its own contribution and round-trip foreign partial
/// sigs without losing them. Only a PSKT payload populates these.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct IncomingPartialSig {
    /// 33-byte compressed secp256k1 public key.
    /// PSKT `partialSigs` is keyed by this.
    pub pubkey: [u8; 33],
    /// 64-byte Schnorr signature.
    pub signature: [u8; 64],
}

impl EmptySlot for IncomingPartialSig {
    const EMPTY: Self = Self {
        pubkey: [0u8; 33],
        signature: [0u8; 64],
    };
}
