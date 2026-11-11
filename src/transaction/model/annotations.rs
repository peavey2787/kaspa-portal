//! Optional facts a coordinator attaches to inputs and outputs.
//!
//! Each one is either wholly present or wholly absent, so a model can never
//! hold half of one. Every hint is untrusted: the signer re-derives and matches
//! it before relying on it.

use serde::{Deserialize, Serialize};

/// Standard-account path hint `/branch/index` beneath the account key.
/// Branch 0 is receive, 1 is change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Derivation {
    pub branch: u8,
    pub index: u32,
}

/// Coordinated-multisig path beneath `m/45'/111111'/account'`, written
/// `/cosigner/chain/index`. The signer must still prove the derived public key
/// is in the redeem script before signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ms45Derivation {
    pub cosigner: u32,
    pub chain: u32,
    pub index: u32,
}

/// The complete selector assignment that chooses a covenant input's path.
/// Signers and finalizers act only on this; branch names are never consulted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CovenantExecution {
    pub supplied_mask: u16,
    pub supplied_true_mask: u16,
}

impl CovenantExecution {
    /// A selector can be assigned true only if it was supplied at all.
    #[must_use]
    pub const fn is_well_formed(self) -> bool {
        self.supplied_true_mask & !self.supplied_mask == 0
    }
}

/// KIP-20 covenant binding of an output (transaction version 1 and later).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Covenant {
    pub authorizing_input: u16,
    pub id: [u8; 32],
}
