//! KIP-22 pay-to-public-key-hash wallets: P2SH over `<P> OP_CHECKSIG`, derived
//! at m/22'/111111'/account'/change/address_index on every network. The chain
//! sees only the script hash until the first spend reveals the key.

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::primitives::address::{p2pk_script, p2sh_script, script_hash, script_to_p2sh_address};

use super::bip32::{derive_child, derive_path, Bip32Error, ExtendedPrivKey, HARDENED_BIT};

const PURPOSE: u32 = 22 + HARDENED_BIT;
const COIN_TYPE: u32 = 111_111 + HARDENED_BIT;

/// Byte length of a KIP-22 redeem script.
pub const REDEEM_SCRIPT_LEN: usize = 34;

/// Addresses per chain searched when recognizing a wallet's own script. A signer
/// reviewing a transaction runs this for every output, so it stays small; an
/// output beyond it is shown as a payment rather than hidden as change.
pub const OWNERSHIP_SCAN_DEPTH: u32 = 20;

/// Which BIP44 chain an address belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chain {
    Receive,
    Change,
}

impl Chain {
    #[must_use]
    pub const fn index(self) -> u32 {
        match self {
            Self::Receive => 0,
            Self::Change => 1,
        }
    }
}

/// `<P> OP_CHECKSIG`, byte-identical to a P2PK script over the same key.
#[must_use]
pub fn redeem_script(xonly: &[u8; 32]) -> [u8; REDEEM_SCRIPT_LEN] {
    p2pk_script(xonly)
}

/// Whether `script` has the shape of a KIP-22 redeem script.
#[must_use]
pub fn is_redeem_script(script: &[u8]) -> bool {
    script.len() == REDEEM_SCRIPT_LEN && script[0] == 0x20 && script[33] == 0xac
}

/// The P2SH script hash committed to on chain for `xonly`.
#[must_use]
pub fn redeem_script_hash(xonly: &[u8; 32]) -> [u8; 32] {
    script_hash(&redeem_script(xonly))
}

/// The P2SH address for `xonly` under a Kaspa address prefix.
#[must_use]
pub fn address(xonly: &[u8; 32], prefix: &str) -> String {
    script_to_p2sh_address(&redeem_script(xonly), prefix)
}

/// Derive the account key at m/22'/111111'/account'.
pub fn derive_account_key(seed: &[u8; 64], account: u32) -> Result<ExtendedPrivKey, Bip32Error> {
    if account >= HARDENED_BIT {
        return Err(Bip32Error::InvalidKey);
    }
    derive_path(seed, &[PURPOSE, COIN_TYPE, account + HARDENED_BIT])
}

/// Derive the key at change/address_index below a KIP-22 account key.
pub fn derive_address_key(
    account: &ExtendedPrivKey,
    chain: Chain,
    index: u32,
) -> Result<ExtendedPrivKey, Bip32Error> {
    if index >= HARDENED_BIT {
        return Err(Bip32Error::InvalidKey);
    }
    derive_child(&derive_child(account, chain.index())?, index)
}

/// Find the chain and index whose P2SH script is `script_public_key`, proving an
/// output belongs to this account without trusting any host-supplied hint.
pub fn find_owned_script(
    account: &ExtendedPrivKey,
    script_public_key: &[u8],
    checkpoint: &mut (impl FnMut() + ?Sized),
) -> Option<(Chain, u32)> {
    for chain in [Chain::Change, Chain::Receive] {
        for index in 0..OWNERSHIP_SCAN_DEPTH {
            checkpoint();
            let xonly = derive_address_key(account, chain, index)
                .ok()?
                .public_key_x_only()
                .ok()?;
            if p2sh_script(&redeem_script_hash(&xonly)).as_slice() == script_public_key {
                return Some((chain, index));
            }
        }
    }
    None
}

#[cfg(test)]
#[path = "unit_tests/kip22.rs"]
mod unit_tests;
