//! PSKT signature merge and UI status helpers.

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::transaction::model::{
    IncomingPartialSig, SignatureSlots, Transaction, TransactionInput,
};

use super::PskError;

/// After `sign_transaction_multisig` or `sign_transaction_multi_addr`
/// has populated `inp.sigs[]` with new signatures tagged by
/// `pubkey_compressed`, promote them into `inp.incoming_partial_sigs[]`
/// ready for PSKT emission.
///
/// Merging rules:
///   - Existing entries in `incoming_partial_sigs` (from a PSKT that
///     arrived partially signed) are preserved.
///   - Each new entry from `sigs[]` with a non-zero
///     `pubkey_compressed` is inserted — unless a matching pubkey
///     already exists. An identical signature is idempotent; different bytes
///     for the same public key are a hard conflict and abort the merge.
///   - After insertion, the slot array is sorted by pubkey byte order
///     so emission matches `kaspa-wallet-pskt`'s BTreeMap iteration.
///
/// If the fixed signature capacity is already full, the merge fails instead
/// of silently dropping a signature. The complete retained set is sorted by
/// public key only after a successful merge.
///
/// Does not mutate `sigs[]` — KSPT emission on the same tx still works
/// if the caller picks that path instead. Designed to be idempotent:
/// calling this twice is a no-op on the second call.
/// The input's incoming partial signatures with its new `sigs[]` merged in.
fn merged_partial_sigs(
    input: &TransactionInput,
) -> Result<SignatureSlots<IncomingPartialSig>, PskError> {
    let mut merged = input.incoming_partial_sigs.clone();
    let original = merged.len();
    for slot in input.sigs.iter() {
        if slot.pubkey_compressed == [0u8; 33] {
            continue;
        }
        match merged
            .iter()
            .find(|entry| entry.pubkey == slot.pubkey_compressed)
        {
            Some(entry) if entry.signature != slot.signature => {
                return Err(PskError::SignatureConflict)
            }
            Some(_) => continue,
            None => {}
        }
        if !merged.push(IncomingPartialSig {
            pubkey: slot.pubkey_compressed,
            signature: slot.signature,
        }) {
            return Err(PskError::TooManyPartialSigs);
        }
    }
    if merged.len() != original {
        merged.sort_unstable_by_key(|entry| entry.pubkey);
    }
    Ok(merged)
}

pub fn move_ksp_sigs_to_pskt(tx: &mut Transaction) -> Result<(), PskError> {
    // Merge every input into a copy first so a late conflict or capacity
    // error cannot leave the transaction half-merged.
    let merged = tx.inputs[..tx.num_inputs]
        .iter()
        .map(merged_partial_sigs)
        .collect::<Result<Vec<_>, _>>()?;
    for (input, sigs) in tx.inputs.iter_mut().zip(merged) {
        input.incoming_partial_sigs = sigs;
    }
    Ok(())
}

/// Return `(cryptographically_valid, required)` for incoming standard-PSKT
/// partial signatures. Invalid, misbound, duplicate, or wrong-sighash entries
/// contribute zero; structural parsing never promotes them to valid progress.
pub fn pskt_signature_status(tx: &Transaction) -> (u32, u32) {
    crate::transaction::signature_verification::pskt_status(tx)
}
