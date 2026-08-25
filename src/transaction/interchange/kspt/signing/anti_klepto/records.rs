use crate::transaction::signing::anti_klepto::protocol::{NonceCommitment, SignatureProof};

use crate::{
    crypto::{anti_klepto as crypto, schnorr::SchnorrSignature},
    transaction::model::Transaction,
};

use crate::transaction::interchange::kspt::PsktError;

pub fn nonce_commitment_records(
    tx: &Transaction,
    initial_counts: &[u8],
) -> Result<alloc::vec::Vec<NonceCommitment>, PsktError> {
    let mut records = alloc::vec::Vec::new();
    for input_index in 0..tx.num_inputs {
        let input = tx
            .inputs
            .get(input_index)
            .ok_or(PsktError::InvalidSignatureState)?;
        let start = usize::from(
            *initial_counts
                .get(input_index)
                .ok_or(PsktError::InvalidSignatureState)?,
        );
        let end = usize::from(input.sig_count);
        let signatures = input
            .sigs
            .get(start..end)
            .ok_or(PsktError::InvalidSignatureState)?;
        for (slot, sig) in (start..end).zip(signatures.iter()) {
            if !sig.present || sig.pubkey_compressed[0] == 0 {
                return Err(PsktError::InvalidSignatureState);
            }
            let provisional = SchnorrSignature {
                bytes: sig.signature,
            };
            let mut canonical_public_key = [0u8; 33];
            canonical_public_key[0] = 0x02;
            canonical_public_key[1..].copy_from_slice(&sig.pubkey_compressed[1..]);
            records.push(NonceCommitment {
                input_index: u32::try_from(input_index).map_err(|_| PsktError::TooManyInputs)?,
                signature_slot: slot as u8,
                public_key: canonical_public_key,
                nonce_point: crypto::provisional_nonce_point(&provisional),
            });
        }
    }
    if records.is_empty() {
        Err(PsktError::NoInputs)
    } else {
        Ok(records)
    }
}

pub fn proof_records(
    tx: &Transaction,
    initial_counts: &[u8],
) -> Result<alloc::vec::Vec<SignatureProof>, PsktError> {
    let mut proofs = alloc::vec::Vec::new();
    for input_index in 0..tx.num_inputs {
        let input = tx
            .inputs
            .get(input_index)
            .ok_or(PsktError::InvalidSignatureState)?;
        let start = usize::from(
            *initial_counts
                .get(input_index)
                .ok_or(PsktError::InvalidSignatureState)?,
        );
        let end = usize::from(input.sig_count);
        let signatures = input
            .sigs
            .get(start..end)
            .ok_or(PsktError::InvalidSignatureState)?;
        for (slot, sig) in (start..end).zip(signatures.iter()) {
            if !sig.present {
                return Err(PsktError::InvalidSignatureState);
            }
            proofs.push(SignatureProof {
                input_index: u32::try_from(input_index).map_err(|_| PsktError::TooManyInputs)?,
                signature_slot: slot as u8,
            });
        }
    }
    if proofs.is_empty() {
        Err(PsktError::NoInputs)
    } else {
        Ok(proofs)
    }
}
