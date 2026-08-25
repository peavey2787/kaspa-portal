const KSTL_SUBNETWORK_ID_HEX: &str = "4b53544c00000000000000000000000000000000";
const KSTL_GAS: u64 = 0;
const KSTL_TRANSACTION_VERSION: u16 = 1;
const STEALTH_PROOF_VERSION: u8 = 1;
const STEALTH_PROOF_LENGTH: usize = 34;

/// Contract-level sequence-commit lane data.
///
/// This type intentionally contains no transaction mutation logic. Callers can
/// hand it to the transaction API to stamp the lane onto a PSKB wire value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceCommitProof {
    pub subnetwork_id_hex: &'static str,
    pub gas: u64,
    pub transaction_version: u16,
    pub payload: [u8; STEALTH_PROOF_LENGTH],
}

/// Construct the canonical KSTL stealth sequence-commit proof payload.
#[must_use]
pub fn stealth_proof(ephemeral_public_key: &[u8; 32], view_tag: u8) -> SequenceCommitProof {
    let mut payload = [0u8; STEALTH_PROOF_LENGTH];
    payload[0] = STEALTH_PROOF_VERSION;
    payload[1..33].copy_from_slice(ephemeral_public_key);
    payload[33] = view_tag;
    SequenceCommitProof {
        subnetwork_id_hex: KSTL_SUBNETWORK_ID_HEX,
        gas: KSTL_GAS,
        transaction_version: KSTL_TRANSACTION_VERSION,
        payload,
    }
}
