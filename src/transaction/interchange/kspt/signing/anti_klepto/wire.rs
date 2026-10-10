//! Host verification entry points over compact KSPT wire bytes.

use crate::transaction::{
    interchange::kspt::decode_compact_kspt,
    signing::anti_klepto::protocol::{Commitment, Signed},
};

use super::{validate_host_commitment, verify_host_transcript, AntiKleptoVerifyError};

/// [`validate_host_commitment`] for the request's compact KSPT bytes.
pub fn validate_host_commitment_wire(
    original: &[u8],
    commitment: &Commitment<'_>,
) -> Result<(), AntiKleptoVerifyError> {
    validate_host_commitment(&decode_compact_kspt(original)?, commitment)
}

/// [`verify_host_transcript`] for the request's and response's compact KSPT bytes.
pub fn verify_host_transcript_wire(
    original: &[u8],
    signed: &[u8],
    commitment: &Commitment<'_>,
    signed_message: &Signed<'_>,
    host_secret: &[u8; 32],
) -> Result<(), AntiKleptoVerifyError> {
    verify_host_transcript(
        &decode_compact_kspt(original)?,
        &decode_compact_kspt(signed)?,
        commitment,
        signed_message,
        host_secret,
    )
}
