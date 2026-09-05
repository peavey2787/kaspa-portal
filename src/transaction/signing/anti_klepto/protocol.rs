//! Canonical v1 host-assisted anti-klepto transaction-signing wire protocol.
//!
//! The v1 framing uses 32-bit transaction lengths, proof counts, and input
//! indices. `kaspa-portal` 1.0.1 accepts this canonical format only; historical
//! application framing is intentionally not part of the SDK surface.

use sha2::{Digest, Sha256};

pub use crate::crypto::anti_klepto::{host_scalar_material, SESSION_ID_LEN};

pub const MAGIC: [u8; 4] = *b"KAKP";
pub const VERSION: u8 = 1;
pub const HASH_LEN: usize = 32;

const HEADER_LEN: usize = 4 + 1 + 1 + SESSION_ID_LEN;
const REVEAL_LEN: usize = HEADER_LEN + HASH_LEN;
const REQUEST_FIXED_LEN: usize = HEADER_LEN + HASH_LEN + HASH_LEN + 4;
const COMMITMENT_FIXED_LEN: usize = HEADER_LEN + HASH_LEN + 4;
const COMMITMENT_RECORD_LEN: usize = 4 + 1 + 33 + 33;
const SIGNED_FIXED_LEN: usize = HEADER_LEN + HASH_LEN + 4;
const SIGNATURE_PROOF_LEN: usize = 4 + 1;
const HOST_COMMIT_DOMAIN: &[u8] = b"KaspaPortal/anti-klepto/host-commit/v1";
const TX_DIGEST_DOMAIN: &[u8] = b"KaspaPortal/anti-klepto/tx/v1";
const SESSION_DOMAIN: &[u8] = b"KaspaPortal/anti-klepto/session/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    Request = 1,
    Commitment = 2,
    Reveal = 3,
    Signed = 4,
}

impl MessageKind {
    fn from_byte(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::Request),
            2 => Ok(Self::Commitment),
            3 => Ok(Self::Reveal),
            4 => Ok(Self::Signed),
            _ => Err(WireError::WrongKind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion,
    WrongKind,
    InvalidLength,
    TooManyProofs,
    OutputTooSmall,
    SessionMismatch,
    TransactionMismatch,
    HostCommitmentMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub version: u8,
    pub kind: MessageKind,
    pub session_id: [u8; SESSION_ID_LEN],
}

#[derive(Debug)]
pub struct Request<'a> {
    pub session_id: [u8; SESSION_ID_LEN],
    pub host_commitment: [u8; HASH_LEN],
    pub transaction_digest: [u8; HASH_LEN],
    pub transaction: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonceCommitment {
    pub input_index: u32,
    pub signature_slot: u8,
    pub public_key: [u8; 33],
    pub nonce_point: [u8; 33],
}

#[derive(Debug)]
pub struct Commitment<'a> {
    pub session_id: [u8; SESSION_ID_LEN],
    pub transaction_digest: [u8; HASH_LEN],
    record_bytes: &'a [u8],
    count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureProof {
    pub input_index: u32,
    pub signature_slot: u8,
}

#[derive(Debug)]
pub struct Signed<'a> {
    pub session_id: [u8; SESSION_ID_LEN],
    pub transaction_digest: [u8; HASH_LEN],
    proof_bytes: &'a [u8],
    proof_count: usize,
    pub transaction: &'a [u8],
}

pub fn is_message(input: &[u8]) -> bool {
    input.len() >= HEADER_LEN && input[..4] == MAGIC && input[4] == VERSION
}

pub fn host_commitment(host_secret: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    domain_hash(HOST_COMMIT_DOMAIN, &[host_secret])
}

pub fn transaction_digest(transaction: &[u8]) -> [u8; HASH_LEN] {
    domain_hash(TX_DIGEST_DOMAIN, &[transaction])
}

pub fn session_id(commitment: &[u8; HASH_LEN], tx_digest: &[u8; HASH_LEN]) -> [u8; SESSION_ID_LEN] {
    let digest = domain_hash(SESSION_DOMAIN, &[commitment, tx_digest]);
    let mut session = [0u8; SESSION_ID_LEN];
    session.copy_from_slice(&digest[..SESSION_ID_LEN]);
    session
}

pub fn verify_host_secret(
    expected_commitment: &[u8; HASH_LEN],
    host_secret: &[u8; HASH_LEN],
) -> bool {
    crate::primitives::bytes::constant_time_eq_32(
        expected_commitment,
        &host_commitment(host_secret),
    )
}

pub fn encode_request(
    host_secret: &[u8; HASH_LEN],
    transaction: &[u8],
    output: &mut [u8],
) -> Result<usize, WireError> {
    let tx_len = u32::try_from(transaction.len()).map_err(|_| WireError::InvalidLength)?;
    let needed = REQUEST_FIXED_LEN
        .checked_add(transaction.len())
        .ok_or(WireError::InvalidLength)?;
    ensure_output(output, needed)?;

    let host_commit = host_commitment(host_secret);
    let tx_digest = transaction_digest(transaction);
    let session = session_id(&host_commit, &tx_digest);
    write_header(output, MessageKind::Request, &session)?;
    output[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(&host_commit);
    output[HEADER_LEN + 32..HEADER_LEN + 64].copy_from_slice(&tx_digest);
    output[HEADER_LEN + 64..REQUEST_FIXED_LEN].copy_from_slice(&tx_len.to_le_bytes());
    output[REQUEST_FIXED_LEN..needed].copy_from_slice(transaction);
    Ok(needed)
}

pub fn parse_request(input: &[u8]) -> Result<Request<'_>, WireError> {
    let header = parse_header(input, MessageKind::Request)?;
    if input.len() < REQUEST_FIXED_LEN {
        return Err(WireError::Truncated);
    }
    let host_commitment_value = array32(&input[HEADER_LEN..HEADER_LEN + 32]);
    let transaction_digest_value = array32(&input[HEADER_LEN + 32..HEADER_LEN + 64]);
    let transaction_len = read_u32(&input[HEADER_LEN + 64..REQUEST_FIXED_LEN])?;
    let transaction = exact_tail(input, REQUEST_FIXED_LEN, transaction_len)?;
    validate_request_binding(
        &header,
        &host_commitment_value,
        &transaction_digest_value,
        transaction,
    )?;
    Ok(Request {
        session_id: header.session_id,
        host_commitment: host_commitment_value,
        transaction_digest: transaction_digest_value,
        transaction,
    })
}

fn validate_request_binding(
    header: &Header,
    host_commitment_value: &[u8; HASH_LEN],
    transaction_digest_value: &[u8; HASH_LEN],
    transaction: &[u8],
) -> Result<(), WireError> {
    if transaction_digest(transaction) != *transaction_digest_value {
        return Err(WireError::TransactionMismatch);
    }
    if session_id(host_commitment_value, transaction_digest_value) != header.session_id {
        return Err(WireError::SessionMismatch);
    }
    Ok(())
}

pub fn encode_commitment(
    session: &[u8; SESSION_ID_LEN],
    tx_digest: &[u8; HASH_LEN],
    records: &[NonceCommitment],
    output: &mut [u8],
) -> Result<usize, WireError> {
    let count = nonzero_count(records.len())?;
    let records_len = records
        .len()
        .checked_mul(COMMITMENT_RECORD_LEN)
        .ok_or(WireError::InvalidLength)?;
    let needed = COMMITMENT_FIXED_LEN
        .checked_add(records_len)
        .ok_or(WireError::InvalidLength)?;
    ensure_output(output, needed)?;

    write_header(output, MessageKind::Commitment, session)?;
    output[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(tx_digest);
    output[HEADER_LEN + 32..COMMITMENT_FIXED_LEN].copy_from_slice(&count.to_le_bytes());
    for (index, record) in records.iter().enumerate() {
        write_commitment_record(record, &mut output[commitment_record_range(index)])?;
    }
    Ok(needed)
}

pub fn parse_commitment(input: &[u8]) -> Result<Commitment<'_>, WireError> {
    let header = parse_header(input, MessageKind::Commitment)?;
    if input.len() < COMMITMENT_FIXED_LEN {
        return Err(WireError::Truncated);
    }
    let transaction_digest = array32(&input[HEADER_LEN..HEADER_LEN + 32]);
    let count = read_u32(&input[HEADER_LEN + 32..COMMITMENT_FIXED_LEN])?;
    if count == 0 {
        return Err(WireError::TooManyProofs);
    }
    let records_len = count
        .checked_mul(COMMITMENT_RECORD_LEN)
        .ok_or(WireError::InvalidLength)?;
    if COMMITMENT_FIXED_LEN.checked_add(records_len) != Some(input.len()) {
        return Err(WireError::InvalidLength);
    }
    Ok(Commitment {
        session_id: header.session_id,
        transaction_digest,
        record_bytes: &input[COMMITMENT_FIXED_LEN..],
        count,
    })
}

impl Commitment<'_> {
    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn record(&self, index: usize) -> Option<NonceCommitment> {
        if index >= self.count {
            return None;
        }
        Some(read_commitment_record(
            &self.record_bytes[index * COMMITMENT_RECORD_LEN..(index + 1) * COMMITMENT_RECORD_LEN],
        ))
    }
}

pub fn encode_reveal(
    session: &[u8; SESSION_ID_LEN],
    host_secret: &[u8; HASH_LEN],
    output: &mut [u8],
) -> Result<usize, WireError> {
    ensure_output(output, REVEAL_LEN)?;
    write_header(output, MessageKind::Reveal, session)?;
    output[HEADER_LEN..REVEAL_LEN].copy_from_slice(host_secret);
    Ok(REVEAL_LEN)
}

pub fn parse_reveal(input: &[u8]) -> Result<([u8; SESSION_ID_LEN], [u8; HASH_LEN]), WireError> {
    let header = parse_header(input, MessageKind::Reveal)?;
    if input.len() != REVEAL_LEN {
        return Err(WireError::InvalidLength);
    }
    Ok((header.session_id, array32(&input[HEADER_LEN..REVEAL_LEN])))
}

pub fn encode_signed(
    session: &[u8; SESSION_ID_LEN],
    tx_digest: &[u8; HASH_LEN],
    proofs: &[SignatureProof],
    transaction: &[u8],
    output: &mut [u8],
) -> Result<usize, WireError> {
    let count = nonzero_count(proofs.len())?;
    let tx_len = u32::try_from(transaction.len()).map_err(|_| WireError::InvalidLength)?;
    let proofs_len = proofs
        .len()
        .checked_mul(SIGNATURE_PROOF_LEN)
        .ok_or(WireError::InvalidLength)?;
    let length_offset = SIGNED_FIXED_LEN
        .checked_add(proofs_len)
        .ok_or(WireError::InvalidLength)?;
    let tx_start = length_offset
        .checked_add(4)
        .ok_or(WireError::InvalidLength)?;
    let needed = tx_start
        .checked_add(transaction.len())
        .ok_or(WireError::InvalidLength)?;
    ensure_output(output, needed)?;

    write_header(output, MessageKind::Signed, session)?;
    output[HEADER_LEN..HEADER_LEN + 32].copy_from_slice(tx_digest);
    output[HEADER_LEN + 32..SIGNED_FIXED_LEN].copy_from_slice(&count.to_le_bytes());
    for (index, proof) in proofs.iter().enumerate() {
        let start = SIGNED_FIXED_LEN + index * SIGNATURE_PROOF_LEN;
        output[start..start + 4].copy_from_slice(&proof.input_index.to_le_bytes());
        output[start + 4] = proof.signature_slot;
    }
    output[length_offset..tx_start].copy_from_slice(&tx_len.to_le_bytes());
    output[tx_start..needed].copy_from_slice(transaction);
    Ok(needed)
}

pub fn parse_signed(input: &[u8]) -> Result<Signed<'_>, WireError> {
    let header = parse_header(input, MessageKind::Signed)?;
    if input.len() < SIGNED_FIXED_LEN {
        return Err(WireError::Truncated);
    }
    let transaction_digest = array32(&input[HEADER_LEN..HEADER_LEN + 32]);
    let proof_count = read_u32(&input[HEADER_LEN + 32..SIGNED_FIXED_LEN])?;
    if proof_count == 0 {
        return Err(WireError::TooManyProofs);
    }
    let proofs_len = proof_count
        .checked_mul(SIGNATURE_PROOF_LEN)
        .ok_or(WireError::InvalidLength)?;
    let length_offset = SIGNED_FIXED_LEN
        .checked_add(proofs_len)
        .ok_or(WireError::InvalidLength)?;
    let tx_start = length_offset
        .checked_add(4)
        .ok_or(WireError::InvalidLength)?;
    if tx_start > input.len() {
        return Err(WireError::Truncated);
    }
    let transaction_len = read_u32(&input[length_offset..tx_start])?;
    let transaction = exact_tail(input, tx_start, transaction_len)?;
    Ok(Signed {
        session_id: header.session_id,
        transaction_digest,
        proof_bytes: &input[SIGNED_FIXED_LEN..length_offset],
        proof_count,
        transaction,
    })
}

impl Signed<'_> {
    pub const fn proof_count(&self) -> usize {
        self.proof_count
    }

    pub fn proof(&self, index: usize) -> Option<SignatureProof> {
        if index >= self.proof_count {
            return None;
        }
        let offset = index * SIGNATURE_PROOF_LEN;
        let bytes = &self.proof_bytes[offset..offset + SIGNATURE_PROOF_LEN];
        Some(SignatureProof {
            input_index: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            signature_slot: bytes[4],
        })
    }
}

fn parse_header(input: &[u8], expected: MessageKind) -> Result<Header, WireError> {
    if input.len() < HEADER_LEN {
        return Err(WireError::Truncated);
    }
    if input[..4] != MAGIC {
        return Err(WireError::InvalidMagic);
    }
    if input[4] != VERSION {
        return Err(WireError::UnsupportedVersion);
    }
    let kind = MessageKind::from_byte(input[5])?;
    if kind != expected {
        return Err(WireError::WrongKind);
    }
    let mut session_id = [0u8; SESSION_ID_LEN];
    session_id.copy_from_slice(&input[6..HEADER_LEN]);
    Ok(Header {
        version: VERSION,
        kind,
        session_id,
    })
}

fn write_header(
    output: &mut [u8],
    kind: MessageKind,
    session_id: &[u8; SESSION_ID_LEN],
) -> Result<(), WireError> {
    ensure_output(output, HEADER_LEN)?;
    output[..4].copy_from_slice(&MAGIC);
    output[4] = VERSION;
    output[5] = kind as u8;
    output[6..HEADER_LEN].copy_from_slice(session_id);
    Ok(())
}

fn write_commitment_record(record: &NonceCommitment, output: &mut [u8]) -> Result<(), WireError> {
    ensure_output(output, COMMITMENT_RECORD_LEN)?;
    output[..4].copy_from_slice(&record.input_index.to_le_bytes());
    output[4] = record.signature_slot;
    output[5..38].copy_from_slice(&record.public_key);
    output[38..71].copy_from_slice(&record.nonce_point);
    Ok(())
}

fn read_commitment_record(bytes: &[u8]) -> NonceCommitment {
    let mut public_key = [0u8; 33];
    public_key.copy_from_slice(&bytes[5..38]);
    let mut nonce_point = [0u8; 33];
    nonce_point.copy_from_slice(&bytes[38..71]);
    NonceCommitment {
        input_index: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        signature_slot: bytes[4],
        public_key,
        nonce_point,
    }
}

fn commitment_record_range(index: usize) -> core::ops::Range<usize> {
    let start = COMMITMENT_FIXED_LEN + index * COMMITMENT_RECORD_LEN;
    start..start + COMMITMENT_RECORD_LEN
}

fn nonzero_count(count: usize) -> Result<u32, WireError> {
    if count == 0 {
        return Err(WireError::TooManyProofs);
    }
    u32::try_from(count).map_err(|_| WireError::TooManyProofs)
}

fn exact_tail(input: &[u8], start: usize, length: usize) -> Result<&[u8], WireError> {
    start
        .checked_add(length)
        .filter(|end| *end == input.len())
        .map(|end| &input[start..end])
        .ok_or(WireError::InvalidLength)
}

fn ensure_output(output: &[u8], needed: usize) -> Result<(), WireError> {
    if output.len() < needed {
        Err(WireError::OutputTooSmall)
    } else {
        Ok(())
    }
}

fn domain_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn array32(bytes: &[u8]) -> [u8; 32] {
    let mut value = [0u8; 32];
    value.copy_from_slice(bytes);
    value
}

fn read_u32(input: &[u8]) -> Result<usize, WireError> {
    if input.len() < 4 {
        return Err(WireError::Truncated);
    }
    usize::try_from(u32::from_le_bytes([input[0], input[1], input[2], input[3]]))
        .map_err(|_| WireError::InvalidLength)
}

#[cfg(test)]
#[path = "unit-tests/anti_klepto_tests.rs"]
mod anti_klepto_tests;
