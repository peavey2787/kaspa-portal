//! Verify-once PSKT/KSPT pipeline.
//!
//! A PSKT is parsed, schema-checked and authorized exactly once; finalizers
//! serialize the typed [`VerifiedTransaction`] that came out of that single
//! pass and never reparse the source. Compact KSPT crosses the signer
//! boundary under explicit grammar [`Limits`] chosen by the caller.

#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
mod compact;
mod relay;
mod relay_fields;
mod schema_validate;
mod specialized;
mod verified;
mod verified_finalize;
mod wire;

use crate::{
    primitives::address::KaspaNetwork,
    transaction::interchange::kspt::wire::{Derivation, Limits, FLAG_SIGNED_OR_COMPLETE},
};

pub use verified::{
    VerifiedCovenantRoute, VerifiedInput, VerifiedOutput, VerifiedSignature, VerifiedTransaction,
    VerifiedWitnessPlan,
};
pub use wire::{MAX_PSKT_JSON_BYTES, MAX_PSKT_WIRE_HEX_CHARS};

/// Translate a PSKT/PSKB into the compact KSPT the signer reviews.
pub fn encode_pskt(
    pskt_hex: &str,
    network: KaspaNetwork,
    limits: Limits,
) -> Result<Vec<u8>, String> {
    relay::encode_pskt(pskt_hex, network, limits)
}

/// Verify a signed KSPT against its original PSKT and merge the signatures.
pub fn merge_signed_kspt(
    original_pskt_hex: &str,
    signed_kspt: &[u8],
    network: KaspaNetwork,
    limits: Limits,
) -> Result<String, String> {
    compact::validate_and_merge(original_pskt_hex, signed_kspt, network, limits)
}

/// Whether every input carries enough cryptographically valid signatures.
pub fn is_complete(pskt_hex: &str, network: KaspaNetwork, limits: Limits) -> Result<bool, String> {
    relay::is_complete(pskt_hex, network, limits)
}

/// Count of cryptographically valid signatures per input.
pub fn verified_signature_counts(
    pskt_hex: &str,
    network: KaspaNetwork,
    limits: Limits,
) -> Result<Vec<u8>, String> {
    relay::verified_signature_counts(pskt_hex, network, limits)
}

/// Finalize a complete PSKT into consensus JSON from its single verified parse.
pub fn finalize_json(pskt_hex: &str, limits: Limits) -> Result<String, String> {
    let transaction = relay::verify_complete_transaction(pskt_hex, KaspaNetwork::Mainnet, limits)?;
    let verified = verified::from_compact(transaction)?;
    verified_finalize::finalize_json(&verified)
}

/// Record the signer's receive/change derivation for one input.
pub fn attach_input_derivation(
    pskt_hex: &str,
    input_index: usize,
    derivation: Derivation,
) -> Result<String, String> {
    wire::attach_input_derivation(pskt_hex, input_index, derivation)
}

/// Record the signer's receive/change derivation for one output.
pub fn attach_output_derivation(
    pskt_hex: &str,
    output_index: usize,
    derivation: Derivation,
) -> Result<String, String> {
    wire::attach_output_derivation(pskt_hex, output_index, derivation)
}

/// Parse the inner ASCII-hex PSKT JSON body with the exact canonical grammar.
pub fn decode_json_body(body_hex: &[u8]) -> Result<serde_json::Value, String> {
    wire::decode_json_body_hex(body_hex)
}

/// Encode the inner PSKT JSON body only if it satisfies the canonical grammar.
pub fn encode_json_body(root: &serde_json::Value) -> Result<Vec<u8>, String> {
    wire::encode_json_body_hex(root)
}

/// Verify every signature and completion invariant of a compact KSPT and
/// return the exact typed transaction and witness plan that was authorized.
///
/// Raw covenant KSPT is refused: specialized proofs live only in the
/// original PSKT, so covenant spends must be merged and finalized from it.
pub fn verify_complete_kspt(data: &[u8], limits: Limits) -> Result<VerifiedTransaction, String> {
    let transaction = compact::parse(data, limits)?;
    if transaction.flags != FLAG_SIGNED_OR_COMPLETE {
        return Err("Compact KSPT is not marked fully signed".to_string());
    }
    if transaction.inputs.iter().any(|input| {
        !input.redeem.is_empty() && relay_fields::parse_multisig_redeem(&input.redeem).is_none()
    }) {
        return Err(
            "Raw covenant KSPT broadcast is disabled; merge the signed KSPT into its original PSKT so the typed covenant witness plan can be verified"
                .to_string(),
        );
    }
    if !compact::verified_complete(&transaction)? {
        return Err("Compact KSPT is not cryptographically complete".to_string());
    }
    verified::from_compact(transaction)
}

/// Verify a complete PSKT once and return its typed authorized form.
pub fn verify_complete_pskt(
    pskt_hex: &str,
    network: KaspaNetwork,
    limits: Limits,
) -> Result<VerifiedTransaction, String> {
    let transaction = relay::verify_complete_transaction(pskt_hex, network, limits)?;
    verified::from_compact(transaction)
}

#[cfg(test)]
pub(crate) mod test_support {
    /// The KasKold signer capacity these vectors were written against.
    pub(crate) const SIGNER_TEST_LIMITS: crate::transaction::interchange::kspt::wire::Limits =
        crate::transaction::interchange::kspt::wire::Limits::new(32, 8, 768);

    pub(crate) use super::relay_fields::{
        find_pubkey_position, parse_ms45, parse_multisig_redeem, InputFields,
    };
    pub(crate) use super::wire::{
        decode, document, encode, parse_derivation, Format, MAX_PSKT_WIRE_HEX_CHARS,
    };

    pub(crate) fn sighash_all_for_pskt(
        pskt_hex: &str,
        network: crate::primitives::address::KaspaNetwork,
        input_index: usize,
    ) -> Result<[u8; 32], String> {
        super::compact::test_sighash_all_for_pskt(pskt_hex, network, input_index)
    }

    pub(crate) fn compact_covenant_execution_for_test(
        data: &[u8],
        input_index: usize,
    ) -> Result<Option<(u16, u16)>, String> {
        let transaction = super::compact::parse(
            data,
            crate::transaction::interchange::kspt::wire::Limits::grammar(),
        )?;
        transaction
            .inputs
            .get(input_index)
            .map(|input| input.covenant_execution)
            .ok_or_else(|| "KSPT input index out of range".to_string())
    }
}

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
