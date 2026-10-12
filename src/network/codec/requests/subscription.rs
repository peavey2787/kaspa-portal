use crate::network::{
    codec::{primitives::WireWriter, requests::address::write_address},
    error::NetworkError,
    wrpc::{
        operation::Operation,
        request::{self, WrpcRequest},
    },
};

/// rusty-kaspa `notify::scope::Scope` variant indices. The wRPC Subscribe body
/// is `u16` version 1 followed by the Borsh-encoded `Scope` enum: a `u8`
/// variant index, then that variant's Borsh fields (no version, no length).
#[derive(Clone, Copy)]
enum SubscriptionScope {
    BlockAdded = 0,
    UtxosChanged = 4,
    VirtualDaaScoreChanged = 6,
}

fn encode_subscription_payload(scope: SubscriptionScope, fields: &[u8]) -> Vec<u8> {
    let mut payload = WireWriter::new();
    payload.write_u16(1);
    payload.write_u8(scope as u8);
    payload.write_raw(fields);
    payload.into_vec()
}

fn encode_subscription_request(
    request_id: u64,
    scope: SubscriptionScope,
    fields: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    let payload = encode_subscription_payload(scope, fields);
    request::encode(&WrpcRequest {
        id: request_id,
        operation: Operation::Subscribe,
        payload: &payload,
    })
}

/// Encode the BlockAdded subscription body without the outer request envelope.
/// The transport assigns the live request id and can therefore replay this body
/// after reconnecting.
pub fn block_added_payload() -> Result<Vec<u8>, NetworkError> {
    Ok(encode_subscription_payload(
        SubscriptionScope::BlockAdded,
        &[],
    ))
}

pub fn block_added(request_id: u64) -> Result<Vec<u8>, NetworkError> {
    encode_subscription_request(request_id, SubscriptionScope::BlockAdded, &[])
}

/// Encode a UtxosChanged subscription body for `addresses` (replayable).
pub fn utxos_changed_payload(addresses: &[String]) -> Result<Vec<u8>, NetworkError> {
    Ok(encode_subscription_payload(
        SubscriptionScope::UtxosChanged,
        &utxos_changed_fields(addresses)?,
    ))
}

/// Borsh `UtxosChangedScope { addresses: Vec<Address> }`.
fn utxos_changed_fields(addresses: &[String]) -> Result<Vec<u8>, NetworkError> {
    let mut fields = WireWriter::new();
    fields.write_count(addresses.len())?;
    for address in addresses {
        write_address(&mut fields, address)?;
    }
    Ok(fields.into_vec())
}

/// Encode a VirtualDaaScoreChanged subscription body (replayable).
pub fn virtual_daa_score_changed_payload() -> Result<Vec<u8>, NetworkError> {
    Ok(encode_subscription_payload(
        SubscriptionScope::VirtualDaaScoreChanged,
        &[],
    ))
}

pub fn utxos_changed(address: &str, request_id: u64) -> Result<Vec<u8>, NetworkError> {
    encode_subscription_request(
        request_id,
        SubscriptionScope::UtxosChanged,
        &utxos_changed_fields(&[address.to_owned()])?,
    )
}
