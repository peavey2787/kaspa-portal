//! Decoded Kaspa wRPC notifications that Portal subscribers can receive.

use crate::{
    network::{
        codec::{primitives::WireReader, responses::utxo::decode_entries},
        error::NetworkError,
    },
    primitives::utxo::UtxoEntry,
};

use super::{
    block_added::{
        self, decode_exact_payload, expect_u16_version, require_empty, OwnedBlockAddedNotification,
        BLOCK_ADDED_NOTIFICATION_OPERATION,
    },
    response::{self, ResponseKind},
};

/// Kaspa wRPC operation code for a `UtxosChangedNotification`.
pub const UTXOS_CHANGED_NOTIFICATION_OPERATION: u8 = 64;
/// Kaspa wRPC operation code for a `VirtualDaaScoreChangedNotification`.
pub const VIRTUAL_DAA_SCORE_CHANGED_NOTIFICATION_OPERATION: u8 = 66;

const MAX_WRPC_BLOB_BYTES: usize = 32 * 1024 * 1024;
const NOTIFICATION_VARIANT_UTXOS_CHANGED: u16 = 4;
const NOTIFICATION_VARIANT_VIRTUAL_DAA_SCORE_CHANGED: u16 = 6;

/// Outputs added to and removed from subscribed addresses by one virtual change.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UtxosChangedNotification {
    pub added: Vec<UtxoEntry>,
    pub removed: Vec<UtxoEntry>,
}

/// A decoded notification delivered on a Portal subscription.
#[derive(Clone, Debug)]
pub enum Notification {
    BlockAdded(OwnedBlockAddedNotification),
    UtxosChanged(UtxosChangedNotification),
    VirtualDaaScoreChanged(u64),
}

/// Decode one raw wRPC frame as a supported notification. `Ok(None)` means a
/// notification kind Portal does not expose; RPC responses are rejected.
pub fn decode(frame: &[u8]) -> Result<Option<Notification>, NetworkError> {
    let decoded = response::decode(frame)?;
    if decoded.id.is_some() || !matches!(decoded.kind, ResponseKind::Notification) {
        return Err(NetworkError::UnexpectedResponse(
            "Kaspa RPC response reached the notification decoder".into(),
        ));
    }
    match decoded.raw_operation {
        Some(BLOCK_ADDED_NOTIFICATION_OPERATION) => {
            Ok(block_added::decode(frame)?.map(|block| Notification::BlockAdded(block.into())))
        }
        Some(UTXOS_CHANGED_NOTIFICATION_OPERATION) => {
            let body = variant_body(decoded.payload, NOTIFICATION_VARIANT_UTXOS_CHANGED)?;
            decode_utxos_changed(body).map(|value| Some(Notification::UtxosChanged(value)))
        }
        Some(VIRTUAL_DAA_SCORE_CHANGED_NOTIFICATION_OPERATION) => {
            let body = variant_body(
                decoded.payload,
                NOTIFICATION_VARIANT_VIRTUAL_DAA_SCORE_CHANGED,
            )?;
            decode_virtual_daa_score(body)
                .map(|score| Some(Notification::VirtualDaaScoreChanged(score)))
        }
        _ => Ok(None),
    }
}

/// Unwrap `Payload<Notification>` -> `Notification(v1, variant)` -> body bytes.
fn variant_body(payload: &[u8], expected_variant: u16) -> Result<&[u8], NetworkError> {
    let notification = decode_exact_payload(payload, "Notification")?;
    let mut reader = WireReader::new(notification);
    expect_u16_version(&mut reader, "Notification")?;
    let variant = reader.read_u16()?;
    if variant != expected_variant {
        return Err(NetworkError::InvalidEncoding(format!(
            "notification operation carried Notification variant {variant}"
        )));
    }
    let body = reader.read_bytes(MAX_WRPC_BLOB_BYTES)?;
    require_empty(&reader, "Notification")?;
    Ok(body)
}

fn decode_utxos_changed(body: &[u8]) -> Result<UtxosChangedNotification, NetworkError> {
    let mut reader = WireReader::new(body);
    expect_u16_version(&mut reader, "UtxosChangedNotification")?;
    let added = decode_entries(reader.read_bytes(MAX_WRPC_BLOB_BYTES)?)?;
    let removed = decode_entries(reader.read_bytes(MAX_WRPC_BLOB_BYTES)?)?;
    require_empty(&reader, "UtxosChangedNotification")?;
    Ok(UtxosChangedNotification { added, removed })
}

fn decode_virtual_daa_score(body: &[u8]) -> Result<u64, NetworkError> {
    let mut reader = WireReader::new(body);
    expect_u16_version(&mut reader, "VirtualDaaScoreChangedNotification")?;
    let score = reader.read_u64()?;
    require_empty(&reader, "VirtualDaaScoreChangedNotification")?;
    Ok(score)
}
