use crate::network::{codec::primitives::WireReader, error::NetworkError};

use super::response::{self, ResponseKind};

/// Kaspa wRPC operation code for a `BlockAddedNotification`.
pub const BLOCK_ADDED_NOTIFICATION_OPERATION: u8 = 60;

const MAX_WRPC_BLOB_BYTES: usize = 32 * 1024 * 1024;
const MAX_BLOCK_TRANSACTIONS: usize = 1_000_000;
const MAX_PARENT_LEVELS: usize = 1_024;
const MAX_PARENTS_PER_LEVEL: usize = 65_536;

const SERIALIZER_VERSION_V1: u16 = 1;
const NOTIFICATION_VARIANT_BLOCK_ADDED: u16 = 0;

/// A transaction observed in a Kaspa `BlockAdded` notification.
///
/// The application payload borrows directly from the notification frame so the
/// Portal boundary does not allocate/copy every transaction payload in a block.
#[derive(Clone, Debug)]
pub struct BlockAddedTransaction<'a> {
    pub transaction_id: Option<String>,
    pub payload: &'a [u8],
}

/// Public, transport-safe view of a Kaspa `BlockAdded` notification.
#[derive(Clone, Debug)]
pub struct BlockAddedNotification<'a> {
    pub block_hash: String,
    pub daa_score: u64,
    pub transactions: Vec<BlockAddedTransaction<'a>>,
}

/// Owned BlockAdded transaction returned by the high-level NetworkApi.
#[derive(Clone, Debug)]
pub struct OwnedBlockAddedTransaction {
    pub transaction_id: Option<String>,
    pub payload: Vec<u8>,
}

/// Owned BlockAdded notification returned by the high-level NetworkApi.
#[derive(Clone, Debug)]
pub struct OwnedBlockAddedNotification {
    pub block_hash: String,
    pub daa_score: u64,
    pub transactions: Vec<OwnedBlockAddedTransaction>,
}

impl From<BlockAddedNotification<'_>> for OwnedBlockAddedNotification {
    fn from(value: BlockAddedNotification<'_>) -> Self {
        Self {
            block_hash: value.block_hash,
            daa_score: value.daa_score,
            transactions: value
                .transactions
                .into_iter()
                .map(|transaction| OwnedBlockAddedTransaction {
                    transaction_id: transaction.transaction_id,
                    payload: transaction.payload.to_vec(),
                })
                .collect(),
        }
    }
}

/// Decode one raw wRPC frame as a Kaspa `BlockAdded` notification.
///
/// Kaspa wRPC transports `Serializable<Notification>`. The exact nesting is:
///
/// `Payload<Notification>` -> `Notification(v1, BlockAdded=0)` ->
/// `Payload<BlockAddedNotification>` -> `BlockAddedNotification(v1)` ->
/// `Payload<RpcBlock>` -> `RpcBlock(v1, ...)`.
///
/// `Ok(None)` means the frame is another notification operation. RPC responses
/// are rejected because response routing belongs to the Portal driver, not the
/// notification consumer.
pub fn decode(frame: &[u8]) -> Result<Option<BlockAddedNotification<'_>>, NetworkError> {
    let decoded = response::decode(frame)?;
    if decoded.id.is_some() {
        return Err(NetworkError::UnexpectedResponse(
            "Kaspa RPC response reached BlockAdded notification decoder".into(),
        ));
    }
    match decoded.kind {
        ResponseKind::Notification => {}
        ResponseKind::Error(code) => {
            return Err(NetworkError::RemoteError(format!(
                "BlockAdded notification kind={code}"
            )))
        }
        ResponseKind::Success => {
            return Err(NetworkError::UnexpectedResponse(
                "Kaspa server message without request id was not marked as a notification".into(),
            ))
        }
    }
    if decoded.raw_operation != Some(BLOCK_ADDED_NOTIFICATION_OPERATION) {
        return Ok(None);
    }

    // wRPC registers notifications as `Serializable<kaspa_rpc_core::Notification>`.
    // `Serializable<T>` is Borsh-encoded as workflow_serializer's length-prefixed
    // `Payload<T>` wrapper.
    let notification = decode_exact_payload(decoded.payload, "Notification")?;
    let mut notification_reader = WireReader::new(notification);
    expect_u16_version(&mut notification_reader, "Notification")?;
    let variant = notification_reader.read_u16()?;
    if variant != NOTIFICATION_VARIANT_BLOCK_ADDED {
        return Err(NetworkError::InvalidEncoding(format!(
            "BlockAdded operation carried Notification variant {variant}"
        )));
    }

    // Notification::BlockAdded uses serialize!(BlockAddedNotification, ...), so
    // the variant body is another workflow_serializer Payload.
    let block_added = notification_reader.read_bytes(MAX_WRPC_BLOB_BYTES)?;
    require_empty(&notification_reader, "Notification")?;

    let mut block_added_reader = WireReader::new(block_added);
    expect_u16_version(&mut block_added_reader, "BlockAddedNotification")?;
    let block = block_added_reader.read_bytes(MAX_WRPC_BLOB_BYTES)?;
    require_empty(&block_added_reader, "BlockAddedNotification")?;

    decode_rpc_block(block).map(Some)
}

fn decode_exact_payload<'a>(data: &'a [u8], label: &str) -> Result<&'a [u8], NetworkError> {
    let mut reader = WireReader::new(data);
    let payload = reader.read_bytes(MAX_WRPC_BLOB_BYTES)?;
    require_empty(&reader, label)?;
    Ok(payload)
}

fn expect_u16_version(reader: &mut WireReader<'_>, label: &str) -> Result<(), NetworkError> {
    let version = reader.read_u16()?;
    if version != SERIALIZER_VERSION_V1 {
        return Err(NetworkError::InvalidEncoding(format!(
            "unsupported {label} serializer version {version}"
        )));
    }
    Ok(())
}

fn require_empty(reader: &WireReader<'_>, label: &str) -> Result<(), NetworkError> {
    if reader.remaining().is_empty() {
        Ok(())
    } else {
        Err(NetworkError::InvalidEncoding(format!(
            "trailing bytes after {label}"
        )))
    }
}

fn decode_rpc_block(block: &[u8]) -> Result<BlockAddedNotification<'_>, NetworkError> {
    let mut reader = WireReader::new(block);
    expect_u16_version(&mut reader, "RpcBlock")?;

    // RpcBlock uses serialize!(RpcHeader), serialize!(Vec<RpcTransaction>), then
    // serialize!(Option<RpcBlockVerboseData>). We only need header identity and
    // transaction payloads, but still consume the final verbose payload so the
    // wire layout is validated end-to-end.
    let header = reader.read_bytes(MAX_WRPC_BLOB_BYTES)?;
    let transactions = reader.read_bytes(MAX_WRPC_BLOB_BYTES)?;
    let _block_verbose = reader.read_bytes(MAX_WRPC_BLOB_BYTES)?;
    require_empty(&reader, "RpcBlock")?;

    let (block_hash, daa_score) = decode_rpc_header_identity(header)?;

    // workflow_serializer::Serializer for Vec<V> stores a u32 count, then each
    // item as a length-prefixed Payload<V>.
    let mut tx_reader = WireReader::new(transactions);
    let count = usize::try_from(tx_reader.read_u32()?).map_err(|_| NetworkError::InvalidLength)?;
    if count > MAX_BLOCK_TRANSACTIONS {
        return Err(NetworkError::InvalidEncoding(
            "Kaspa BlockAdded transaction count exceeds safety bound".into(),
        ));
    }

    let mut decoded_transactions = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let transaction = tx_reader.read_bytes(MAX_WRPC_BLOB_BYTES)?;
        decoded_transactions.push(decode_live_transaction(transaction)?);
    }
    require_empty(&tx_reader, "Vec<RpcTransaction>")?;

    Ok(BlockAddedNotification {
        block_hash,
        daa_score,
        transactions: decoded_transactions,
    })
}

fn decode_rpc_header_identity(header: &[u8]) -> Result<(String, u64), NetworkError> {
    let mut reader = WireReader::new(header);
    expect_u16_version(&mut reader, "RpcHeader")?;
    let block_hash = hex::encode(reader.read_exact(32)?);
    let _header_version = reader.read_u16()?;

    // parents_by_level is Borsh Vec<Vec<Hash>> (not a workflow Payload blob).
    skip_borsh_hash_levels(&mut reader)?;

    reader.read_exact(32)?; // hash merkle root
    reader.read_exact(32)?; // accepted-id merkle root
    reader.read_exact(32)?; // UTXO commitment
    reader.read_u64()?; // timestamp
    reader.read_u32()?; // bits
    reader.read_u64()?; // nonce
    let daa_score = reader.read_u64()?;
    reader.read_exact(24)?; // blue work (Uint192)
    reader.read_u64()?; // blue score
    reader.read_exact(32)?; // pruning point
    require_empty(&reader, "RpcHeader")?;

    Ok((block_hash, daa_score))
}

fn skip_borsh_hash_levels(reader: &mut WireReader<'_>) -> Result<(), NetworkError> {
    let levels = usize::try_from(reader.read_u32()?).map_err(|_| NetworkError::InvalidLength)?;
    if levels > MAX_PARENT_LEVELS {
        return Err(NetworkError::InvalidEncoding(
            "Kaspa header parent-level count exceeds safety bound".into(),
        ));
    }
    for _ in 0..levels {
        let parents =
            usize::try_from(reader.read_u32()?).map_err(|_| NetworkError::InvalidLength)?;
        if parents > MAX_PARENTS_PER_LEVEL {
            return Err(NetworkError::InvalidEncoding(
                "Kaspa header parent count exceeds safety bound".into(),
            ));
        }
        let bytes = parents.checked_mul(32).ok_or(NetworkError::InvalidLength)?;
        reader.read_exact(bytes)?;
    }
    Ok(())
}

fn decode_live_transaction(transaction: &[u8]) -> Result<BlockAddedTransaction<'_>, NetworkError> {
    let mut reader = WireReader::new(transaction);
    expect_u16_version(&mut reader, "RpcTransaction")?;
    let _transaction_version = reader.read_u16()?;
    reader.read_bytes(MAX_WRPC_BLOB_BYTES)?; // serialize!(Vec<RpcTransactionInput>)
    reader.read_bytes(MAX_WRPC_BLOB_BYTES)?; // serialize!(Vec<RpcTransactionOutput>)
    reader.read_u64()?; // lock time
    reader.read_exact(20)?; // subnetwork id
    reader.read_u64()?; // gas
    let payload = reader.read_bytes(MAX_WRPC_BLOB_BYTES)?; // Borsh Vec<u8>
    reader.read_u64()?; // storage mass
    let verbose = reader.read_bytes(MAX_WRPC_BLOB_BYTES)?; // serialize!(Option<RpcTransactionVerboseData>)
    require_empty(&reader, "RpcTransaction")?;

    Ok(BlockAddedTransaction {
        transaction_id: transaction_id_from_verbose(verbose),
        payload,
    })
}

fn transaction_id_from_verbose(optional: &[u8]) -> Option<String> {
    let mut option = WireReader::new(optional);
    match option.read_u8().ok()? {
        0 => None,
        1 => {
            // workflow_serializer::Serializer for Option<T> stores tag=1 then
            // a Payload<T>. RpcTransactionVerboseData begins with u8 version 1
            // followed by the 32-byte transaction id.
            let verbose = option.read_bytes(MAX_WRPC_BLOB_BYTES).ok()?;
            if !option.remaining().is_empty() {
                return None;
            }
            let mut verbose_reader = WireReader::new(verbose);
            if verbose_reader.read_u8().ok()? != 1 {
                return None;
            }
            let transaction_id = hex::encode(verbose_reader.read_exact(32).ok()?);
            verbose_reader.read_exact(32).ok()?; // transaction hash
            verbose_reader.read_u64().ok()?; // compute mass
            verbose_reader.read_exact(32).ok()?; // block hash
            verbose_reader.read_u64().ok()?; // block time
            if !verbose_reader.remaining().is_empty() {
                return None;
            }
            Some(transaction_id)
        }
        _ => None,
    }
}
