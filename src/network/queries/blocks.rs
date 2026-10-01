use crate::network::{
    client::NetworkClient,
    codec::{requests, responses},
    wrpc::{block_added::OwnedBlockAddedNotification, operation::Operation},
};

/// Blocks (with transactions) the node has accepted past `low_hash`.
pub async fn since(
    client: &NetworkClient,
    low_hash: &[u8; 32],
) -> Result<Vec<OwnedBlockAddedNotification>, String> {
    let response = client
        .call(
            Operation::GetBlocks,
            &requests::block::encode_get_blocks(low_hash),
        )
        .await
        .map_err(String::from)?;
    responses::blocks::decode(&response).map_err(String::from)
}

pub async fn get_raw(client: &NetworkClient, hash: &[u8; 32]) -> Result<Vec<u8>, String> {
    client
        .call(
            Operation::GetBlock,
            &requests::block::encode_get_block(hash),
        )
        .await
        .map_err(String::from)
}
