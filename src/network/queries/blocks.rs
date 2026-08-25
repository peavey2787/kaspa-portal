use crate::network::{client::NetworkClient, codec::requests, wrpc::operation::Operation};

pub async fn get_raw(client: &NetworkClient, hash: &[u8; 32]) -> Result<Vec<u8>, String> {
    client
        .call(
            Operation::GetBlock,
            &requests::block::encode_get_block(hash),
        )
        .await
        .map_err(String::from)
}
