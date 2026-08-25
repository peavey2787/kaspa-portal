use crate::network::{
    client::NetworkClient,
    codec::{requests, responses},
    wrpc::operation::Operation,
};

pub async fn virtual_daa_score(client: &NetworkClient) -> Result<u64, String> {
    let response = client
        .call(
            Operation::GetBlockDagInfo,
            &requests::block::encode_empty_query(),
        )
        .await
        .map_err(String::from)?;
    responses::dag::virtual_daa_score(&response).map_err(String::from)
}
