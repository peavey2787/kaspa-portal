use crate::network::{
    client::NetworkClient,
    codec::{requests, responses},
    model::fee_estimate::FeeEstimate,
    wrpc::operation::Operation,
};

pub async fn get(client: &NetworkClient) -> Result<FeeEstimate, String> {
    let response = client
        .call(Operation::GetFeeEstimate, &requests::fee::encode())
        .await
        .map_err(String::from)?;
    responses::fee::decode(&response).map_err(String::from)
}
