use crate::{
    network::{client::NetworkClient, codec::responses::submission, wrpc::operation::Operation},
    transaction::{broadcast::encoder, consensus::ConsensusTransaction},
};

pub async fn submit(
    client: &NetworkClient,
    transaction: &ConsensusTransaction,
) -> Result<String, String> {
    let payload = encoder::encode_submit_request(transaction, false).map_err(String::from)?;
    let response = client
        .call(Operation::SubmitTransaction, &payload)
        .await
        .map_err(String::from)?;
    submission::decode(&response).map_err(String::from)
}
