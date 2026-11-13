use crate::{
    network::{client::NetworkClient, codec::responses::submission, wrpc::operation::Operation},
    transaction::{broadcast::encoder, consensus::ConsensusTransaction},
};

pub async fn submit(
    client: &NetworkClient,
    transaction: &ConsensusTransaction,
) -> Result<String, String> {
    let payload = encoder::encode_submit_request(transaction, false).map_err(String::from)?;
    let response = call(client, Operation::SubmitTransaction, &payload).await?;
    submission::decode(&response).map_err(String::from)
}

/// Submit `transaction` in place of the mempool transaction it double-spends,
/// such as a send stuck below the market feerate. The node accepts it only
/// when it pays a higher feerate than everything it replaces, and returns the
/// new transaction id.
pub async fn submit_replacement(
    client: &NetworkClient,
    transaction: &ConsensusTransaction,
) -> Result<String, String> {
    let payload = encoder::encode_replacement_request(transaction).map_err(String::from)?;
    let response = call(client, Operation::SubmitTransactionReplacement, &payload).await?;
    submission::decode_replacement(&response).map_err(String::from)
}

async fn call(
    client: &NetworkClient,
    operation: Operation,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    client.call(operation, payload).await.map_err(String::from)
}
