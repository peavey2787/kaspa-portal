use crate::{
    network::{
        client::NetworkClient,
        codec::{requests::utxo, responses},
        wrpc::operation::Operation,
    },
    primitives::utxo::UtxoEntry,
};

pub async fn fetch_for_address(
    client: &NetworkClient,
    address: &str,
) -> Result<Vec<UtxoEntry>, String> {
    fetch_for_addresses(client, &[address.to_owned()]).await
}

pub async fn fetch_for_addresses(
    client: &NetworkClient,
    addresses: &[String],
) -> Result<Vec<UtxoEntry>, String> {
    let payload = utxo::encode(addresses).map_err(String::from)?;
    let response = client
        .call(Operation::GetUtxosByAddresses, &payload)
        .await
        .map_err(String::from)?;
    responses::utxo::decode(&response).map_err(String::from)
}
