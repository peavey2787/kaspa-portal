use std::sync::Arc;

use crate::{
    chain::{tx_lookup::ChainTransaction, utxo::UtxoEntry},
    error::{Error, Result},
    network::{client::NetworkClient, model::fee_estimate::FeeEstimate, queries},
    primitives::{BlockHash, DaaScore},
};

type TransactionLookup = dyn Fn(&str) -> Result<Option<ChainTransaction>> + Send + Sync;

#[derive(Clone)]
pub struct ChainApi {
    client: NetworkClient,
    transaction_lookup: Option<Arc<TransactionLookup>>,
}

impl ChainApi {
    pub(crate) fn new(client: NetworkClient) -> Self {
        Self {
            client,
            transaction_lookup: None,
        }
    }

    pub(crate) fn with_transaction_lookup(mut self, lookup: Arc<TransactionLookup>) -> Self {
        self.transaction_lookup = Some(lookup);
        self
    }

    pub async fn virtual_daa_score(&self) -> Result<DaaScore> {
        queries::chain::virtual_daa_score(&self.client)
            .await
            .map(DaaScore::new)
            .map_err(|error| Error::Network(error.to_string()))
    }

    pub async fn block_raw(&self, hash: &BlockHash) -> Result<Vec<u8>> {
        queries::blocks::get_raw(&self.client, &hash.0)
            .await
            .map_err(|error| Error::Network(error.to_string()))
    }

    pub async fn utxos(&self, address: &str) -> Result<Vec<UtxoEntry>> {
        queries::utxos::fetch_for_address(&self.client, address)
            .await
            .map_err(|error| Error::Network(error.to_string()))
    }

    pub async fn utxos_many(&self, addresses: &[String]) -> Result<Vec<UtxoEntry>> {
        queries::utxos::fetch_for_addresses(&self.client, addresses)
            .await
            .map_err(|error| Error::Network(error.to_string()))
    }

    /// Look up a transaction by txid from the Portal indexer.
    pub fn transaction(&self, txid: &str) -> Result<Option<ChainTransaction>> {
        match &self.transaction_lookup {
            Some(lookup) => lookup(txid),
            None => Ok(None),
        }
    }

    /// Return the complete raw indexed transaction representation by txid.
    pub fn transaction_raw(&self, txid: &str) -> Result<Option<serde_json::Value>> {
        self.transaction(txid)
            .map(|value| value.map(|transaction| transaction.raw))
    }

    pub async fn fee_estimate(&self) -> Result<FeeEstimate> {
        queries::fees::get(&self.client)
            .await
            .map_err(|error| Error::Network(error.to_string()))
    }
}
