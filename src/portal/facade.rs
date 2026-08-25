use crate::{
    chain::ChainApi,
    contract::ContractApi,
    error::{Error, Result},
    indexer::IndexerApi,
    network::{config::NetworkConfig, facade::NetworkApi, health::NetworkHealth},
    portal::{KaspaPortalBuilder, PortalConfig},
    privacy::PrivacyApi,
    randomness::RandomnessApi,
    transaction::TransactionApi,
    wallet::WalletApi,
};

#[derive(Clone)]
pub struct KaspaPortal {
    config: PortalConfig,
    network: Option<NetworkApi>,
    chain: Option<ChainApi>,
    wallet: WalletApi,
    transaction: TransactionApi,
    contract: ContractApi,
    privacy: PrivacyApi,
    indexer: IndexerApi,
    randomness: RandomnessApi,
}

impl KaspaPortal {
    pub fn builder() -> KaspaPortalBuilder {
        KaspaPortalBuilder::default()
    }

    pub(crate) fn from_config(config: PortalConfig) -> Result<Self> {
        let endpoint = config.endpoint.clone();
        let client = endpoint
            .as_deref()
            .map(|endpoint| {
                crate::platform::network_client(endpoint, config.timeout_ms, config.max_retries)
            })
            .transpose()
            .map_err(|error| Error::Network(error.to_string()))?;
        let network = endpoint
            .as_ref()
            .zip(client.clone())
            .map(|(value, client)| {
                NetworkApi::new(
                    NetworkConfig {
                        network: config.network,
                        endpoint: value.clone(),
                        timeout_ms: config.timeout_ms,
                        max_retries: config.max_retries,
                    },
                    client,
                )
            });
        let indexer = crate::platform::indexer_api(config.indexer.clone())?;
        let chain = client.clone().map(|client| {
            let lookup_indexer = indexer.clone();
            ChainApi::new(client).with_transaction_lookup(std::sync::Arc::new(move |txid| {
                lookup_indexer.transaction(txid).map(|value| {
                    value.map(|transaction| {
                        crate::chain::tx_lookup::ChainTransaction::from_indexed_parts(
                            transaction.txid,
                            transaction.payload,
                            transaction.raw,
                        )
                    })
                })
            }))
        });
        let wallet = WalletApi::new(chain.clone(), config.network.address_prefix());
        let transaction = TransactionApi::new(client);

        Ok(Self {
            indexer,
            randomness: RandomnessApi::new(crate::platform::curby_client()),
            contract: ContractApi::new(),
            privacy: PrivacyApi::new(),
            config,
            network,
            chain,
            wallet,
            transaction,
        })
    }

    pub fn config(&self) -> &PortalConfig {
        &self.config
    }

    pub fn network(&self) -> Result<&NetworkApi> {
        self.network.as_ref().ok_or_else(|| {
            Error::Config("network API requires an endpoint; build with .endpoint(...)".into())
        })
    }

    pub fn chain(&self) -> Result<&ChainApi> {
        self.chain
            .as_ref()
            .ok_or_else(|| Error::Config("chain API requires an endpoint".into()))
    }

    pub fn wallet(&self) -> &WalletApi {
        &self.wallet
    }

    pub fn transaction(&self) -> &TransactionApi {
        &self.transaction
    }

    pub fn contract(&self) -> &ContractApi {
        &self.contract
    }

    pub fn privacy(&self) -> &PrivacyApi {
        &self.privacy
    }

    pub fn indexer(&self) -> &IndexerApi {
        &self.indexer
    }

    pub fn randomness(&self) -> &RandomnessApi {
        &self.randomness
    }

    pub async fn connect(&self) -> Result<NetworkHealth> {
        self.network()?.connect().await
    }

    pub fn disconnect(&self) -> Result<()> {
        self.network()?.disconnect();
        Ok(())
    }
}
