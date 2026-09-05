#[cfg(not(target_arch = "wasm32"))]
use std::sync::{Arc, Mutex};

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

#[cfg(not(target_arch = "wasm32"))]
struct LiveIndexerRuntime {
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl LiveIndexerRuntime {
    fn new() -> Self {
        Self {
            task: Mutex::new(None),
        }
    }

    fn abort(&self) {
        if let Ok(mut slot) = self.task.lock() {
            if let Some(handle) = slot.take() {
                handle.abort();
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Drop for LiveIndexerRuntime {
    fn drop(&mut self) {
        if let Ok(slot) = self.task.get_mut() {
            if let Some(handle) = slot.take() {
                handle.abort();
            }
        }
    }
}

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
    #[cfg(not(target_arch = "wasm32"))]
    live_indexer_runtime: Arc<LiveIndexerRuntime>,
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
            #[cfg(not(target_arch = "wasm32"))]
            live_indexer_runtime: Arc::new(LiveIndexerRuntime::new()),
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

    /// Subscribe to BlockAdded and feed decoded block/transaction payload data
    /// directly into this Portal's indexer. This is a native convenience bridge:
    /// applications that prefer raw BlockAdded consumption should use
    /// `network().subscribe_block_added()` + `network().next_block_added()` instead.
    ///
    /// The live bridge owns the BlockAdded consumer while active. Payload matcher
    /// rules therefore work without the application manufacturing
    /// `IndexedTransaction` values itself.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn start_live_indexer(&self) -> Result<()> {
        {
            let mut slot = self
                .live_indexer_runtime
                .task
                .lock()
                .map_err(|_| Error::Indexer("live indexer task lock poisoned".into()))?;
            if slot.as_ref().is_some_and(|handle| !handle.is_finished()) {
                return Ok(());
            }
            *slot = None;
        }

        self.indexer.start()?;
        let network = self.network()?.clone();
        network.subscribe_block_added().await?;
        let indexer = self.indexer.clone();
        let handle = tokio::spawn(async move {
            loop {
                match network.next_block_added().await {
                    Ok(block) => {
                        if ingest_live_block_added(&indexer, block).is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        // The transport reconnects and replays successful
                        // subscriptions. Keep the live consumer present so the
                        // next wait can attach to the restored socket.
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
            }
        });

        let mut slot = match self.live_indexer_runtime.task.lock() {
            Ok(slot) => slot,
            Err(_) => {
                handle.abort();
                return Err(Error::Indexer("live indexer task lock poisoned".into()));
            }
        };
        if let Some(previous) = slot.replace(handle) {
            previous.abort();
        }
        Ok(())
    }

    pub fn disconnect(&self) -> Result<()> {
        #[cfg(not(target_arch = "wasm32"))]
        self.live_indexer_runtime.abort();
        self.network()?.disconnect();
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn ingest_live_block_added(
    indexer: &IndexerApi,
    block: crate::network::wrpc::block_added::OwnedBlockAddedNotification,
) -> Result<()> {
    use crate::indexer::{BlockBatch, IndexedBlock, IndexedTransaction};

    let observed_at_ms = crate::platform::native::time::now_ms().map_err(Error::Indexer)?;
    let block_hash = block.block_hash;
    let daa_score = block.daa_score;
    let txids = block
        .transactions
        .iter()
        .filter_map(|transaction| transaction.transaction_id.clone())
        .collect::<Vec<_>>();
    let transactions = block
        .transactions
        .into_iter()
        .filter_map(|transaction| {
            let crate::network::wrpc::block_added::OwnedBlockAddedTransaction {
                transaction_id,
                payload,
            } = transaction;
            transaction_id.map(|txid| IndexedTransaction {
                txid,
                block_hash: Some(block_hash.clone()),
                daa_score: Some(daa_score),
                observed_at_ms,
                addresses: Vec::new(),
                payload,
                raw: serde_json::Value::Null,
            })
        })
        .collect::<Vec<_>>();

    indexer.ingest_block_batch(BlockBatch {
        block: IndexedBlock {
            hash: block_hash,
            daa_score: Some(daa_score),
            observed_at_ms,
            txids,
            raw: serde_json::Value::Null,
        },
        transactions,
    })?;
    Ok(())
}
