use crate::{indexer::IndexerConfig, primitives::NetworkId};

#[derive(Clone, Debug)]
pub struct PortalConfig {
    pub network: NetworkId,
    pub endpoint: Option<String>,
    pub timeout_ms: u64,
    pub max_retries: u8,
    pub indexer: IndexerConfig,
}

impl Default for PortalConfig {
    fn default() -> Self {
        Self {
            network: NetworkId::Mainnet,
            endpoint: None,
            timeout_ms: 15_000,
            max_retries: 3,
            indexer: IndexerConfig::default(),
        }
    }
}

impl PortalConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1_000..=120_000).contains(&self.timeout_ms) {
            return Err("network timeout must be 1000..=120000 ms".into());
        }
        if self.max_retries > 10 {
            return Err("max_retries must be <= 10".into());
        }
        if let Some(endpoint) = &self.endpoint {
            let endpoint = endpoint.trim();
            if !(endpoint.starts_with("ws://") || endpoint.starts_with("wss://")) {
                return Err("endpoint must use ws:// or wss://".into());
            }
        }
        self.indexer.validate()
    }
}
