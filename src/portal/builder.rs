use crate::{
    error::{Error, Result},
    indexer::IndexerConfig,
    portal::{facade::KaspaPortal, PortalConfig},
    primitives::NetworkId,
};

#[derive(Clone, Debug, Default)]
pub struct KaspaPortalBuilder {
    config: PortalConfig,
}

impl KaspaPortalBuilder {
    pub fn network(mut self, network: NetworkId) -> Self {
        self.config.network = network;
        self
    }

    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.config.endpoint = Some(endpoint.into());
        self
    }

    pub fn timeout_ms(mut self, value: u64) -> Self {
        self.config.timeout_ms = value;
        self
    }

    pub fn max_retries(mut self, value: u8) -> Self {
        self.config.max_retries = value;
        self
    }

    pub fn indexer(mut self, value: IndexerConfig) -> Self {
        self.config.indexer = value;
        self
    }

    pub fn build(self) -> Result<KaspaPortal> {
        self.config.validate().map_err(Error::Config)?;
        KaspaPortal::from_config(self.config)
    }

    pub async fn connect(self) -> Result<KaspaPortal> {
        let portal = self.build()?;
        portal.connect().await?;
        Ok(portal)
    }
}
