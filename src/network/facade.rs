use std::sync::{Arc, RwLock};

use crate::{
    error::{Error, Result},
    network::{
        client::NetworkClient,
        config::NetworkConfig,
        health::{ConnectionStatus, NetworkHealth},
        queries,
    },
    primitives::NetworkId,
};

#[derive(Clone)]
pub struct NetworkApi {
    config: Arc<NetworkConfig>,
    status: Arc<RwLock<ConnectionStatus>>,
    client: NetworkClient,
}

impl NetworkApi {
    pub(crate) fn new(config: NetworkConfig, client: NetworkClient) -> Self {
        Self {
            config: Arc::new(config),
            status: Arc::new(RwLock::new(ConnectionStatus::Disconnected)),
            client,
        }
    }

    pub fn network_id(&self) -> NetworkId {
        self.config.network
    }

    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Clone the platform-neutral client for advanced low-level builders.
    pub fn client(&self) -> NetworkClient {
        self.client.clone()
    }

    pub fn status(&self) -> ConnectionStatus {
        self.status
            .read()
            .map(|status| status.clone())
            .unwrap_or(ConnectionStatus::Degraded)
    }

    pub async fn connect(&self) -> Result<NetworkHealth> {
        self.set_status(ConnectionStatus::Connecting);
        match queries::chain::virtual_daa_score(&self.client).await {
            Ok(score) => {
                self.set_status(ConnectionStatus::Connected);
                Ok(NetworkHealth {
                    status: ConnectionStatus::Connected,
                    endpoint: self.endpoint().to_owned(),
                    virtual_daa_score: Some(score),
                })
            }
            Err(error) => {
                self.set_status(ConnectionStatus::Disconnected);
                Err(Error::Network(error.to_string()))
            }
        }
    }

    pub fn disconnect(&self) {
        self.set_status(ConnectionStatus::Disconnected);
    }

    pub async fn reconnect(&self) -> Result<NetworkHealth> {
        self.disconnect();
        self.connect().await
    }

    pub async fn health(&self) -> Result<NetworkHealth> {
        let score = queries::chain::virtual_daa_score(&self.client)
            .await
            .map_err(|error| Error::Network(error.to_string()))?;
        Ok(NetworkHealth {
            status: ConnectionStatus::Connected,
            endpoint: self.endpoint().to_owned(),
            virtual_daa_score: Some(score),
        })
    }

    fn set_status(&self, value: ConnectionStatus) {
        if let Ok(mut status) = self.status.write() {
            *status = value;
        }
    }
}
