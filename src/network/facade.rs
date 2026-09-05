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
        self.client.disconnect();
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

    /// Subscribe to Kaspa BlockAdded notifications on this Portal's persistent
    /// native wRPC connection. The transport owns request ids and reconnect
    /// replay; callers never construct or decode raw wRPC frames.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn subscribe_block_added(&self) -> Result<()> {
        use crate::network::{codec::requests::subscription, wrpc::operation::Operation};

        let payload = subscription::block_added_payload()
            .map_err(|error| Error::Network(error.to_string()))?;
        self.client
            .call(Operation::Subscribe, &payload)
            .await
            .map(|_| ())
            .map_err(|error| Error::Network(error.to_string()))
    }

    /// Receive the next decoded BlockAdded notification from this Portal's
    /// persistent native wRPC connection. Other notification operations are
    /// ignored without leaking wire-level framing to the application.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn next_block_added(
        &self,
    ) -> Result<crate::network::wrpc::block_added::OwnedBlockAddedNotification> {
        loop {
            let frame = self
                .client
                .next_notification()
                .await
                .map_err(|error| Error::Network(error.to_string()))?;
            if let Some(notification) = crate::network::wrpc::block_added::decode(&frame)
                .map_err(|error| Error::Network(error.to_string()))?
            {
                return Ok(notification.into());
            }
        }
    }

    fn set_status(&self, value: ConnectionStatus) {
        if let Ok(mut status) = self.status.write() {
            *status = value;
        }
    }
}
