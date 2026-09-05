use alloc::{sync::Arc, vec::Vec};

use crate::network::{
    error::NetworkError, transport::traits::Transport, wrpc::operation::Operation,
};

/// Platform-neutral wRPC client backed by an injected transport adapter.
#[derive(Clone)]
pub struct NetworkClient {
    transport: Arc<dyn Transport>,
}

impl NetworkClient {
    pub fn new<T>(transport: T) -> Self
    where
        T: Transport + 'static,
    {
        Self {
            transport: Arc::new(transport),
        }
    }

    pub fn from_shared_transport(transport: Arc<dyn Transport>) -> Self {
        Self { transport }
    }

    pub async fn call(
        &self,
        operation: Operation,
        payload: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        self.transport.call(operation, payload).await
    }

    /// Close the persistent transport owned by this client.
    pub(crate) fn disconnect(&self) {
        self.transport.disconnect();
    }

    /// Receive the next asynchronous Kaspa notification from the same native
    /// wRPC connection used for request/response traffic.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) async fn next_notification(&self) -> Result<Vec<u8>, NetworkError> {
        self.transport.next_notification().await
    }
}
