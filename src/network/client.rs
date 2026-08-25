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
}
