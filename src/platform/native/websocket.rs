use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, Stream, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::network::{
    error::NetworkError,
    wrpc::{
        error_payload,
        operation::Operation,
        request::{self, WrpcRequest},
        response::{self, ResponseKind},
    },
};

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

pub struct NativeWebSocketTransport {
    endpoint: String,
    timeout: Duration,
    max_retries: u8,
}

impl NativeWebSocketTransport {
    pub fn new(endpoint: &str) -> Result<Self, NetworkError> {
        Self::with_config(endpoint, DEFAULT_TIMEOUT.as_millis() as u64, 0)
    }

    pub fn with_config(
        endpoint: &str,
        timeout_ms: u64,
        max_retries: u8,
    ) -> Result<Self, NetworkError> {
        let endpoint = endpoint.trim();
        if !(endpoint.starts_with("ws://") || endpoint.starts_with("wss://")) {
            return Err(NetworkError::InvalidUrl);
        }
        Ok(Self {
            endpoint: endpoint.to_owned(),
            timeout: Duration::from_millis(timeout_ms),
            max_retries,
        })
    }

    async fn connect(
        &self,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        NetworkError,
    > {
        let mut retry = 0u8;
        loop {
            let result = tokio::time::timeout(self.timeout, connect_async(&self.endpoint)).await;
            match result {
                Ok(Ok((stream, _))) => return Ok(stream),
                Ok(Err(_error)) if retry < self.max_retries => {
                    let delay_ms = 250u64.saturating_mul(1u64 << u32::from(retry.min(4)));
                    retry = retry.saturating_add(1);
                    tokio::time::sleep(Duration::from_millis(delay_ms.min(4_000))).await;
                }
                Err(_) if retry < self.max_retries => {
                    let delay_ms = 250u64.saturating_mul(1u64 << u32::from(retry.min(4)));
                    retry = retry.saturating_add(1);
                    tokio::time::sleep(Duration::from_millis(delay_ms.min(4_000))).await;
                }
                Ok(Err(error)) => return Err(NetworkError::ConnectionFailed(error.to_string())),
                Err(_) => return Err(NetworkError::ConnectTimeout),
            }
        }
    }

    async fn call_inner(
        &self,
        operation: Operation,
        payload: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        let mut stream = self.connect().await?;
        let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let bytes = request::encode(&WrpcRequest {
            id: request_id,
            operation,
            payload,
        })?;
        stream
            .send(Message::Binary(bytes.into()))
            .await
            .map_err(|_| NetworkError::SendFailed)?;
        let response = tokio::time::timeout(self.timeout, receive_binary(&mut stream))
            .await
            .map_err(|_| NetworkError::ResponseTimeout)??;
        validate_response(&response, request_id, operation)
    }
}

async fn receive_binary<S>(stream: &mut S) -> Result<Vec<u8>, NetworkError>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    while let Some(frame) = stream.next().await {
        match frame.map_err(|error| NetworkError::ConnectionFailed(error.to_string()))? {
            Message::Binary(bytes) => return Ok(bytes.to_vec()),
            Message::Close(frame) => {
                return Err(NetworkError::ConnectionFailed(format!(
                    "closed before RPC response: {frame:?}"
                )))
            }
            Message::Text(_) => {
                return Err(NetworkError::UnexpectedResponse("non-binary frame".into()))
            }
            _ => {}
        }
    }
    Err(NetworkError::ConnectionFailed(
        "connection ended before RPC response".into(),
    ))
}

fn validate_response(
    bytes: &[u8],
    expected_id: u64,
    expected_operation: Operation,
) -> Result<Vec<u8>, NetworkError> {
    let decoded = response::decode(bytes)?;
    if let Some(actual) = decoded.id {
        if actual != expected_id {
            return Err(NetworkError::MismatchedRequestId {
                expected: expected_id,
                actual,
            });
        }
    }
    if let Some(actual) = decoded.raw_operation {
        if decoded.operation != Some(expected_operation) {
            return Err(NetworkError::MismatchedOperation {
                expected: expected_operation.code(),
                actual,
            });
        }
    }
    match decoded.kind {
        ResponseKind::Success => Ok(decoded.payload.to_vec()),
        ResponseKind::Error(code) => Err(NetworkError::RemoteError(format!(
            "kind={code}: {}",
            error_payload::decode(decoded.payload)
        ))),
    }
}

impl crate::network::transport::traits::Transport for NativeWebSocketTransport {
    fn call<'a>(
        &'a self,
        operation: Operation,
        payload: &'a [u8],
    ) -> crate::network::transport::traits::TransportFuture<'a> {
        Box::pin(self.call_inner(operation, payload))
    }
}
