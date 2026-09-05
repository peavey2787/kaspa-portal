use std::sync::{atomic::AtomicU64, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::network::{error::NetworkError, wrpc::operation::Operation};

use super::websocket_driver::run_driver;
use super::websocket_io::reconnectable_transport_error;

pub(super) static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const DRIVER_COMMAND_CAPACITY: usize = 128;
pub(super) const MAX_QUEUED_NOTIFICATIONS: usize = 256;

pub(super) type NativeStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub(super) enum DriverCommand {
    Call {
        operation: Operation,
        payload: Vec<u8>,
        response: oneshot::Sender<Result<Vec<u8>, NetworkError>>,
    },
    NextNotification {
        response: oneshot::Sender<Result<Vec<u8>, NetworkError>>,
    },
}

#[derive(Clone)]
struct DriverHandle {
    commands: mpsc::Sender<DriverCommand>,
    shutdown: watch::Sender<bool>,
}

pub(super) struct QueuedCall {
    pub(super) operation: Operation,
    pub(super) payload: Vec<u8>,
    pub(super) response: oneshot::Sender<Result<Vec<u8>, NetworkError>>,
}

pub(super) struct ActiveCall {
    pub(super) request_id: u64,
    pub(super) operation: Operation,
    pub(super) payload: Vec<u8>,
    pub(super) response: oneshot::Sender<Result<Vec<u8>, NetworkError>>,
    pub(super) deadline: Instant,
}

/// Native Kaspa wRPC transport with one reusable websocket per Portal instance.
///
/// A single driver task owns the socket. RPC request/response traffic and
/// asynchronous notifications are demultiplexed on that socket. Successful
/// subscriptions are remembered by the driver and replayed after reconnect.
pub struct NativeWebSocketTransport {
    endpoint: String,
    timeout: Duration,
    max_retries: u8,
    driver: Mutex<Option<DriverHandle>>,
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
            driver: Mutex::new(None),
        })
    }

    fn driver_sender(&self) -> mpsc::Sender<DriverCommand> {
        let mut slot = self
            .driver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(handle) = slot.as_ref() {
            if !handle.commands.is_closed() {
                return handle.commands.clone();
            }
        }

        let (commands, receiver) = mpsc::channel(DRIVER_COMMAND_CAPACITY);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let endpoint = self.endpoint.clone();
        let timeout = self.timeout;
        let max_retries = self.max_retries;
        tokio::spawn(async move {
            run_driver(endpoint, timeout, max_retries, receiver, shutdown_rx).await;
        });
        *slot = Some(DriverHandle {
            commands: commands.clone(),
            shutdown,
        });
        commands
    }

    fn reset_driver_if_closed(&self) {
        let mut slot = self
            .driver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot
            .as_ref()
            .is_some_and(|handle| handle.commands.is_closed())
        {
            *slot = None;
        }
    }

    fn shutdown_driver(&self) {
        let handle = self
            .driver
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            // A watch channel is used for shutdown so a full bounded RPC queue
            // cannot prevent an explicit disconnect from reaching the driver.
            let _ = handle.shutdown.send(true);
        }
    }

    async fn call_once(
        &self,
        operation: Operation,
        payload: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        let sender = self.driver_sender();
        let (response_tx, response_rx) = oneshot::channel();
        if sender
            .send(DriverCommand::Call {
                operation,
                payload: payload.to_vec(),
                response: response_tx,
            })
            .await
            .is_err()
        {
            self.reset_driver_if_closed();
            return Err(NetworkError::ConnectionFailed(
                "Kaspa wRPC driver stopped before request submission".into(),
            ));
        }
        response_rx.await.unwrap_or_else(|_| {
            Err(NetworkError::ConnectionFailed(
                "Kaspa wRPC driver stopped before request completion".into(),
            ))
        })
    }

    async fn call_inner(
        &self,
        operation: Operation,
        payload: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        let mut retried_stale_connection = false;
        loop {
            match self.call_once(operation, payload).await {
                Ok(value) => return Ok(value),
                Err(error)
                    if operation != Operation::SubmitTransaction
                        && !retried_stale_connection
                        && reconnectable_transport_error(&error) =>
                {
                    retried_stale_connection = true;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn next_notification_once(&self) -> Result<Vec<u8>, NetworkError> {
        let sender = self.driver_sender();
        let (response_tx, response_rx) = oneshot::channel();
        if sender
            .send(DriverCommand::NextNotification {
                response: response_tx,
            })
            .await
            .is_err()
        {
            self.reset_driver_if_closed();
            return Err(NetworkError::ConnectionFailed(
                "Kaspa wRPC driver stopped before notification wait".into(),
            ));
        }
        response_rx.await.unwrap_or_else(|_| {
            Err(NetworkError::ConnectionFailed(
                "Kaspa wRPC driver stopped during notification wait".into(),
            ))
        })
    }

    async fn next_notification_inner(&self) -> Result<Vec<u8>, NetworkError> {
        let mut retried_stale_connection = false;
        loop {
            match self.next_notification_once().await {
                Ok(notification) => return Ok(notification),
                Err(error)
                    if !retried_stale_connection && reconnectable_transport_error(&error) =>
                {
                    retried_stale_connection = true;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

pub(super) async fn sleep_connect_backoff(retry: u8) {
    let exponent = u32::from(retry.saturating_sub(1).min(4));
    let delay_ms = 250u64.saturating_mul(1u64 << exponent).min(4_000);
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
}

impl crate::network::transport::traits::Transport for NativeWebSocketTransport {
    fn call<'a>(
        &'a self,
        operation: Operation,
        payload: &'a [u8],
    ) -> crate::network::transport::traits::TransportFuture<'a> {
        Box::pin(self.call_inner(operation, payload))
    }

    fn disconnect(&self) {
        self.shutdown_driver();
    }

    fn next_notification<'a>(
        &'a self,
    ) -> crate::network::transport::traits::NotificationFuture<'a> {
        Box::pin(self.next_notification_inner())
    }
}
