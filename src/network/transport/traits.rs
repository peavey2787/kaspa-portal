use alloc::{boxed::Box, vec::Vec};
use core::{future::Future, pin::Pin};

use crate::network::{error::NetworkError, wrpc::operation::Operation};

#[cfg(not(target_arch = "wasm32"))]
pub type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, NetworkError>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, NetworkError>> + 'a>>;

/// Future resolving to one raw notification (or subscription ack) frame.
pub type NotificationFuture<'a> = TransportFuture<'a>;

/// Platform transport contract used by the Kaspa wRPC domain.
///
/// Implementations live under `platform/`; protocol code depends only on this
/// interface and never imports browser/native transport types directly.
pub trait Transport: Send + Sync {
    fn call<'a>(&'a self, operation: Operation, payload: &'a [u8]) -> TransportFuture<'a>;

    /// Close any persistent transport resources owned by this client.
    /// Browser transports currently open request-scoped sockets, so the
    /// default is intentionally a no-op.
    fn disconnect(&self) {}

    /// Register a Kaspa notification scope. Persistent transports send it on
    /// their shared connection; browser transports use a notification socket.
    fn subscribe<'a>(&'a self, payload: &'a [u8]) -> TransportFuture<'a> {
        self.call(Operation::Subscribe, payload)
    }

    fn next_notification<'a>(&'a self) -> NotificationFuture<'a> {
        Box::pin(async {
            Err(NetworkError::UnexpectedResponse(
                "transport does not expose Kaspa notifications".into(),
            ))
        })
    }
}
