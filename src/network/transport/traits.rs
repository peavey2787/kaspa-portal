use alloc::{boxed::Box, vec::Vec};
use core::{future::Future, pin::Pin};

use crate::network::{error::NetworkError, wrpc::operation::Operation};

#[cfg(not(target_arch = "wasm32"))]
pub type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, NetworkError>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, NetworkError>> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub type NotificationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, NetworkError>> + Send + 'a>>;

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

    #[cfg(not(target_arch = "wasm32"))]
    fn next_notification<'a>(&'a self) -> NotificationFuture<'a> {
        Box::pin(async {
            Err(NetworkError::UnexpectedResponse(
                "transport does not expose Kaspa notifications".into(),
            ))
        })
    }
}
