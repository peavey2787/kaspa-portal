//! Kaspa Portal is a capability-oriented Kaspa SDK for native Rust and WebAssembly.
//! The crate exposes a small high-level [`KaspaPortal`] facade while keeping each
//! protocol, cryptographic primitive, and advanced subsystem directly reachable.

extern crate alloc;

pub mod chain;
pub mod contract;
pub mod crypto;
pub mod error;
pub mod indexer;
pub mod network;
pub mod platform;
pub mod portal;
pub mod prelude;
pub mod primitives;
pub mod privacy;
pub mod randomness;
pub mod transaction;
pub mod wallet;

pub use error::{Error, Result};
pub use portal::{KaspaPortal, KaspaPortalBuilder, PortalConfig};

#[cfg(test)]
pub(crate) mod test_support {
    use alloc::boxed::Box;

    use crate::network::{
        client::NetworkClient,
        error::NetworkError,
        transport::traits::{Transport, TransportFuture},
        wrpc::operation::Operation,
    };

    pub(crate) fn ready<F: core::future::Future>(future: F) -> F::Output {
        futures::executor::block_on(future)
    }

    pub(crate) struct FailTransport;

    impl Transport for FailTransport {
        fn call<'a>(&'a self, _operation: Operation, _payload: &'a [u8]) -> TransportFuture<'a> {
            Box::pin(async {
                Err(NetworkError::ConnectionFailed(
                    "test transport unavailable".into(),
                ))
            })
        }
    }

    pub(crate) fn fail_network_client() -> NetworkClient {
        NetworkClient::new(FailTransport)
    }
}
