//! Kaspa Portal is a capability-oriented Kaspa SDK for native Rust and WebAssembly.
//! The crate exposes a small high-level [`KaspaPortal`] facade while keeping each
//! protocol, cryptographic primitive, and advanced subsystem directly reachable.
//!
//! Without the default `std` feature the crate is a `no_std` + `alloc` signing
//! core (keys, derivation, mnemonics, addresses, transaction model, sighash,
//! signing, PSKT/KSPT interchange, crypto) for embedded signers.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

/// The `alloc` items the `std` prelude would provide, for `no_std` builds of the
/// signing core. Core modules glob-import this only when `std` is off.
#[cfg(not(feature = "std"))]
pub(crate) mod alloc_prelude {
    pub(crate) use alloc::borrow::ToOwned;
    pub(crate) use alloc::format;
    pub(crate) use alloc::string::{String, ToString};
    pub(crate) use alloc::vec;
    pub(crate) use alloc::vec::Vec;
}

#[cfg(feature = "std")]
pub mod chain;
pub mod contract;
pub mod crypto;
pub mod error;
#[cfg(feature = "std")]
pub mod indexer;
pub mod network;
#[cfg(feature = "std")]
pub mod platform;
#[cfg(feature = "std")]
pub mod portal;
#[cfg(feature = "std")]
pub mod prelude;
pub mod primitives;
pub mod privacy;
#[cfg(feature = "std")]
pub mod randomness;
pub mod transaction;
pub mod wallet;

pub use error::{Error, Result};
#[cfg(feature = "std")]
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
