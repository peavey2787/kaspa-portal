#[cfg(feature = "std")]
pub mod client;
#[cfg(feature = "std")]
pub mod config;
#[cfg(feature = "std")]
pub mod facade;
#[cfg(feature = "std")]
pub mod health;
#[cfg(feature = "std")]
pub mod retry;
#[cfg(feature = "std")]
pub mod transport;
#[cfg(feature = "std")]
pub use facade::NetworkApi;
pub mod codec;
pub mod error;
#[cfg(feature = "std")]
pub mod model;
#[cfg(feature = "std")]
pub mod queries;
#[cfg(feature = "std")]
pub mod resolver;
#[cfg(feature = "std")]
pub mod wrpc;

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
