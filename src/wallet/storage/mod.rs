//! Platform-neutral persistence contracts for wallet state.
//!
//! Kaspa Portal deliberately does not couple wallet persistence to a device,
//! filesystem, or browser database. Implementations persist opaque encrypted
//! records produced by application policy; secret-key handling remains in the
//! wallet/crypto layers.

use alloc::{boxed::Box, string::String, vec::Vec};
use core::{future::Future, pin::Pin};

pub type StorageFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, WalletStorageError>> + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedWalletRecord {
    pub schema: u16,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalletStorageError {
    InvalidNamespace,
    InvalidSchema,
    Backend(String),
}

pub trait WalletStorage {
    fn load<'a>(&'a self, namespace: &'a str) -> StorageFuture<'a, Option<EncryptedWalletRecord>>;
    fn save<'a>(
        &'a self,
        namespace: &'a str,
        record: &'a EncryptedWalletRecord,
    ) -> StorageFuture<'a, ()>;
    fn clear<'a>(&'a self, namespace: &'a str) -> StorageFuture<'a, ()>;
}
