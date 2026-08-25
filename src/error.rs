use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("chain error: {0}")]
    Chain(String),
    #[error("wallet error: {0}")]
    Wallet(String),
    #[error("transaction error: {0}")]
    Transaction(String),
    #[error("contract error: {0}")]
    Contract(String),
    #[error("privacy error: {0}")]
    Privacy(String),
    #[error("indexer error: {0}")]
    Indexer(String),
    #[error("randomness beacon error: {0}")]
    Beacon(String),
    #[error("VRF error: {0}")]
    Vrf(String),
    #[error("cryptography error: {0}")]
    Crypto(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("platform error: {0}")]
    Platform(String),
}
