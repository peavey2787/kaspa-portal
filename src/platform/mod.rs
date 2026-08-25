//! Target-specific adapters. Core Kaspa logic must not live here.

use crate::network::{client::NetworkClient, error::NetworkError};

#[cfg(not(target_arch = "wasm32"))]
pub mod native;

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
pub mod browser;

#[cfg(all(target_arch = "wasm32", not(feature = "wasm")))]
compile_error!("kaspa-portal browser builds require `--features wasm`");

pub(crate) fn network_client(
    endpoint: &str,
    timeout_ms: u64,
    max_retries: u8,
) -> Result<NetworkClient, NetworkError> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = max_retries;
        browser::websocket::BrowserWebSocketTransport::with_timeout(endpoint, timeout_ms)
            .map(NetworkClient::new)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        native::websocket::NativeWebSocketTransport::with_config(endpoint, timeout_ms, max_retries)
            .map(NetworkClient::new)
    }
}

pub(crate) fn indexer_api(
    config: crate::indexer::IndexerConfig,
) -> crate::error::Result<crate::indexer::IndexerApi> {
    #[cfg(target_arch = "wasm32")]
    let clock = browser::time::now_ms;
    #[cfg(not(target_arch = "wasm32"))]
    let clock = native::time::now_ms;
    crate::indexer::IndexerApi::with_clock(config, clock)
}

pub(crate) fn curby_client() -> crate::randomness::source::curby::CurbyClient {
    use std::sync::Arc;
    #[cfg(target_arch = "wasm32")]
    let io: Arc<dyn crate::randomness::source::curby::CurbyIo> =
        Arc::new(browser::curby::BrowserCurbyIo);
    #[cfg(not(target_arch = "wasm32"))]
    let io: Arc<dyn crate::randomness::source::curby::CurbyIo> =
        Arc::new(native::curby::NativeCurbyIo);
    crate::randomness::source::curby::CurbyClient::new(io)
}
