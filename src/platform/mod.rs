//! Target-specific adapters. Core Kaspa logic must not live here.

use crate::network::{client::NetworkClient, error::NetworkError};

#[cfg(not(target_arch = "wasm32"))]
pub mod native;

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
pub mod browser;

#[cfg(all(target_arch = "wasm32", feature = "std", not(feature = "browser")))]
compile_error!("kaspa-portal browser builds require `--features browser` or `--features wasm`");

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

/// Fetch a small text resource (resolver answers) over HTTPS.
pub(crate) async fn fetch_text(url: &str) -> Result<String, String> {
    #[cfg(target_arch = "wasm32")]
    {
        browser::fetch::fetch_text(url).await
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        native::http::fetch_text(url).await
    }
}

/// Ask every public resolver concurrently; healthy `wss://` endpoints in
/// first-answer order.
pub(crate) async fn resolve_public_endpoints(network: crate::primitives::NetworkId) -> Vec<String> {
    use crate::network::resolver;
    let queries = resolver::PUBLIC_RESOLVERS.iter().map(|base| async move {
        let body = fetch_text(&resolver::query_url(base, network)).await.ok()?;
        resolver::parse_endpoint(&body).ok()
    });
    let answers = futures_util::future::join_all(queries).await;
    resolver::unique_endpoints(answers.into_iter().flatten())
}
