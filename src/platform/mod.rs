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

/// Ask every public resolver concurrently; each answer (a `wss://` endpoint
/// or the reason that resolver failed) is yielded as soon as it arrives.
pub(crate) fn public_endpoint_answers(
    network: crate::primitives::NetworkId,
) -> impl futures_util::Stream<Item = Result<String, String>> + Unpin {
    use crate::network::resolver;
    resolver::PUBLIC_RESOLVERS
        .iter()
        .map(|base| async move {
            let body = fetch_text(&resolver::query_url(base, network)).await;
            body.and_then(|body| resolver::parse_endpoint(&body).map_err(|error| error.to_string()))
                .map_err(|error| format!("{base}: {error}"))
        })
        .collect::<futures_util::stream::FuturesUnordered<_>>()
}
