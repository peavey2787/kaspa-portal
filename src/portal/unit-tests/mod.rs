mod resolved;

use crate::{primitives::NetworkId, KaspaPortal};
#[test]
fn offline_portal_builds_without_endpoint() {
    let p = KaspaPortal::builder()
        .network(NetworkId::Mainnet)
        .build()
        .unwrap();
    assert!(p.network().is_err());
    assert_eq!(p.wallet().prefix(), "kaspa");
    assert_eq!(p.config().network, NetworkId::Mainnet);
}

/// Native connects run on multi-threaded Tokio runtimes, so both the
/// explicit-endpoint and the resolver-raced connect futures must be `Send`.
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn native_connect_futures_are_send() {
    fn require_send<T: Send>(_: &T) {}
    let resolved = KaspaPortal::builder().network(NetworkId::Mainnet).connect();
    require_send(&resolved);
    let explicit = KaspaPortal::builder()
        .network(NetworkId::Mainnet)
        .endpoint("wss://example.invalid")
        .connect();
    require_send(&explicit);
}
