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
