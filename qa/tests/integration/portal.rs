use kaspa_portal::{primitives::NetworkId, KaspaPortal};

#[test]
fn offline_portal_exposes_offline_domains_but_not_network_domains() {
    let portal = KaspaPortal::builder()
        .network(NetworkId::Mainnet)
        .build()
        .unwrap();

    assert_eq!(
        portal
            .network()
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("invalid configuration: network API requires an endpoint; build with .endpoint(...)")
    );
    assert_eq!(
        portal
            .chain()
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("invalid configuration: chain API requires an endpoint")
    );
    assert_eq!(portal.wallet().prefix(), "kaspa");
    let _ = portal.transaction();
    let _ = portal.contract();
    let _ = portal.privacy();
    let _ = portal.indexer();
    let _ = portal.randomness();
}
