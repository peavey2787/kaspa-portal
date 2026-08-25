use kaspa_portal::{primitives::NetworkId, KaspaPortal};

#[test]
fn offline_portal_exposes_offline_domains_but_not_network_domains() {
    let portal = KaspaPortal::builder()
        .network(NetworkId::Mainnet)
        .build()
        .unwrap();

    assert!(portal.network().is_err());
    assert!(portal.chain().is_err());
    assert_eq!(portal.wallet().prefix(), "kaspa");
    let _ = portal.transaction();
    let _ = portal.contract();
    let _ = portal.privacy();
    let _ = portal.indexer();
    let _ = portal.randomness();
}
