use kaspa_portal::{
    indexer::IndexerConfig, network::health::ConnectionStatus, KaspaPortal, PortalConfig,
};

use crate::support::standard_network;

#[test]
#[ignore = "Pass 2 E2E: run through qa/scripts/run-e2e-rust"]
fn rust_offline_portal_network() {
    let custom_indexer = IndexerConfig {
        max_transactions: 123,
        ..IndexerConfig::default()
    };
    let config = PortalConfig {
        network: standard_network(),
        endpoint: Some("ws://127.0.0.1:17210".into()),
        timeout_ms: 5_000,
        max_retries: 2,
        indexer: custom_indexer.clone(),
    };
    config.validate().expect("valid portal config");
    assert_eq!(
        PortalConfig {
            timeout_ms: 999,
            ..config.clone()
        }
        .validate()
        .err()
        .map(|error| error.to_string())
        .as_deref(),
        Some("network timeout must be 1000..=120000 ms")
    );

    let portal = KaspaPortal::builder()
        .network(standard_network())
        .endpoint("ws://127.0.0.1:17210")
        .timeout_ms(5_000)
        .max_retries(2)
        .indexer(custom_indexer)
        .build()
        .expect("offline portal construction");

    assert_eq!(portal.config().network, standard_network());
    assert_eq!(portal.config().timeout_ms, 5_000);
    assert_eq!(portal.config().max_retries, 2);
    assert_eq!(
        portal.network().expect("network facade").network_id(),
        standard_network()
    );
    assert_eq!(
        portal.network().expect("network facade").endpoint(),
        "ws://127.0.0.1:17210"
    );
    let _client = portal.network().expect("network facade").client();
    assert_eq!(
        portal.network().expect("network facade").status(),
        ConnectionStatus::Disconnected
    );
    let _ = portal.chain().expect("chain facade");
    let _ = portal.wallet();
    let _ = portal.transaction();
    let _ = portal.contract();
    let _ = portal.privacy();
    let _ = portal.indexer();
    let _ = portal.randomness();

    portal.network().expect("network facade").disconnect();
    portal.disconnect().expect("portal disconnect");
    assert_eq!(
        portal.network().expect("network facade").status(),
        ConnectionStatus::Disconnected
    );

    let no_endpoint = KaspaPortal::builder()
        .network(standard_network())
        .build()
        .expect("endpoint-free portal");
    assert_eq!(
        no_endpoint
            .network()
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("invalid configuration: network API requires an endpoint; build with .endpoint(...)")
    );
    assert_eq!(
        no_endpoint
            .chain()
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("invalid configuration: chain API requires an endpoint")
    );
}
