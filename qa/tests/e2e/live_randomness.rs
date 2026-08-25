use kaspa_portal::{
    primitives::BlockHash,
    randomness::source::kaspa::KaspaEntropyEvidence,
    KaspaPortal,
};

use crate::support::{live_endpoint, live_genesis_hash, live_network, live_network_name};

#[tokio::test]
#[ignore = "Pass 2 live E2E: requires the configured public standard network"]
async fn rust_live_standard_randomness() {
    let portal = KaspaPortal::builder()
        .network(live_network())
        .endpoint(live_endpoint())
        .connect()
        .await
        .expect("connect public selected network");
    let bytes = hex::decode(live_genesis_hash()).expect("selected-network genesis hex");
    let hash: [u8; 32] = bytes.try_into().expect("32-byte selected-network genesis hash");
    let raw = portal
        .chain()
        .expect("chain")
        .block_raw(&BlockHash::new(hash))
        .await
        .expect("prove selected-network genesis exists on public endpoint");
    assert!(!raw.is_empty());

    let beacon = portal.randomness().beacon();
    beacon
        .observe_kaspa_block(KaspaEntropyEvidence::finalized(hash, None))
        .expect("observe live-proven selected-network block");
    let result = beacon
        .generate_live(
            live_network(),
            1,
            false,
            format!("kaspa-portal-live-{}", live_network_name()).as_bytes().to_vec(),
        )
        .await
        .expect("generate live beacon from selected-network evidence");
    assert!(beacon.verify(&result).expect("verify live beacon").valid);
}
