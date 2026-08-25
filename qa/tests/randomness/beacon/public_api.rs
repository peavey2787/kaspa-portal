use kaspa_portal::{
    primitives::NetworkId,
    randomness::{
        beacon::BeaconRequest,
        extractor::ExtractorConfig,
        source::kaspa::KaspaEntropyEvidence,
    },
    KaspaPortal,
};

#[test]
fn same_canonical_public_evidence_produces_same_beacon_output() {
    let request = BeaconRequest {
        network: NetworkId::Testnet10,
        context: b"deterministic-public-draw".to_vec(),
        kaspa: vec![
            KaspaEntropyEvidence::finalized([3; 32], Some(10)),
            KaspaEntropyEvidence::finalized([4; 32], Some(11)),
        ],
        curby: None,
        extractor: ExtractorConfig::default(),
    };
    let portal = KaspaPortal::builder().build().unwrap();
    let beacon = portal.randomness().beacon();
    let first = beacon.generate(request.clone()).unwrap();
    let second = beacon.generate(request).unwrap();
    assert_eq!(first, second);
    assert!(beacon.verify(&first).unwrap().valid);
}
