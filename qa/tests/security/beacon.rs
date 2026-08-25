use kaspa_portal::{
    primitives::NetworkId,
    randomness::{
        beacon::BeaconRequest,
        extractor::ExtractorConfig,
        source::kaspa::KaspaEntropyEvidence,
    },
    KaspaPortal,
};

fn request() -> BeaconRequest {
    BeaconRequest {
        network: NetworkId::Mainnet,
        context: b"kaspa-portal-security-test".to_vec(),
        kaspa: vec![
            KaspaEntropyEvidence::finalized([0x11; 32], Some(100)),
            KaspaEntropyEvidence::finalized([0x22; 32], Some(101)),
        ],
        curby: None,
        extractor: ExtractorConfig::default(),
    }
}

#[test]
fn tampered_beacon_output_is_rejected() {
    let portal = KaspaPortal::builder().build().unwrap();
    let beacon = portal.randomness().beacon();
    let mut result = beacon.generate(request()).unwrap();
    assert!(beacon.verify(&result).unwrap().valid);
    result.output[17] ^= 0x80;
    assert!(!beacon.verify(&result).unwrap().valid);
}

#[test]
fn nonfinal_kaspa_evidence_is_rejected() {
    let portal = KaspaPortal::builder().build().unwrap();
    let mut request = request();
    request.kaspa[0].finalized = false;
    assert!(portal.randomness().beacon().generate(request).is_err());
}
