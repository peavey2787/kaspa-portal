use super::*;
fn req() -> BeaconRequest {
    BeaconRequest {
        network: NetworkId::Mainnet,
        context: b"draw".to_vec(),
        kaspa: vec![
            KaspaEntropyEvidence {
                block_hash: [1; 32],
                daa_score: Some(1),
                finalized: true,
            },
            KaspaEntropyEvidence {
                block_hash: [2; 32],
                daa_score: Some(2),
                finalized: true,
            },
        ],
        curby: None,
        extractor: ExtractorConfig::default(),
    }
}
#[test]
fn proof_verifies() {
    let r = generate(req()).unwrap();
    assert!(verify_result(&r).unwrap().valid)
}
#[test]
fn tamper_fails() {
    let mut r = generate(req()).unwrap();
    r.output[0] ^= 1;
    assert!(!verify_result(&r).unwrap().valid)
}
