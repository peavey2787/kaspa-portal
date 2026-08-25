use kaspa_portal::{
    primitives::NetworkId,
    randomness::{
        beacon::BeaconRequest, extractor::ExtractorConfig, source::kaspa::KaspaEntropyEvidence,
    },
    KaspaPortal, Result,
};

fn main() -> Result<()> {
    let portal = KaspaPortal::builder().build()?;

    let vrf = portal.randomness().vrf();
    let (secret, public) = vrf.generate_keypair()?;
    let result = vrf.prove(&secret, b"kaspa-portal-example")?;
    let verified = vrf.verify(&public, b"kaspa-portal-example", &result.proof)?;
    assert_eq!(verified, result.output);

    let beacon = portal.randomness().beacon();
    let result = beacon.generate(BeaconRequest {
        network: NetworkId::Mainnet,
        context: b"public-drawing-example".to_vec(),
        kaspa: vec![KaspaEntropyEvidence::finalized([0x42; 32], Some(1))],
        curby: None,
        extractor: ExtractorConfig::default(),
    })?;
    assert!(beacon.verify(&result)?.valid);
    println!(
        "vrf={} beacon={}",
        hex::encode(verified.0),
        hex::encode(result.output)
    );
    Ok(())
}
