use std::hint::black_box;

use kaspa_portal::{
    randomness::{
        beacon::BeaconRequest, extractor::ExtractorConfig, source::kaspa::KaspaEntropyEvidence,
    },
    wallet::key::xpub::{derive_and_serialize_kpub, KPUB_MAX_LEN},
    KaspaPortal,
};

pub fn run(iteration: usize) -> Result<(), String> {
    let portal = KaspaPortal::builder()
        .network(super::standard_network())
        .build()
        .map_err(|error| error.to_string())?;
    let randomness = portal.randomness();
    let (secret, public) = randomness
        .vrf()
        .generate_keypair()
        .map_err(|error| error.to_string())?;
    let input = format!("resource-vrf-{iteration}");
    let result = randomness
        .vrf()
        .prove(&secret, input.as_bytes())
        .map_err(|error| error.to_string())?;
    let verified = randomness
        .vrf()
        .verify(&public, input.as_bytes(), &result.proof)
        .map_err(|error| error.to_string())?;

    let evidence = KaspaEntropyEvidence::finalized([0x41; 32], Some(123_456));
    let beacon = randomness
        .beacon()
        .generate(BeaconRequest {
            network: super::standard_network(),
            context: input.as_bytes().to_vec(),
            kaspa: vec![evidence],
            curby: None,
            extractor: ExtractorConfig::default(),
        })
        .map_err(|error| error.to_string())?;
    let beacon_valid = randomness
        .beacon()
        .verify(&beacon)
        .map_err(|error| error.to_string())?;

    let mut encoded = [0u8; KPUB_MAX_LEN];
    let len = derive_and_serialize_kpub(&[0x31; 64], &mut encoded)
        .map_err(|error| error.to_string())?;
    let kpub = std::str::from_utf8(&encoded[..len]).map_err(|error| error.to_string())?;
    let stealth = portal.privacy().stealth();
    let metadata = stealth
        .derive_metadata(kpub)
        .map_err(|error| error.to_string())?;
    let payment = stealth
        .generate_payment(&metadata, &[0x53; 32])
        .map_err(|error| error.to_string())?;

    if iteration == 0 {
        let covenant_portal = KaspaPortal::builder()
            .network(super::covenant_network())
            .build()
            .map_err(|error| error.to_string())?;
        let zk = covenant_portal.contract().zk();
        let (proving, verifying) = zk.trusted_setup().map_err(|error| error.to_string())?;
        let (proof, input, _) = zk
            .prove_crowdfund(&proving, &[10_000_000, 20_000_000])
            .map_err(|error| error.to_string())?;
        let valid = zk
            .verify(&verifying, &proof, &input)
            .map_err(|error| error.to_string())?;
        black_box(valid);
    }
    black_box((verified, beacon_valid.valid, payment.one_time_pubkey));
    Ok(())
}
