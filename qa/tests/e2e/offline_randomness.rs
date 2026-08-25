use kaspa_portal::{
    randomness::{
        beacon::BeaconRequest,
        extractor::ExtractorConfig,
        source::kaspa::KaspaEntropyEvidence,
        vrf::VrfSecretKey,
    },
    KaspaPortal,
};

#[test]
#[ignore = "Pass 2 E2E: run through qa/scripts/run-e2e-rust"]
fn rust_offline_randomness() {
    let portal = KaspaPortal::builder()
        .network(crate::support::standard_network())
        .build()
        .expect("offline portal");
    let randomness = portal.randomness();
    let beacon = randomness.beacon();
    let vrf = randomness.vrf();

    let evidence = KaspaEntropyEvidence::finalized([0x41; 32], Some(123_456));
    beacon
        .observe_kaspa_block(evidence.clone())
        .expect("observe finalized Kaspa block");
    let request = BeaconRequest {
        network: crate::support::standard_network(),
        context: b"kaspa-portal-e2e".to_vec(),
        kaspa: vec![evidence],
        curby: None,
        extractor: ExtractorConfig::default(),
    };
    let generated = beacon.generate(request).expect("generate beacon");
    assert_ne!(generated.output, [0u8; 32]);
    let verification = beacon.verify(&generated).expect("verify beacon");
    assert!(verification.valid);
    assert!(verification.kaspa_evidence_finalized);
    assert!(!verification.uses_curby);

    let fixed_secret = VrfSecretKey::from_bytes([0x21; 32]);
    let fixed_public = fixed_secret.public_key();
    assert_eq!(fixed_secret.expose_secret(), [0x21; 32]);
    let fixed_result = vrf
        .prove(&fixed_secret, b"kaspa-portal-e2e-vrf")
        .expect("VRF proof");
    let fixed_output = vrf
        .verify(&fixed_public, b"kaspa-portal-e2e-vrf", &fixed_result.proof)
        .expect("VRF verify");
    assert_eq!(fixed_output, fixed_result.output);

    let (generated_secret, generated_public) = vrf.generate_keypair().expect("generate VRF keypair");
    assert_eq!(generated_secret.public_key(), generated_public);
    let generated_result = vrf
        .prove(&generated_secret, b"generated-key-e2e")
        .expect("generated-key VRF proof");
    assert_eq!(
        vrf.verify(
            &generated_public,
            b"generated-key-e2e",
            &generated_result.proof,
        )
        .expect("generated-key VRF verify"),
        generated_result.output
    );
    assert!(
        vrf.verify(
            &generated_public,
            b"tampered-input",
            &generated_result.proof,
        )
        .is_err()
    );
}
