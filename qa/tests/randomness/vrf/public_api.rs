use kaspa_portal::KaspaPortal;

#[test]
fn generated_vrf_key_proves_and_verifies_without_wallet_key_reuse() {
    let portal = KaspaPortal::builder().build().unwrap();
    let vrf = portal.randomness().vrf();
    let (secret, public) = vrf.generate_keypair().unwrap();
    let message = b"kaspa-portal-vrf-public-api";
    let result = vrf.prove(&secret, message).unwrap();
    let verified = vrf.verify(&public, message, &result.proof).unwrap();
    assert_eq!(verified, result.output);
    assert!(vrf.verify(&public, b"different", &result.proof).is_err());
}
