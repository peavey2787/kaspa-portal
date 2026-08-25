use kaspa_portal::KaspaPortal;

use crate::support::standard_network;

use crate::support::{deterministic_kpub, raw_scanner_fixture};

#[test]
#[ignore = "Pass 2 E2E: run through qa/scripts/run-e2e-rust"]
fn rust_offline_privacy() {
    let network = standard_network();
    let portal = KaspaPortal::builder()
        .network(network)
        .build()
        .expect("offline portal");
    let stealth = portal.privacy().stealth();
    let kpub = deterministic_kpub(0x31);

    let metadata = stealth.derive_metadata(&kpub).expect("derive stealth metadata");
    let encoded = stealth.encode_metadata(&metadata);
    assert_eq!(encoded.len(), 128);
    let decoded = stealth.decode_metadata(&encoded).expect("decode stealth metadata");
    assert_eq!(stealth.encode_metadata(&decoded), encoded);

    let payment = stealth
        .generate_payment(&decoded, &[0x53; 32])
        .expect("generate stealth payment");
    assert_ne!(payment.one_time_pubkey, [0u8; 32]);
    assert_ne!(payment.ephemeral_pubkey, [0u8; 32]);

    let announcement = stealth.announcement_address(network.address_prefix());
    assert!(announcement.starts_with(&format!("{}:", network.address_prefix())));

    let transaction_id = [0x61; 32];
    let raw = raw_scanner_fixture(&transaction_id, b"portal-e2e-preimage");
    assert_eq!(
        stealth.scan_raw_for_preimage(&raw, &transaction_id),
        Some(b"portal-e2e-preimage".to_vec())
    );
    assert_eq!(stealth.scan_raw_for_preimage(&raw, &[0x62; 32]), None);
}
