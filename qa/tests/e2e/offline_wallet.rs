use kaspa_portal::KaspaPortal;

use crate::support::standard_network;

use crate::support::{deterministic_kpub, deterministic_raw_kpub};

#[test]
#[ignore = "Pass 2 E2E: run through qa/scripts/run-e2e-rust"]
fn rust_offline_wallet() {
    let network = standard_network();
    let portal = KaspaPortal::builder()
        .network(network)
        .build()
        .expect("offline portal");
    let wallet_api = portal.wallet();

    let kpub = deterministic_kpub(7);
    let wallet = wallet_api.import_kpub(&kpub).expect("text kpub import");
    assert_eq!(wallet.receive_addresses.len(), 20);
    assert_eq!(wallet.change_addresses.len(), 20);
    let expected_prefix = format!("{}:", network.address_prefix());
    assert!(wallet
        .receive_addresses
        .iter()
        .all(|value| value.starts_with(&expected_prefix)));

    let raw = deterministic_raw_kpub(7);
    let raw_wallet = wallet_api.import_kpub_raw(&raw).expect("raw kpub import");
    assert_eq!(raw_wallet.kpub, wallet.kpub);
    assert_eq!(raw_wallet.receive_addresses, wallet.receive_addresses);

    let extended = wallet_api
        .extend_addresses(&wallet, 3, 2)
        .expect("extend address ranges");
    assert_eq!(extended.receive_addresses.len(), 23);
    assert_eq!(extended.change_addresses.len(), 22);
    assert_eq!(&extended.receive_addresses[..20], wallet.receive_addresses.as_slice());

    let words12 = wallet_api.mnemonic_12_from_entropy(&[0x11; 16]);
    let words24 = wallet_api.mnemonic_24_from_entropy(&[0x22; 32]);
    assert_eq!(words12.indices.len(), 12);
    assert_eq!(words24.indices.len(), 24);
    assert_eq!(wallet_api.prefix(), network.address_prefix());
}
