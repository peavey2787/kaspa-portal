use kaspa_portal::{
    primitives::NetworkId,
    wallet::key::xpub::{derive_and_serialize_multisig_kpub, KPUB_MAX_LEN},
};

pub const FUNDED_XPRV_ENV: &str = "KASPA_PORTAL_E2E_XPRV";
pub const MIN_FUNDED_BALANCE_SOMPI: u64 = 1_000_000_000;
pub const SPEND_AMOUNT_SOMPI: u64 = 100_000_000;
pub const PRIORITY_FEE_SOMPI: u64 = 300_000;

pub fn standard_network_name() -> String {
    std::env::var("KASPA_PORTAL_E2E_STANDARD_NETWORK").unwrap_or_else(|_| "testnet-10".to_owned())
}

pub fn covenant_network_name() -> String {
    std::env::var("KASPA_PORTAL_E2E_COVENANT_NETWORK").unwrap_or_else(|_| "testnet-12".to_owned())
}

pub fn standard_network() -> NetworkId {
    NetworkId::parse(&standard_network_name()).expect("valid standard E2E network")
}

pub fn covenant_network() -> NetworkId {
    NetworkId::parse(&covenant_network_name()).expect("valid covenant E2E network")
}

pub fn standard_endpoint() -> String {
    std::env::var("KASPA_PORTAL_E2E_STANDARD_ENDPOINT")
        .or_else(|_| std::env::var("KASPA_PORTAL_E2E_ENDPOINT"))
        .unwrap_or_else(|_| "wss://photon-10.kaspa.red/kaspa/testnet-10/wrpc/borsh".to_owned())
}

pub fn covenant_endpoint() -> String {
    std::env::var("KASPA_PORTAL_E2E_COVENANT_ENDPOINT")
        .unwrap_or_else(|_| "ws://tn12-node.kaspa.com:17210".to_owned())
}

pub fn deterministic_multisig_kpub(seed_byte: u8) -> String {
    let seed = [seed_byte; 64];
    let mut encoded = [0u8; KPUB_MAX_LEN];
    let len = derive_and_serialize_multisig_kpub(&seed, &mut encoded)
        .expect("derive deterministic multisig kpub");
    std::str::from_utf8(&encoded[..len])
        .expect("multisig kpub text")
        .to_owned()
}
