use kaspa_portal::{
    primitives::NetworkId,
    wallet::{
        account::derivation::WalletData,
        key::xpub::{derive_and_serialize_kpub, derive_and_serialize_multisig_kpub, KPUB_MAX_LEN},
    },
    KaspaPortal,
};

pub const DEFAULT_STANDARD_NETWORK: &str = "testnet-10";
pub const DEFAULT_STANDARD_ENDPOINT: &str =
    "wss://photon-10.kaspa.red/kaspa/testnet-10/wrpc/borsh";
pub const DEFAULT_STANDARD_GENESIS_HASH: &str =
    "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370";
pub const INDEXED_FIXTURE_TXID: &str =
    "5201b38ed218ca4cf392a71ce446d75fd667b954e2efdebec1acf83e48892e2a";

pub fn now_ms() -> u64 {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_millis();
    u64::try_from(millis).expect("current Unix milliseconds fit in u64")
}

pub fn live_network_name() -> String {
    std::env::var("KASPA_PORTAL_E2E_STANDARD_NETWORK")
        .unwrap_or_else(|_| DEFAULT_STANDARD_NETWORK.to_owned())
}

pub fn live_network() -> NetworkId {
    NetworkId::parse(&live_network_name()).expect("valid standard E2E network")
}

pub fn live_endpoint() -> String {
    std::env::var("KASPA_PORTAL_E2E_STANDARD_ENDPOINT")
        .or_else(|_| std::env::var("KASPA_PORTAL_E2E_ENDPOINT"))
        .unwrap_or_else(|_| DEFAULT_STANDARD_ENDPOINT.to_owned())
}

pub fn live_genesis_hash() -> String {
    std::env::var("KASPA_PORTAL_E2E_STANDARD_GENESIS_HASH")
        .unwrap_or_else(|_| DEFAULT_STANDARD_GENESIS_HASH.to_owned())
}

pub fn deterministic_wallet(portal: &KaspaPortal, seed_byte: u8) -> WalletData {
    let seed = [seed_byte; 64];
    let mut encoded = [0u8; KPUB_MAX_LEN];
    let len = derive_and_serialize_kpub(&seed, &mut encoded).expect("derive deterministic kpub");
    let text = std::str::from_utf8(&encoded[..len]).expect("kpub text");
    portal.wallet().import_kpub(text).expect("import kpub")
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
