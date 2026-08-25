use kaspa_portal::wallet::address::{
    encode_address_str_for_network, validate_kaspa_address, AddressType, KaspaNetwork, MAX_ADDR_LEN,
};

#[test]
fn generated_mainnet_p2pk_address_validates() {
    let mut buffer = [0u8; MAX_ADDR_LEN];
    let address = encode_address_str_for_network(
        &[0x42; 32],
        AddressType::P2pk,
        KaspaNetwork::Mainnet,
        &mut buffer,
    );
    assert!(address.starts_with("kaspa:"));
    assert!(validate_kaspa_address(address.as_bytes()));
}
