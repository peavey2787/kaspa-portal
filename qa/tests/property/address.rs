use kaspa_portal::wallet::address::{
    encode_address_str_for_network, validate_kaspa_address, AddressType, KaspaNetwork, MAX_ADDR_LEN,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn every_encoded_p2pk_address_validates(pubkey in any::<[u8; 32]>()) {
        let mut buffer = [0u8; MAX_ADDR_LEN];
        let address = encode_address_str_for_network(
            &pubkey,
            AddressType::P2pk,
            KaspaNetwork::Mainnet,
            &mut buffer,
        );
        prop_assert!(validate_kaspa_address(address.as_bytes()));
    }
}
