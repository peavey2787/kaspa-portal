use super::{ship_escrow_terms, ShippingEscrowTerms};

fn terms(product_sompi: u64) -> ShippingEscrowTerms {
    ShippingEscrowTerms {
        seller_pubkey: [0xa1; 32],
        deliverer_pubkey: [0xa2; 32],
        buyer_pubkey: [0xa3; 32],
        arbiter_pubkey: [0xa4; 32],
        product_sompi,
        fee_sompi: 7_777,
        cltv1_deadline: 111_111,
        cltv2_deadline: 222_222,
        salt: [9; 8],
    }
}

#[test]
fn built_scripts_read_back_to_their_terms() {
    for product in [1_000_000, 100_000_000_000] {
        let expected = terms(product);
        let script = super::build_ship_escrow_script(expected.request()).unwrap();
        assert_eq!(ship_escrow_terms(&script), Some(expected));
    }
}

#[test]
fn altered_or_foreign_scripts_are_not_shipment_escrows() {
    let mut script = super::build_ship_escrow_script(terms(1_000_000).request()).unwrap();
    assert_eq!(ship_escrow_terms(&script[..script.len() - 1]), None);
    *script.last_mut().unwrap() ^= 1;
    assert_eq!(ship_escrow_terms(&script), None);
    assert_eq!(ship_escrow_terms(&[0x51]), None);
}
