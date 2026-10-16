//! Shipment-escrow terms read back from a redeem script.
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

use crate::contract::script::{complete_elements, element_integer};
use crate::primitives::script::Element;

use super::script::{
    build_ship_escrow_script, ShippingEscrowScriptRequest, ShippingEscrowTranches,
};

// Element positions of the variable fields in what the builder emits.
const SALT: usize = 0;
const TOTAL: usize = 5;
const DELIVERER_PUBKEY: usize = 10;
const SELLER_SPK: usize = 23;
const ARBITER_PUBKEY: usize = 31;
const PICKUP_DEADLINE: usize = 34;
const BUYER_SPK: usize = 39;
const DELIVERY_DEADLINE: usize = 61;
const FEE: usize = 75;

/// Everything [`build_ship_escrow_script`] was given, salt included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShippingEscrowTerms {
    pub seller_pubkey: [u8; 32],
    pub deliverer_pubkey: [u8; 32],
    pub buyer_pubkey: [u8; 32],
    pub arbiter_pubkey: [u8; 32],
    pub product_sompi: u64,
    pub fee_sompi: u64,
    pub cltv1_deadline: u64,
    pub cltv2_deadline: u64,
    pub salt: [u8; 8],
}

/// Recognize `script` as exactly what [`build_ship_escrow_script`] builds.
#[must_use]
pub fn ship_escrow_terms(script: &[u8]) -> Option<ShippingEscrowTerms> {
    let elements = complete_elements(script)?;
    let integer = |at: usize| elements.get(at).and_then(element_integer);
    let fee_sompi = integer(FEE)?;
    let terms = ShippingEscrowTerms {
        seller_pubkey: spk_pubkey(elements.get(SELLER_SPK)?)?,
        deliverer_pubkey: bytes(elements.get(DELIVERER_PUBKEY)?)?,
        buyer_pubkey: spk_pubkey(elements.get(BUYER_SPK)?)?,
        arbiter_pubkey: bytes(elements.get(ARBITER_PUBKEY)?)?,
        product_sompi: integer(TOTAL)?.checked_sub(fee_sompi)?,
        fee_sompi,
        cltv1_deadline: integer(PICKUP_DEADLINE)?,
        cltv2_deadline: integer(DELIVERY_DEADLINE)?,
        salt: bytes(elements.get(SALT)?)?,
    };
    (build_ship_escrow_script(terms.request()).ok()? == script).then_some(terms)
}

impl ShippingEscrowTerms {
    /// The funded total and what stays locked after the pickup tranche.
    pub fn tranches(&self) -> Result<ShippingEscrowTranches, String> {
        ShippingEscrowTranches::new(self.product_sompi, self.fee_sompi)
    }

    fn request(&self) -> ShippingEscrowScriptRequest<'_> {
        ShippingEscrowScriptRequest {
            seller_pubkey: &self.seller_pubkey,
            deliverer_pubkey: &self.deliverer_pubkey,
            buyer_pubkey: &self.buyer_pubkey,
            arbiter_pubkey: &self.arbiter_pubkey,
            product_sompi: self.product_sompi,
            fee_sompi: self.fee_sompi,
            cltv1_deadline: self.cltv1_deadline,
            cltv2_deadline: self.cltv2_deadline,
            salt: &self.salt,
        }
    }
}

fn bytes<const N: usize>(element: &Element<'_>) -> Option<[u8; N]> {
    element.data.try_into().ok()
}

// A P2PK script public key is `00 00 20 <key> OP_CHECKSIG`.
fn spk_pubkey(element: &Element<'_>) -> Option<[u8; 32]> {
    element.data.get(3..35)?.try_into().ok()
}

#[cfg(test)]
#[path = "unit-tests/terms.rs"]
mod unit_tests;
