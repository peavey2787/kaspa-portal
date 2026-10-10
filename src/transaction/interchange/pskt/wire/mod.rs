// Kaspa Portal — PSKT / PSKB wire handling
// License: GPL-3.0

mod envelope;
mod json;
mod mutation;

pub use envelope::detect_format_hex;
pub(crate) use envelope::{
    decode_root, decode_root_for_review, encode_root, first_pskt_from_pskb_mut,
    pskt_from_root_for_review,
};
#[cfg(test)]
pub(crate) use envelope::{format_wire_error, ErrorStyle};
#[cfg(test)]
pub(crate) use mutation::inject_tx_payload;
pub use mutation::{set_payload, set_tx_lane};
