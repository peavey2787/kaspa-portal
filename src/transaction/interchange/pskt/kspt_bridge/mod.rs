// Kaspa Portal — organized PSKT subsystem
// License: GPL-3.0

#[cfg(feature = "std")]
mod encoder;
mod merger;
mod parser_compact;
mod parser_transaction;
mod reader;
#[cfg(feature = "std")]
mod relay;

pub(crate) use crate::transaction::interchange::pskt::model::KsptSigRecord;
#[cfg(all(test, feature = "std"))]
pub(crate) use encoder::{collect_finalized_covenant_signature, collect_signatures};
#[cfg(feature = "std")]
pub(crate) use encoder::{encode_compact_kspt_input, encode_output_kspt, KsptEncodingMode};
pub use merger::merge_signed_kspt_into_pskb;
pub(crate) use parser_compact::{parse_compact_kspt_signatures, xonly_at_position};
pub(crate) use parser_transaction::parse_compact_kspt_transaction;
#[cfg(test)]
pub(crate) use parser_transaction::require_compact_trailer_progress;
pub(crate) use reader::KsptReader;
#[cfg(all(test, feature = "std"))]
pub(crate) use relay::first_outpoint;
#[cfg(feature = "std")]
pub use relay::relay_pskb_as_kspt_hex_for_network;
