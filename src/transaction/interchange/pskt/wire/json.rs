#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
// Kaspa Portal — PSKT JSON body encoding
// License: GPL-3.0

use serde_json::Value;

use crate::transaction::interchange::pskt::error::PsktWireError;

/// The canonical strict grammar is the pipeline's; review and mutation share it.
pub(crate) fn decode_json_body(body_hex: &[u8]) -> Result<Value, PsktWireError> {
    crate::transaction::interchange::pskt::pipeline::decode_json_body(body_hex)
        .map_err(PsktWireError::Json)
}

pub(crate) fn encode_json_body(root: &Value) -> Result<Vec<u8>, String> {
    crate::transaction::interchange::pskt::pipeline::encode_json_body(root)
}
