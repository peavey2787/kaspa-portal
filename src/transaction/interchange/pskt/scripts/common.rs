#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
// Kaspa Portal — organized PSKT subsystem
// License: GPL-3.0

pub(crate) fn push_data_item(ss: &mut Vec<u8>, data: &[u8]) -> Result<(), String> {
    // Signature-script items never need OP_PUSHDATA4.
    if data.len() > usize::from(u16::MAX) {
        return Err("data item too large".into());
    }
    crate::contract::script::push_data(ss, data);
    Ok(())
}

pub fn push_redeem_script(buf: &mut Vec<u8>, redeem: &[u8]) -> Result<(), String> {
    push_data_item(buf, redeem).map_err(|_| "redeem script too large".to_string())
}
