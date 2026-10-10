#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
// Kaspa Portal — organized PSKT subsystem
// License: GPL-3.0

pub(crate) fn push_data_item(ss: &mut Vec<u8>, data: &[u8]) -> Result<(), String> {
    let len = data.len();
    if len == 0 {
        ss.push(0x00); // OP_0 = empty
    } else if len <= 75 {
        ss.push(len as u8);
    } else if len <= 255 {
        ss.push(0x4C);
        ss.push(len as u8);
    } else if len <= 65535 {
        ss.push(0x4D);
        ss.extend_from_slice(&(len as u16).to_le_bytes());
    } else {
        return Err("data item too large".into());
    }
    ss.extend_from_slice(data);
    Ok(())
}

pub fn push_redeem_script(buf: &mut Vec<u8>, redeem: &[u8]) -> Result<(), String> {
    push_data_item(buf, redeem).map_err(|_| "redeem script too large".to_string())
}
