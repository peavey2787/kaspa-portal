#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
use crate::primitives::multisig_script::{encode, encoded_len, MAX_SCRIPT_KEYS};

pub fn build_redeem_script(threshold: u8, public_keys: &[[u8; 32]]) -> Result<Vec<u8>, String> {
    // Bounded before allocating; more keys than a script can declare fail to encode.
    let mut script = vec![0u8; encoded_len(public_keys.len().min(MAX_SCRIPT_KEYS))];
    encode(threshold, public_keys, &mut script)
        .ok_or_else(|| format!("Invalid {}-of-{} multisig", threshold, public_keys.len()))?;
    Ok(script)
}
