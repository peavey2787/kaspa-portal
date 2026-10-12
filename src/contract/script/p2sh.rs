#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

pub fn script_to_address(redeem_script: &[u8], prefix: &str) -> Result<String, String> {
    Ok(crate::primitives::address::script_to_p2sh_address(
        redeem_script,
        prefix,
    ))
}
