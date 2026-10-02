use super::{number::find_preceding_script_integer, opcode};
#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;

pub fn extract_cltv_locktime(script: &[u8]) -> Result<Option<u64>, String> {
    find_preceding_script_integer(script, opcode::OP_CHECKLOCKTIMEVERIFY)
}

pub fn extract_csv_sequence(script: &[u8]) -> Result<Option<u64>, String> {
    find_preceding_script_integer(script, opcode::OP_CHECKSEQUENCEVERIFY)
}
