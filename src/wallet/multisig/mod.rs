mod address_index;
mod descriptor;
pub mod grammar;
mod redeem_script;

pub use address_index::{resolve_address_path, ResolvedMultisigPath};
pub use descriptor::MultisigDescriptor;
pub use redeem_script::build_redeem_script;

/// Most cosigners one `OP_CHECKMULTISIG` redeem script may name.
pub const MAX_MULTISIG_KEYS: usize = 16;

#[cfg(test)]
#[path = "unit-tests/mod.rs"]
mod unit_tests;
