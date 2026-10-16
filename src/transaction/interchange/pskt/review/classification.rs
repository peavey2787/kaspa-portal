#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
// Kaspa Portal — organized PSKT subsystem
// License: GPL-3.0

pub(crate) fn classify_input_script(
    spk: &[u8],
    redeem: Option<&[u8]>,
) -> (String, Option<u8>, Option<u8>) {
    if crate::primitives::address::p2sh_hash(spk).is_some() {
        return classify_p2sh_redeem(redeem);
    }
    if crate::primitives::address::p2pk_xonly(spk).is_some() {
        return ("p2pk".into(), None, None);
    }
    ("unknown".into(), None, None)
}

fn classify_p2sh_redeem(redeem: Option<&[u8]>) -> (String, Option<u8>, Option<u8>) {
    let Some(script) = redeem else {
        return ("p2sh".into(), None, None);
    };
    if let Some((m, n)) =
        crate::transaction::interchange::pskt::pipeline::parse_multisig_redeem(script)
    {
        return ("p2sh-multisig".into(), Some(m), Some(n));
    }
    if script.first() == Some(&0x63) {
        return ("p2sh-covenant".into(), None, None);
    }
    ("p2sh".into(), None, None)
}

pub(crate) fn classify_output_script(spk: &[u8], network_prefix: &str) -> (String, Option<String>) {
    // P2SH
    if let Some(hash) = crate::primitives::address::p2sh_hash(spk) {
        return (
            "p2sh".into(),
            Some(crate::primitives::address::encode_p2sh_address(
                &hash,
                network_prefix,
            )),
        );
    }
    // P2PK
    if let Some(pk) = crate::primitives::address::p2pk_xonly(spk) {
        return (
            "p2pk".into(),
            Some(crate::primitives::address::encode_p2pk_address(
                &pk,
                network_prefix,
            )),
        );
    }
    ("unknown".into(), None)
}
