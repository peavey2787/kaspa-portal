#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
// Kaspa Portal — organized PSKT subsystem
// License: GPL-3.0

pub(crate) fn classify_input_script(
    spk: &[u8],
    redeem: Option<&[u8]>,
) -> (String, Option<u8>, Option<u8>) {
    if is_p2sh_script(spk) {
        return classify_p2sh_redeem(redeem);
    }
    if is_p2pk_script(spk) {
        return ("p2pk".into(), None, None);
    }
    ("unknown".into(), None, None)
}

fn is_p2sh_script(spk: &[u8]) -> bool {
    spk.len() == 35 && spk[0] == 0xAA && spk[1] == 0x20 && spk[34] == 0x87
}

fn is_p2pk_script(spk: &[u8]) -> bool {
    spk.len() == 34 && spk[0] == 0x20 && spk[33] == 0xAC
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
    if spk.len() == 35 && spk[0] == 0xAA && spk[1] == 0x20 && spk[34] == 0x87 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&spk[2..34]);
        return (
            "p2sh".into(),
            Some(crate::primitives::address::encode_p2sh_address(
                &hash,
                network_prefix,
            )),
        );
    }
    // P2PK
    if spk.len() == 34 && spk[0] == 0x20 && spk[33] == 0xAC {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&spk[1..33]);
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
