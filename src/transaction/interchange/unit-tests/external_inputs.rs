//! Every parser that consumes data from outside the device must be total:
//! truncated input and noise of any length yields an error, never a panic.

use crate::{
    crypto::kdf::password,
    transaction::{
        interchange::{kspt, pskt::standard, qr},
        model::Transaction,
        signing::private_swap,
    },
    wallet::key::xpub,
};

fn noise(len: usize, state: &mut u64) -> alloc::vec::Vec<u8> {
    (0..len)
        .map(|_| {
            *state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (*state >> 32) as u8
        })
        .collect()
}

fn parse_everything(data: &[u8]) {
    let _ = password::parse_metadata(data);
    let _ = private_swap::parse_private_swap_script(data);
    let _ = standard::detect_tx_format(data);
    let _ = qr::parse_frame(data);
    let _ = kspt::SignedResponse::parse(data);
    let mut tx = Transaction::try_new().expect("transaction storage");
    let _ = kspt::parse_compact_kspt(data, &mut tx);
    let mut scratch = alloc::vec![0u8; 4096];
    let mut parsed = crate::transaction::interchange::pskt::shared::PsktParsed::empty();
    let _ = standard::parse_pskt(data, &mut scratch, &mut tx, &mut parsed);
    let mut out = [0u8; 78];
    let _ = xpub::decode_kpub_or_xpub(data, &mut out);
    let _ = xpub::parse_kpub_parts(data);
    parse_signing_protocols(data);
}

fn parse_signing_protocols(data: &[u8]) {
    use crate::transaction::signing::{anti_klepto::protocol as anti_klepto, covenant::protocol};

    let _ = anti_klepto::parse_request(data);
    let _ = anti_klepto::parse_commitment(data);
    let _ = anti_klepto::parse_reveal(data);
    let _ = anti_klepto::parse_signed(data);
    let _ = protocol::parse_request(data);
    let _ = protocol::parse_reveal(data);
    let _ = protocol::parse_response(data);
    let _ = protocol::private_swap::parse_request(data);
    let _ = protocol::private_swap::parse_reveal(data);
    let _ = protocol::private_swap::parse_response(data);
}

#[test]
fn externally_controlled_parsers_are_total_over_truncated_and_noise_inputs() {
    let mut state = 0x3c6e_f372_fe94_f82bu64;
    for len in 0..=600usize {
        let data = noise(len, &mut state);
        let result = std::panic::catch_unwind(|| parse_everything(&data));
        assert!(result.is_ok(), "external parser panicked at length {len}");
    }
}

#[test]
fn externally_controlled_parsers_are_total_over_valid_magic_prefixes() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for magic in [&b"KSPT\x01"[..], b"KSSN\x01", b"PSKT", b"{\"", b"kpub1:"] {
        for len in 0..=256usize {
            let mut data = magic.to_vec();
            data.extend(noise(len, &mut state));
            let result = std::panic::catch_unwind(|| parse_everything(&data));
            assert!(
                result.is_ok(),
                "parser panicked after {magic:?} + {len} bytes"
            );
        }
    }
}
