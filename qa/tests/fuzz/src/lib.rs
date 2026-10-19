//! Fuzz harness bodies, shared by the libFuzzer targets and by a stable smoke
//! test that drives every harness on each validation run.
//!
//! Each harness must never panic on hostile input. Where Portal can re-emit
//! what it accepted, the harness also checks that the encoding round-trips,
//! so the fuzzer finds wrong answers as well as crashes.

use kaspa_portal::{
    contract::script::{extract_cltv_locktime, extract_csv_sequence},
    indexer::{IndexedTransaction, IndexerApi, IndexerConfig},
    network::wrpc::{block_added, notification, validate_response},
    randomness::beacon::{verify_result, BeaconResult},
    transaction::{
        interchange::{
            kspt::{parse_compact_kspt, serialize_compact_kspt_vec, wire::Limits},
            pskt::{
                parse_summary, pipeline,
                shared::{PsktParsed, TxInputFormat},
                standard::{parse_pskt, serialize_pskt_vec, PSKB_MAGIC, PSKT_MAGIC},
            },
            qr::{
                decode_frame, encode_frame, frame::MIN_ENCODED_FRAME_LEN, parse_frame,
                reset_decoder, session_id, MAX_FRAMES,
            },
        },
        model::Transaction,
    },
    wallet::address::validate_kaspa_address,
};

#[cfg(test)]
mod smoke;

pub fn address(data: &[u8]) {
    let _ = validate_kaspa_address(data);
}

pub fn beacon_proof(data: &[u8]) {
    if let Ok(value) = serde_json::from_slice::<BeaconResult>(data) {
        let _ = verify_result(&value);
    }
}

pub fn indexer_transaction(data: &[u8]) {
    let Ok(tx) = serde_json::from_slice::<IndexedTransaction>(data) else {
        return;
    };
    if let Ok(indexer) = IndexerApi::with_clock(IndexerConfig::default(), || Ok(0)) {
        let _ = indexer.ingest_transaction(tx);
    }
}

pub fn script(data: &[u8]) {
    let _ = extract_cltv_locktime(data);
    let _ = extract_csv_sequence(data);
}

/// A compact KSPT Portal accepts re-encodes to a stable form.
pub fn kspt(data: &[u8]) {
    let mut transaction = Transaction::try_new().expect("transaction storage");
    if parse_compact_kspt(data, &mut transaction).is_err() {
        return;
    }
    let encoded = serialize_compact_kspt_vec(&transaction).expect("accepted KSPT re-encodes");
    let mut reparsed = Transaction::try_new().expect("transaction storage");
    parse_compact_kspt(&encoded, &mut reparsed).expect("re-encoded KSPT parses");
    assert_eq!(
        serialize_compact_kspt_vec(&reparsed).expect("reparsed KSPT re-encodes"),
        encoded,
        "KSPT encoding is not stable"
    );
}

/// Fuzz the PSKT/PSKB JSON body directly: the first byte picks the envelope
/// and the rest is the JSON, hex-wrapped exactly as the wire carries it.
pub fn pskt(data: &[u8]) {
    let Some((wire, format)) = pskt_wire(data) else {
        return;
    };
    let Some(first) = pskt_canonical(&wire, format) else {
        return;
    };
    let second = pskt_canonical(&first, format).expect("canonical PSKT parses");
    assert_eq!(second, first, "PSKT canonical form is not stable");
}

fn pskt_wire(data: &[u8]) -> Option<(Vec<u8>, TxInputFormat)> {
    let (&selector, json) = data.split_first()?;
    let (magic, format) = if selector & 1 == 0 {
        (PSKT_MAGIC, TxInputFormat::PsktSingle)
    } else {
        (PSKB_MAGIC, TxInputFormat::PsktPskb)
    };
    let mut wire = magic.to_vec();
    wire.extend_from_slice(hex::encode(json).as_bytes());
    Some((wire, format))
}

fn pskt_canonical(wire: &[u8], format: TxInputFormat) -> Option<Vec<u8>> {
    let mut scratch = vec![0u8; wire.len() / 2 + 1];
    let mut transaction = Transaction::try_new().expect("transaction storage");
    let mut parsed = PsktParsed::empty();
    parse_pskt(wire, &mut scratch, &mut transaction, &mut parsed).ok()?;
    Some(
        serialize_pskt_vec(&transaction, &parsed, &scratch, format)
            .expect("accepted PSKT re-serializes"),
    )
}

pub fn pskb(data: &[u8]) {
    // PSKB/PSKT wire APIs accept hexadecimal text. Hex-encoding arbitrary
    // fuzzer bytes keeps every byte representable while still exercising the
    // full envelope detection, JSON/schema parser, and review path.
    let _ = parse_summary(&hex::encode(data), "kaspa");
}

pub fn signed_transaction(data: &[u8]) {
    if let Ok(verified) = pipeline::verify_complete_kspt(data, Limits::grammar()) {
        let _ = verified.to_consensus();
    }
}

/// Every wRPC frame decoder Portal exposes to node responses.
pub fn rpc_response(data: &[u8]) {
    let _ = validate_response(data);
    let _ = notification::decode(data);
    let _ = block_added::decode(data);
}

/// A QR frame Portal accepts is exactly what its encoder emits, up to
/// trailing zero padding.
pub fn qr_frame(data: &[u8]) {
    let Ok(frame) = parse_frame(data) else {
        return;
    };
    let mut encoded = vec![0u8; data.len().max(MIN_ENCODED_FRAME_LEN)];
    let written = encode_frame(
        &frame.session_id,
        frame.frame_index,
        frame.total_frames,
        frame.fragment,
        &mut encoded,
    )
    .expect("accepted frame re-encodes");
    let common = written.min(data.len());
    assert_eq!(
        &encoded[..common],
        &data[..common],
        "QR frame re-encoding differs"
    );
    assert!(
        data[common..].iter().all(|byte| *byte == 0),
        "non-zero QR padding accepted"
    );
}

const FRAGMENT_LEN: usize = 91;

/// Any payload split into session frames reassembles exactly, whichever frame
/// arrives first and however often frames repeat.
pub fn qr_session(data: &[u8]) {
    let Some((&rotation, payload)) = data.split_first() else {
        return;
    };
    let fragments: Vec<&[u8]> = payload.chunks(FRAGMENT_LEN).collect();
    if fragments.len() < 2 || fragments.len() > MAX_FRAMES {
        return;
    }
    let frames = session_frames(payload, &fragments);
    let count = frames.len();
    let start = usize::from(rotation) % count;
    reset_decoder();
    for step in 0..count {
        let frame = &frames[(start + step) % count];
        let last = step + 1 == count;
        let expected = last.then(|| hex::encode(payload));
        assert_eq!(decode_frame(frame), Ok(expected), "frame {step} of {count}");
        if !last {
            assert_eq!(decode_frame(frame), Ok(None), "repeated frame {step}");
        }
    }
}

fn session_frames(payload: &[u8], fragments: &[&[u8]]) -> Vec<String> {
    let identifier = session_id(payload);
    let total = u8::try_from(fragments.len()).expect("bounded frame count");
    fragments
        .iter()
        .zip(0u8..)
        .map(|(fragment, index)| {
            let mut frame = [0u8; 128];
            let written = encode_frame(&identifier, index, total, fragment, &mut frame)
                .expect("bounded frame encodes");
            hex::encode(&frame[..written])
        })
        .collect()
}
