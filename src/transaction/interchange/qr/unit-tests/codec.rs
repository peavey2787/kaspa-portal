//! QR framing round-trips through the decoder, and SVG rendering draws exactly
//! the code's dark modules.

use std::collections::BTreeSet;

use super::{
    decode_frame, decoder_progress, frame_payloads, generate_frames, generate_svg_from_text,
    qr_to_svg, reset_decoder, MAX_FRAMES, MAX_FRAME_DATA, SINGLE_FRAME_DATA,
};
use crate::transaction::interchange::qr::frame::{encode_frame, session_id};

fn data(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index * 7 % 251) as u8).collect()
}

#[test]
fn payloads_fit_one_code_up_to_its_capacity_then_split_evenly() {
    assert_eq!(
        frame_payloads(&data(SINGLE_FRAME_DATA)),
        Ok(vec![data(SINGLE_FRAME_DATA)])
    );
    assert_eq!(
        frame_payloads(&data(SINGLE_FRAME_DATA + 1)).unwrap().len(),
        2
    );
    assert_eq!(frame_payloads(&data(3 * MAX_FRAME_DATA)).unwrap().len(), 3);
    assert_eq!(
        frame_payloads(&data(3 * MAX_FRAME_DATA + 1)).unwrap().len(),
        4
    );
    assert_eq!(
        frame_payloads(&data(MAX_FRAMES * MAX_FRAME_DATA))
            .unwrap()
            .len(),
        MAX_FRAMES
    );
    assert!(frame_payloads(&data(MAX_FRAMES * MAX_FRAME_DATA + 1))
        .unwrap_err()
        .contains("Too large"));
    assert_eq!(frame_payloads(&[]), Err("Empty data".to_string()));
}

#[test]
fn frames_reassemble_in_any_order_and_report_progress() {
    let original = data(500);
    let payloads = frame_payloads(&original).unwrap();
    assert_eq!(payloads.len(), 6);
    assert_eq!(decoder_progress(), "0/0");
    let (last, rest) = payloads.split_last().unwrap();
    for payload in rest.iter().rev() {
        assert_eq!(decode_frame(&hex::encode(payload)), Ok(None));
        // An identical repeat is ignored.
        assert_eq!(decode_frame(&hex::encode(payload)), Ok(None));
    }
    assert_eq!(
        decoder_progress(),
        r#"{"total":6,"count":5,"bits":[1,1,1,1,1,0]}"#
    );
    assert_eq!(
        decode_frame(&hex::encode(last)),
        Ok(Some(hex::encode(&original)))
    );
    // Completion resets the decoder for the next transfer.
    assert_eq!(decoder_progress(), "0/0");
}

fn frame(session_data: &[u8], index: u8, total: u8, fragment: &[u8]) -> String {
    let mut payload = [0u8; SINGLE_FRAME_DATA];
    let length = encode_frame(
        &session_id(session_data),
        index,
        total,
        fragment,
        &mut payload,
    )
    .expect("test frame encodes");
    hex::encode(&payload[..length])
}

#[test]
fn conflicting_mixed_and_forged_frames_are_rejected() {
    let original = data(182);
    let other = data(183);
    assert_eq!(
        decode_frame(&frame(&original, 0, 2, &original[..91])),
        Ok(None)
    );
    assert!(decode_frame(&frame(&original, 0, 2, &original[1..92]))
        .unwrap_err()
        .contains("Conflicting duplicate"));
    assert_eq!(decoder_progress(), "0/0");

    assert_eq!(
        decode_frame(&frame(&original, 0, 2, &original[..91])),
        Ok(None)
    );
    assert!(decode_frame(&frame(&other, 1, 2, &other[91..]))
        .unwrap_err()
        .contains("Mixed multi-frame"));
    assert_eq!(decoder_progress(), "0/0");

    // Fragments that do not hash to the announced session are refused.
    assert_eq!(
        decode_frame(&frame(&other, 0, 2, &original[..91])),
        Ok(None)
    );
    assert!(decode_frame(&frame(&other, 1, 2, &original[91..]))
        .unwrap_err()
        .contains("digest mismatch"));
    assert_eq!(decoder_progress(), "0/0");

    assert!(decode_frame("zz").unwrap_err().contains("Invalid hex"));
    assert!(decode_frame("00")
        .unwrap_err()
        .contains("Invalid multi-frame"));
}

#[test]
fn reset_decoder_abandons_a_transfer_in_progress() {
    let original = data(182);
    assert_eq!(
        decode_frame(&frame(&original, 0, 2, &original[..91])),
        Ok(None)
    );
    assert_eq!(decoder_progress(), r#"{"total":2,"count":1,"bits":[1,0]}"#);
    reset_decoder();
    assert_eq!(decoder_progress(), "0/0");
    assert_eq!(
        decode_frame(&frame(&original, 1, 2, &original[91..])),
        Ok(None)
    );
}

#[test]
fn a_rejected_frame_never_blocks_the_next_transfer() {
    let first = data(182);
    let second = data(183);
    assert_eq!(decode_frame(&frame(&first, 0, 2, &first[..91])), Ok(None));
    assert!(decode_frame(&frame(&second, 1, 2, &second[91..]))
        .unwrap_err()
        .contains("Mixed multi-frame"));
    // No reset_decoder call: the second transfer assembles on its own.
    assert_eq!(decode_frame(&frame(&second, 0, 2, &second[..91])), Ok(None));
    assert_eq!(
        decode_frame(&frame(&second, 1, 2, &second[91..])),
        Ok(Some(hex::encode(&second)))
    );

    // Text that is not a frame leaves a transfer in progress untouched.
    assert_eq!(decode_frame(&frame(&first, 0, 2, &first[..91])), Ok(None));
    assert!(decode_frame("00").is_err());
    assert_eq!(
        decode_frame(&frame(&first, 1, 2, &first[91..])),
        Ok(Some(hex::encode(&first)))
    );
}

#[test]
fn generated_frames_are_numbered_and_rendered() {
    let single = generate_frames(&hex::encode(data(20))).unwrap();
    assert_eq!(single.len(), 1);
    assert_eq!((single[0].frame_num, single[0].total_frames), (0, 1));
    assert_eq!(single[0].svg, qr_to_svg(&data(20)).unwrap());

    let multi = generate_frames(&hex::encode(data(400))).unwrap();
    let payloads = frame_payloads(&data(400)).unwrap();
    assert_eq!(multi.len(), payloads.len());
    for ((frame, payload), index) in multi.iter().zip(&payloads).zip(0u8..) {
        assert_eq!(
            (frame.frame_num, frame.total_frames),
            (index, multi.len() as u8)
        );
        assert_eq!(frame.svg, qr_to_svg(payload).unwrap());
    }
    assert!(generate_frames("xyz").unwrap_err().contains("Invalid hex"));
}

#[test]
fn svg_draws_each_dark_module_offset_by_the_quiet_border() {
    let payload = b"kaspa portal";
    let code = qrcode::QrCode::new(payload).unwrap();
    let width = code.width();
    let expected: BTreeSet<(usize, usize)> = code
        .to_colors()
        .iter()
        .enumerate()
        .filter(|(_, color)| **color == qrcode::types::Color::Dark)
        .map(|(index, _)| (index % width + 2, index / width + 2))
        .collect();

    let svg = qr_to_svg(payload).unwrap();
    let side = width + 4;
    assert!(svg.starts_with(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {side} {side}\""
    )));
    assert!(svg.ends_with("</svg>"));
    let drawn: BTreeSet<(usize, usize)> = svg
        .split("<rect x=\"")
        .skip(1)
        .map(|rect| {
            let (x, rest) = rect.split_once("\" y=\"").unwrap();
            let (y, _) = rest.split_once('"').unwrap();
            (x.parse().unwrap(), y.parse().unwrap())
        })
        .collect();
    assert_eq!(drawn, expected);
    assert_eq!(generate_svg_from_text("kaspa portal"), Ok(svg));
}
