// Kaspa Portal — QR frame generation and decoder
// License: GPL-3.0
//
// qr.rs — Generate QR frames as SVG strings, decode multi-frame protocol.
// Uses the session-bound shared frame format from `transaction::interchange::qr::frame`.

//! Animated-QR frame encoding and decoding for air-gapped transfer between
//! Kaspa Portal producers and consumers.

use serde::Serialize;
use std::cell::RefCell;
use std::fmt::Write;

const MAX_FRAME_DATA: usize = 91;

/// Maximum number of frames for a multi-frame QR payload. Sized to
/// cover a 3-input 2-of-3 PSKT on the tightest hardware envelope
/// (~37 B/frame on the tightest supported QR path ≈ 50 frames), with margin.
const MAX_FRAMES: usize = crate::transaction::interchange::qr::frame::MAX_FRAMES;

// ─── Frame generation ───

#[derive(Debug, Serialize)]
pub struct QrFrame {
    pub frame_num: u8,
    pub total_frames: u8,
    pub svg: String,
}

pub fn generate_frames(kspt_hex: &str) -> Result<Vec<QrFrame>, String> {
    let data = hex::decode(kspt_hex).map_err(|e| format!("Invalid hex: {}", e))?;

    if data.is_empty() {
        return Err("Empty data".into());
    }

    // Single frame if small enough
    if data.len() <= 134 {
        let svg = qr_to_svg(&data)?;
        return Ok(vec![QrFrame {
            frame_num: 0,
            total_frames: 1,
            svg,
        }]);
    }

    // Multi-frame
    let total_frames = data.len().div_ceil(MAX_FRAME_DATA);
    if total_frames > MAX_FRAMES {
        return Err(format!(
            "Too large: {} bytes ({} frames, max {})",
            data.len(),
            total_frames,
            MAX_FRAMES
        ));
    }

    let balanced_size = data.len().div_ceil(total_frames);
    let total = total_frames as u8;
    let identifier = crate::transaction::interchange::qr::frame::session_id(&data);
    let mut frames = Vec::with_capacity(total_frames);

    for frame_num in 0..total_frames {
        let start = frame_num * balanced_size;
        let end = (start + balanced_size).min(data.len());
        let fragment = &data[start..end];
        let mut payload = [0u8; 134];
        let encoded_length = crate::transaction::interchange::qr::frame::encode_frame(
            &identifier,
            frame_num as u8,
            total,
            fragment,
            &mut payload,
        )
        .map_err(|error| format!("Frame encoding failed: {:?}", error))?;

        let svg = qr_to_svg(&payload[..encoded_length])?;
        frames.push(QrFrame {
            frame_num: frame_num as u8,
            total_frames: total,
            svg,
        });
    }

    Ok(frames)
}

fn qr_to_svg(data: &[u8]) -> Result<String, String> {
    use qrcode::QrCode;

    let code = QrCode::new(data).map_err(|e| format!("QR failed: {:?}", e))?;

    let modules = code.to_colors();
    let size = code.width();
    let border = 2;
    let total = size + 4;

    let svg_capacity = total.saturating_mul(total).saturating_mul(60);
    let mut svg = String::with_capacity(svg_capacity);
    let _ = write!(svg, "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {total} {total}\" shape-rendering=\"crispEdges\"><rect width=\"{total}\" height=\"{total}\" fill=\"white\"/>");

    for (i, color) in modules.iter().enumerate() {
        if *color == qrcode::types::Color::Dark {
            let x = (i % size) + border;
            let y = (i / size) + border;
            let _ = write!(
                svg,
                "<rect x=\"{}\" y=\"{}\" width=\"1\" height=\"1\" fill=\"black\"/>",
                x, y
            );
        }
    }

    svg.push_str("</svg>");
    Ok(svg)
}

// ─── Multi-frame decoder ───

thread_local! {
    static DECODER: RefCell<DecoderState> = RefCell::new(DecoderState::new());
}

struct DecoderState {
    session_id: [u8; crate::transaction::interchange::qr::frame::SESSION_ID_LEN],
    session_active: bool,
    total_frames: u8,
    received: [bool; MAX_FRAMES],
    fragments: [Vec<u8>; MAX_FRAMES],
}

impl DecoderState {
    fn new() -> Self {
        Self {
            session_id: [0; crate::transaction::interchange::qr::frame::SESSION_ID_LEN],
            session_active: false,
            total_frames: 0,
            received: [false; MAX_FRAMES],
            fragments: core::array::from_fn(|_| Vec::new()),
        }
    }

    fn reset(&mut self) {
        self.session_id.fill(0);
        self.session_active = false;
        self.total_frames = 0;
        self.received = [false; MAX_FRAMES];
        for fragment in &mut self.fragments {
            fragment.clear();
        }
    }

    fn accept_session(
        &mut self,
        session_id: [u8; crate::transaction::interchange::qr::frame::SESSION_ID_LEN],
        total_frames: u8,
    ) -> Result<(), String> {
        if crate::transaction::interchange::qr::security::authorize_frame_session(
            self.session_active,
            &self.session_id,
            self.total_frames,
            &session_id,
            total_frames,
        )
        .is_err()
        {
            return Err("Mixed multi-frame QR session rejected".to_string());
        }
        if !self.session_active {
            self.session_id = session_id;
            self.session_active = true;
            self.total_frames = total_frames;
        }
        Ok(())
    }
}

pub fn decode_frame(frame_hex: &str) -> Result<Option<String>, String> {
    let payload = hex::decode(frame_hex).map_err(|error| format!("Invalid hex: {}", error))?;
    let frame = crate::transaction::interchange::qr::frame::parse_frame(&payload)
        .map_err(|error| format!("Invalid multi-frame QR: {:?}", error))?;
    let frame_index = usize::from(frame.frame_index);
    let total = usize::from(frame.total_frames);

    DECODER.with(|cell| {
        let mut state = cell.borrow_mut();
        state.accept_session(frame.session_id, frame.total_frames)?;

        if state.received[frame_index] {
            if state.fragments[frame_index].as_slice() != frame.fragment {
                return Err("Conflicting duplicate QR frame rejected".to_string());
            }
            return Ok(None);
        }
        state.received[frame_index] = true;
        state.fragments[frame_index] = frame.fragment.to_vec();

        if !(0..total).all(|index| state.received[index]) {
            return Ok(None);
        }

        let mut complete = Vec::new();
        for index in 0..total {
            complete.extend_from_slice(&state.fragments[index]);
        }
        let expected_session = state.session_id;
        if !crate::transaction::interchange::qr::frame::verify_session(&complete, &expected_session)
        {
            state.reset();
            return Err("Assembled QR session digest mismatch".to_string());
        }
        state.reset();
        Ok(Some(hex::encode(complete)))
    })
}

pub fn reset_decoder() {
    DECODER.with(|cell| {
        cell.borrow_mut().reset();
    });
}

/// Returns "received/total" string, e.g. "3/6" or "0/0" if no frames yet
pub fn decoder_progress() -> String {
    DECODER.with(|cell| {
        let state = cell.borrow();
        let total = state.total_frames as usize;
        if total == 0 {
            return "0/0".into();
        }
        let received = (0..total).filter(|&i| state.received[i]).count();
        let bits: Vec<String> = (0..total)
            .map(|i| {
                if state.received[i] {
                    "1".into()
                } else {
                    "0".into()
                }
            })
            .collect();
        format!(
            "{{\"total\":{},\"count\":{},\"bits\":[{}]}}",
            total,
            received,
            bits.join(",")
        )
    })
}

/// Generate a single QR code SVG from a plain UTF-8 string (no framing, no hex encoding).
/// Used for swap invites and other non-KSPT data exchange.
pub fn generate_svg_from_text(text: &str) -> Result<String, String> {
    qr_to_svg(text.as_bytes())
}
