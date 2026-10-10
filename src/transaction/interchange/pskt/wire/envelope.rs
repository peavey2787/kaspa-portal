#[cfg(not(feature = "std"))]
use crate::alloc_prelude::*;
// Kaspa Portal — PSKT / PSKB envelope encoding
// License: GPL-3.0

use serde_json::Value;

use super::super::error::PsktWireError;
use super::super::model::{PsktFormat, PSKB_MAGIC, PSKT_MAGIC};
use super::json::{decode_json_body, encode_json_body};

#[derive(Clone, Copy)]
pub(crate) enum ErrorStyle {
    Standard,
    Review,
}

/// Detect the outer PSKT/PSKB wire envelope without decoding the payload.
pub fn detect_format_hex(hex_str: &str) -> PsktFormat {
    let Some(prefix) = hex_str.as_bytes().get(..8) else {
        return PsktFormat::Unknown;
    };
    if prefix.eq_ignore_ascii_case(b"50534b42") {
        PsktFormat::Pskb
    } else if prefix.eq_ignore_ascii_case(b"50534b54") {
        PsktFormat::PsktSingle
    } else {
        PsktFormat::Unknown
    }
}

fn decode_wire(wire_hex: &str) -> Result<(PsktFormat, Value), PsktWireError> {
    validate_outer_hex(wire_hex)?;
    let format = detect_format_hex(wire_hex);
    if format == PsktFormat::Unknown {
        return Err(PsktWireError::UnknownFormat);
    }

    let wire = hex::decode(wire_hex).map_err(|error| PsktWireError::OuterHex(error.to_string()))?;
    let expected_magic: &[u8; 4] = match format {
        PsktFormat::Pskb => PSKB_MAGIC,
        PsktFormat::PsktSingle => PSKT_MAGIC,
        PsktFormat::Unknown => return Err(PsktWireError::UnknownFormat),
    };
    if wire.get(..4) != Some(expected_magic.as_slice()) {
        return Err(PsktWireError::MagicMismatch);
    }

    Ok((format, decode_json_body(&wire[4..])?))
}

/// The signer's resource ceiling and lowercase-hex rule apply before any
/// allocation, exactly as on the verified pipeline's own decoder.
fn validate_outer_hex(wire_hex: &str) -> Result<(), PsktWireError> {
    if wire_hex.len() > crate::transaction::interchange::pskt::pipeline::MAX_PSKT_WIRE_HEX_CHARS {
        return Err(PsktWireError::OuterHex(
            "payload exceeds signer-compatible resource ceiling".to_string(),
        ));
    }
    let bytes = wire_hex.as_bytes();
    if !bytes.len().is_multiple_of(2)
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(PsktWireError::OuterHex(
            "outer PSKT/PSKB must be even-length lowercase hexadecimal".to_string(),
        ));
    }
    Ok(())
}

fn decode_root_with_style(
    wire_hex: &str,
    style: ErrorStyle,
) -> Result<(PsktFormat, Value), String> {
    decode_wire(wire_hex).map_err(|error| format_wire_error(error, style))
}

pub(crate) fn format_wire_error(error: PsktWireError, style: ErrorStyle) -> String {
    match (style, error) {
        (_, PsktWireError::UnknownFormat) => "Not a PSKT/PSKB payload".to_string(),
        (ErrorStyle::Standard, PsktWireError::OuterHex(message)) => {
            format!("outer hex: {message}")
        }
        (ErrorStyle::Review, PsktWireError::OuterHex(message)) => {
            format!("Bad outer hex: {message}")
        }
        (_, PsktWireError::MagicMismatch) => {
            "wire magic does not match detected format".to_string()
        }
        (_, PsktWireError::Json(message)) => format!("JSON parse: {message}"),
    }
}

pub(crate) fn decode_root(wire_hex: &str) -> Result<(PsktFormat, Value), String> {
    decode_root_with_style(wire_hex, ErrorStyle::Standard)
}

pub(crate) fn decode_root_for_review(wire_hex: &str) -> Result<(PsktFormat, Value), String> {
    decode_root_with_style(wire_hex, ErrorStyle::Review)
}

fn validate_single_pskt(root: &Value, format: PsktFormat) -> Result<(), String> {
    match format {
        PsktFormat::Pskb => {
            let entries = root
                .as_array()
                .ok_or_else(|| "PSKB body is not an array".to_string())?;
            if entries.len() != 1 {
                return Err(format!(
                    "PSKB must wrap exactly 1 PSKT, got {}",
                    entries.len()
                ));
            }
            Ok(())
        }
        PsktFormat::PsktSingle => Ok(()),
        PsktFormat::Unknown => Err("Not a PSKT/PSKB payload".into()),
    }
}

pub(crate) fn pskt_from_root_for_review(
    root: &Value,
    format: PsktFormat,
) -> Result<&Value, String> {
    validate_single_pskt(root, format)?;
    match format {
        PsktFormat::Pskb => root
            .as_array()
            .and_then(|entries| entries.first())
            .ok_or_else(|| "validated PSKB entry missing".to_string()),
        PsktFormat::PsktSingle => Ok(root),
        PsktFormat::Unknown => Err("Not a PSKT/PSKB payload".into()),
    }
}

pub(crate) fn first_pskt_from_pskb_mut(root: &mut Value) -> Result<&mut Value, String> {
    pskb_entries_mut(root)?
        .first_mut()
        .ok_or_else(|| "empty PSKB".to_string())
}

fn pskb_entries_mut(root: &mut Value) -> Result<&mut Vec<Value>, String> {
    root.as_array_mut()
        .ok_or_else(|| "PSKB not array".to_string())
}

pub(crate) fn encode_root(format: PsktFormat, root: &Value) -> Result<String, String> {
    let body = encode_json_body(root)?;
    let magic: &[u8; 4] = match format {
        PsktFormat::Pskb => PSKB_MAGIC,
        PsktFormat::PsktSingle => PSKT_MAGIC,
        PsktFormat::Unknown => return Err("cannot encode unknown PSKT format".into()),
    };
    let mut wire = Vec::with_capacity(4 + body.len());
    wire.extend_from_slice(magic);
    wire.extend_from_slice(&body);
    Ok(hex::encode(wire))
}
