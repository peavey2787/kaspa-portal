use crate::transaction::interchange::pskt::{
    error::PsktWireError,
    wire::{decode_root, decode_root_for_review, format_wire_error, ErrorStyle},
};

fn clone_error(error: &PsktWireError) -> PsktWireError {
    match error {
        PsktWireError::UnknownFormat => PsktWireError::UnknownFormat,
        PsktWireError::OuterHex(message) => PsktWireError::OuterHex(message.clone()),
        PsktWireError::MagicMismatch => PsktWireError::MagicMismatch,
        PsktWireError::Json(message) => PsktWireError::Json(message.clone()),
    }
}

#[test]
fn wire_error_formatting_covers_standard_and_review_styles() {
    let cases = [
        (
            PsktWireError::UnknownFormat,
            "Not a PSKT/PSKB payload",
            "Not a PSKT/PSKB payload",
        ),
        (
            PsktWireError::OuterHex("bad".into()),
            "outer hex: bad",
            "Bad outer hex: bad",
        ),
        (
            PsktWireError::MagicMismatch,
            "wire magic does not match detected format",
            "wire magic does not match detected format",
        ),
        (
            PsktWireError::Json("bad".into()),
            "JSON parse: bad",
            "JSON parse: bad",
        ),
    ];

    for (error, standard, review) in cases {
        assert_eq!(
            format_wire_error(clone_error(&error), ErrorStyle::Standard),
            standard,
        );
        assert_eq!(format_wire_error(error, ErrorStyle::Review), review);
    }
}

#[test]
fn exact_four_byte_magic_is_not_misclassified_as_a_short_outer_envelope() {
    let standard = decode_root("50534b54").unwrap_err();
    assert_ne!(standard, "payload too short");
    assert!(standard.starts_with("JSON parse:") || standard.starts_with("inner hex:"));

    let review = decode_root_for_review("50534b42").unwrap_err();
    assert_ne!(review, "Payload too short");
    assert!(review.starts_with("JSON parse:") || review.starts_with("Bad inner hex:"));
}

#[test]
fn outer_envelope_is_lowercase_hex_within_the_signer_ceiling() {
    use crate::transaction::interchange::pskt::{detect_format_hex, PsktFormat};

    // Detection never slices inside a multi-byte character.
    assert_eq!(detect_format_hex("50534b\u{e9}"), PsktFormat::Unknown);
    assert_eq!(detect_format_hex("50534B42"), PsktFormat::Pskb);
    assert_eq!(detect_format_hex("50534b5"), PsktFormat::Unknown);

    let body = hex::encode(hex::encode(br#"{"global":{}}"#));
    let lower = format!("50534b54{body}");
    assert!(decode_root(&lower).is_ok());
    assert_eq!(
        decode_root(&lower.to_ascii_uppercase()).unwrap_err(),
        "outer hex: outer PSKT/PSKB must be even-length lowercase hexadecimal"
    );
    assert!(decode_root(&lower[..lower.len() - 1]).is_err());
    let oversized =
        "0".repeat(crate::transaction::interchange::pskt::pipeline::MAX_PSKT_WIRE_HEX_CHARS + 2);
    assert_eq!(
        decode_root(&format!("50534b54{oversized}")).unwrap_err(),
        "outer hex: payload exceeds signer-compatible resource ceiling"
    );
}
