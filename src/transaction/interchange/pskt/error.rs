// Kaspa Portal — PSKT / PSKB wire errors
// License: GPL-3.0

#[derive(Debug)]
pub(crate) enum PsktWireError {
    UnknownFormat,
    OuterHex(String),
    TooShort,
    MagicMismatch,
    InnerHex(String),
    Json(String),
}
