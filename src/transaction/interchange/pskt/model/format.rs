// Kaspa Portal — PSKT / PSKB format model
// License: GPL-3.0

use serde::Serialize;

pub(crate) const PSKB_MAGIC: &[u8; 4] = b"PSKB";
pub(crate) const PSKT_MAGIC: &[u8; 4] = b"PSKT";

/// Detected wire format for a given hex payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PsktFormat {
    /// `PSKB` magic — body is `[<PSKT>]`.
    Pskb,
    /// `PSKT` magic — body is `<PSKT>` directly.
    PsktSingle,
    /// Not a PSKT-shaped payload.
    Unknown,
}
