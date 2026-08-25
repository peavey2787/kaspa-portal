//! Transaction envelope classification for compact KSPT, PSKB, and PSKT.

use crate::transaction::interchange::pskt::shared::TxInputFormat;

use super::PskError;

pub const PSKB_MAGIC: &[u8; 4] = b"PSKB";
pub const PSKT_MAGIC: &[u8; 4] = b"PSKT";
pub const KSPT_MAGIC: &[u8; 4] = b"KSPT";
const KSPT_VERSION: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectedFormat {
    KsptCompact,
    PsktPskb,
    PsktSingle,
    Unknown,
}

impl DetectedFormat {
    #[must_use]
    pub const fn to_tx_input_format(self) -> Option<TxInputFormat> {
        match self {
            Self::KsptCompact => Some(TxInputFormat::KsptCompact),
            Self::PsktPskb => Some(TxInputFormat::PsktPskb),
            Self::PsktSingle => Some(TxInputFormat::PsktSingle),
            Self::Unknown => None,
        }
    }
}

#[must_use]
pub fn detect_tx_format(data: &[u8]) -> DetectedFormat {
    if data.starts_with(KSPT_MAGIC) && data.get(4) == Some(&KSPT_VERSION) {
        DetectedFormat::KsptCompact
    } else if data.starts_with(PSKB_MAGIC) {
        DetectedFormat::PsktPskb
    } else if data.starts_with(PSKT_MAGIC) {
        DetectedFormat::PsktSingle
    } else {
        DetectedFormat::Unknown
    }
}

pub fn strip_pskt_magic(data: &[u8]) -> Result<&[u8], PskError> {
    if data.len() < 4 {
        return Err(PskError::TooShort);
    }
    let magic = &data[..4];
    if magic != PSKB_MAGIC && magic != PSKT_MAGIC {
        return Err(PskError::BadMagic);
    }
    let body = &data[4..];
    if body.is_empty() {
        return Err(PskError::TruncatedEnvelope);
    }
    Ok(body)
}
