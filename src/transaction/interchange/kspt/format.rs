/// Magic bytes for compact KSPT transaction envelopes.
pub(crate) const KSPT_MAGIC: [u8; 4] = *b"KSPT";
/// Magic bytes for KSSN signature responses.
pub(crate) const KSSN_MAGIC: [u8; 4] = *b"KSSN";

pub(crate) const KSPT_VERSION_CURRENT: u8 = 0x01;
pub(crate) const KSSN_VERSION_CURRENT: u8 = 0x01;

pub(crate) const FLAG_SIGNED_OR_COMPLETE: u8 = 0x01;
pub(crate) const PARTIAL_SIGNED_ALLOWED_FLAGS: u8 = FLAG_SIGNED_OR_COMPLETE;

pub(crate) const STEALTH_TRAILER_MARKER: u8 = b'S';
pub(crate) const COVENANT_TRAILER_MARKER: u8 = b'C';
pub(crate) const NETWORK_TRAILER_MARKER: u8 = b'N';
pub(crate) const DERIVATION_TRAILER_MARKER: u8 = b'D';
/// Coordinated-multisig v1 derivation records. Each record carries
/// index(u8)+cosigner(u32 LE)+chain(u32 LE)+address_index(u32 LE).
pub(crate) const MS45_INPUT_TRAILER_MARKER: u8 = b'I';
pub(crate) const MS45_OUTPUT_TRAILER_MARKER: u8 = b'O';
