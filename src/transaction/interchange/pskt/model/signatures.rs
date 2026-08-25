// Kaspa Portal — parsed KSPT signature records
// License: GPL-3.0

pub(crate) struct KsptSigRecord {
    pub(crate) pubkey_pos: u8,
    pub(crate) sighash_type: u8,
    pub(crate) sig: [u8; 64],
}
