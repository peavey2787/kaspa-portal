//! Power-on known-answer self-tests for embedded signers.
//!
//! Hardware wallets run these at boot, before any key is touched, to catch a
//! miscompiled or corrupted cryptographic core. Each runner returns
//! `(passed, total)`; the unit tests assert every runner passes on the host.

pub mod address;
pub mod bip32;
pub mod bip39;
pub mod kspt;
pub mod schnorr;
pub mod sighash;
pub mod xpub;
