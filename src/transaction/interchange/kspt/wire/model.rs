//! Value types and limits of the canonical compact KSPT v1 grammar.

pub(crate) use super::super::format::{
    COVENANT_EXECUTION_TRAILER_MARKER as COVENANT_EXECUTION_MARKER,
    COVENANT_TRAILER_MARKER as COVENANT_MARKER,
    DERIVATION_TRAILER_MARKER as OUTPUT_DERIVATION_MARKER,
    INPUT_DERIVATION_TRAILER_MARKER as INPUT_DERIVATION_MARKER,
    MS45_INPUT_TRAILER_MARKER as MS45_INPUT_MARKER,
    MS45_OUTPUT_TRAILER_MARKER as MS45_OUTPUT_MARKER, NETWORK_TRAILER_MARKER as NETWORK_MARKER,
    PARTIAL_SIGNED_ALLOWED_FLAGS as ALLOWED_FLAGS, STEALTH_TRAILER_MARKER as STEALTH_MARKER,
};
pub use super::super::format::{
    FLAG_SIGNED_OR_COMPLETE, KSPT_MAGIC as MAGIC, KSPT_VERSION_CURRENT as KSPT_VERSION,
};
pub use crate::transaction::model::{MAX_REDEEM_SIZE, MAX_SCRIPT_SIZE};
/// Most signature records one input may carry.
pub const MAX_SIGNATURE_RECORDS: usize = crate::transaction::model::MAX_SIGS_PER_INPUT;
/// Most outputs the grammar can describe.
pub const MAX_OUTPUTS: u8 = crate::transaction::model::MAX_OUTPUTS as u8;
pub(crate) const EXTENDED_SCRIPT_LENGTH: u8 = 0xff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    max_inputs: u32,
    max_outputs: u8,
    max_payload: usize,
}

impl Limits {
    pub const fn new(max_inputs: u32, max_outputs: u8, max_payload: usize) -> Self {
        Self {
            max_inputs,
            max_outputs,
            max_payload,
        }
    }

    /// Most inputs accepted.
    pub const fn max_inputs(self) -> u32 {
        self.max_inputs
    }

    /// Most outputs accepted.
    pub const fn max_outputs(self) -> u8 {
        self.max_outputs
    }

    /// Largest payload accepted, in bytes.
    pub const fn max_payload(self) -> usize {
        self.max_payload
    }

    /// The widest limits the grammar itself permits.
    pub const fn grammar() -> Self {
        Self::new(u32::MAX, MAX_OUTPUTS, u16::MAX as usize)
    }

    pub(crate) fn validate_inputs(self, input_count: u32) -> Result<(), super::WireError> {
        if input_count > self.max_inputs {
            return Err(super::WireError::TooManyInputs);
        }
        Ok(())
    }

    pub(crate) fn validate_outputs(self, output_count: u8) -> Result<(), super::WireError> {
        if output_count > self.max_outputs {
            return Err(super::WireError::TooManyOutputs);
        }
        Ok(())
    }

    pub(crate) fn validate_payload(self, payload_len: usize) -> Result<(), super::WireError> {
        if payload_len > self.max_payload {
            return Err(super::WireError::PayloadTooLong);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Global<'a> {
    pub flags: u8,
    pub version: u16,
    pub input_count: u32,
    pub output_count: u8,
    pub locktime: u64,
    pub subnetwork_id: [u8; 20],
    pub gas: u64,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Input<'a> {
    pub previous_tx_id: [u8; 32],
    pub previous_index: u32,
    pub amount: u64,
    pub sequence: u64,
    pub sig_op_count: u8,
    pub script_version: u16,
    pub script: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Signature {
    pub position: u8,
    pub sighash: u8,
    pub bytes: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Output<'a> {
    pub amount: u64,
    pub script_version: u16,
    pub script: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Derivation {
    pub branch: u8,
    pub index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ms45Derivation {
    pub cosigner: u32,
    pub chain: u32,
    pub index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CovenantExecution {
    pub supplied_mask: u16,
    pub supplied_true_mask: u16,
}

pub const fn valid_covenant_execution(value: CovenantExecution) -> bool {
    value.supplied_true_mask & !value.supplied_mask == 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Covenant {
    pub authorizing_input: u16,
    pub id: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedEnvelope {
    pub flags: u8,
}

pub const fn valid_sighash(value: u8) -> bool {
    matches!(value, 0x01 | 0x02 | 0x04 | 0x81 | 0x82 | 0x84)
}

pub const fn valid_network(value: u8) -> bool {
    value >= 1 && value <= 4
}

pub const fn valid_derivation(value: Derivation) -> bool {
    value.branch <= 1 && value.index < 0x8000_0000
}

pub const fn valid_ms45(value: Ms45Derivation) -> bool {
    value.chain <= 1 && value.cosigner < 0x8000_0000 && value.index < 0x8000_0000
}
