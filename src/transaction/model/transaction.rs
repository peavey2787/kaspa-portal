// Kaspa protocol implementation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::primitives::address::KaspaNetwork;
use alloc::vec::Vec;

use super::{
    constants::{
        SubnetworkId, DEFAULT_INPUT_CAPACITY, MAX_OUTPUTS, MAX_PAYLOAD_SIZE, MAX_REDEEM_SIZE,
        MAX_SCRIPT_SIZE, REDEEM_POOL_SIZE, SUBNETWORK_ID_NATIVE,
    },
    input::TransactionInput,
    output::TransactionOutput,
};

/// Aggregate monetary totals for a transaction after checked arithmetic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionAmounts {
    pub input_total: u64,
    pub output_total: u64,
    pub fee: u64,
}

/// Monetary-shape failures that must reject a transaction before review/signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionAmountError {
    InputTotalOverflow,
    OutputTotalOverflow,
    OutputsExceedInputs,
}

/// Storage-allocation and redeem-script storage failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionStorageError {
    AllocationFailed,
    RedeemScriptTooLarge,
    RedeemPoolFull,
}

/// A complete Kaspa transaction with inputs, outputs, and metadata.
#[derive(Debug)]
pub struct Transaction {
    pub version: u16,
    pub inputs: Vec<TransactionInput>,
    pub num_inputs: usize,
    pub outputs: [TransactionOutput; MAX_OUTPUTS],
    pub num_outputs: usize,
    /// Network bound by mandatory KSPT v1 metadata for address review.
    /// `Unknown` is valid only for a newly constructed, not-yet-serialized model.
    pub network: KaspaNetwork,
    pub locktime: u64,
    pub subnetwork_id: SubnetworkId,
    pub gas: u64,
    pub payload: [u8; MAX_PAYLOAD_SIZE],
    pub payload_len: usize,
    /// Stealth address tweak: if non-zero, the signing key is
    /// account_privkey + stealth_tweak (scalar addition mod n).
    /// Set by KasSee when spending a stealth UTXO.
    pub stealth_tweak: [u8; 32],
    pub has_stealth_tweak: bool,
    /// Shared pool for redeem scripts > MAX_SCRIPT_SIZE bytes.
    /// Inputs with `redeem_in_pool == true` store their redeem data here
    /// at `redeem_script_offset..redeem_script_offset + redeem_script_len`.
    pub redeem_pool: [u8; REDEEM_POOL_SIZE],
    /// Next free byte in redeem_pool.
    pub redeem_pool_used: usize,
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Transaction {
    /// Create an empty transaction. The input vector starts with capacity for
    /// ordinary eight-input transactions but grows dynamically as a PSKT/KSPT
    /// declares more inputs.
    pub fn new() -> Self {
        let mut inputs = Vec::with_capacity(DEFAULT_INPUT_CAPACITY);
        inputs.resize_with(DEFAULT_INPUT_CAPACITY, TransactionInput::empty);
        Self {
            version: 0,
            inputs,
            num_inputs: 0,
            outputs: core::array::from_fn(|_| TransactionOutput::empty()),
            num_outputs: 0,
            network: KaspaNetwork::Unknown,
            locktime: 0,
            subnetwork_id: SUBNETWORK_ID_NATIVE,
            gas: 0,
            payload: [0u8; MAX_PAYLOAD_SIZE],
            payload_len: 0,
            stealth_tweak: [0u8; 32],
            has_stealth_tweak: false,
            redeem_pool: [0u8; REDEEM_POOL_SIZE],
            redeem_pool_used: 0,
        }
    }

    /// Reset the transaction while retaining allocated input capacity.
    pub fn clear(&mut self) {
        self.version = 0;
        self.num_inputs = 0;
        for input in &mut self.inputs {
            *input = TransactionInput::empty();
        }
        for output in &mut self.outputs {
            *output = TransactionOutput::empty();
        }
        self.num_outputs = 0;
        self.network = KaspaNetwork::Unknown;
        self.locktime = 0;
        self.subnetwork_id = SUBNETWORK_ID_NATIVE;
        self.gas = 0;
        self.payload.fill(0);
        self.payload_len = 0;
        self.stealth_tweak.fill(0);
        self.has_stealth_tweak = false;
        self.redeem_pool.fill(0);
        self.redeem_pool_used = 0;
    }

    /// Ensure storage exists for every declared input. This grows only the
    /// backing vector; `num_inputs` remains controlled by the parser/builder.
    pub fn ensure_input_slots(&mut self, count: usize) -> Result<(), TransactionStorageError> {
        if count > self.inputs.len() {
            self.inputs
                .try_reserve(count - self.inputs.len())
                .map_err(|_| TransactionStorageError::AllocationFailed)?;
            self.inputs.resize_with(count, TransactionInput::empty);
        }
        Ok(())
    }

    /// Get the redeem script bytes for input `idx`.
    /// Returns the inline buffer if the script fits, or the pool slice
    /// if `redeem_in_pool` is set.
    pub fn redeem_bytes(&self, idx: usize) -> &[u8] {
        let inp = &self.inputs[idx];
        if inp.redeem_script_len == 0 {
            return &[];
        }
        if inp.redeem_in_pool {
            let off = inp.redeem_script_offset as usize;
            &self.redeem_pool[off..off + inp.redeem_script_len]
        } else {
            &inp.redeem_script[..inp.redeem_script_len]
        }
    }

    /// Store a redeem script for input `idx`. Scripts <= MAX_SCRIPT_SIZE
    /// go inline; larger ones go into the shared pool.
    /// Returns an explicit storage error if the script or shared pool cannot be stored.
    pub fn store_redeem(&mut self, idx: usize, data: &[u8]) -> Result<(), TransactionStorageError> {
        let len = data.len();
        if len == 0 {
            self.inputs[idx].redeem_script_len = 0;
            self.inputs[idx].redeem_in_pool = false;
            return Ok(());
        }
        if len <= MAX_SCRIPT_SIZE {
            self.inputs[idx].redeem_script[..len].copy_from_slice(data);
            self.inputs[idx].redeem_script_len = len;
            self.inputs[idx].redeem_in_pool = false;
        } else {
            if len > MAX_REDEEM_SIZE {
                return Err(TransactionStorageError::RedeemScriptTooLarge);
            }
            let off = self.redeem_pool_used;
            if off + len > REDEEM_POOL_SIZE {
                return Err(TransactionStorageError::RedeemPoolFull);
            }
            self.redeem_pool[off..off + len].copy_from_slice(data);
            self.inputs[idx].redeem_script_offset = off as u16;
            self.inputs[idx].redeem_script_len = len;
            self.inputs[idx].redeem_in_pool = true;
            self.redeem_pool_used = off + len;
        }
        Ok(())
    }

    /// Get the transaction inputs slice.
    pub fn inputs(&self) -> &[TransactionInput] {
        &self.inputs[..self.num_inputs]
    }

    /// Get the transaction outputs slice.
    pub fn outputs(&self) -> &[TransactionOutput] {
        &self.outputs[..self.num_outputs]
    }

    /// Returns true if the transaction subnetwork is native (not a registry tx).
    pub fn is_native(&self) -> bool {
        self.subnetwork_id == SUBNETWORK_ID_NATIVE
    }

    /// Calculate aggregate transaction amounts with checked arithmetic.
    ///
    /// A transaction is invalid if either aggregate exceeds `u64::MAX` or if
    /// outputs exceed inputs. Callers must propagate the error rather than
    /// displaying or signing a fabricated/saturated fee.
    pub fn checked_amounts(&self) -> Result<TransactionAmounts, TransactionAmountError> {
        let input_total = self.inputs().iter().try_fold(0u64, |total, input| {
            total
                .checked_add(input.utxo_entry.amount)
                .ok_or(TransactionAmountError::InputTotalOverflow)
        })?;
        let output_total = self.outputs().iter().try_fold(0u64, |total, output| {
            total
                .checked_add(output.value)
                .ok_or(TransactionAmountError::OutputTotalOverflow)
        })?;
        let fee = input_total
            .checked_sub(output_total)
            .ok_or(TransactionAmountError::OutputsExceedInputs)?;
        Ok(TransactionAmounts {
            input_total,
            output_total,
            fee,
        })
    }

    /// Calculate total sompi across inputs without overflow.
    pub fn total_input_value(&self) -> Result<u64, TransactionAmountError> {
        self.checked_amounts().map(|amounts| amounts.input_total)
    }

    /// Calculate total sompi across outputs without overflow.
    pub fn total_output_value(&self) -> Result<u64, TransactionAmountError> {
        self.checked_amounts().map(|amounts| amounts.output_total)
    }

    /// Implicit fee = inputs - outputs, rejecting an invalid monetary shape.
    pub fn fee(&self) -> Result<u64, TransactionAmountError> {
        self.checked_amounts().map(|amounts| amounts.fee)
    }

    /// Format a sompi value as KAS (no-alloc, returns in buffer)
    /// Example: 123_456_789 sompi -> "1.23456789"
    pub fn format_kas(sompi: u64, buf: &mut [u8]) -> usize {
        let kas = sompi / 100_000_000;
        let frac = sompi % 100_000_000;
        let mut pos = 0;

        // Integer part
        pos += Self::write_u64(kas, &mut buf[pos..]);

        // Decimal point
        if pos < buf.len() {
            buf[pos] = b'.';
            pos += 1;
        }

        // Fractional part (8 digits with leading zeros)
        let mut frac_buf = [b'0'; 8];
        let mut f = frac;
        for i in (0..8).rev() {
            frac_buf[i] = b'0' + (f % 10) as u8;
            f /= 10;
        }

        // Write fraction (trim unnecessary trailing zeros)
        let mut last_nonzero = 0;
        for (i, digit) in frac_buf.iter().enumerate() {
            if *digit != b'0' {
                last_nonzero = i;
            }
        }
        let frac_digits = if frac == 0 { 2 } else { last_nonzero + 1 };
        for digit in frac_buf.iter().take(frac_digits) {
            if pos < buf.len() {
                buf[pos] = *digit;
                pos += 1;
            }
        }

        pos
    }

    fn write_u64(mut val: u64, buf: &mut [u8]) -> usize {
        if val == 0 {
            if !buf.is_empty() {
                buf[0] = b'0';
            }
            return 1;
        }
        let mut digits = [0u8; 20];
        let mut count = 0;
        while val > 0 {
            digits[count] = b'0' + (val % 10) as u8;
            val /= 10;
            count += 1;
        }
        let written = count.min(buf.len());
        for i in 0..written {
            buf[i] = digits[count - 1 - i];
        }
        written
    }
}
