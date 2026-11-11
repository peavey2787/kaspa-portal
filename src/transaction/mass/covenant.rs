//! Fee estimates for covenant-shaped transactions.

use super::{
    MASS_PER_SCRIPT_PUBLIC_KEY_BYTE, MASS_PER_SIG_OP, MASS_PER_TX_BYTE, MAX_STORAGE_MASS,
    MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM,
};

/// Transaction shape priced by the covenant fee estimate: P2PK funding
/// inputs, at most one P2SH covenant input carrying `redeem_bytes`, a
/// covenant output with `binding_bytes` of covenant binding, a P2PK change
/// output and `payload_bytes` of payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CovenantFeeShape {
    pub p2pk_inputs: u64,
    pub redeem_bytes: u64,
    pub payload_bytes: u64,
    pub binding_bytes: u64,
}

impl CovenantFeeShape {
    /// Minimum-rate fee for the shape with a 15% markup, never below 0.001 KAS.
    pub fn calculate(self) -> Result<u64, String> {
        const FEE_MARKUP_PERCENT: u64 = 115;
        const MINIMUM_FEE: u64 = 100_000;
        const BASE_TRANSACTION_BYTES: u64 = 46;
        const PER_P2PK_INPUT_BYTES: u64 = 45 + 66 + 4;
        const P2SH_INPUT_FIXED_BYTES: u64 = 118;
        const COVENANT_OUTPUT_BYTES: u64 = 35;
        const CHANGE_OUTPUT_BYTES: u64 = 43;
        const FRAMING_BYTES: u64 = 10;
        const SCRIPT_PUBLIC_KEY_MASS: u64 = (35 + 34) * MASS_PER_SCRIPT_PUBLIC_KEY_BYTE;

        let has_p2sh_input = self.redeem_bytes > 0;
        let input_count = self
            .p2pk_inputs
            .checked_add(u64::from(has_p2sh_input))
            .ok_or_else(|| "Covenant fee input-count overflow".to_string())?;
        let p2pk_bytes = self
            .p2pk_inputs
            .checked_mul(PER_P2PK_INPUT_BYTES)
            .ok_or_else(|| "Covenant fee input-byte estimate overflow".to_string())?;
        let p2sh_bytes = P2SH_INPUT_FIXED_BYTES
            .checked_add(self.redeem_bytes)
            .ok_or_else(|| "Covenant P2SH input-byte estimate overflow".to_string())?
            * u64::from(has_p2sh_input);
        let covenant_output_bytes = COVENANT_OUTPUT_BYTES
            .checked_add(self.binding_bytes)
            .ok_or_else(|| "Covenant fee output-byte estimate overflow".to_string())?;
        let estimated_transaction_bytes = BASE_TRANSACTION_BYTES
            .checked_add(p2pk_bytes)
            .and_then(|value| value.checked_add(p2sh_bytes))
            .and_then(|value| value.checked_add(covenant_output_bytes))
            .and_then(|value| value.checked_add(CHANGE_OUTPUT_BYTES))
            .and_then(|value| value.checked_add(self.payload_bytes))
            .and_then(|value| value.checked_add(FRAMING_BYTES))
            .ok_or_else(|| "Covenant transaction-byte estimate overflow".to_string())?;
        let signature_operation_mass = input_count
            .checked_mul(MASS_PER_SIG_OP)
            .ok_or_else(|| "Covenant signature-operation mass overflow".to_string())?;
        let compute_mass = estimated_transaction_bytes
            .checked_mul(MASS_PER_TX_BYTE)
            .and_then(|value| value.checked_add(signature_operation_mass))
            .and_then(|value| value.checked_add(SCRIPT_PUBLIC_KEY_MASS))
            .ok_or_else(|| "Covenant compute-mass estimate overflow".to_string())?;
        let fee = compute_mass
            .checked_mul(MIN_STANDARD_FEE_RATE_SOMPI_PER_GRAM)
            .and_then(|value| value.checked_mul(FEE_MARKUP_PERCENT))
            .map(|value| value / 100)
            .ok_or_else(|| "Covenant fee estimate overflow".to_string())?;
        Ok(fee.max(MINIMUM_FEE))
    }
}

/// A covenant thread spend that pays `withdraw` to a standard address and
/// returns the remainder to the covenant thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadWithdrawFee {
    pub thread_amount: u64,
    pub withdraw: u64,
    /// Fee floor; the remainder is estimated after it.
    pub minimum_fee: u64,
    pub fee_rate_sompi_per_gram: u64,
}

impl ThreadWithdrawFee {
    /// Compute mass of a one-input, two-output covenant thread spend.
    const COMPUTE_MASS: u64 = 2_500;
    /// Script-public-key lengths of the payout (P2PK) and the covenant (P2SH).
    const PAYOUT_SCRIPT_LEN: usize = 34;
    const COVENANT_SCRIPT_LEN: usize = 35;

    /// The larger of the compute and KIP-9 storage mass at the fee rate, never
    /// below the floor. Refuses a withdrawal whose remainder pushes storage
    /// mass past the consensus limit.
    pub fn calculate(self) -> Result<u64, String> {
        let remainder = self
            .thread_amount
            .checked_sub(self.withdraw)
            .and_then(|value| value.checked_sub(self.minimum_fee))
            .filter(|value| *value > 0 && self.withdraw > 0);
        let Some(remainder) = remainder else {
            return Ok(self.minimum_fee);
        };
        use crate::transaction::builder::planning::amounts::{
            storage_mass_estimate, utxo_plurality,
        };
        let covenant = utxo_plurality(Self::COVENANT_SCRIPT_LEN, true);
        let storage = storage_mass_estimate(
            &[(self.thread_amount, covenant)],
            &[
                (
                    self.withdraw,
                    utxo_plurality(Self::PAYOUT_SCRIPT_LEN, false),
                ),
                (remainder, covenant),
            ],
        )?;
        if storage > MAX_STORAGE_MASS {
            return Err("withdrawal leaves too small a remainder (storage mass)".to_string());
        }
        let fee = storage
            .max(Self::COMPUTE_MASS)
            .checked_mul(self.fee_rate_sompi_per_gram)
            .ok_or_else(|| "thread withdrawal fee overflow".to_string())?;
        Ok(fee.max(self.minimum_fee))
    }

    /// The largest withdrawal, at most `cap`, whose priced fee still leaves
    /// `minimum_return` in the covenant. `withdraw` is ignored; returns 0 when
    /// no withdrawal fits.
    #[must_use]
    pub fn maximum_withdraw(self, cap: u64, minimum_return: u64) -> u64 {
        let ceiling = self
            .thread_amount
            .saturating_sub(minimum_return)
            .saturating_sub(self.minimum_fee)
            .min(cap);
        // Fixes the answer one bit at a time from the top; a fit is monotone
        // in the amount, so this is a bounded 64-step binary search.
        (0..u64::BITS).rev().fold(0, |best, bit| {
            let candidate = best + (1 << bit);
            if candidate <= ceiling && self.leaves_return(candidate, minimum_return) {
                candidate
            } else {
                best
            }
        })
    }

    fn leaves_return(self, withdraw: u64, minimum_return: u64) -> bool {
        let priced = Self { withdraw, ..self }.calculate();
        priced.is_ok_and(|fee| {
            self.thread_amount
                .checked_sub(withdraw)
                .and_then(|left| left.checked_sub(fee))
                .is_some_and(|left| left >= minimum_return)
        })
    }
}
