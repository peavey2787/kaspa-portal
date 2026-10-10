#[derive(Debug, Clone, Copy)]
pub(super) struct DepositFeePolicy {
    payload_len: u64,
    tag_genesis: bool,
}

impl DepositFeePolicy {
    pub(super) fn new(payload_len: u64, tag_genesis: bool) -> Self {
        Self {
            payload_len,
            tag_genesis,
        }
    }

    pub(super) fn calculate(self, input_count: u64) -> Result<u64, String> {
        crate::transaction::mass::CovenantFeeShape {
            p2pk_inputs: input_count,
            redeem_bytes: 0,
            payload_bytes: self.payload_len,
            binding_bytes: if self.tag_genesis { 32 } else { 0 },
        }
        .calculate()
    }
}
