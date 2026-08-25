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
        crate::transaction::mass::estimate_covenant_deposit_fee(
            self.payload_len,
            self.tag_genesis,
            input_count,
        )
    }
}
