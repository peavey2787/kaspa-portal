#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Subscribe,
    #[cfg(any(target_arch = "wasm32", test))]
    GetSink,
    SubmitTransaction,
    SubmitTransactionReplacement,
    GetBlock,
    GetBlocks,
    GetBlockDagInfo,
    GetUtxosByAddresses,
    GetFeeEstimate,
}

impl Operation {
    pub const fn code(self) -> u8 {
        match self {
            Self::Subscribe => 3,
            #[cfg(any(target_arch = "wasm32", test))]
            Self::GetSink => 120,
            Self::SubmitTransaction => 125,
            Self::GetBlock => 126,
            Self::GetBlocks => 129,
            Self::GetBlockDagInfo => 131,
            Self::GetUtxosByAddresses => 135,
            Self::SubmitTransactionReplacement => 146,
            Self::GetFeeEstimate => 147,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            3 => Some(Self::Subscribe),
            #[cfg(any(target_arch = "wasm32", test))]
            120 => Some(Self::GetSink),
            125 => Some(Self::SubmitTransaction),
            126 => Some(Self::GetBlock),
            129 => Some(Self::GetBlocks),
            131 => Some(Self::GetBlockDagInfo),
            135 => Some(Self::GetUtxosByAddresses),
            146 => Some(Self::SubmitTransactionReplacement),
            147 => Some(Self::GetFeeEstimate),
            _ => None,
        }
    }

    /// Whether this operation hands the node a transaction. A submission is
    /// never retried: the node may have accepted the first attempt.
    pub const fn is_submission(self) -> bool {
        matches!(
            self,
            Self::SubmitTransaction | Self::SubmitTransactionReplacement
        )
    }
}
