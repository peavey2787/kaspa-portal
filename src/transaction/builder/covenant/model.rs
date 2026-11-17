use crate::wallet::account::derivation::WalletData;

/// Smallest change output that clears the KIP-9 storage-mass floor.
pub const KIP9_MIN_CHANGE_SOMPI: u64 = 10_000_000;

#[derive(Clone, Copy)]
pub enum CovenantEncoding<'a> {
    Payload {
        payload_hex: &'a str,
        tag_genesis: bool,
    },
    BoundGenesis,
}

impl<'a> CovenantEncoding<'a> {
    pub(crate) fn tag_genesis(self) -> bool {
        match self {
            Self::Payload { tag_genesis, .. } => tag_genesis,
            Self::BoundGenesis => true,
        }
    }

    pub(crate) fn uses_tagged_genesis_policy(self) -> bool {
        matches!(
            self,
            Self::Payload {
                tag_genesis: true,
                ..
            }
        )
    }
}

/// How far a manually selected covenant deposit may stray from the amount
/// asked for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CovenantFundingPolicy {
    /// A selection short of the amount plus fee deposits what it holds, less
    /// the fee; change is kept as an output.
    AdjustToSelection,
    /// As `AdjustToSelection`, and change below the KIP-9 storage-mass floor
    /// is folded into the covenant output.
    FoldSubKip9Change,
    /// The covenant receives exactly the amount asked for, because its script
    /// dispatches on that amount and holds any other value forever. A
    /// selection short of the amount plus fee is refused.
    Exact,
}

pub struct CovenantBuildRequest<'a> {
    pub wallet: &'a WalletData,
    pub covenant_address: &'a str,
    pub send_amount: u64,
    pub fee: u64,
    pub change_address: &'a str,
    pub utxo_indices_csv: &'a str,
    pub funding_policy: CovenantFundingPolicy,
    pub encoding: CovenantEncoding<'a>,
}
