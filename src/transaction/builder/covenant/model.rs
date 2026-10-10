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

/// What a manually selected covenant send does with change below the KIP-9
/// storage-mass floor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CovenantDustPolicy {
    /// Keep the change output as requested.
    Preserve,
    /// Fold the change into the covenant output, so the whole selection
    /// (less the fee) funds the covenant.
    FoldSubKip9Change,
}

pub struct CovenantBuildRequest<'a> {
    pub wallet: &'a WalletData,
    pub covenant_address: &'a str,
    pub send_amount: u64,
    pub fee: u64,
    pub change_address: &'a str,
    pub utxo_indices_csv: &'a str,
    pub dust_policy: CovenantDustPolicy,
    pub encoding: CovenantEncoding<'a>,
}
