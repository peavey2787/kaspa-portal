use crate::wallet::account::derivation::WalletData;

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

pub struct CovenantBuildRequest<'a> {
    pub wallet: &'a WalletData,
    pub covenant_address: &'a str,
    pub send_amount: u64,
    pub fee: u64,
    pub change_address: &'a str,
    pub utxo_indices_csv: &'a str,
    pub encoding: CovenantEncoding<'a>,
}
